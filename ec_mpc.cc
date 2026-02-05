// Copyright 2025 Guowei Ling.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "examples/oryxcpp/ec_mpc.h"

#include <cstring>
#include <vector>

#include "examples/oryxcpp/spdz_mpc.h"
#include "yacl/base/exception.h"
#include "yacl/link/context.h"
#include "yacl/utils/serialize.h"

namespace yacl::examples::pii {

EcMpcSystem::EcMpcSystem(
    size_t rank, size_t world_size,
    const std::vector<std::shared_ptr<yacl::link::Context>>& ctxs,
    std::shared_ptr<yacl::crypto::EcGroup> ec_group,
    bool malicious_security)
    : rank_(rank),
      world_size_(world_size),
      ec_group_(ec_group),
      malicious_security_(malicious_security) {
  YACL_ENFORCE(!ctxs.empty(), "Contexts vector cannot be empty");
  ctx_ = ctxs[0];  // Use the first (and only) context
  YACL_ENFORCE(ec_group_ != nullptr, "EC group cannot be null");
  
  // Get the order of the curve (n)
  prime_ = ec_group_->GetOrder();

  // Generate MAC key share αi (only for malicious security)
  if (malicious_security_) {
    // In SPDZ, the global MAC key α = Σαi is secret-shared
    // Each party generates its own random MAC key share αi
    // The global key α = Σαi is never reconstructed
    yacl::math::MPInt::RandomLtN(prime_, &mac_key_share_);
  } else {
    // Semi-honest: no MAC key needed
    mac_key_share_ = yacl::math::MPInt(0);
  }
}

EcPointShare EcMpcSystem::GenerateRandomShare() {
  EcPointShare share;
  
  // Generate random δP (only for malicious security)
  if (malicious_security_) {
    // Generate random scalar for delta point
    yacl::math::MPInt delta_scalar;
    yacl::math::MPInt::RandomLtN(prime_, &delta_scalar);
    share.delta_point = ec_group_->MulBase(delta_scalar);  // δP = δ * G
  } else {
    // For semi-honest, we can use infinity point
    yacl::math::MPInt zero;
    zero.SetZero();
    share.delta_point = ec_group_->MulBase(zero);  // Infinity point
  }
  
  // Generate random point share
  yacl::math::MPInt random_scalar;
  yacl::math::MPInt::RandomLtN(prime_, &random_scalar);
  share.point_share = ec_group_->MulBase(random_scalar);  // Random point on curve
  
  // MAC share will be computed during Open() based on opened_point (only for malicious)
  share.mac_share = yacl::math::MPInt(0);
  
  return share;
}

EcPointShare EcMpcSystem::RandomShare() {
  // Generate random share locally
  EcPointShare share = GenerateRandomShare();
  
  // Broadcast delta_point and point_share to all other parties
  // Serialize delta_point
  auto delta_buf = ec_group_->SerializePoint(share.delta_point);
  auto point_buf = ec_group_->SerializePoint(share.point_share);
  
  uint32_t delta_len = static_cast<uint32_t>(delta_buf.size());
  uint32_t point_len = static_cast<uint32_t>(point_buf.size());
  
  std::vector<uint8_t> data(sizeof(delta_len) + delta_buf.size() +
                           sizeof(point_len) + point_buf.size());
  size_t offset = 0;
  std::memcpy(data.data() + offset, &delta_len, sizeof(delta_len));
  offset += sizeof(delta_len);
  std::memcpy(data.data() + offset, delta_buf.data<uint8_t>(), delta_buf.size());
  offset += delta_buf.size();
  std::memcpy(data.data() + offset, &point_len, sizeof(point_len));
  offset += sizeof(point_len);
  std::memcpy(data.data() + offset, point_buf.data<uint8_t>(), point_buf.size());
  
  // Send to all other parties (use Send instead of SendAsync to ensure synchronization)
  for (size_t i = 0; i < world_size_; ++i) {
    if (i == rank_) continue;
    ctx_->Send(i, yacl::ByteContainerView(data), "random_share");
  }
  
  // Receive from all other parties
  for (size_t i = 0; i < world_size_; ++i) {
    if (i == rank_) continue;
    auto recv_data = ctx_->Recv(i, "random_share");
    // Process received share if needed (currently just receives for synchronization)
  }
  
  return share;
}

EcPointShare EcMpcSystem::ShareMyValue(const yacl::crypto::EcPoint& point) {
  EcPointShare share;
  
  // Generate random δP (only for malicious security)
  if (malicious_security_) {
    yacl::math::MPInt delta_scalar;
    yacl::math::MPInt::RandomLtN(prime_, &delta_scalar);
    share.delta_point = ec_group_->MulBase(delta_scalar);
  } else {
    yacl::math::MPInt zero(0);
    share.delta_point = ec_group_->MulBase(zero);  // Infinity point
  }
  
  // Generate random point shares
  // For point P, we need to generate shares P1, ..., Pn such that ΣPi = P
  std::vector<yacl::crypto::EcPoint> all_point_shares(world_size_);
  // Start with infinity point
  yacl::math::MPInt zero(0);
  yacl::crypto::EcPoint sum = ec_group_->MulBase(zero);
  
  // Generate random shares for parties 0 to n-2
  for (size_t i = 0; i < world_size_ - 1; ++i) {
    yacl::math::MPInt random_scalar;
    yacl::math::MPInt::RandomLtN(prime_, &random_scalar);
    all_point_shares[i] = ec_group_->MulBase(random_scalar);
    sum = ec_group_->Add(sum, all_point_shares[i]);
  }
  
  // Last share makes sum equal to point
  // P = ΣPi, so Pn-1 = P - Σ_{i=0}^{n-2} Pi
  all_point_shares[world_size_ - 1] = ec_group_->Sub(point, sum);
  
  share.point_share = all_point_shares[rank_];
  
  // MAC share will be computed during Open() based on opened_point
  // For now, set it to 0 (will be recomputed during Open)
  share.mac_share = yacl::math::MPInt(0);
  
  // Send delta_point and each party's point share to all other parties
  std::string tag = "share_ec_point_" + std::to_string(rank_);
  for (size_t i = 0; i < world_size_; ++i) {
    if (i != rank_) {
      auto delta_buf = ec_group_->SerializePoint(share.delta_point);
      auto point_buf = ec_group_->SerializePoint(all_point_shares[i]);
      
      uint32_t delta_len = static_cast<uint32_t>(delta_buf.size());
      uint32_t point_len = static_cast<uint32_t>(point_buf.size());
      
      std::vector<uint8_t> data(sizeof(delta_len) + delta_buf.size() +
                               sizeof(point_len) + point_buf.size());
      size_t offset = 0;
      std::memcpy(data.data() + offset, &delta_len, sizeof(delta_len));
      offset += sizeof(delta_len);
      std::memcpy(data.data() + offset, delta_buf.data<uint8_t>(), delta_buf.size());
      offset += delta_buf.size();
      std::memcpy(data.data() + offset, &point_len, sizeof(point_len));
      offset += sizeof(point_len);
      std::memcpy(data.data() + offset, point_buf.data<uint8_t>(), point_buf.size());
      
      ctx_->Send(i, yacl::ByteContainerView(data), tag);
    }
  }
  
  return share;
}

EcPointShare EcMpcSystem::ShareValue(const yacl::crypto::EcPoint& point, size_t sharer_rank) {
  // Check if this party should receive (point is infinity and we're not the sharer)
  // Note: We use a different approach - check if rank != sharer_rank to determine receiver
  yacl::math::MPInt zero(0);
  yacl::crypto::EcPoint infinity = ec_group_->MulBase(zero);
  bool is_infinity = ec_group_->IsInfinity(point) || ec_group_->PointEqual(point, infinity);
  
  if (is_infinity && rank_ != sharer_rank) {
    // This party is a receiver, wait for share from sharer_rank
    std::string tag = "share_ec_point_" + std::to_string(sharer_rank);
    auto recv_data = ctx_->Recv(sharer_rank, tag);
    
    uint32_t delta_len, point_len;
    const uint8_t* data_ptr = reinterpret_cast<const uint8_t*>(recv_data.data());
    std::memcpy(&delta_len, data_ptr, sizeof(delta_len));
    
    EcPointShare share;
    share.delta_point = ec_group_->DeserializePoint(
        yacl::ByteContainerView(data_ptr + sizeof(delta_len), delta_len));
    
    size_t offset = sizeof(delta_len) + delta_len;
    std::memcpy(&point_len, data_ptr + offset, sizeof(point_len));
    offset += sizeof(point_len);
    
    share.point_share = ec_group_->DeserializePoint(
        yacl::ByteContainerView(data_ptr + offset, point_len));
    
    // MAC share will be computed during Open() based on opened_point
    // For now, set it to 0 (will be recomputed during Open)
    share.mac_share = yacl::math::MPInt(0);
    
    return share;
  }
  
  // This party is sharing its own value
  return ShareMyValue(point);
}

EcPointShare EcMpcSystem::Add(const EcPointShare& a, const EcPointShare& b) {
  EcPointShare result;
  
  // Add delta points: δP + δQ
  result.delta_point = ec_group_->Add(a.delta_point, b.delta_point);
  
  // Add point shares: Pi + Qi
  result.point_share = ec_group_->Add(a.point_share, b.point_share);
  
  // Add MAC shares: γi(P) + γi(Q)
  result.mac_share = (a.mac_share + b.mac_share) % prime_;
  
  return result;
}

EcPointShare EcMpcSystem::Sub(const EcPointShare& a, const EcPointShare& b) {
  EcPointShare result;
  
  // Subtract delta points: δP - δQ
  result.delta_point = ec_group_->Sub(a.delta_point, b.delta_point);
  
  // Subtract point shares: Pi - Qi
  result.point_share = ec_group_->Sub(a.point_share, b.point_share);
  
  // Subtract MAC shares: γi(P) - γi(Q)
  result.mac_share = (a.mac_share - b.mac_share + prime_) % prime_;
  
  return result;
}

EcPointShare EcMpcSystem::MulScalar(const yacl::math::MPInt& scalar, const EcPointShare& point) {
  EcPointShare result;
  
  // Scalar multiplication on delta point: k * δP
  result.delta_point = ec_group_->Mul(point.delta_point, scalar);
  
  // Scalar multiplication on point share: k * Pi
  result.point_share = ec_group_->Mul(point.point_share, scalar);
  
  // Scalar multiplication on MAC share: k * γi(P)
  result.mac_share = (scalar * point.mac_share) % prime_;
  
  return result;
}

yacl::crypto::EcPoint EcMpcSystem::PartialOpen(const EcPointShare& share) {
  // Reconstruct the point by exchanging point shares
  yacl::crypto::EcPoint point = share.point_share;
  
  // Exchange shares with all other parties
  // Send my share
  for (size_t i = 0; i < world_size_; ++i) {
    if (i != rank_) {
      auto point_buf = ec_group_->SerializePoint(share.point_share);
      uint32_t len = static_cast<uint32_t>(point_buf.size());
      std::vector<uint8_t> data(sizeof(len) + point_buf.size());
      std::memcpy(data.data(), &len, sizeof(len));
      std::memcpy(data.data() + sizeof(len), point_buf.data<uint8_t>(), point_buf.size());
      ctx_->SendAsync(i, yacl::ByteContainerView(data), "partial_open_ec");
    }
  }
  
  // Receive shares from all other parties
  for (size_t i = 0; i < world_size_; ++i) {
    if (i != rank_) {
      auto data = ctx_->Recv(i, "partial_open_ec");
      uint32_t len;
      std::memcpy(&len, data.data(), sizeof(len));
      const uint8_t* data_ptr = reinterpret_cast<const uint8_t*>(data.data());
      yacl::crypto::EcPoint other_share = ec_group_->DeserializePoint(
          yacl::ByteContainerView(data_ptr + sizeof(len), len));
      point = ec_group_->Add(point, other_share);
    }
  }
  
  return point;
}

yacl::crypto::EcPoint EcMpcSystem::Open(const EcPointShare& share) {
  // Open the point
  yacl::crypto::EcPoint opened_point = PartialOpen(share);
  
  // MAC verification (only for malicious security)
  if (malicious_security_) {
    // Compute MAC share based on opened_point: γi(P) = αi * H(P + δP)
    // This should match what was computed in ShareValue, but we compute it here
    // to ensure consistency with opened_point
    auto point_plus_delta = ec_group_->Add(opened_point, share.delta_point);
    auto serialized = ec_group_->SerializePoint(point_plus_delta);
    yacl::math::MPInt hash_value;
    if (serialized.size() >= 32) {
      hash_value.FromMagBytes(yacl::ByteContainerView(serialized.data(), 32), yacl::Endian::native);
      hash_value = hash_value % prime_;
    } else {
      std::vector<uint8_t> padded(32, 0);
      std::memcpy(padded.data(), serialized.data(), serialized.size());
      hash_value.FromMagBytes(yacl::ByteContainerView(padded), yacl::Endian::native);
      hash_value = hash_value % prime_;
    }
    yacl::math::MPInt computed_mac_share = (mac_key_share_ * hash_value) % prime_;
    
    // Create a new share with the computed MAC share for verification
    EcPointShare share_with_mac = share;
    share_with_mac.mac_share = computed_mac_share;
    
    // Verify MAC
    if (!VerifyMac(share_with_mac, opened_point)) {
      YACL_THROW("MAC verification failed, aborting protocol");
    }
  }
  
  return opened_point;
}

bool EcMpcSystem::VerifyMac(const EcPointShare& share,
                            const yacl::crypto::EcPoint& opened_point) {
  // MAC verification for elliptic curve points
  // Compute expected MAC contribution: ti = γi(P) - αi * H(P + δP)
  auto point_plus_delta = ec_group_->Add(opened_point, share.delta_point);
  auto serialized = ec_group_->SerializePoint(point_plus_delta);
  yacl::math::MPInt hash_value;
  if (serialized.size() >= 32) {
    hash_value.FromMagBytes(yacl::ByteContainerView(serialized.data(), 32), yacl::Endian::native);
    hash_value = hash_value % prime_;
  } else {
    std::vector<uint8_t> padded(32, 0);
    std::memcpy(padded.data(), serialized.data(), serialized.size());
    hash_value.FromMagBytes(yacl::ByteContainerView(padded), yacl::Endian::native);
    hash_value = hash_value % prime_;
  }
  
  yacl::math::MPInt expected_mac_contribution = (mac_key_share_ * hash_value) % prime_;
  yacl::math::MPInt ti = (share.mac_share - expected_mac_contribution + prime_) % prime_;
  
  // Exchange ti with all other parties and verify Σti = 0
  auto ti_buf = ti.ToMagBytes();
  uint32_t ti_len = static_cast<uint32_t>(ti_buf.size());
  std::vector<uint8_t> data(sizeof(ti_len) + ti_buf.size());
  std::memcpy(data.data(), &ti_len, sizeof(ti_len));
  std::memcpy(data.data() + sizeof(ti_len), ti_buf.data<uint8_t>(), ti_buf.size());
  
  for (size_t i = 0; i < world_size_; ++i) {
    if (i != rank_) {
      ctx_->SendAsync(i, yacl::ByteContainerView(data), "mac_verify_ec");
    }
  }
  
  // Receive ti from all other parties
  yacl::math::MPInt sum_ti = ti;
  for (size_t i = 0; i < world_size_; ++i) {
    if (i != rank_) {
      auto recv_data = ctx_->Recv(i, "mac_verify_ec");
      uint32_t recv_ti_len;
      const uint8_t* recv_data_ptr = reinterpret_cast<const uint8_t*>(recv_data.data());
      std::memcpy(&recv_ti_len, recv_data_ptr, sizeof(recv_ti_len));
      yacl::math::MPInt other_ti;
      other_ti.FromMagBytes(
          yacl::ByteContainerView(recv_data_ptr + sizeof(recv_ti_len), recv_ti_len),
          yacl::Endian::native);
      sum_ti = (sum_ti + other_ti) % prime_;
    }
  }
  
  // Check if Σti = 0
  yacl::math::MPInt zero(0);
  return (sum_ti == zero);
}

EcPointShare EcMpcSystem::SharePublicPoint(const yacl::crypto::EcPoint& point) {
  // Create a share for a public point (all parties know it)
  // For a public point P, we create shares where:
  // - Party 0: point_share = P, others: point_share = 0
  // - delta_point = 0 (infinity) for semi-honest, or random for malicious
  EcPointShare share;
  
  if (malicious_security_) {
    // For malicious security, generate random delta
    yacl::math::MPInt delta_scalar;
    yacl::math::MPInt::RandomLtN(prime_, &delta_scalar);
    share.delta_point = ec_group_->MulBase(delta_scalar);
  } else {
    // For semi-honest, delta is infinity
    yacl::math::MPInt zero(0);
    share.delta_point = ec_group_->MulBase(zero);
  }
  
  // Point share: Party 0 gets the point, others get infinity
  if (rank_ == 0) {
    share.point_share = point;
  } else {
    yacl::math::MPInt zero(0);
    share.point_share = ec_group_->MulBase(zero);
  }
  
  // MAC share: will be computed during Open() if needed
  share.mac_share = yacl::math::MPInt(0);
  
  return share;
}

EcPointShare EcMpcSystem::MulSecretScalarPublicPoint(const SecretShare& k_share,
                                                     const yacl::crypto::EcPoint& public_point) {
  // Compute [k] * P = [k*P] where [k] is secret-shared and P is public
  // Simple protocol: each party computes k_i * P and shares it, then combine
  // [k*P] = Σ_i [k_i * P]_i where k_i is party i's share of [k]
  
  // Each party computes k_i * P (where k_i is this party's share of [k])
  yacl::crypto::EcPoint k_i_P = ec_group_->Mul(public_point, k_share.value_share);
  
  // Share k_i * P and combine shares from all parties
  EcPointShare result = ShareMyValue(k_i_P);
  for (size_t j = 0; j < world_size_; ++j) {
    if (j != rank_) {
      yacl::math::MPInt zero(0);
      yacl::crypto::EcPoint infinity = ec_group_->MulBase(zero);
      EcPointShare k_j_P_share = ShareValue(infinity, j);
      result = Add(result, k_j_P_share);
    }
  }
  
  return result;
}

EcPointShare EcMpcSystem::MulSecretScalar(const SecretShare& k_share,
                                           const EcPointShare& point_share,
                                           SpdzMpcSystem* fp_mpc) {
  // Compute [k] * [P] = [k*P] using SecSarMul3_G protocol from the paper
  // Protocol:
  // 1. Use Beaver triple ([a], [b], [c]) over F_p where c = a * b mod p
  // 2. [B] = SecSarMul1_G([b], G) - secret scalar [b] * public point G
  // 3. [C] = SecSarMul1_G([c], G) - secret scalar [c] * public point G
  // 4. [u] = SecSub_Fp([k], [a]) - [k] - [a] in Fp
  // 5. [T] = SecSub_G([P], [B]) - [P] - [B] in G
  // 6. Partially open u and T
  // 7. [V] = SecSarMul1_G([u], T) - secret scalar [u] * public point T
  // 8. [Z] = SecSarMul1_G([a], T) - secret scalar [a] * public point T
  // 9. [U] = SecSarMul2_G(u, [B]) - public scalar u * secret point [B]
  // 10. [k*P] = [C] + [V] + [Z] + [U]
  
  YACL_ENFORCE(fp_mpc != nullptr, "Fp MPC system is required for SecSarMul3_G");
  
  // Step 1: Generate Beaver triple ([a], [b], [c]) over F_p
  auto [a_share, b_share, c_share] = fp_mpc->GenerateBeaverTriple();
  
  // Step 2: [B] = SecSarMul1_G([b], G) - secret scalar [b] * public point G
  // Each party computes b_i * G and shares it, then combine
  yacl::crypto::EcPoint G = ec_group_->GetGenerator();
  yacl::crypto::EcPoint b_i_G = ec_group_->Mul(G, b_share.value_share);
  EcPointShare B_share = ShareMyValue(b_i_G);
  // Combine shares from all parties: [B] = Σ_i [b_i * G]_i
  for (size_t j = 0; j < world_size_; ++j) {
    if (j != rank_) {
      yacl::math::MPInt zero(0);
      yacl::crypto::EcPoint infinity = ec_group_->MulBase(zero);
      EcPointShare B_j_share = ShareValue(infinity, j);
      B_share = Add(B_share, B_j_share);
    }
  }
  
  // Step 3: [C] = SecSarMul1_G([c], G) - secret scalar [c] * public point G
  yacl::crypto::EcPoint c_i_G = ec_group_->Mul(G, c_share.value_share);
  EcPointShare C_share = ShareMyValue(c_i_G);
  // Combine shares from all parties
  for (size_t j = 0; j < world_size_; ++j) {
    if (j != rank_) {
      yacl::math::MPInt zero(0);
      yacl::crypto::EcPoint infinity = ec_group_->MulBase(zero);
      EcPointShare C_j_share = ShareValue(infinity, j);
      C_share = Add(C_share, C_j_share);
    }
  }
  
  // Step 4: [u] = SecSub_Fp([k], [a]) - [k] - [a] in Fp
  SecretShare u_share = fp_mpc->Sub(k_share, a_share);
  
  // Step 5: [T] = SecSub_G([P], [B]) - [P] - [B] in G
  EcPointShare T_share = Sub(point_share, B_share);
  
  // Step 6: Partially open u and T
  yacl::math::MPInt u = fp_mpc->PartialOpen(u_share);
  yacl::crypto::EcPoint T = PartialOpen(T_share);
  
  // Step 7: [V] = SecSarMul1_G([u], T) - secret scalar [u] * public point T
  // Since T is public, we can compute [u] * T by: each party computes u_i * T and shares it
  yacl::crypto::EcPoint u_i_T = ec_group_->Mul(T, u_share.value_share);
  EcPointShare V_share = ShareMyValue(u_i_T);
  // Combine shares from all parties
  for (size_t j = 0; j < world_size_; ++j) {
    if (j != rank_) {
      yacl::math::MPInt zero(0);
      yacl::crypto::EcPoint infinity = ec_group_->MulBase(zero);
      EcPointShare V_j_share = ShareValue(infinity, j);
      V_share = Add(V_share, V_j_share);
    }
  }
  
  // Step 8: [Z] = SecSarMul1_G([a], T) - secret scalar [a] * public point T
  yacl::crypto::EcPoint a_i_T = ec_group_->Mul(T, a_share.value_share);
  EcPointShare Z_share = ShareMyValue(a_i_T);
  // Combine shares from all parties
  for (size_t j = 0; j < world_size_; ++j) {
    if (j != rank_) {
      yacl::math::MPInt zero(0);
      yacl::crypto::EcPoint infinity = ec_group_->MulBase(zero);
      EcPointShare Z_j_share = ShareValue(infinity, j);
      Z_share = Add(Z_share, Z_j_share);
    }
  }
  
  // Step 9: [U] = SecSarMul2_G(u, [B]) - public scalar u * secret point [B]
  EcPointShare U_share = MulScalar(u, B_share);
  
  // Step 10: [k*P] = [C] + [V] + [Z] + [U]
  EcPointShare result = Add(C_share, V_share);
  result = Add(result, Z_share);
  result = Add(result, U_share);
  
  return result;
}

}  // namespace yacl::examples::pii
