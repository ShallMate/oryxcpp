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

#include "examples/oryxcpp/pairing_mpc.h"

#include <cstring>
#include <vector>

#include "examples/oryxcpp/spdz_mpc.h"
#include "yacl/base/exception.h"
#include "yacl/link/context.h"
#include "yacl/utils/serialize.h"

namespace yacl::examples::pii {

PairingMpcSystem::PairingMpcSystem(
    size_t rank, size_t world_size,
    const std::vector<std::shared_ptr<yacl::link::Context>>& ctxs,
    std::shared_ptr<yacl::crypto::PairingGroup> pairing_group,
    bool malicious_security)
    : rank_(rank),
      world_size_(world_size),
      pairing_group_(pairing_group),
      malicious_security_(malicious_security) {
  YACL_ENFORCE(!ctxs.empty(), "Contexts vector cannot be empty");
  ctx_ = ctxs[0];
  YACL_ENFORCE(pairing_group_ != nullptr, "Pairing group cannot be null");

  // Get G1, G2, GT groups
  auto g1 = pairing_group_->GetGroup1();
  auto g2 = pairing_group_->GetGroup2();
  gt_group_ = pairing_group_->GetGroupT();
  YACL_ENFORCE(gt_group_ != nullptr, "GT group cannot be null");

  // Get the order (same for G1, G2, GT)
  prime_ = pairing_group_->GetOrder();

  // Initialize MPC systems for G1 and G2
  g1_mpc_ = std::make_unique<EcMpcSystem>(rank, world_size, ctxs, g1, malicious_security);
  g2_mpc_ = std::make_unique<EcMpcSystem>(rank, world_size, ctxs, g2, malicious_security);

  // Generate MAC key share for GT (only for malicious security)
  if (malicious_security_) {
    yacl::math::MPInt::RandomLtN(prime_, &mac_key_share_);
  } else {
    mac_key_share_ = yacl::math::MPInt(0);
  }
}

// ========== G1 Operations ==========

EcPointShare PairingMpcSystem::RandomShareG1() {
  return g1_mpc_->RandomShare();
}

EcPointShare PairingMpcSystem::ShareValueG1(const yacl::crypto::EcPoint& point,
                                            size_t sharer_rank) {
  return g1_mpc_->ShareValue(point, sharer_rank);
}

EcPointShare PairingMpcSystem::ShareMyValueG1(const yacl::crypto::EcPoint& point) {
  return g1_mpc_->ShareMyValue(point);
}

EcPointShare PairingMpcSystem::AddG1(const EcPointShare& a, const EcPointShare& b) {
  return g1_mpc_->Add(a, b);
}

EcPointShare PairingMpcSystem::SubG1(const EcPointShare& a, const EcPointShare& b) {
  return g1_mpc_->Sub(a, b);
}

EcPointShare PairingMpcSystem::MulScalarG1(const yacl::math::MPInt& scalar,
                                           const EcPointShare& point) {
  return g1_mpc_->MulScalar(scalar, point);
}

yacl::crypto::EcPoint PairingMpcSystem::OpenG1(const EcPointShare& share) {
  return g1_mpc_->Open(share);
}

yacl::crypto::EcPoint PairingMpcSystem::PartialOpenG1(const EcPointShare& share) {
  return g1_mpc_->PartialOpen(share);
}

// ========== G2 Operations ==========

EcPointShare PairingMpcSystem::RandomShareG2() {
  return g2_mpc_->RandomShare();
}

EcPointShare PairingMpcSystem::ShareValueG2(const yacl::crypto::EcPoint& point,
                                            size_t sharer_rank) {
  return g2_mpc_->ShareValue(point, sharer_rank);
}

EcPointShare PairingMpcSystem::ShareMyValueG2(const yacl::crypto::EcPoint& point) {
  return g2_mpc_->ShareMyValue(point);
}

EcPointShare PairingMpcSystem::AddG2(const EcPointShare& a, const EcPointShare& b) {
  return g2_mpc_->Add(a, b);
}

EcPointShare PairingMpcSystem::SubG2(const EcPointShare& a, const EcPointShare& b) {
  return g2_mpc_->Sub(a, b);
}

EcPointShare PairingMpcSystem::MulScalarG2(const yacl::math::MPInt& scalar,
                                           const EcPointShare& point) {
  return g2_mpc_->MulScalar(scalar, point);
}

yacl::crypto::EcPoint PairingMpcSystem::OpenG2(const EcPointShare& share) {
  return g2_mpc_->Open(share);
}

yacl::crypto::EcPoint PairingMpcSystem::PartialOpenG2(const EcPointShare& share) {
  return g2_mpc_->PartialOpen(share);
}

// ========== GT Operations (multiplicative group) ==========

GtElementShare PairingMpcSystem::GenerateRandomShareGT() {
  // Generate random δg (only for malicious security)
  yacl::Item delta_element = malicious_security_ 
      ? gt_group_->Random() 
      : gt_group_->GetIdentityOne();

  // Generate random element share
  yacl::Item element_share = gt_group_->Random();

  // MAC share will be computed during Open() based on opened_element
  yacl::math::MPInt mac_share(0);

  return GtElementShare(delta_element, element_share, mac_share);
}

GtElementShare PairingMpcSystem::RandomShareGT() {
  // Generate random share locally
  GtElementShare share = GenerateRandomShareGT();

  // Broadcast delta_element and element_share to all other parties
  auto delta_buf = gt_group_->Serialize(share.delta_element);
  auto element_buf = gt_group_->Serialize(share.element_share);

  uint32_t delta_len = static_cast<uint32_t>(delta_buf.size());
  uint32_t element_len = static_cast<uint32_t>(element_buf.size());

  std::vector<uint8_t> data(sizeof(delta_len) + static_cast<size_t>(delta_buf.size()) +
                           sizeof(element_len) + static_cast<size_t>(element_buf.size()));
  size_t offset = 0;
  std::memcpy(data.data() + offset, &delta_len, sizeof(delta_len));
  offset += sizeof(delta_len);
  std::memcpy(data.data() + offset, delta_buf.data<uint8_t>(), static_cast<size_t>(delta_buf.size()));
  offset += static_cast<size_t>(delta_buf.size());
  std::memcpy(data.data() + offset, &element_len, sizeof(element_len));
  offset += sizeof(element_len);
  std::memcpy(data.data() + offset, element_buf.data<uint8_t>(), static_cast<size_t>(element_buf.size()));

  // Send to all other parties
  for (size_t i = 0; i < world_size_; ++i) {
    if (i == rank_) continue;
    ctx_->Send(i, yacl::ByteContainerView(data), "random_share_gt");
  }

  // Receive from all other parties
  for (size_t i = 0; i < world_size_; ++i) {
    if (i == rank_) continue;
    auto recv_data = ctx_->Recv(i, "random_share_gt");
    // Process received share if needed (currently just receives for synchronization)
  }

  return share;
}

GtElementShare PairingMpcSystem::ShareMyValueGT(const yacl::Item& element) {
  YACL_ENFORCE(gt_group_ != nullptr, "GT group cannot be null");
  
  // Generate random δg (only for malicious security)
  yacl::Item delta_element = malicious_security_
      ? gt_group_->Random()
      : gt_group_->GetIdentityOne();

  // Generate random element shares (multiplicative)
  // For element g, we need to generate shares g1, ..., gn such that Πgi = g
  std::vector<yacl::Item> all_element_shares;
  all_element_shares.reserve(world_size_);
  yacl::Item product = gt_group_->GetIdentityOne();

  // Generate random shares for parties 0 to n-2
  for (size_t i = 0; i < world_size_ - 1; ++i) {
    yacl::Item random_item = gt_group_->Random();
    all_element_shares.push_back(gt_group_->DeepCopy(random_item));
    product = gt_group_->Mul(product, all_element_shares[i]);
  }

  // Last share makes product equal to element
  // g = Πgi, so gn-1 = g / (Π_{i=0}^{n-2} gi)
  yacl::Item last_share = gt_group_->Div(element, product);
  all_element_shares.push_back(gt_group_->DeepCopy(last_share));
  
  YACL_ENFORCE(rank_ < all_element_shares.size(), 
               "rank_ out of bounds: {} >= {}", rank_, all_element_shares.size());
  
  // Use at() for bounds checking and DeepCopy for Item
  const yacl::Item& element_share_ref = all_element_shares.at(rank_);
  yacl::Item element_share = gt_group_->DeepCopy(element_share_ref);

  // MAC share will be computed during Open() based on opened_element
  yacl::math::MPInt mac_share(0);

  // Send delta_element and each party's element share to all other parties
  std::string tag = "share_gt_element_" + std::to_string(rank_);
  YACL_ENFORCE(all_element_shares.size() == world_size_,
               "all_element_shares size mismatch: {} != {}", 
               all_element_shares.size(), world_size_);
  for (size_t i = 0; i < world_size_; ++i) {
    if (i != rank_) {
      YACL_ENFORCE(i < all_element_shares.size(), 
                   "Index out of bounds: {} >= {}", i, all_element_shares.size());
      auto delta_buf = gt_group_->Serialize(delta_element);
      YACL_ENFORCE(gt_group_ != nullptr, "gt_group_ is null before Serialize");
      auto element_buf = gt_group_->Serialize(all_element_shares[i]);

      uint32_t delta_len = static_cast<uint32_t>(delta_buf.size());
      uint32_t element_len = static_cast<uint32_t>(element_buf.size());

  std::vector<uint8_t> data(sizeof(delta_len) + static_cast<size_t>(delta_buf.size()) +
                           sizeof(element_len) + static_cast<size_t>(element_buf.size()));
      size_t offset = 0;
      std::memcpy(data.data() + offset, &delta_len, sizeof(delta_len));
      offset += sizeof(delta_len);
      std::memcpy(data.data() + offset, delta_buf.data<uint8_t>(), static_cast<size_t>(delta_buf.size()));
      offset += static_cast<size_t>(delta_buf.size());
      std::memcpy(data.data() + offset, &element_len, sizeof(element_len));
      offset += sizeof(element_len);
      std::memcpy(data.data() + offset, element_buf.data<uint8_t>(), static_cast<size_t>(element_buf.size()));

      ctx_->Send(i, yacl::ByteContainerView(data), tag);
    }
  }

  return GtElementShare(delta_element, element_share, mac_share);
}

GtElementShare PairingMpcSystem::ShareValueGT(const yacl::Item& element,
                                               size_t sharer_rank) {
  // If this party is not the sharer, receive the share
  if (rank_ != sharer_rank) {
    // This party is a receiver, wait for share from sharer_rank
    std::string tag = "share_gt_element_" + std::to_string(sharer_rank);
    auto recv_data = ctx_->Recv(sharer_rank, tag);

    // Validate received data size
    size_t recv_size = static_cast<size_t>(recv_data.size());
    YACL_ENFORCE(recv_size >= sizeof(uint32_t) * 2,
                 "Received data too small: {} bytes", recv_size);

    uint32_t delta_len, element_len;
    const uint8_t* data_ptr = recv_data.data<uint8_t>();
    std::memcpy(&delta_len, data_ptr, sizeof(delta_len));

    // Validate delta_len is reasonable (not too large)
    YACL_ENFORCE(delta_len > 0 && delta_len <= recv_size,
                 "Invalid delta_len: {} (recv_size: {})", delta_len, recv_size);
    
    // Validate delta_len
    YACL_ENFORCE(recv_size >= sizeof(delta_len) + delta_len + sizeof(element_len),
                 "Received data too small for delta: {} bytes, need {}",
                 recv_size, sizeof(delta_len) + delta_len + sizeof(element_len));

    yacl::Item delta_element = gt_group_->Deserialize(
        yacl::ByteContainerView(data_ptr + sizeof(delta_len), delta_len));

    size_t offset = sizeof(delta_len) + static_cast<size_t>(delta_len);
    std::memcpy(&element_len, data_ptr + offset, sizeof(element_len));
    offset += sizeof(element_len);

    // Validate element_len is reasonable (not too large)
    YACL_ENFORCE(element_len > 0 && element_len <= recv_size,
                 "Invalid element_len: {} (recv_size: {})", element_len, recv_size);
    
    // Validate element_len
    YACL_ENFORCE(recv_size >= offset + element_len,
                 "Received data too small for element: {} bytes, need {}",
                 recv_size, offset + element_len);

    yacl::Item element_share = gt_group_->Deserialize(
        yacl::ByteContainerView(data_ptr + offset, element_len));

    // MAC share will be computed during Open() based on opened_element
    yacl::math::MPInt mac_share(0);

    return GtElementShare(delta_element, element_share, mac_share);
  }

  // This party is sharing its own value
  return ShareMyValueGT(element);
}

GtElementShare PairingMpcSystem::MulGT(const GtElementShare& a, const GtElementShare& b) {
  // Multiply delta elements: δg * δh
  yacl::Item delta_element = gt_group_->Mul(a.delta_element, b.delta_element);

  // Multiply element shares: gi * hi
  yacl::Item element_share = gt_group_->Mul(a.element_share, b.element_share);

  // Add MAC shares: γi(g) + γi(h) (MAC is additive in exponent)
  yacl::math::MPInt mac_share = (a.mac_share + b.mac_share) % prime_;

  return GtElementShare(delta_element, element_share, mac_share);
}

GtElementShare PairingMpcSystem::DivGT(const GtElementShare& a, const GtElementShare& b) {
  // Divide delta elements: δg / δh
  yacl::Item delta_element = gt_group_->Div(a.delta_element, b.delta_element);

  // Divide element shares: gi / hi
  yacl::Item element_share = gt_group_->Div(a.element_share, b.element_share);

  // Subtract MAC shares: γi(g) - γi(h)
  yacl::math::MPInt mac_share = (a.mac_share - b.mac_share + prime_) % prime_;

  return GtElementShare(delta_element, element_share, mac_share);
}

GtElementShare PairingMpcSystem::PowGT(const yacl::math::MPInt& exponent,
                                        const GtElementShare& element) {
  // Power on delta element: (δg)^k
  yacl::Item delta_element = gt_group_->Pow(element.delta_element, exponent);

  // Power on element share: gi^k
  yacl::Item element_share = gt_group_->Pow(element.element_share, exponent);

  // Scalar multiplication on MAC share: k * γi(g)
  yacl::math::MPInt mac_share = (exponent * element.mac_share) % prime_;

  return GtElementShare(delta_element, element_share, mac_share);
}

yacl::Item PairingMpcSystem::PartialOpenGT(const GtElementShare& share) {
  // Reconstruct the element by exchanging element shares
  yacl::Item element = share.element_share;

  // Exchange shares with all other parties
  // Send my share
  for (size_t i = 0; i < world_size_; ++i) {
    if (i != rank_) {
      auto element_buf = gt_group_->Serialize(share.element_share);
      uint32_t len = static_cast<uint32_t>(element_buf.size());
      std::vector<uint8_t> data(sizeof(len) + static_cast<size_t>(element_buf.size()));
      std::memcpy(data.data(), &len, sizeof(len));
      std::memcpy(data.data() + sizeof(len), element_buf.data<uint8_t>(), static_cast<size_t>(element_buf.size()));
      ctx_->Send(i, yacl::ByteContainerView(data), "partial_open_gt");
    }
  }

  // Receive shares from all other parties
  for (size_t i = 0; i < world_size_; ++i) {
    if (i != rank_) {
      auto recv_data = ctx_->Recv(i, "partial_open_gt");
      // Validate received data size
      size_t recv_size = static_cast<size_t>(recv_data.size());
      YACL_ENFORCE(recv_size >= sizeof(uint32_t),
                   "Received data too small: {} bytes", recv_size);
      
      uint32_t len;
      const uint8_t* data_ptr = recv_data.data<uint8_t>();
      std::memcpy(&len, data_ptr, sizeof(len));
      
      // Validate len
      YACL_ENFORCE(recv_size >= sizeof(len) + len,
                   "Received data too small for element: {} bytes, need {}",
                   recv_size, sizeof(len) + len);
      
      yacl::Item other_share = gt_group_->Deserialize(
          yacl::ByteContainerView(data_ptr + sizeof(len), len));
      element = gt_group_->Mul(element, other_share);
    }
  }

  return element;
}

yacl::Item PairingMpcSystem::OpenGT(const GtElementShare& share) {
  // Open the element
  yacl::Item opened_element = PartialOpenGT(share);

  // MAC verification (only for malicious security)
  if (malicious_security_) {
    // Compute MAC share based on opened_element: γi(g) = αi * H(g * δg)
    // For multiplicative group, MAC is computed on g * δg
    auto element_times_delta = gt_group_->Mul(opened_element, share.delta_element);
    auto serialized = gt_group_->Serialize(element_times_delta);
    yacl::math::MPInt hash_value;
    size_t serialized_size = static_cast<size_t>(serialized.size());
    if (serialized_size >= 32) {
      hash_value.FromMagBytes(yacl::ByteContainerView(serialized.data<uint8_t>(), 32), yacl::Endian::native);
      hash_value = hash_value % prime_;
    } else {
      std::vector<uint8_t> padded(32, 0);
      std::memcpy(padded.data(), serialized.data<uint8_t>(), serialized_size);
      hash_value.FromMagBytes(yacl::ByteContainerView(padded), yacl::Endian::native);
      hash_value = hash_value % prime_;
    }
    yacl::math::MPInt computed_mac_share = (mac_key_share_ * hash_value) % prime_;

    // Create a new share with the computed MAC share for verification
    GtElementShare share_with_mac = share;
    share_with_mac.mac_share = computed_mac_share;

    // Verify MAC
    if (!VerifyMacGT(share_with_mac, opened_element)) {
      YACL_THROW("MAC verification failed for GT, aborting protocol");
    }
  }

  return opened_element;
}

bool PairingMpcSystem::VerifyMacGT(const GtElementShare& share,
                                   const yacl::Item& opened_element) {
  // MAC verification for GT (multiplicative group)
  // Compute expected MAC contribution: ti = γi(g) - αi * H(g * δg)
  auto element_times_delta = gt_group_->Mul(opened_element, share.delta_element);
  auto serialized = gt_group_->Serialize(element_times_delta);
  yacl::math::MPInt hash_value;
  size_t serialized_size = static_cast<size_t>(serialized.size());
  if (serialized_size >= 32) {
    hash_value.FromMagBytes(yacl::ByteContainerView(serialized.data<uint8_t>(), 32), yacl::Endian::native);
    hash_value = hash_value % prime_;
  } else {
    std::vector<uint8_t> padded(32, 0);
    std::memcpy(padded.data(), serialized.data<uint8_t>(), serialized_size);
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
      ctx_->Send(i, yacl::ByteContainerView(data), "mac_verify_gt");
    }
  }

  // Receive ti from all other parties
  yacl::math::MPInt sum_ti = ti;
  for (size_t i = 0; i < world_size_; ++i) {
    if (i != rank_) {
      auto recv_data = ctx_->Recv(i, "mac_verify_gt");
      // Validate received data size
      size_t recv_size = static_cast<size_t>(recv_data.size());
      YACL_ENFORCE(recv_size >= sizeof(uint32_t),
                   "Received data too small: {} bytes", recv_size);
      
      uint32_t recv_ti_len;
      const uint8_t* recv_data_ptr = recv_data.data<uint8_t>();
      std::memcpy(&recv_ti_len, recv_data_ptr, sizeof(recv_ti_len));
      
      // Validate recv_ti_len
      YACL_ENFORCE(recv_size >= sizeof(recv_ti_len) + recv_ti_len,
                   "Received data too small for ti: {} bytes, need {}",
                   recv_size, sizeof(recv_ti_len) + recv_ti_len);
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

// SecPair1: e([P], Q) = [e(P, Q)] where [P] ∈ G1 is secret-shared, Q ∈ G2 is public
GtElementShare PairingMpcSystem::PairingSecretG1(const EcPointShare& g1_share,
                                                  const yacl::crypto::EcPoint& g2_public) {
  // Each party computes e(P_i, Q) locally using its share P_i
  // Since Q is public, e(P_i, Q) is also public (can be computed locally)
  // Due to bilinearity: e(P, Q) = e(P_0 + P_1 + ..., Q) = e(P_0, Q) * e(P_1, Q) * ...
  // So we compute e(P_i, Q) locally, exchange with all parties, multiply, then share the result
  YACL_ENFORCE(pairing_group_ != nullptr, "pairing_group_ is null");
  YACL_ENFORCE(gt_group_ != nullptr, "gt_group_ is null");
  yacl::Item local_pairing = pairing_group_->Pairing(g1_share.point_share, g2_public);

  // Exchange e(P_i, Q) with all other parties (these are public values)
  // Send my e(P_i, Q) to all other parties
  auto local_pairing_buf = gt_group_->Serialize(local_pairing);
  uint32_t pairing_len = static_cast<uint32_t>(local_pairing_buf.size());
  for (size_t j = 0; j < world_size_; ++j) {
    if (j != rank_) {
      std::string tag = "pairing_g1_value_" + std::to_string(rank_);
      std::vector<uint8_t> data(sizeof(pairing_len) + static_cast<size_t>(local_pairing_buf.size()));
      std::memcpy(data.data(), &pairing_len, sizeof(pairing_len));
      std::memcpy(data.data() + sizeof(pairing_len), local_pairing_buf.data<uint8_t>(), static_cast<size_t>(local_pairing_buf.size()));
      ctx_->Send(j, yacl::ByteContainerView(data), tag);
    }
  }
  
  // Receive e(P_j, Q) from all other parties and multiply
  yacl::Item product = gt_group_->DeepCopy(local_pairing);  // Start with my own e(P_i, Q)
  for (size_t i = 0; i < world_size_; ++i) {
    if (i != rank_) {
      // Receive e(P_i, Q) from party i
      std::string tag = "pairing_g1_value_" + std::to_string(i);
      auto recv_data = ctx_->Recv(i, tag);
      
      size_t recv_size = static_cast<size_t>(recv_data.size());
      YACL_ENFORCE(recv_size >= sizeof(uint32_t),
                   "Received data too small: {} bytes", recv_size);
      
      const uint8_t* data_ptr = recv_data.data<uint8_t>();
      uint32_t other_pairing_len;
      std::memcpy(&other_pairing_len, data_ptr, sizeof(other_pairing_len));
      
      YACL_ENFORCE(recv_size >= sizeof(other_pairing_len) + other_pairing_len,
                   "Received data too small: {} bytes, need {}",
                   recv_size, sizeof(other_pairing_len) + other_pairing_len);
      
      yacl::Item other_pairing = gt_group_->Deserialize(
          yacl::ByteContainerView(data_ptr + sizeof(other_pairing_len), other_pairing_len));
      
      product = gt_group_->Mul(product, other_pairing);
    }
  }

  // Now product = e(P_0, Q) * e(P_1, Q) * ... = e(P, Q)
  // Share this result: [e(P, Q)]
  // Since e(P, Q) is a public value (all parties computed it), Party 0 shares it and others receive
  // Use ShareValueGT with sharer_rank=0, so Party 0 shares and others receive
  GtElementShare result = ShareValueGT(product, 0);
  return result;
}

// SecPair2: e(P, [Q]) = [e(P, Q)] where P ∈ G1 is public, [Q] ∈ G2 is secret-shared
GtElementShare PairingMpcSystem::PairingSecretG2(const yacl::crypto::EcPoint& g1_public,
                                                  const EcPointShare& g2_share) {
  // Each party computes e(P, Q_i) locally using its share Q_i
  // Since P is public, this is secure
  // Due to bilinearity: e(P, Q) = e(P, Q_0 + Q_1 + ...) = e(P, Q_0) * e(P, Q_1) * ...
  yacl::Item local_pairing = pairing_group_->Pairing(g1_public, g2_share.point_share);

  // Exchange e(P, Q_i) with all other parties (these are public values since P is public)
  // Send my e(P, Q_i) to all other parties
  auto local_pairing_buf = gt_group_->Serialize(local_pairing);
  uint32_t pairing_len = static_cast<uint32_t>(local_pairing_buf.size());
  for (size_t j = 0; j < world_size_; ++j) {
    if (j != rank_) {
      std::string tag = "pairing_g2_value_" + std::to_string(rank_);
      std::vector<uint8_t> data(sizeof(pairing_len) + static_cast<size_t>(local_pairing_buf.size()));
      std::memcpy(data.data(), &pairing_len, sizeof(pairing_len));
      std::memcpy(data.data() + sizeof(pairing_len), local_pairing_buf.data<uint8_t>(), static_cast<size_t>(local_pairing_buf.size()));
      ctx_->Send(j, yacl::ByteContainerView(data), tag);
    }
  }
  
  // Receive e(P, Q_j) from all other parties and multiply (these are public values)
  yacl::Item product = gt_group_->DeepCopy(local_pairing);  // Start with my own e(P, Q_i)
  for (size_t i = 0; i < world_size_; ++i) {
    if (i != rank_) {
      // Receive e(P, Q_i) from party i
      std::string tag = "pairing_g2_value_" + std::to_string(i);
      auto recv_data = ctx_->Recv(i, tag);
      
      size_t recv_size = static_cast<size_t>(recv_data.size());
      YACL_ENFORCE(recv_size >= sizeof(uint32_t),
                   "Received data too small: {} bytes", recv_size);
      
      const uint8_t* data_ptr = recv_data.data<uint8_t>();
      uint32_t other_pairing_len;
      std::memcpy(&other_pairing_len, data_ptr, sizeof(other_pairing_len));
      
      YACL_ENFORCE(recv_size >= sizeof(other_pairing_len) + other_pairing_len,
                   "Received data too small: {} bytes, need {}",
                   recv_size, sizeof(other_pairing_len) + other_pairing_len);
      
      yacl::Item other_pairing = gt_group_->Deserialize(
          yacl::ByteContainerView(data_ptr + sizeof(other_pairing_len), other_pairing_len));
      
      product = gt_group_->Mul(product, other_pairing);
    }
  }

  // Now product = e(P, Q_0) * e(P, Q_1) * ... = e(P, Q)
  // Share this result: [e(P, Q)]
  // Since e(P, Q) is a public value (all parties computed it), Party 0 shares it and others receive
  GtElementShare result = ShareValueGT(product, 0);
  return result;
}

// SecPair3: e([P], [Q]) = [e(P, Q)] where both [P] ∈ G1 and [Q] ∈ G2 are secret-shared
// Protocol based on Beaver triple over Fp
GtElementShare PairingMpcSystem::PairingSecret(const EcPointShare& g1_share,
                                                const EcPointShare& g2_share,
                                                SpdzMpcSystem* fp_mpc) {
  YACL_ENFORCE(fp_mpc != nullptr, "Fp MPC system is required for SecPair3");

  auto g1 = pairing_group_->GetGroup1();
  auto g2 = pairing_group_->GetGroup2();

  // Step 1: Generate Beaver triple ([a], [b], [c]) over Fp where c = a * b mod p
  auto [a_share, b_share, c_share] = fp_mpc->GenerateBeaverTriple();

  // Step 2: Compute [A] = [a] * G1 (secret scalar [a] * public generator G1)
  // First, share the public generator G1
  yacl::crypto::EcPoint g1_generator = g1->GetGenerator();
  EcPointShare g1_gen_share = SharePublicPointG1(g1_generator);
  // Then compute [a] * [G1] = [a * G1] using MulSecretScalar
  EcPointShare A_share = g1_mpc_->MulSecretScalar(a_share, g1_gen_share, fp_mpc);

  // Step 3: Compute [B] = [b] * G2 (secret scalar [b] * public generator G2)
  yacl::crypto::EcPoint g2_generator = g2->GetGenerator();
  EcPointShare g2_gen_share = SharePublicPointG2(g2_generator);
  EcPointShare B_share = g2_mpc_->MulSecretScalar(b_share, g2_gen_share, fp_mpc);

  // Step 4: Compute [C] = [c] * G1 (secret scalar [c] * public generator G1)
  EcPointShare C_share = g1_mpc_->MulSecretScalar(c_share, g1_gen_share, fp_mpc);

  // Step 5: Compute [V] = [P] - [A] in G1
  EcPointShare V_share = g1_mpc_->Sub(g1_share, A_share);

  // Step 6: Compute [W] = [Q] - [B] in G2
  EcPointShare W_share = g2_mpc_->Sub(g2_share, B_share);

  // Step 7: Partially open V and W
  yacl::crypto::EcPoint V = g1_mpc_->PartialOpen(V_share);
  yacl::crypto::EcPoint W = g2_mpc_->PartialOpen(W_share);

  // Step 8: Compute intermediate pairings using SecPair1 and SecPair2
  // [U] = SecPair1([V], W) = e([V], W) where W is public
  GtElementShare U_share = PairingSecretG1(V_share, W);

  // [K] = SecPair1([C], G2) = e([C], G2_generator) where G2_generator is public
  GtElementShare K_share = PairingSecretG1(C_share, g2_generator);

  // [R] = SecPair1([A], W) = e([A], W) where W is public
  GtElementShare R_share = PairingSecretG1(A_share, W);

  // [M] = SecPair2(V, [B]) = e(V, [B]) where V is public
  GtElementShare M_share = PairingSecretG2(V, B_share);

  // Step 9: Compute [e(P, Q)] = [U] * [K] * [R] * [M] in GT (multiplicative)
  GtElementShare result = MulGT(U_share, K_share);
  result = MulGT(result, R_share);
  result = MulGT(result, M_share);

  return result;
}

// Helper: Share a public point in G1 (all parties know it)
EcPointShare PairingMpcSystem::SharePublicPointG1(const yacl::crypto::EcPoint& point) {
  // For a public point, Party 0 shares it and others receive
  if (rank_ == 0) {
    return g1_mpc_->ShareMyValue(point);
  } else {
    yacl::math::MPInt zero;
    zero.SetZero();
    yacl::crypto::EcPoint infinity = pairing_group_->GetGroup1()->MulBase(zero);
    return g1_mpc_->ShareValue(infinity, 0);
  }
}

// Helper: Share a public point in G2 (all parties know it)
EcPointShare PairingMpcSystem::SharePublicPointG2(const yacl::crypto::EcPoint& point) {
  // For a public point, Party 0 shares it and others receive
  if (rank_ == 0) {
    return g2_mpc_->ShareMyValue(point);
  } else {
    yacl::math::MPInt zero;
    zero.SetZero();
    yacl::crypto::EcPoint infinity = pairing_group_->GetGroup2()->MulBase(zero);
    return g2_mpc_->ShareValue(infinity, 0);
  }
}

}  // namespace yacl::examples::pii
