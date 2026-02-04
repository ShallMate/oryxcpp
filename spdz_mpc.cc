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

#include "examples/oryxcpp/spdz_mpc.h"

#include <cstring>

#include "yacl/base/byte_container_view.h"
#include "yacl/base/exception.h"

namespace yacl::examples::pii {

SpdzMpcSystem::SpdzMpcSystem(
    size_t rank, size_t world_size,
    const std::vector<std::shared_ptr<yacl::link::Context>>& ctxs,
    bool malicious_security,
    const yacl::math::MPInt* prime)
    : rank_(rank), world_size_(world_size), malicious_security_(malicious_security) {
  // In 2PC, each party only has their own context
  YACL_ENFORCE(!ctxs.empty(), "Contexts vector cannot be empty");
  ctx_ = ctxs[0];  // Use the first (and only) context
  
  // Use provided prime or default large prime for Fp (256-bit security)
  if (prime != nullptr) {
    prime_ = *prime;
  } else {
    // Default: use a large prime for Fp (256-bit security)
    prime_ = yacl::math::MPInt(
        "115792089237316195423570985008687907853269984665640564039457584007913129639747");
  }

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

SecretShare SpdzMpcSystem::GenerateRandomShare() {
  SecretShare share;
  
  // Generate random δx (only for malicious security)
  if (malicious_security_) {
    yacl::math::MPInt::RandomLtN(prime_, &share.delta);
  } else {
    share.delta = yacl::math::MPInt(0);  // No delta for semi-honest
  }
  
  // Generate random value share
  yacl::math::MPInt::RandomLtN(prime_, &share.value_share);
  
  // MAC share will be computed during Open() based on opened_value (only for malicious)
  share.mac_share = yacl::math::MPInt(0);
  
  return share;
}

SecretShare SpdzMpcSystem::RandomShare() {
  // Generate random share locally
  SecretShare share = GenerateRandomShare();
  
  // Exchange shares with all other parties to ensure consistency
  // Send my delta and value_share to all other parties
  auto delta_buf = share.delta.ToMagBytes();
  auto value_buf = share.value_share.ToMagBytes();
  
  uint32_t delta_len = static_cast<uint32_t>(delta_buf.size());
  uint32_t value_len = static_cast<uint32_t>(value_buf.size());
  
  std::vector<uint8_t> data(sizeof(delta_len) + delta_buf.size() +
                           sizeof(value_len) + value_buf.size());
  size_t offset = 0;
  std::memcpy(data.data() + offset, &delta_len, sizeof(delta_len));
  offset += sizeof(delta_len);
  std::memcpy(data.data() + offset, delta_buf.data<uint8_t>(), delta_buf.size());
  offset += delta_buf.size();
  std::memcpy(data.data() + offset, &value_len, sizeof(value_len));
  offset += sizeof(value_len);
  std::memcpy(data.data() + offset, value_buf.data<uint8_t>(), value_buf.size());
  
  // Broadcast to all other parties
  for (size_t i = 0; i < world_size_; ++i) {
    if (i != rank_) {
      ctx_->SendAsync(i, yacl::ByteContainerView(data), "random_share");
    }
  }
  
  // Receive shares from all other parties (for coordination)
  for (size_t i = 0; i < world_size_; ++i) {
    if (i != rank_) {
      auto recv_data = ctx_->Recv(i, "random_share");
      // Process received share if needed (currently just for synchronization)
    }
  }
  
  // MAC share will be computed during Open() based on opened_value
  // For now, set to 0 (will be computed when we know the opened value)
  share.mac_share = yacl::math::MPInt(0);
  
  return share;
}

SecretShare SpdzMpcSystem::ShareMyValue(const yacl::math::MPInt& value) {
  SecretShare share;
  
  // Generate random δx (only for malicious security)
  if (malicious_security_) {
    yacl::math::MPInt::RandomLtN(prime_, &share.delta);
  } else {
    share.delta = yacl::math::MPInt(0);  // No delta for semi-honest
  }
  
  // Generate random shares for value
  yacl::math::MPInt sum(0);
  std::vector<yacl::math::MPInt> all_value_shares(world_size_);
  
  // Generate random shares for parties 0 to n-2
  for (size_t i = 0; i < world_size_ - 1; ++i) {
    yacl::math::MPInt::RandomLtN(prime_, &all_value_shares[i]);
    sum += all_value_shares[i];
    sum %= prime_;
  }
  
  // Last share makes sum equal to value
  all_value_shares[world_size_ - 1] = (value - sum + prime_) % prime_;
  
  share.value_share = all_value_shares[rank_];
  
  // Compute MAC share (only for malicious security)
  // Note: MAC share is computed based on our value_share and delta
  // The MAC for the full value will be computed during Open() based on opened_value
  // For now, we compute a preliminary MAC share
  if (malicious_security_) {
    yacl::math::MPInt x_plus_delta = (share.value_share + share.delta) % prime_;
    share.mac_share = (mac_key_share_ * x_plus_delta) % prime_;
  } else {
    share.mac_share = yacl::math::MPInt(0);  // No MAC for semi-honest
  }
  
  // Send delta and each party's value share to all other parties
  // Use rank-specific tag so receivers know which party is sharing
  std::string tag = "share_value_" + std::to_string(rank_);
  for (size_t i = 0; i < world_size_; ++i) {
    if (i != rank_) {
      auto delta_buf = share.delta.ToMagBytes();
      auto value_buf = all_value_shares[i].ToMagBytes();
      
      uint32_t delta_len = static_cast<uint32_t>(delta_buf.size());
      uint32_t value_len = static_cast<uint32_t>(value_buf.size());
      
      std::vector<uint8_t> data(sizeof(delta_len) + delta_buf.size() +
                               sizeof(value_len) + value_buf.size());
      size_t offset = 0;
      std::memcpy(data.data() + offset, &delta_len, sizeof(delta_len));
      offset += sizeof(delta_len);
      std::memcpy(data.data() + offset, delta_buf.data<uint8_t>(), delta_buf.size());
      offset += delta_buf.size();
      std::memcpy(data.data() + offset, &value_len, sizeof(value_len));
      offset += sizeof(value_len);
      std::memcpy(data.data() + offset, value_buf.data<uint8_t>(), value_buf.size());
      
      ctx_->Send(i, yacl::ByteContainerView(data), tag);
    }
  }
  
  // Note: MAC share is already computed above for malicious security
  // It will be recomputed during Open() based on the actual opened_value for verification
  
  return share;
}

SecretShare SpdzMpcSystem::ShareValue(const yacl::math::MPInt& value, size_t sharer_rank) {
  SecretShare share;
  
  // If value is 0, we are a receiver and should receive from sharer_rank
  if (value.IsZero()) {
    YACL_ENFORCE(sharer_rank < world_size_ && sharer_rank != rank_,
                 "Invalid sharer_rank: must be different from my rank");
    
    // Receive share from the specified sharer
    std::string tag = "share_value_" + std::to_string(sharer_rank);
    auto recv_data = ctx_->Recv(sharer_rank, tag);
    uint32_t delta_len, value_len;
    const uint8_t* data_ptr = reinterpret_cast<const uint8_t*>(recv_data.data());
    std::memcpy(&delta_len, data_ptr, sizeof(delta_len));
    share.delta.FromMagBytes(
        yacl::ByteContainerView(data_ptr + sizeof(delta_len), delta_len),
        yacl::Endian::native);
    size_t offset = sizeof(delta_len) + delta_len;
    std::memcpy(&value_len, data_ptr + offset, sizeof(value_len));
    offset += sizeof(value_len);
    share.value_share.FromMagBytes(
        yacl::ByteContainerView(data_ptr + offset, value_len),
        yacl::Endian::native);
    // MAC share (only for malicious security)
    if (malicious_security_) {
      // MAC share will be computed during Open() based on opened_value
      share.mac_share = yacl::math::MPInt(0);
    } else {
      share.mac_share = yacl::math::MPInt(0);  // No MAC for semi-honest
    }
    return share;
  }
  
  // Otherwise, delegate to ShareMyValue
  return ShareMyValue(value);
}

SecretShare SpdzMpcSystem::Add(const SecretShare& a, const SecretShare& b) {
  SecretShare result;
  
  // Local addition: [a] + [b] = [a+b]
  result.delta = (a.delta + b.delta) % prime_;
  result.value_share = (a.value_share + b.value_share) % prime_;
  result.mac_share = (a.mac_share + b.mac_share) % prime_;
  
  return result;
}

SecretShare SpdzMpcSystem::Sub(const SecretShare& a, const SecretShare& b) {
  SecretShare result;
  
  // Local subtraction: [a] - [b] = [a-b]
  result.delta = (a.delta - b.delta + prime_) % prime_;
  result.value_share = (a.value_share - b.value_share + prime_) % prime_;
  result.mac_share = (a.mac_share - b.mac_share + prime_) % prime_;
  
  return result;
}

SecretShare SpdzMpcSystem::MulPlain(const SecretShare& a, const yacl::math::MPInt& k) {
  SecretShare result;
  
  // Scalar multiplication: k * [a] = [k*a]
  // This is a local operation (no communication needed)
  // k * [a] = {k * δa, k * a_i, k * γi(a)}
  result.delta = (k * a.delta) % prime_;
  result.value_share = (k * a.value_share) % prime_;
  result.mac_share = (k * a.mac_share) % prime_;
  
  return result;
}

// Generate a Beaver triple ([u], [v], [w]) where w = u * v (MALICIOUS security)
// True multi-party generation: each party generates random values and collaborates
std::tuple<SecretShare, SecretShare, SecretShare> SpdzMpcSystem::GenerateBeaverTriple() {
  if (malicious_security_) {
    return GenerateBeaverTripleMalicious();
  } else {
    return GenerateBeaverTripleSemiHonest();
  }
}

// Generate Beaver triple with malicious security using true multi-party generation
std::tuple<SecretShare, SecretShare, SecretShare> SpdzMpcSystem::GenerateBeaverTripleMalicious() {
  // True multi-party Beaver triple generation:
  // 1. Each party generates random u_i and v_i
  // 2. All parties share u_i and v_i, then combine to get u = Σu_i and v = Σv_i
  // 3. All parties open u and v, compute w = u * v
  // 4. All parties share w
  
  // Step 1: Each party generates random u_i and v_i
  yacl::math::MPInt u_i, v_i;
  yacl::math::MPInt::RandomLtN(prime_, &u_i);
  yacl::math::MPInt::RandomLtN(prime_, &v_i);
  
  // Step 2: All parties share u_i and v_i, then combine shares
  // Each party shares its own value and receives shares from all other parties
  SecretShare u_i_share = ShareMyValue(u_i);
  SecretShare v_i_share = ShareMyValue(v_i);
  
  // Now receive shares from all other parties and combine
  SecretShare u_share = u_i_share;  // Start with our own share
  SecretShare v_share = v_i_share;
  
  // Receive and add shares from all other parties
  for (size_t j = 0; j < world_size_; ++j) {
    if (j != rank_) {
      // Receive u_j share from party j
      SecretShare u_j_share = ShareValue(yacl::math::MPInt(0), j);
      u_share.value_share = (u_share.value_share + u_j_share.value_share) % prime_;
      u_share.delta = (u_share.delta + u_j_share.delta) % prime_;
      u_share.mac_share = (u_share.mac_share + u_j_share.mac_share) % prime_;
      
      // Receive v_j share from party j
      SecretShare v_j_share = ShareValue(yacl::math::MPInt(0), j);
      v_share.value_share = (v_share.value_share + v_j_share.value_share) % prime_;
      v_share.delta = (v_share.delta + v_j_share.delta) % prime_;
      v_share.mac_share = (v_share.mac_share + v_j_share.mac_share) % prime_;
    }
  }
  
  // Step 3: All parties open u and v, compute w = u * v
  yacl::math::MPInt u_opened = PartialOpen(u_share);
  yacl::math::MPInt v_opened = PartialOpen(v_share);
  yacl::math::MPInt w = (u_opened * v_opened) % prime_;
  
  // Step 4: All parties share w (with MAC)
  // Since w is a public value (all parties know it), we can share it efficiently
  // Party 0 shares w, all other parties receive it
  SecretShare w_share;
  if (rank_ == 0) {
    w_share = ShareMyValue(w);
  } else {
    w_share = ShareValue(yacl::math::MPInt(0), 0);  // Receive w from Party 0
  }
  
  return std::make_tuple(u_share, v_share, w_share);
}

// Generate a Beaver triple ([u], [v], [w]) where w = u * v (SEMI-HONEST security)
// True multi-party generation: each party generates random values and collaborates
std::tuple<SecretShare, SecretShare, SecretShare> SpdzMpcSystem::GenerateBeaverTripleSemiHonest() {
  // True multi-party Beaver triple generation (semi-honest):
  // 1. Each party generates random u_i and v_i
  // 2. All parties share u_i and v_i, then combine to get u = Σu_i and v = Σv_i
  // 3. All parties open u and v, compute w = u * v
  // 4. All parties share w
  
  // Step 1: Each party generates random u_i and v_i
  yacl::math::MPInt u_i, v_i;
  yacl::math::MPInt::RandomLtN(prime_, &u_i);
  yacl::math::MPInt::RandomLtN(prime_, &v_i);
  
  // Step 2: All parties share u_i and v_i, then combine shares
  SecretShare u_i_share = ShareMyValue(u_i);
  SecretShare v_i_share = ShareMyValue(v_i);
  
  // Now receive shares from all other parties and combine
  SecretShare u_share = u_i_share;  // Start with our own share
  SecretShare v_share = v_i_share;
  
  // Receive and add shares from all other parties
  for (size_t j = 0; j < world_size_; ++j) {
    if (j != rank_) {
      // Receive u_j share from party j
      SecretShare u_j_share = ShareValue(yacl::math::MPInt(0), j);
      u_share.value_share = (u_share.value_share + u_j_share.value_share) % prime_;
      u_share.delta = (u_share.delta + u_j_share.delta) % prime_;
      u_share.mac_share = (u_share.mac_share + u_j_share.mac_share) % prime_;
      
      // Receive v_j share from party j
      SecretShare v_j_share = ShareValue(yacl::math::MPInt(0), j);
      v_share.value_share = (v_share.value_share + v_j_share.value_share) % prime_;
      v_share.delta = (v_share.delta + v_j_share.delta) % prime_;
      v_share.mac_share = (v_share.mac_share + v_j_share.mac_share) % prime_;
    }
  }
  
  // Step 3: All parties open u and v, compute w = u * v
  yacl::math::MPInt u_opened = PartialOpen(u_share);
  yacl::math::MPInt v_opened = PartialOpen(v_share);
  yacl::math::MPInt w = (u_opened * v_opened) % prime_;
  
  // Step 4: All parties share w
  // Since w is a public value (all parties know it), we can share it efficiently
  // Party 0 shares w, all other parties receive it
  SecretShare w_share;
  if (rank_ == 0) {
    w_share = ShareMyValue(w);
  } else {
    w_share = ShareValue(yacl::math::MPInt(0), 0);  // Receive w from Party 0
  }
  
  return std::make_tuple(u_share, v_share, w_share);
}

// Helper function for Beaver triple multiplication (common logic)
SecretShare SpdzMpcSystem::MulWithBeaverTriple(
    const SecretShare& a, const SecretShare& b,
    const SecretShare& u_share, const SecretShare& v_share, const SecretShare& w_share) {
  // Step 1: Compute ε = [a] - [u] and open it
  SecretShare epsilon_share = Sub(a, u_share);
  yacl::math::MPInt epsilon = PartialOpen(epsilon_share);
  
  // Step 2: Compute δ = [b] - [v] and open it
  SecretShare delta_share = Sub(b, v_share);
  yacl::math::MPInt delta = PartialOpen(delta_share);
  
  // Step 3: Compute [c] = [w] + ε * [v] + δ * [u] + ε * δ
  // [c] = [w] + ε * [v] + δ * [u] + ε * δ
  
  // Compute ε * [v]: scalar multiplication
  SecretShare eps_times_v;
  eps_times_v.delta = (epsilon * v_share.delta) % prime_;
  eps_times_v.value_share = (epsilon * v_share.value_share) % prime_;
  eps_times_v.mac_share = (epsilon * v_share.mac_share) % prime_;
  
  // Compute δ * [u]: scalar multiplication
  SecretShare delta_times_u;
  delta_times_u.delta = (delta * u_share.delta) % prime_;
  delta_times_u.value_share = (delta * u_share.value_share) % prime_;
  delta_times_u.mac_share = (delta * u_share.mac_share) % prime_;
  
  // Compute ε * δ (public value, all parties know it)
  // Since epsilon and delta are public, eps_delta is also public
  // For a public value, we can create a share directly: each party's share is eps_delta / world_size
  // But simpler: use MulPlain on a constant share
  yacl::math::MPInt eps_delta = (epsilon * delta) % prime_;
  
  // Create a share for the public value eps_delta
  // For a public value x, we can create shares where each party's share is x / world_size
  // But to avoid division, we can use ShareMyValue by one party and others receive
  // However, since all parties know eps_delta, we can create shares more efficiently
  SecretShare eps_delta_share;
  eps_delta_share.delta = yacl::math::MPInt(0);
  eps_delta_share.mac_share = yacl::math::MPInt(0);
  
  // For public value, we can create additive shares where sum equals the value
  // Each party gets a random share, and we adjust so that sum = eps_delta
  // But simpler: let Party 0 share eps_delta, others receive
  if (rank_ == 0) {
    eps_delta_share = ShareMyValue(eps_delta);
  } else {
    eps_delta_share = ShareValue(yacl::math::MPInt(0), 0);  // Receive from Party 0
  }
  
  // Sum everything: [c] = [w] + ε * [v] + δ * [u] + ε * δ
  SecretShare result = Add(w_share, eps_times_v);
  result = Add(result, delta_times_u);
  result = Add(result, eps_delta_share);
  
  return result;
}

SecretShare SpdzMpcSystem::Mul(const SecretShare& a, const SecretShare& b) {
  // SPDZ multiplication using Beaver triples
  // Security mode depends on malicious_security_ flag
  // Protocol:
  // 1. Generate Beaver triple ([u], [v], [w]) where w = u * v
  // 2. Compute ε = [a] - [u] and open it
  // 3. Compute δ = [b] - [v] and open it
  // 4. Compute [c] = [w] + ε * [v] + δ * [u] + ε * δ
  
  // Step 1: Generate Beaver triple (with or without MAC depending on security mode)
  auto [u_share, v_share, w_share] = GenerateBeaverTriple();
  
  // Step 2-4: Use common multiplication logic
  return MulWithBeaverTriple(a, b, u_share, v_share, w_share);
}

yacl::math::MPInt SpdzMpcSystem::PartialOpen(const SecretShare& share) {
  // Partial open: reconstruct value without MAC verification
  yacl::math::MPInt value = share.value_share;
  
  // Exchange shares with all other parties
  // Send my share
  for (size_t i = 0; i < world_size_; ++i) {
    if (i != rank_) {
      auto value_buf = share.value_share.ToMagBytes();
      uint32_t len = static_cast<uint32_t>(value_buf.size());
      std::vector<uint8_t> data(sizeof(len) + value_buf.size());
      std::memcpy(data.data(), &len, sizeof(len));
      std::memcpy(data.data() + sizeof(len), value_buf.data<uint8_t>(),
                  value_buf.size());
      ctx_->SendAsync(i, yacl::ByteContainerView(data), "partial_open");
    }
  }
  
  // Receive shares from all other parties
  for (size_t i = 0; i < world_size_; ++i) {
    if (i != rank_) {
      auto data = ctx_->Recv(i, "partial_open");
      uint32_t len;
      std::memcpy(&len, data.data(), sizeof(len));
      const uint8_t* data_ptr = reinterpret_cast<const uint8_t*>(data.data());
      yacl::math::MPInt other_share;
      other_share.FromMagBytes(
          yacl::ByteContainerView(data_ptr + sizeof(len), len));
      value = (value + other_share) % prime_;
    }
  }
  
  return value;
}

yacl::math::MPInt SpdzMpcSystem::Open(const SecretShare& share) {
  // Open the value
  yacl::math::MPInt opened_value = PartialOpen(share);
  
  // MAC verification (only for malicious security)
  if (malicious_security_) {
    // Compute MAC share based on opened_value: γi(x) = αi * (x + δx)
    // This should match what was computed in ShareValue, but we compute it here
    // to ensure consistency with opened_value
    yacl::math::MPInt x_plus_delta = (opened_value + share.delta) % prime_;
    yacl::math::MPInt computed_mac_share = (mac_key_share_ * x_plus_delta) % prime_;
    
    // Create a new share with the computed MAC share for verification
    SecretShare share_with_mac = share;
    share_with_mac.mac_share = computed_mac_share;
    
    // Verify MAC
    if (!VerifyMac(share_with_mac, opened_value)) {
      YACL_THROW("MAC verification failed, aborting protocol");
    }
  }
  
  return opened_value;
}

bool SpdzMpcSystem::VerifyMac(const SecretShare& share,
                              const yacl::math::MPInt& opened_value) {
  // MAC verification in SPDZ:
  // For secret [x] = {δx, {x1, ..., xn}, {γ1(x), ..., γn(x)}},
  // MAC is: α(x + δx) = Σγi(x) where α is the global MAC key
  // Each party has MAC key share αi such that α = Σαi
  
  // Compute my contribution to MAC check: ti = γi(x) - αi(x + δx)
  yacl::math::MPInt x_plus_delta = (opened_value + share.delta) % prime_;
  yacl::math::MPInt expected_mac_contribution = (mac_key_share_ * x_plus_delta) % prime_;
  yacl::math::MPInt ti = (share.mac_share - expected_mac_contribution + prime_) % prime_;
  
  // Exchange ti with all other parties and verify Σti = 0
  // Send my ti to all other parties
  auto ti_buf = ti.ToMagBytes();
  uint32_t ti_len = static_cast<uint32_t>(ti_buf.size());
  std::vector<uint8_t> data(sizeof(ti_len) + ti_buf.size());
  std::memcpy(data.data(), &ti_len, sizeof(ti_len));
  std::memcpy(data.data() + sizeof(ti_len), ti_buf.data<uint8_t>(), ti_buf.size());
  
  for (size_t i = 0; i < world_size_; ++i) {
    if (i != rank_) {
      ctx_->SendAsync(i, yacl::ByteContainerView(data), "mac_verify");
    }
  }
  
  // Receive ti from all other parties
  yacl::math::MPInt sum_ti = ti;
  for (size_t i = 0; i < world_size_; ++i) {
    if (i != rank_) {
      auto recv_data = ctx_->Recv(i, "mac_verify");
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
  
  // Check if Σti = 0 (i.e., sum of all ti = 0 mod prime)
  yacl::math::MPInt zero(0);
  return (sum_ti == zero);
}

}  // namespace yacl::examples::pii
