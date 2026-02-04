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

#include "examples/oryxcpp/mpc_system.h"

#include <algorithm>
#include <random>

#include "yacl/base/byte_container_view.h"
#include "yacl/crypto/hash/hash_interface.h"
#include "yacl/kernel/algorithms/silent_vole.h"

namespace yacl::examples::pii {

MpcSystem::MpcSystem(size_t rank, size_t world_size,
                     const std::vector<std::shared_ptr<yacl::link::Context>>& ctxs)
    : rank_(rank), world_size_(world_size), ctxs_(ctxs) {
  // Use a large prime for Fp (256-bit security)
  // In production, this should be a proper prime from a standard curve
  prime_ = yacl::math::MPInt(
      "115792089237316195423570985008687907853269984665640564039457584007913129639747");
}

std::vector<yacl::math::MPInt> MpcSystem::GenerateRandomShares(
    const yacl::math::MPInt& secret) {
  std::vector<yacl::math::MPInt> shares(world_size_);
  
  // Generate random shares for parties 0 to n-2
  yacl::math::MPInt sum(0);
  for (size_t i = 0; i < world_size_ - 1; ++i) {
    yacl::math::MPInt::RandomLtN(prime_, &shares[i]);
    sum += shares[i];
    sum %= prime_;
  }
  
  // Last share is computed to make sum equal to secret
  shares[world_size_ - 1] = (secret - sum + prime_) % prime_;
  
  return shares;
}

std::vector<yacl::math::MPInt> MpcSystem::ShareFp(
    const yacl::math::MPInt& secret) {
  // Generate shares locally
  std::vector<yacl::math::MPInt> shares = GenerateRandomShares(secret);
  
  // Distribute shares to all parties via network
  for (size_t i = 0; i < world_size_; ++i) {
    if (i != rank_) {
      // Serialize share
      std::vector<uint8_t> share_bytes = shares[i].ToBytes();
      uint32_t len = share_bytes.size();
      
      std::vector<uint8_t> data(sizeof(len) + share_bytes.size());
      std::memcpy(data.data(), &len, sizeof(len));
      std::memcpy(data.data() + sizeof(len), share_bytes.data(),
                  share_bytes.size());
      
      ctxs_[rank_]->SendAsync(i, yacl::ByteContainerView(data),
                               "share_fp");
    }
  }
  
  // Receive shares from other parties
  std::vector<yacl::math::MPInt> received_shares(world_size_);
  received_shares[rank_] = shares[rank_];  // My own share
  
  for (size_t i = 0; i < world_size_; ++i) {
    if (i != rank_) {
      auto data = ctxs_[rank_]->Recv(i, "share_fp");
      
      uint32_t len;
      std::memcpy(&len, data.data(), sizeof(len));
      std::vector<uint8_t> share_bytes(data.begin() + sizeof(len),
                                       data.begin() + sizeof(len) + len);
      
      received_shares[i] = yacl::math::MPInt(share_bytes);
    }
  }
  
  return received_shares;
}

yacl::math::MPInt MpcSystem::ReconstructFp(
    const std::vector<yacl::math::MPInt>& shares) {
  YACL_ENFORCE(shares.size() == world_size_,
               "Number of shares must equal world size");
  
  // Sum all shares
  yacl::math::MPInt result(0);
  for (const auto& share : shares) {
    result += share;
    result %= prime_;
  }
  
  return result;
}

std::vector<yacl::math::MPInt> MpcSystem::AddFp(
    const std::vector<yacl::math::MPInt>& shares_a,
    const std::vector<yacl::math::MPInt>& shares_b) {
  YACL_ENFORCE(shares_a.size() == world_size_ && shares_b.size() == world_size_,
               "Share vectors must have world_size elements");
  
  // Local addition: [a] + [b] = [a+b] (no communication needed)
  std::vector<yacl::math::MPInt> result(world_size_);
  for (size_t i = 0; i < world_size_; ++i) {
    result[i] = (shares_a[i] + shares_b[i]) % prime_;
  }
  
  return result;
}

std::vector<yacl::math::MPInt> MpcSystem::MulFp(
    const std::vector<yacl::math::MPInt>& shares_a,
    const std::vector<yacl::math::MPInt>& shares_b) {
  YACL_ENFORCE(shares_a.size() == world_size_ && shares_b.size() == world_size_,
               "Share vectors must have world_size elements");
  
  // For secure multiplication, we use Beaver triples via VOLE
  // Simplified version: use VOLE to generate multiplication triples
  
  // Step 1: Generate random triple (a, b, c) where c = a * b
  // In a full implementation, this would use VOLE protocol
  // For now, we use a simplified approach with communication
  
  // Local multiplication of shares
  yacl::math::MPInt local_prod = (shares_a[rank_] * shares_b[rank_]) % prime_;
  
  // Exchange local products and compute result
  std::vector<yacl::math::MPInt> local_products(world_size_);
  local_products[rank_] = local_prod;
  
  // Exchange local products
  for (size_t i = 0; i < world_size_; ++i) {
    if (i != rank_) {
      std::vector<uint8_t> prod_bytes = local_prod.ToBytes();
      uint32_t len = prod_bytes.size();
      std::vector<uint8_t> data(sizeof(len) + prod_bytes.size());
      std::memcpy(data.data(), &len, sizeof(len));
      std::memcpy(data.data() + sizeof(len), prod_bytes.data(),
                  prod_bytes.size());
      ctxs_[rank_]->SendAsync(i, yacl::ByteContainerView(data), "mul_local");
    }
  }
  
  for (size_t i = 0; i < world_size_; ++i) {
    if (i != rank_) {
      auto data = ctxs_[rank_]->Recv(i, "mul_local");
      uint32_t len;
      std::memcpy(&len, data.data(), sizeof(len));
      std::vector<uint8_t> prod_bytes(data.begin() + sizeof(len),
                                      data.begin() + sizeof(len) + len);
      local_products[i] = yacl::math::MPInt(prod_bytes);
    }
  }
  
  // Compute result shares (simplified - in full implementation use Beaver triples)
  std::vector<yacl::math::MPInt> result(world_size_);
  yacl::math::MPInt sum(0);
  for (const auto& prod : local_products) {
    sum += prod;
    sum %= prime_;
  }
  
  // Distribute sum as shares
  result = GenerateRandomShares(sum);
  
  return result;
}

std::vector<yacl::math::MPInt> MpcSystem::CompareFp(
    const std::vector<yacl::math::MPInt>& shares_a,
    const std::vector<yacl::math::MPInt>& shares_b) {
  // Secure comparison using secure subtraction and bit extraction
  // [a] < [b] is equivalent to checking if [b] - [a] > 0
  
  // Compute [diff] = [b] - [a]
  std::vector<yacl::math::MPInt> neg_a(world_size_);
  for (size_t i = 0; i < world_size_; ++i) {
    neg_a[i] = (prime_ - shares_a[i]) % prime_;
  }
  
  std::vector<yacl::math::MPInt> diff_shares = AddFp(shares_b, neg_a);
  
  // Check if diff > 0 (simplified - in full implementation use bit decomposition)
  // For now, return shares of 1 if diff > prime_/2 (treating as signed)
  yacl::math::MPInt diff = ReconstructFp(diff_shares);
  yacl::math::MPInt half_prime = prime_ / 2;
  
  yacl::math::MPInt result_val(0);
  if (diff > half_prime) {
    result_val = yacl::math::MPInt(0);  // diff is negative, so a >= b
  } else {
    result_val = yacl::math::MPInt(1);  // diff is positive, so a < b
  }
  
  return ShareFp(result_val);
}

yacl::math::MPInt MpcSystem::OpenFp(
    const std::vector<yacl::math::MPInt>& shares) {
  // Each party sends their share to all others
  for (size_t i = 0; i < world_size_; ++i) {
    if (i != rank_) {
      std::vector<uint8_t> share_bytes = shares[rank_].ToBytes();
      uint32_t len = share_bytes.size();
      std::vector<uint8_t> data(sizeof(len) + share_bytes.size());
      std::memcpy(data.data(), &len, sizeof(len));
      std::memcpy(data.data() + sizeof(len), share_bytes.data(),
                  share_bytes.size());
      ctxs_[rank_]->SendAsync(i, yacl::ByteContainerView(data), "open_fp");
    }
  }
  
  // Receive shares from all parties
  std::vector<yacl::math::MPInt> all_shares(world_size_);
  all_shares[rank_] = shares[rank_];
  
  for (size_t i = 0; i < world_size_; ++i) {
    if (i != rank_) {
      auto data = ctxs_[rank_]->Recv(i, "open_fp");
      uint32_t len;
      std::memcpy(&len, data.data(), sizeof(len));
      std::vector<uint8_t> share_bytes(data.begin() + sizeof(len),
                                      data.begin() + sizeof(len) + len);
      all_shares[i] = yacl::math::MPInt(share_bytes);
    }
  }
  
  return ReconstructFp(all_shares);
}

}  // namespace yacl::examples::pii
