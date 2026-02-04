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

#pragma once

#include <memory>
#include <vector>

#include "yacl/base/int128.h"
#include "yacl/crypto/ecc/ecc_spi.h"
#include "yacl/link/context.h"
#include "yacl/math/mpint/mp_int.h"

namespace yacl::examples::pii {

// MPC System for PII protocol
// This implements a true MPC framework without trusted third party
// All parties communicate directly via yacl::link::Context
class MpcSystem {
 public:
  // Initialize MPC system with n parties
  // Each party calls this with their own rank and all contexts
  MpcSystem(size_t rank, size_t world_size,
            const std::vector<std::shared_ptr<yacl::link::Context>>& ctxs);

  // Share a secret value in Fp (prime field)
  // Returns shares distributed to all parties
  std::vector<yacl::math::MPInt> ShareFp(const yacl::math::MPInt& secret);

  // Reconstruct a secret from shares
  yacl::math::MPInt ReconstructFp(const std::vector<yacl::math::MPInt>& shares);

  // Secure addition: [a] + [b] = [a+b]
  std::vector<yacl::math::MPInt> AddFp(
      const std::vector<yacl::math::MPInt>& shares_a,
      const std::vector<yacl::math::MPInt>& shares_b);

  // Secure multiplication: [a] * [b] = [a*b]
  // Uses VOLE for secure multiplication
  std::vector<yacl::math::MPInt> MulFp(
      const std::vector<yacl::math::MPInt>& shares_a,
      const std::vector<yacl::math::MPInt>& shares_b);

  // Secure comparison: [a] < [b]?
  // Returns shares of comparison result (0 or 1)
  std::vector<yacl::math::MPInt> CompareFp(
      const std::vector<yacl::math::MPInt>& shares_a,
      const std::vector<yacl::math::MPInt>& shares_b);

  // Open a shared value (reveal to all parties)
  yacl::math::MPInt OpenFp(const std::vector<yacl::math::MPInt>& shares);

  // Get the prime modulus
  const yacl::math::MPInt& GetPrime() const { return prime_; }

  // Get my rank
  size_t GetRank() const { return rank_; }

  // Get world size
  size_t GetWorldSize() const { return world_size_; }

 private:
  size_t rank_;
  size_t world_size_;
  std::vector<std::shared_ptr<yacl::link::Context>> ctxs_;
  yacl::math::MPInt prime_;  // Prime modulus for Fp

  // Helper: Generate random shares for a secret
  std::vector<yacl::math::MPInt> GenerateRandomShares(
      const yacl::math::MPInt& secret);
};

}  // namespace yacl::examples::pii
