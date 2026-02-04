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
#include "yacl/link/context.h"
#include "yacl/math/mpint/mp_int.h"

namespace yacl::examples::pii {

// SPDZ-style additive secret sharing with MAC
// [x] = {δx, {x1, ..., xn}, {γ1(x), ..., γn(x)}}
// where x = Σxi, and MAC: α(x + δx) = Σγi(x)
struct SecretShare {
  yacl::math::MPInt delta;  // δx
  yacl::math::MPInt value_share;  // xi (my share of the value)
  yacl::math::MPInt mac_share;  // γi(x) (my share of the MAC)
};

// SPDZ-style MPC system for PII protocol
// Implements Protocol 2 from the paper
class SpdzMpcSystem {
 public:
  // Initialize SPDZ MPC system
  // Each party has their own MAC key share αi (only for malicious security)
  // @param malicious_security: if true, use malicious security with MAC verification
  //                            if false, use semi-honest security (more efficient)
  // @param prime: prime modulus (if not provided, uses default large prime)
  //               Can be set to elliptic curve order using ec_group->GetOrder()
  SpdzMpcSystem(size_t rank, size_t world_size,
                const std::vector<std::shared_ptr<yacl::link::Context>>& ctxs,
                bool malicious_security = true,
                const yacl::math::MPInt* prime = nullptr);

  // Frandom: Generate random additive secret shares on Fp
  SecretShare RandomShare();

  // Fshare: Generate secret shares for input value
  // If value is provided (non-zero), this party shares the value
  // If value is 0, this party receives a share from sharer_rank (default: 0)
  SecretShare ShareValue(const yacl::math::MPInt& value, size_t sharer_rank = 0);
  
  // ShareMyValue: Share my own value (always shares, never receives)
  SecretShare ShareMyValue(const yacl::math::MPInt& value);

  // Secure addition: [a] + [b] = [a+b]
  SecretShare Add(const SecretShare& a, const SecretShare& b);

  // Secure subtraction: [a] - [b] = [a-b]
  SecretShare Sub(const SecretShare& a, const SecretShare& b);

  // Scalar multiplication: k * [a] = [k*a] (where k is a public plaintext)
  SecretShare MulPlain(const SecretShare& a, const yacl::math::MPInt& k);

  // Secure multiplication: [a] * [b] = [a*b]
  // Uses Beaver triples: ([u], [v], [w]) where w = u * v
  // Security mode depends on constructor parameter
  SecretShare Mul(const SecretShare& a, const SecretShare& b);

  // Generate a Beaver triple ([u], [v], [w]) where w = u * v
  // Returns (u_share, v_share, w_share)
  // Security mode depends on constructor parameter
  std::tuple<SecretShare, SecretShare, SecretShare> GenerateBeaverTriple();

  // Open a shared value
  // If malicious_security=true: with MAC verification (aborts on failure)
  // If malicious_security=false: without MAC verification (semi-honest)
  yacl::math::MPInt Open(const SecretShare& share);

  // Partial open (without MAC verification, for intermediate values)
  yacl::math::MPInt PartialOpen(const SecretShare& share);
  
  // Check if malicious security is enabled
  bool IsMaliciousSecurity() const { return malicious_security_; }

  // Get the prime modulus
  const yacl::math::MPInt& GetPrime() const { return prime_; }

  // Get my rank
  size_t GetRank() const { return rank_; }

 private:
  size_t rank_;
  size_t world_size_;
  std::shared_ptr<yacl::link::Context> ctx_;  // My own context
  yacl::math::MPInt prime_;
  bool malicious_security_;  // Whether to use malicious security
  yacl::math::MPInt mac_key_share_;  // αi (my share of MAC key α, only used if malicious_security_=true)

  // Helper: Generate random share locally
  SecretShare GenerateRandomShare();

  // Helper: Verify MAC
  bool VerifyMac(const SecretShare& share, const yacl::math::MPInt& opened_value);

  // Helper: Common multiplication logic using Beaver triple
  SecretShare MulWithBeaverTriple(const SecretShare& a, const SecretShare& b,
                                  const SecretShare& u_share, const SecretShare& v_share,
                                  const SecretShare& w_share);

  // Helper: Generate Beaver triple with malicious security
  std::tuple<SecretShare, SecretShare, SecretShare> GenerateBeaverTripleMalicious();
  
  // Helper: Generate Beaver triple with semi-honest security
  std::tuple<SecretShare, SecretShare, SecretShare> GenerateBeaverTripleSemiHonest();
};

}  // namespace yacl::examples::pii
