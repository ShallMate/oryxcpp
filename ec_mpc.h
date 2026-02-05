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
// Forward declaration
struct SecretShare;
class SpdzMpcSystem;
}

namespace yacl::examples::pii {

// Elliptic curve point secret sharing
// [P] = {δP, {P1, ..., Pn}, {γ1(P), ..., γn(P)}}
// where P = ΣPi (point addition), and MAC: α(P + δP) = Σγi(P)
struct EcPointShare {
  yacl::crypto::EcPoint delta_point;  // δP (point on curve)
  yacl::crypto::EcPoint point_share;   // Pi (my share of the point)
  yacl::math::MPInt mac_share;        // γi(P) (my share of the MAC)
};

// Elliptic curve group G MPC system
// Implements SPDZ-style MPC for elliptic curve points
class EcMpcSystem {
 public:
  // Initialize EC MPC system
  // @param ec_group: elliptic curve group
  // @param malicious_security: if true, use malicious security with MAC verification
  EcMpcSystem(size_t rank, size_t world_size,
              const std::vector<std::shared_ptr<yacl::link::Context>>& ctxs,
              std::shared_ptr<yacl::crypto::EcGroup> ec_group,
              bool malicious_security = true);

  // Frandom: Generate random additive secret shares on G
  EcPointShare RandomShare();

  // Fshare: Generate secret shares for input point
  // If point is provided (not infinity), this party shares the point
  // If point is infinity, this party receives a share from sharer_rank
  EcPointShare ShareValue(const yacl::crypto::EcPoint& point, size_t sharer_rank = 0);
  
  // ShareMyValue: Share my own point (always shares, never receives)
  EcPointShare ShareMyValue(const yacl::crypto::EcPoint& point);

  // Secure point addition: [P] + [Q] = [P+Q]
  EcPointShare Add(const EcPointShare& a, const EcPointShare& b);

  // Secure point subtraction: [P] - [Q] = [P-Q]
  EcPointShare Sub(const EcPointShare& a, const EcPointShare& b);

  // Scalar multiplication: k * [P] = [k*P] (where k is a public plaintext scalar)
  EcPointShare MulScalar(const yacl::math::MPInt& scalar, const EcPointShare& point);

  // Secret scalar times public point: [k] * P = [k*P] (where [k] is secret-shared, P is public)
  // Simple protocol: each party computes k_i * P and shares it, then combine
  // [k*P] = Σ_i [k_i * P]_i where k_i is party i's share of [k]
  EcPointShare MulSecretScalarPublicPoint(const SecretShare& k_share, const yacl::crypto::EcPoint& public_point);

  // Secret scalar multiplication: [k] * [P] = [k*P] (where both k and P are secret-shared)
  // Implementation based on preprocessing method (similar to Beaver triple)
  // Protocol:
  // 1. Generate preprocessing triple ([r], [R], [r*R]) where R is a random point, r is random scalar
  // 2. Compute ε = [k] - [r] and open it
  // 3. Compute δ = [P] - [R] and open it
  // 4. Compute [k*P] = [r*R] + ε * [R] + [r] * δ + ε * δ
  // Note: Requires Fp MPC system for scalar operations
  EcPointShare MulSecretScalar(const SecretShare& k_share, const EcPointShare& point_share,
                               SpdzMpcSystem* fp_mpc = nullptr);

  // Open a shared point
  // If malicious_security=true: with MAC verification (aborts on failure)
  // If malicious_security=false: without MAC verification (semi-honest)
  yacl::crypto::EcPoint Open(const EcPointShare& share);

  // Partial open (without MAC verification, for intermediate values)
  yacl::crypto::EcPoint PartialOpen(const EcPointShare& share);
  
  // Check if malicious security is enabled
  bool IsMaliciousSecurity() const { return malicious_security_; }

  // Get the elliptic curve group
  std::shared_ptr<yacl::crypto::EcGroup> GetEcGroup() const { return ec_group_; }

  // Get my rank
  size_t GetRank() const { return rank_; }

 private:
  size_t rank_;
  size_t world_size_;
  std::shared_ptr<yacl::link::Context> ctx_;  // My own context
  std::shared_ptr<yacl::crypto::EcGroup> ec_group_;  // Elliptic curve group
  yacl::math::MPInt prime_;  // Order of the curve (n)
  bool malicious_security_;  // Whether to use malicious security
  yacl::math::MPInt mac_key_share_;  // αi (my share of MAC key α, only used if malicious_security_=true)

  // Helper: Generate random share locally
  EcPointShare GenerateRandomShare();

  // Helper: Verify MAC
  bool VerifyMac(const EcPointShare& share, const yacl::crypto::EcPoint& opened_point);

  // Helper: Create a share for a public point (all parties know it)
  EcPointShare SharePublicPoint(const yacl::crypto::EcPoint& point);
};

}  // namespace yacl::examples::pii
