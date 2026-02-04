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
#include "yacl/crypto/pairing/pairing.h"
#include "yacl/link/context.h"
#include "yacl/math/mpint/mp_int.h"

namespace yacl::examples::oryx {

// ========== Fp (Prime Field) Secret Sharing ==========

// SPDZ-style additive secret sharing on Fp
// [x] = {δx, {x1, ..., xn}, {γ1(x), ..., γn(x)}}
struct FpShare {
  yacl::math::MPInt delta;       // δx
  yacl::math::MPInt value_share; // xi (my share of the value)
  yacl::math::MPInt mac_share;   // γi(x) (my share of the MAC)
};

// ========== Elliptic Curve Point Secret Sharing ==========

// Secret sharing of an elliptic curve point
// [P] = {P1, ..., Pn} where P = P1 + ... + Pn
struct EcPointShare {
  yacl::crypto::EcPoint point_share;  // My share of the point
};

// ========== Bilinear Group Secret Sharing ==========

// Secret sharing of a G1 point
struct G1Share {
  yacl::crypto::EcPoint point_share;  // My share of the G1 point
};

// Secret sharing of a G2 point
struct G2Share {
  yacl::crypto::EcPoint point_share;  // My share of the G2 point
};

// Secret sharing of a GT element (multiplicative group)
// [g] = {g1, ..., gn} where g = g1 * ... * gn
struct GTShare {
  yacl::crypto::GtElement element_share;  // My share of the GT element
};

// ========== Oryx MPC System ==========

// Oryx MPC framework supporting secure computation over:
// - Prime field Fp
// - Elliptic curve groups
// - Bilinear groups G1, G2, GT
// - Pairing operations
class OryxMpcSystem {
 public:
  // Initialize Oryx MPC system
  // @param rank: My party rank (0-indexed)
  // @param world_size: Total number of parties
  // @param ctxs: Communication contexts (one per party)
  // @param ec_group: Elliptic curve group for EC operations (optional)
  // @param pairing_group: Pairing group for bilinear operations (optional)
  OryxMpcSystem(
      size_t rank, size_t world_size,
      const std::vector<std::shared_ptr<yacl::link::Context>>& ctxs,
      std::shared_ptr<yacl::crypto::EcGroup> ec_group = nullptr,
      std::shared_ptr<yacl::crypto::PairingGroup> pairing_group = nullptr);

  // ========== Fp Operations ==========

  // Generate random secret share on Fp
  FpShare FpRandom();

  // Share a value on Fp
  FpShare FpShare(const yacl::math::MPInt& value);

  // Secure addition on Fp: [a] + [b] = [a+b]
  FpShare FpAdd(const FpShare& a, const FpShare& b);

  // Secure subtraction on Fp: [a] - [b] = [a-b]
  FpShare FpSub(const FpShare& a, const FpShare& b);

  // Secure multiplication on Fp: [a] * [b] = [a*b]
  // Uses Beaver triples (simplified for now)
  FpShare FpMul(const FpShare& a, const FpShare& b);

  // Open a shared Fp value
  yacl::math::MPInt FpOpen(const FpShare& share);

  // ========== Elliptic Curve Operations ==========

  // Share an elliptic curve point
  EcPointShare EcShare(const yacl::crypto::EcPoint& point);

  // Secure point addition: [P] + [Q] = [P+Q]
  EcPointShare EcAdd(const EcPointShare& a, const EcPointShare& b);

  // Secure scalar multiplication: [k] * [P] = [k*P]
  // where [k] is an FpShare and [P] is an EcPointShare
  EcPointShare EcMul(const FpShare& scalar, const EcPointShare& point);

  // Secure scalar multiplication with public scalar: k * [P] = [k*P]
  EcPointShare EcMulPublic(const yacl::math::MPInt& scalar,
                           const EcPointShare& point);

  // Open a shared EC point
  yacl::crypto::EcPoint EcOpen(const EcPointShare& share);

  // ========== G1 Operations ==========

  // Share a G1 point
  G1Share G1Share(const yacl::crypto::EcPoint& point);

  // Secure G1 point addition: [P] + [Q] = [P+Q]
  G1Share G1Add(const G1Share& a, const G1Share& b);

  // Secure scalar multiplication on G1: [k] * [P] = [k*P]
  G1Share G1Mul(const FpShare& scalar, const G1Share& point);

  // Open a shared G1 point
  yacl::crypto::EcPoint G1Open(const G1Share& share);

  // ========== G2 Operations ==========

  // Share a G2 point
  G2Share G2Share(const yacl::crypto::EcPoint& point);

  // Secure G2 point addition: [P] + [Q] = [P+Q]
  G2Share G2Add(const G2Share& a, const G2Share& b);

  // Secure scalar multiplication on G2: [k] * [P] = [k*P]
  G2Share G2Mul(const FpShare& scalar, const G2Share& point);

  // Open a shared G2 point
  yacl::crypto::EcPoint G2Open(const G2Share& share);

  // ========== GT Operations ==========

  // Share a GT element
  GTShare GTShare(const yacl::crypto::GtElement& element);

  // Secure GT multiplication: [a] * [b] = [a*b]
  GTShare GTMul(const GTShare& a, const GTShare& b);

  // Secure GT exponentiation: [g]^[k] = [g^k]
  // where [g] is a GTShare and [k] is an FpShare
  GTShare GTPow(const GTShare& base, const FpShare& exponent);

  // Open a shared GT element
  yacl::crypto::GtElement GTOpen(const GTShare& share);

  // ========== Pairing Operations ==========

  // Secure pairing: e([P], [Q]) = [e(P, Q)]
  // where [P] is a G1Share and [Q] is a G2Share
  GTShare Pairing(const G1Share& g1_point, const G2Share& g2_point);

  // Secure pairing with public points: e(P, [Q]) = [e(P, Q)]
  GTShare PairingPublicG1(const yacl::crypto::EcPoint& g1_point,
                          const G2Share& g2_point);

  // Secure pairing with public points: e([P], Q) = [e(P, Q)]
  GTShare PairingPublicG2(const G1Share& g1_point,
                          const yacl::crypto::EcPoint& g2_point);

  // ========== Utility Functions ==========

  // Get the prime modulus for Fp
  const yacl::math::MPInt& GetPrime() const { return prime_; }

  // Get my rank
  size_t GetRank() const { return rank_; }

  // Get world size
  size_t GetWorldSize() const { return world_size_; }

 private:
  size_t rank_;
  size_t world_size_;
  std::shared_ptr<yacl::link::Context> ctx_;  // My own context
  yacl::math::MPInt prime_;
  yacl::math::MPInt mac_key_share_;  // αi (my share of MAC key α)

  // Elliptic curve and pairing groups
  std::shared_ptr<yacl::crypto::EcGroup> ec_group_;
  std::shared_ptr<yacl::crypto::PairingGroup> pairing_group_;

  // Helper: Generate random Fp share locally
  FpShare GenerateRandomFpShare();

  // Helper: Serialize/deserialize EC point for communication
  std::vector<uint8_t> SerializeEcPoint(const yacl::crypto::EcPoint& point);
  yacl::crypto::EcPoint DeserializeEcPoint(
      const std::vector<uint8_t>& data);

  // Helper: Serialize/deserialize GT element for communication
  std::vector<uint8_t> SerializeGtElement(
      const yacl::crypto::GtElement& element);
  yacl::crypto::GtElement DeserializeGtElement(
      const std::vector<uint8_t>& data);

  // Helper: Verify MAC for Fp share
  bool VerifyFpMac(const FpShare& share,
                   const yacl::math::MPInt& opened_value);
};

}  // namespace yacl::examples::oryx
