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

#include "examples/oryxcpp/ec_mpc.h"
#include "yacl/crypto/pairing/pairing.h"
#include "yacl/link/context.h"
#include "yacl/math/galois_field/gf.h"
#include "yacl/math/mpint/mp_int.h"

namespace yacl::examples::pii {

// Forward declaration
struct SecretShare;
class SpdzMpcSystem;

// GT group element secret sharing (multiplicative group)
// [g] = {δg, {g1, ..., gn}, {γ1(g), ..., γn(g)}}
// where g = Πgi (multiplication), and MAC: α(g * δg) = Σγi(g)
struct GtElementShare {
  yacl::Item delta_element;  // δg (element in GT)
  yacl::Item element_share;   // gi (my share of the element)
  yacl::math::MPInt mac_share;      // γi(g) (my share of the MAC)

  // Constructor: initialize with identity elements
  // Note: Item default constructor is private, so we need to initialize from GaloisField
  GtElementShare() = delete;  // Prevent default construction
  
  // Constructor that takes Item objects (for initialization)
  GtElementShare(const yacl::Item& delta, const yacl::Item& element, const yacl::math::MPInt& mac)
      : delta_element(delta), element_share(element), mac_share(mac) {}
};

// Bilinear pairing groups MPC system
// Supports MPC operations on G1, G2 (additive groups) and GT (multiplicative group)
class PairingMpcSystem {
 public:
  // Initialize pairing MPC system
  // @param pairing_group: bilinear pairing group (provides G1, G2, GT)
  // @param malicious_security: if true, use malicious security with MAC verification
  PairingMpcSystem(size_t rank, size_t world_size,
                   const std::vector<std::shared_ptr<yacl::link::Context>>& ctxs,
                   std::shared_ptr<yacl::crypto::PairingGroup> pairing_group,
                   bool malicious_security = true);

  // ========== G1 Operations (using EcMpcSystem) ==========
  
  // RandomShare: Generate random additive secret shares on G1
  EcPointShare RandomShareG1();

  // ShareValue: Generate secret shares for input point in G1
  EcPointShare ShareValueG1(const yacl::crypto::EcPoint& point, size_t sharer_rank = 0);

  // ShareMyValue: Share my own point in G1
  EcPointShare ShareMyValueG1(const yacl::crypto::EcPoint& point);

  // Add: [P] + [Q] = [P+Q] in G1
  EcPointShare AddG1(const EcPointShare& a, const EcPointShare& b);

  // Sub: [P] - [Q] = [P-Q] in G1
  EcPointShare SubG1(const EcPointShare& a, const EcPointShare& b);

  // MulScalar: k * [P] = [k*P] in G1 (k is public)
  EcPointShare MulScalarG1(const yacl::math::MPInt& scalar, const EcPointShare& point);

  // Open: Open a shared point in G1
  yacl::crypto::EcPoint OpenG1(const EcPointShare& share);

  // PartialOpen: Partial open in G1 (without MAC verification)
  yacl::crypto::EcPoint PartialOpenG1(const EcPointShare& share);

  // ========== G2 Operations (using EcMpcSystem) ==========
  
  // RandomShare: Generate random additive secret shares on G2
  EcPointShare RandomShareG2();

  // ShareValue: Generate secret shares for input point in G2
  EcPointShare ShareValueG2(const yacl::crypto::EcPoint& point, size_t sharer_rank = 0);

  // ShareMyValue: Share my own point in G2
  EcPointShare ShareMyValueG2(const yacl::crypto::EcPoint& point);

  // Add: [P] + [Q] = [P+Q] in G2
  EcPointShare AddG2(const EcPointShare& a, const EcPointShare& b);

  // Sub: [P] - [Q] = [P-Q] in G2
  EcPointShare SubG2(const EcPointShare& a, const EcPointShare& b);

  // MulScalar: k * [P] = [k*P] in G2 (k is public)
  EcPointShare MulScalarG2(const yacl::math::MPInt& scalar, const EcPointShare& point);

  // Open: Open a shared point in G2
  yacl::crypto::EcPoint OpenG2(const EcPointShare& share);

  // PartialOpen: Partial open in G2 (without MAC verification)
  yacl::crypto::EcPoint PartialOpenG2(const EcPointShare& share);

  // ========== GT Operations (multiplicative group) ==========
  
  // RandomShare: Generate random multiplicative secret shares on GT
  GtElementShare RandomShareGT();

  // ShareValue: Generate secret shares for input element in GT
  GtElementShare ShareValueGT(const yacl::Item& element, size_t sharer_rank = 0);

  // ShareMyValue: Share my own element in GT
  GtElementShare ShareMyValueGT(const yacl::Item& element);

  // Mul: [g] * [h] = [g*h] in GT (multiplicative)
  GtElementShare MulGT(const GtElementShare& a, const GtElementShare& b);

  // Div: [g] / [h] = [g/h] in GT (multiplicative)
  GtElementShare DivGT(const GtElementShare& a, const GtElementShare& b);

  // Pow: [g]^k = [g^k] in GT (k is public)
  GtElementShare PowGT(const yacl::math::MPInt& exponent, const GtElementShare& element);

  // Open: Open a shared element in GT
  yacl::Item OpenGT(const GtElementShare& share);

  // PartialOpen: Partial open in GT (without MAC verification)
  yacl::Item PartialOpenGT(const GtElementShare& share);

  // ========== Pairing Operations ==========
  
  // SecPair1: e([P], Q) = [e(P, Q)] where [P] ∈ G1 is secret-shared, Q ∈ G2 is public
  // Protocol: Each party computes e(P_i, Q) locally, then shares the result
  GtElementShare PairingSecretG1(const EcPointShare& g1_share,
                                  const yacl::crypto::EcPoint& g2_public);

  // SecPair2: e(P, [Q]) = [e(P, Q)] where P ∈ G1 is public, [Q] ∈ G2 is secret-shared
  // Protocol: Each party computes e(P, Q_i) locally, then shares the result
  GtElementShare PairingSecretG2(const yacl::crypto::EcPoint& g1_public,
                                  const EcPointShare& g2_share);

  // SecPair3: e([P], [Q]) = [e(P, Q)] where both [P] ∈ G1 and [Q] ∈ G2 are secret-shared
  // Protocol: Uses Beaver triple over Fp and SecPair1/SecPair2
  // Requires Fp MPC system for Beaver triple generation
  GtElementShare PairingSecret(const EcPointShare& g1_share,
                                const EcPointShare& g2_share,
                                SpdzMpcSystem* fp_mpc = nullptr);

  // ========== Getters ==========
  
  bool IsMaliciousSecurity() const { return malicious_security_; }
  std::shared_ptr<yacl::crypto::PairingGroup> GetPairingGroup() const { return pairing_group_; }
  std::shared_ptr<yacl::crypto::EcGroup> GetGroup1() const { return g1_mpc_->GetEcGroup(); }
  std::shared_ptr<yacl::crypto::EcGroup> GetGroup2() const { return g2_mpc_->GetEcGroup(); }
  std::shared_ptr<yacl::math::GaloisField> GetGroupT() const { return gt_group_; }
  size_t GetRank() const { return rank_; }

 private:
  size_t rank_;
  size_t world_size_;
  std::shared_ptr<yacl::link::Context> ctx_;
  std::shared_ptr<yacl::crypto::PairingGroup> pairing_group_;
  std::shared_ptr<yacl::math::GaloisField> gt_group_;
  yacl::math::MPInt prime_;  // Order of the groups
  bool malicious_security_;
  yacl::math::MPInt mac_key_share_;  // αi for GT

  // MPC systems for G1 and G2 (additive groups)
  std::unique_ptr<EcMpcSystem> g1_mpc_;
  std::unique_ptr<EcMpcSystem> g2_mpc_;

  // Helper: Generate random share locally for GT
  GtElementShare GenerateRandomShareGT();

  // Helper: Verify MAC for GT
  bool VerifyMacGT(const GtElementShare& share, const yacl::Item& opened_element);

  // Helper: Create a share for a public element in GT
  GtElementShare SharePublicElementGT(const yacl::Item& element);

  // Helper: Share a public point in G1
  EcPointShare SharePublicPointG1(const yacl::crypto::EcPoint& point);

  // Helper: Share a public point in G2
  EcPointShare SharePublicPointG2(const yacl::crypto::EcPoint& point);
};

}  // namespace yacl::examples::pii
