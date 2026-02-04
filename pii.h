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
#include <string>
#include <vector>

#include <memory>
#include <string>
#include <vector>

#include "yacl/base/int128.h"
#include "yacl/link/context.h"

namespace yacl::examples::pii {

// PII input element: (identifier, message, signature)
struct PiiInput {
  std::string identifier;  // id: public key, email, phone number, etc.
  std::string message;    // m: payload attached to the identifier
  std::vector<uint8_t> signature;  // σ: signature for verification
};

// PII output: intersection of verified identifiers
struct PiiOutput {
  std::vector<std::string> intersection;  // Verified identifiers in intersection
  std::vector<bool> verification_results;  // Verification results for each input
};

// Two-party PII protocol
// Input: Each party has a set of (identifier, message, signature) tuples
// Output: Intersection of identifiers that pass verification
PiiOutput Pii2Party(
    const std::shared_ptr<yacl::link::Context>& ctx,
    const std::vector<PiiInput>& my_inputs,
    const std::vector<PiiInput>& peer_inputs);

// Multi-party PII protocol
// Input: Each party has a set of (identifier, message, signature) tuples
// Output: Intersection of identifiers that pass verification from all parties
PiiOutput PiiMultiParty(
    const std::vector<std::shared_ptr<yacl::link::Context>>& ctxs,
    const std::vector<PiiInput>& my_inputs);

// Note: VerifySignature is now implemented in pii_mpc.cc
// This is a simplified version - in full implementation would use MPC

}  // namespace yacl::examples::pii
