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

#include <iostream>
#include <vector>

#include "examples/oryxcpp/pii.h"
#include "yacl/crypto/hash/hash_utils.h"
#include "yacl/link/test_util.h"

int main() {
  // Setup network for 2 parties
  auto lctxs = yacl::link::test::SetupWorld(2);
  lctxs[0]->SetRecvTimeout(120000);
  lctxs[1]->SetRecvTimeout(120000);
  
  // Party 0 inputs
  std::vector<yacl::examples::pii::PiiInput> party0_inputs = {
      {"alice@example.com", "claim1", {}},
      {"bob@example.com", "claim2", {}},
      {"charlie@example.com", "claim3", {}},
  };
  
  // Party 1 inputs
  std::vector<yacl::examples::pii::PiiInput> party1_inputs = {
      {"bob@example.com", "claim2", {}},
      {"charlie@example.com", "claim3", {}},
      {"david@example.com", "claim4", {}},
  };
  
  // Generate signatures (simplified for demo)
  auto generate_signature = [](const std::string& id, const std::string& msg) {
    std::string combined = id + "|" + msg;
    auto hash_array = yacl::crypto::Sha256(yacl::ByteContainerView(combined));
    // Convert array to vector
    std::vector<uint8_t> signature(hash_array.begin(), hash_array.end());
    return signature;
  };
  
  for (auto& input : party0_inputs) {
    input.signature = generate_signature(input.identifier, input.message);
  }
  
  for (auto& input : party1_inputs) {
    input.signature = generate_signature(input.identifier, input.message);
  }
  
  // Run PII protocol
  std::future<yacl::examples::pii::PiiOutput> party0_result = std::async(
      std::launch::async,
      [&]() {
        return yacl::examples::pii::Pii2Party(lctxs[0], party0_inputs, party1_inputs);
      });
  
  std::future<yacl::examples::pii::PiiOutput> party1_result = std::async(
      std::launch::async,
      [&]() {
        return yacl::examples::pii::Pii2Party(lctxs[1], party1_inputs, party0_inputs);
      });
  
  auto result0 = party0_result.get();
  auto result1 = party1_result.get();
  
  // Print results
  std::cout << "Party 0 intersection size: " << result0.intersection.size() << std::endl;
  std::cout << "Party 1 intersection size: " << result1.intersection.size() << std::endl;
  
  std::cout << "Party 0 intersection: ";
  for (const auto& id : result0.intersection) {
    std::cout << id << " ";
  }
  std::cout << std::endl;
  
  std::cout << "Party 1 intersection: ";
  for (const auto& id : result1.intersection) {
    std::cout << id << " ";
  }
  std::cout << std::endl;
  
  // Verify both parties got the same result
  if (result0.intersection == result1.intersection) {
    std::cout << "PII protocol completed successfully!" << std::endl;
  } else {
    std::cout << "Error: Parties got different results!" << std::endl;
  }
  
  return 0;
}
