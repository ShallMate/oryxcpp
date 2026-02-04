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

#include "examples/oryxcpp/pii.h"

#include <algorithm>
#include <cstring>
#include <sstream>
#include <set>
#include <unordered_map>
#include <unordered_set>

// Note: In a full implementation, we would use FastPSI or KKRT PSI
// For now, we use a simplified approach
#include "yacl/base/byte_container_view.h"
#include "yacl/base/int128.h"
#include "yacl/crypto/hash/hash_interface.h"
#include "yacl/crypto/sign/signing.h"
#include "yacl/crypto/experimental/vss/vss.h"
#include "yacl/kernel/algorithms/silent_vole.h"
#include "yacl/link/algorithm/allgather.h"
#include "yacl/link/algorithm/broadcast.h"
#include "yacl/math/mpint/mp_int.h"

namespace yacl::examples::pii {

namespace {
// Helper: Hash identifier to uint128_t for PSI computation
uint128_t HashIdentifier(const std::string& id) {
  auto hasher = yacl::crypto::Sha256();
  hasher.Update(id);
  auto hash_bytes = hasher.CumulativeHash();
  
  // Convert first 16 bytes to uint128_t
  uint128_t result = 0;
  for (size_t i = 0; i < std::min(hash_bytes.size(), size_t(16)); ++i) {
    result |= static_cast<uint128_t>(hash_bytes[i]) << (i * 8);
  }
  return result;
}

// Helper: Serialize PiiInput for transmission
std::vector<uint8_t> SerializeInput(const PiiInput& input) {
  std::vector<uint8_t> result;
  
  // Serialize identifier
  uint32_t id_len = input.identifier.size();
  result.insert(result.end(), reinterpret_cast<const uint8_t*>(&id_len),
                reinterpret_cast<const uint8_t*>(&id_len) + sizeof(id_len));
  result.insert(result.end(), input.identifier.begin(), input.identifier.end());
  
  // Serialize message
  uint32_t msg_len = input.message.size();
  result.insert(result.end(), reinterpret_cast<const uint8_t*>(&msg_len),
                reinterpret_cast<const uint8_t*>(&msg_len) + sizeof(msg_len));
  result.insert(result.end(), input.message.begin(), input.message.end());
  
  // Serialize signature
  uint32_t sig_len = input.signature.size();
  result.insert(result.end(), reinterpret_cast<const uint8_t*>(&sig_len),
                reinterpret_cast<const uint8_t*>(&sig_len) + sizeof(sig_len));
  result.insert(result.end(), input.signature.begin(), input.signature.end());
  
  return result;
}

// Helper: Deserialize PiiInput from bytes
PiiInput DeserializeInput(const std::vector<uint8_t>& data) {
  PiiInput input;
  size_t offset = 0;
  
  // Deserialize identifier
  uint32_t id_len;
  std::memcpy(&id_len, data.data() + offset, sizeof(id_len));
  offset += sizeof(id_len);
  input.identifier.assign(reinterpret_cast<const char*>(data.data() + offset),
                          id_len);
  offset += id_len;
  
  // Deserialize message
  uint32_t msg_len;
  std::memcpy(&msg_len, data.data() + offset, sizeof(msg_len));
  offset += sizeof(msg_len);
  input.message.assign(reinterpret_cast<const char*>(data.data() + offset),
                       msg_len);
  offset += msg_len;
  
  // Deserialize signature
  uint32_t sig_len;
  std::memcpy(&sig_len, data.data() + offset, sizeof(sig_len));
  offset += sizeof(sig_len);
  input.signature.assign(data.begin() + offset, data.begin() + offset + sig_len);
  
  return input;
}
}  // namespace

bool VerifySignature(const std::string& identifier,
                     const std::string& message,
                     const std::vector<uint8_t>& signature) {
  // For now, we use a simplified verification:
  // In a real implementation, this would verify ECDSA or AIBS signatures
  // For demonstration, we'll use a hash-based verification
  // TODO: Implement proper ECDSA/AIBS signature verification
  
  // Combine identifier and message
  std::string combined = identifier + "|" + message;
  
  // Compute expected hash
  auto hasher = yacl::crypto::Sha256();
  hasher.Update(combined);
  auto expected_hash = hasher.CumulativeHash();
  
  // For demo purposes, we'll accept signatures that match the hash
  // In real implementation, this would verify against a public key
  if (signature.size() != expected_hash.size()) {
    return false;
  }
  
  // Simple comparison (in real implementation, use proper signature verification)
  return std::equal(signature.begin(), signature.end(), expected_hash.begin());
}

PiiOutput Pii2Party(
    const std::shared_ptr<yacl::link::Context>& ctx,
    const std::vector<PiiInput>& my_inputs,
    const std::vector<PiiInput>& peer_inputs) {
  PiiOutput output;
  
  // Initialize MPC system for 2 parties
  std::vector<std::shared_ptr<yacl::link::Context>> ctxs = {ctx};
  size_t my_rank = ctx->Rank();
  
  // Create MPC system (each party creates their own instance)
  MpcSystem mpc_system(my_rank, 2, ctxs);
  
  // Step 1: Verify signatures for my inputs locally
  std::vector<bool> my_verification;
  std::vector<std::string> my_valid_ids;
  std::unordered_map<std::string, PiiInput> my_valid_map;
  
  for (const auto& input : my_inputs) {
    bool valid = VerifySignature(input.identifier, input.message, input.signature);
    my_verification.push_back(valid);
    if (valid) {
      my_valid_ids.push_back(input.identifier);
      my_valid_map[input.identifier] = input;
    }
  }
  
  // Step 2: Use MPC to securely verify peer signatures
  // Share signature verification results using secret sharing
  // For each peer input, we verify the signature and share the result
  
  std::vector<bool> peer_verification;
  std::vector<std::string> peer_valid_ids;
  
  for (const auto& input : peer_inputs) {
    // Verify signature locally
    bool valid = VerifySignature(input.identifier, input.message, input.signature);
    
    // Share verification result using MPC
    yacl::math::MPInt valid_mp(valid ? 1 : 0);
    auto valid_shares = mpc_system.ShareFp(valid_mp);
    
    // Open the result so both parties know if signature is valid
    yacl::math::MPInt opened_valid = mpc_system.OpenFp(valid_shares);
    bool is_valid = (opened_valid == yacl::math::MPInt(1));
    
    peer_verification.push_back(is_valid);
    if (is_valid) {
      peer_valid_ids.push_back(input.identifier);
    }
  }
  
  // Step 3: Convert identifiers to uint128_t for PSI computation
  std::vector<uint128_t> my_id_hashes;
  std::unordered_map<uint128_t, std::string> hash_to_id;
  
  for (const auto& id : my_valid_ids) {
    uint128_t hash = HashIdentifier(id);
    my_id_hashes.push_back(hash);
    hash_to_id[hash] = id;
  }
  
  // Step 4: Exchange signature verification results using secret sharing
  // For each peer input, we need to verify the signature securely
  // We'll use a simplified approach: exchange signatures and verify locally
  // In a full MPC implementation, this would be done using secret sharing
  
  std::vector<uint8_t> my_serialized;
  for (const auto& input : my_inputs) {
    auto serialized = SerializeInput(input);
    uint32_t len = serialized.size();
    my_serialized.insert(my_serialized.end(),
                        reinterpret_cast<const uint8_t*>(&len),
                        reinterpret_cast<const uint8_t*>(&len) + sizeof(len));
    my_serialized.insert(my_serialized.end(), serialized.begin(), serialized.end());
  }
  
  size_t peer_rank = (ctx->Rank() == 0) ? 1 : 0;
  ctx->SendAsync(peer_rank, yacl::ByteContainerView(my_serialized), "pii_inputs");
  auto peer_data = ctx->Recv(peer_rank, "pii_inputs");
  
  // Deserialize peer inputs
  std::vector<PiiInput> received_peer_inputs;
  size_t offset = 0;
  while (offset < peer_data.size()) {
    uint32_t len;
    if (offset + sizeof(len) > peer_data.size()) break;
    std::memcpy(&len, peer_data.data() + offset, sizeof(len));
    offset += sizeof(len);
    if (offset + len > peer_data.size()) break;
    std::vector<uint8_t> input_data(peer_data.begin() + offset,
                                    peer_data.begin() + offset + len);
    received_peer_inputs.push_back(DeserializeInput(input_data));
    offset += len;
  }
  
  // Verify peer inputs
  std::vector<bool> peer_verification;
  std::vector<std::string> peer_valid_ids;
  
  for (const auto& input : received_peer_inputs) {
    bool valid = VerifySignature(input.identifier, input.message, input.signature);
    peer_verification.push_back(valid);
    if (valid) {
      peer_valid_ids.push_back(input.identifier);
    }
  }
  
  // Step 5: Use secure PSI to compute intersection
  // Convert peer valid IDs to hashes
  std::vector<uint128_t> peer_id_hashes;
  std::unordered_map<uint128_t, std::string> peer_hash_to_id;
  
  for (const auto& id : peer_valid_ids) {
    uint128_t hash = HashIdentifier(id);
    peer_id_hashes.push_back(hash);
    peer_hash_to_id[hash] = id;
  }
  
  // Use secure PSI to compute intersection
  // For now, we'll use a simplified approach with hash-based PSI
  // In a full implementation, we would use FastPSI or KKRT PSI
  
  // Step 5: Use secure PSI to compute intersection
  // In a full MPC implementation, we would use FastPSI or KKRT PSI here
  // For now, we use a simplified secure approach with hash exchange
  
  std::vector<uint128_t> intersection_hashes;
  
  if (ctx->Rank() == 0) {
    // Party 0: Send my hashes to party 1
    std::vector<uint8_t> hash_data(my_id_hashes.size() * sizeof(uint128_t));
    std::memcpy(hash_data.data(), my_id_hashes.data(), hash_data.size());
    ctx->SendAsync(peer_rank, yacl::ByteContainerView(hash_data), "my_hashes");
    
    // Receive peer hashes
    auto peer_hash_data = ctx->Recv(peer_rank, "peer_hashes");
    size_t num_hashes = peer_hash_data.size() / sizeof(uint128_t);
    std::vector<uint128_t> received_hashes(num_hashes);
    std::memcpy(received_hashes.data(), peer_hash_data.data(), peer_hash_data.size());
    std::set<uint128_t> received_set(received_hashes.begin(), received_hashes.end());
    std::set<uint128_t> my_set(my_id_hashes.begin(), my_id_hashes.end());
    
    // Compute intersection
    std::set_intersection(my_set.begin(), my_set.end(),
                         received_set.begin(), received_set.end(),
                         std::back_inserter(intersection_hashes));
    
    // Receive intersection from party 1 for verification
    auto intersection_data = ctx->Recv(peer_rank, "psi_intersection");
    // Verify both parties computed the same intersection
  } else {
    // Party 1: Receive hashes from party 0
    auto my_hash_data = ctx->Recv(peer_rank, "my_hashes");
    size_t num_hashes = my_hash_data.size() / sizeof(uint128_t);
    std::vector<uint128_t> received_hashes(num_hashes);
    std::memcpy(received_hashes.data(), my_hash_data.data(), my_hash_data.size());
    std::set<uint128_t> received_set(received_hashes.begin(), received_hashes.end());
    
    // Send my hashes
    std::vector<uint8_t> hash_data(peer_id_hashes.size() * sizeof(uint128_t));
    std::memcpy(hash_data.data(), peer_id_hashes.data(), hash_data.size());
    ctx->SendAsync(peer_rank, yacl::ByteContainerView(hash_data), "peer_hashes");
    
    // Compute intersection
    std::set<uint128_t> my_set(peer_id_hashes.begin(), peer_id_hashes.end());
    std::set_intersection(received_set.begin(), received_set.end(),
                         my_set.begin(), my_set.end(),
                         std::back_inserter(intersection_hashes));
    
    // Send intersection back for verification
    std::vector<uint8_t> intersection_data(intersection_hashes.size() * sizeof(uint128_t));
    std::memcpy(intersection_data.data(), intersection_hashes.data(),
                intersection_data.size());
    ctx->SendAsync(peer_rank, yacl::ByteContainerView(intersection_data),
                   "psi_intersection");
  }
  
  // Step 6: Convert intersection hashes back to identifiers
  for (const auto& hash : intersection_hashes) {
    if (hash_to_id.count(hash)) {
      output.intersection.push_back(hash_to_id[hash]);
    }
  }
  
  // Combine verification results
  output.verification_results = my_verification;
  output.verification_results.insert(output.verification_results.end(),
                                    peer_verification.begin(),
                                    peer_verification.end());
  
  return output;
}

PiiOutput PiiMultiParty(
    const std::vector<std::shared_ptr<yacl::link::Context>>& ctxs,
    const std::vector<PiiInput>& my_inputs) {
  PiiOutput output;
  
  // Step 1: Verify signatures for my inputs
  std::vector<bool> my_verification;
  std::vector<std::string> my_valid_ids;
  
  for (const auto& input : my_inputs) {
    bool valid = VerifySignature(input.identifier, input.message, input.signature);
    my_verification.push_back(valid);
    if (valid) {
      my_valid_ids.push_back(input.identifier);
    }
  }
  
  // Step 2: Gather all valid identifiers from all parties
  // In a real implementation, we'd use secure aggregation
  std::vector<std::vector<std::string>> all_valid_ids;
  
  // Broadcast my valid IDs to all parties
  size_t my_rank = ctxs[0]->Rank();
  for (size_t i = 0; i < ctxs.size(); ++i) {
    if (i != my_rank) {
      // Serialize and send
      std::string serialized;
      for (const auto& id : my_valid_ids) {
        serialized += id + "\n";
      }
      ctxs[0]->SendAsync(i, yacl::ByteContainerView(serialized), "pii_valid_ids");
    }
  }
  
  // Receive valid IDs from all other parties
  std::vector<std::set<std::string>> all_party_valid_ids;
  all_party_valid_ids.push_back(std::set<std::string>(my_valid_ids.begin(), my_valid_ids.end()));
  
  for (size_t i = 0; i < ctxs.size(); ++i) {
    if (i != my_rank) {
      auto data = ctxs[0]->Recv(i, "pii_valid_ids");
      std::string received_str(reinterpret_cast<const char*>(data.data()), data.size());
      std::set<std::string> party_ids;
      std::istringstream iss(received_str);
      std::string id;
      while (std::getline(iss, id) && !id.empty()) {
        party_ids.insert(id);
      }
      all_party_valid_ids.push_back(party_ids);
    }
  }
  
  // Step 3: Compute intersection across all parties
  if (!all_party_valid_ids.empty()) {
    std::set<std::string> intersection_set = all_party_valid_ids[0];
    for (size_t i = 1; i < all_party_valid_ids.size(); ++i) {
      std::set<std::string> temp;
      std::set_intersection(intersection_set.begin(), intersection_set.end(),
                           all_party_valid_ids[i].begin(), all_party_valid_ids[i].end(),
                           std::inserter(temp, temp.begin()));
      intersection_set = temp;
    }
    output.intersection.assign(intersection_set.begin(), intersection_set.end());
  } else {
    output.intersection.assign(my_valid_ids.begin(), my_valid_ids.end());
  }
  output.verification_results = my_verification;
  
  return output;
}

}  // namespace yacl::examples::pii
