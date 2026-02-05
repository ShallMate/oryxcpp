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

#include "examples/oryxcpp/pairing_mpc.h"

#include <chrono>
#include <iostream>
#include <thread>
#include <vector>

#include "examples/oryxcpp/spdz_mpc.h"
#include "yacl/base/exception.h"
#include "yacl/crypto/pairing/factory/mcl_pairing_group.h"
#include "yacl/crypto/pairing/pairing.h"
#include "yacl/link/test_util.h"

namespace yacl::examples::pii {

// Helper function to get total statistics from all contexts
struct CommStats {
  size_t sent_bytes = 0;
  size_t sent_actions = 0;
  size_t recv_bytes = 0;
  size_t recv_actions = 0;
};

CommStats GetTotalStats(const std::vector<std::shared_ptr<yacl::link::Context>>& contexts) {
  CommStats total;
  for (const auto& ctx : contexts) {
    auto stats = ctx->GetStats();
    if (stats) {
      total.sent_bytes += stats->sent_bytes.load();
      total.sent_actions += stats->sent_actions.load();
      total.recv_bytes += stats->recv_bytes.load();
      total.recv_actions += stats->recv_actions.load();
    }
  }
  return total;
}

// Helper function to print statistics
void PrintStats(const CommStats& start_stats, const CommStats& end_stats,
                const std::chrono::high_resolution_clock::time_point& start_time,
                const std::chrono::high_resolution_clock::time_point& end_time,
                const std::string& /* test_name */) {
  auto duration_ms = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time);
  auto duration_us = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time);
  size_t sent_bytes = end_stats.sent_bytes - start_stats.sent_bytes;
  size_t sent_actions = end_stats.sent_actions - start_stats.sent_actions;
  size_t recv_bytes = end_stats.recv_bytes - start_stats.recv_bytes;
  size_t recv_actions = end_stats.recv_actions - start_stats.recv_actions;
  
  if (duration_ms.count() > 0) {
    std::cout << "    Time: " << duration_ms.count() << " ms (" << duration_us.count() << " μs)" << std::endl;
  } else {
    std::cout << "    Time: < 1 ms (" << duration_us.count() << " μs)" << std::endl;
  }
  std::cout << "    Communication:" << std::endl;
  std::cout << "      Sent: " << sent_bytes << " bytes (" << sent_actions << " actions)" << std::endl;
  std::cout << "      Received: " << recv_bytes << " bytes (" << recv_actions << " actions)" << std::endl;
  std::cout << "      Total: " << (sent_bytes + recv_bytes) << " bytes ("
            << (sent_actions + recv_actions) << " actions)" << std::endl;
}


// Test RandomShare for G1
void TestRandomShareG1(bool malicious_security, size_t world_size = 2) {
  std::string mode = malicious_security ? "Malicious" : "Semi-Honest";
  std::cout << "Testing RandomShare G1 (" << mode << ", " << world_size << " parties)..." << std::endl;

  auto contexts = yacl::link::test::SetupBrpcWorld(world_size);
  std::vector<std::unique_ptr<PairingMpcSystem>> mpc_systems(world_size);
  std::vector<std::thread> threads;

  // Create pairing group (use BLS12_381 as example)
  // Use MclPGFactory directly to avoid library registration issues
  auto pairing_group = yacl::crypto::MclPGFactory::CreateByName("bls12-381");
  std::shared_ptr<yacl::crypto::PairingGroup> pairing_group_shared(
      pairing_group.release());

  // Record start time and stats
  auto start_time = std::chrono::high_resolution_clock::now();
  auto start_stats = GetTotalStats(contexts);

  for (size_t i = 0; i < world_size; ++i) {
    threads.emplace_back([&, i]() {
      std::vector<std::shared_ptr<yacl::link::Context>> ctx_vec = {contexts[i]};
      mpc_systems[i] = std::make_unique<PairingMpcSystem>(
          i, world_size, ctx_vec, pairing_group_shared, malicious_security);
    });
  }
  for (auto& t : threads) {
    t.join();
  }

  // Generate random shares
  std::vector<EcPointShare> shares(world_size);
  threads.clear();
  for (size_t i = 0; i < world_size; ++i) {
    threads.emplace_back([&, i]() {
      shares[i] = mpc_systems[i]->RandomShareG1();
    });
  }
  for (auto& t : threads) {
    t.join();
  }

  // Open shares
  auto g1 = pairing_group_shared->GetGroup1();
  std::vector<yacl::crypto::EcPoint> opened_values(world_size);
  threads.clear();
  for (size_t i = 0; i < world_size; ++i) {
    threads.emplace_back([&, i]() {
      opened_values[i] = mpc_systems[i]->PartialOpenG1(shares[i]);
    });
  }
  for (auto& t : threads) {
    t.join();
  }

  // Record end time and stats
  auto end_time = std::chrono::high_resolution_clock::now();
  auto end_stats = GetTotalStats(contexts);

  // All parties should get the same opened value
  for (size_t i = 1; i < world_size; ++i) {
    YACL_ENFORCE(g1->PointEqual(opened_values[0], opened_values[i]),
                 "RandomShare G1 test failed: parties disagree");
  }

  std::cout << "  RandomShare G1 (" << mode << ", " << world_size << " parties)..." << std::endl;
  PrintStats(start_stats, end_stats, start_time, end_time, "RandomShareG1");
}

// Test Add for G1
void TestAddG1(bool malicious_security, size_t world_size = 2) {
  std::string mode = malicious_security ? "Malicious" : "Semi-Honest";
  std::cout << "Testing Add G1 (" << mode << ", " << world_size << " parties)..." << std::endl;

  auto contexts = yacl::link::test::SetupBrpcWorld(world_size);
  std::vector<std::unique_ptr<PairingMpcSystem>> mpc_systems(world_size);
  std::vector<std::thread> threads;

  // Use MclPGFactory directly to avoid library registration issues
  auto pairing_group = yacl::crypto::MclPGFactory::CreateByName("bls12-381");
  std::shared_ptr<yacl::crypto::PairingGroup> pairing_group_shared(
      pairing_group.release());
  auto g1 = pairing_group_shared->GetGroup1();

  // Record start time and stats
  auto start_time = std::chrono::high_resolution_clock::now();
  auto start_stats = GetTotalStats(contexts);

  for (size_t i = 0; i < world_size; ++i) {
    threads.emplace_back([&, i]() {
      std::vector<std::shared_ptr<yacl::link::Context>> ctx_vec = {contexts[i]};
      mpc_systems[i] = std::make_unique<PairingMpcSystem>(
          i, world_size, ctx_vec, pairing_group_shared, malicious_security);
    });
  }
  for (auto& t : threads) {
    t.join();
  }

  // Party 0 shares point P (100 * G), Party 1 shares point Q (200 * G)
  yacl::math::MPInt scalar_a("100");
  yacl::math::MPInt scalar_b("200");
  yacl::crypto::EcPoint point_a = g1->MulBase(scalar_a);
  yacl::crypto::EcPoint point_b = g1->MulBase(scalar_b);
  yacl::crypto::EcPoint expected = g1->Add(point_a, point_b);

  std::vector<EcPointShare> share_a(world_size), share_b(world_size);
  threads.clear();
  for (size_t i = 0; i < world_size; ++i) {
    threads.emplace_back([&, i]() {
      if (i == 0) {
        share_a[i] = mpc_systems[i]->ShareValueG1(point_a, 0);
      } else {
        yacl::math::MPInt zero;
        zero.SetZero();
        yacl::crypto::EcPoint infinity = g1->MulBase(zero);
        share_a[i] = mpc_systems[i]->ShareValueG1(infinity, 0);
      }
      std::this_thread::sleep_for(std::chrono::milliseconds(10));
      if (i == 1 || (world_size > 2 && i == 1)) {
        share_b[i] = mpc_systems[i]->ShareValueG1(point_b, 1);
      } else {
        yacl::math::MPInt zero;
        zero.SetZero();
        yacl::crypto::EcPoint infinity = g1->MulBase(zero);
        share_b[i] = mpc_systems[i]->ShareValueG1(infinity, 1);
      }
    });
  }
  for (auto& t : threads) {
    t.join();
  }

  // Compute [P] + [Q]
  std::vector<EcPointShare> result_shares(world_size);
  threads.clear();
  for (size_t i = 0; i < world_size; ++i) {
    threads.emplace_back([&, i]() {
      result_shares[i] = mpc_systems[i]->AddG1(share_a[i], share_b[i]);
    });
  }
  for (auto& t : threads) {
    t.join();
  }

  // Open result
  std::vector<yacl::crypto::EcPoint> results(world_size);
  threads.clear();
  for (size_t i = 0; i < world_size; ++i) {
    threads.emplace_back([&, i]() {
      results[i] = mpc_systems[i]->OpenG1(result_shares[i]);
    });
  }
  for (auto& t : threads) {
    t.join();
  }

  // All parties should agree and result should be P + Q
  for (size_t i = 1; i < world_size; ++i) {
    YACL_ENFORCE(g1->PointEqual(results[0], results[i]),
                 "Add G1 test failed: parties disagree");
    YACL_ENFORCE(g1->PointEqual(results[i], expected),
                 "Add G1 test failed: result != expected");
  }

  // Verify: opened result matches plaintext computation
  bool matches = g1->PointEqual(results[0], expected);
  YACL_ENFORCE(matches, "Add G1 test failed: MPC result != plaintext computation");

  // Record end time and stats
  auto end_time = std::chrono::high_resolution_clock::now();
  auto end_stats = GetTotalStats(contexts);

  std::cout << "  Add G1 (" << mode << ", " << world_size
            << " parties) test PASSED (opened value matches plaintext: " << std::endl;
  PrintStats(start_stats, end_stats, start_time, end_time, "AddG1");
}

// Test RandomShare for G2
void TestRandomShareG2(bool malicious_security, size_t world_size = 2) {
  std::string mode = malicious_security ? "Malicious" : "Semi-Honest";
  std::cout << "Testing RandomShare G2 (" << mode << ", " << world_size << " parties)..." << std::endl;

  auto contexts = yacl::link::test::SetupBrpcWorld(world_size);
  std::vector<std::unique_ptr<PairingMpcSystem>> mpc_systems(world_size);
  std::vector<std::thread> threads;

  // Create pairing group (use BLS12_381 as example)
  auto pairing_group = yacl::crypto::MclPGFactory::CreateByName("bls12-381");
  std::shared_ptr<yacl::crypto::PairingGroup> pairing_group_shared(
      pairing_group.release());

  // Record start time and stats
  auto start_time = std::chrono::high_resolution_clock::now();
  auto start_stats = GetTotalStats(contexts);

  for (size_t i = 0; i < world_size; ++i) {
    threads.emplace_back([&, i]() {
      std::vector<std::shared_ptr<yacl::link::Context>> ctx_vec = {contexts[i]};
      mpc_systems[i] = std::make_unique<PairingMpcSystem>(
          i, world_size, ctx_vec, pairing_group_shared, malicious_security);
    });
  }
  for (auto& t : threads) {
    t.join();
  }

  // Generate random shares
  std::vector<EcPointShare> shares(world_size);
  threads.clear();
  for (size_t i = 0; i < world_size; ++i) {
    threads.emplace_back([&, i]() {
      shares[i] = mpc_systems[i]->RandomShareG2();
    });
  }
  for (auto& t : threads) {
    t.join();
  }

  // Open shares
  auto g2 = pairing_group_shared->GetGroup2();
  std::vector<yacl::crypto::EcPoint> opened_values(world_size);
  threads.clear();
  for (size_t i = 0; i < world_size; ++i) {
    threads.emplace_back([&, i]() {
      opened_values[i] = mpc_systems[i]->PartialOpenG2(shares[i]);
    });
  }
  for (auto& t : threads) {
    t.join();
  }

  // All parties should get the same opened value
  for (size_t i = 1; i < world_size; ++i) {
    YACL_ENFORCE(g2->PointEqual(opened_values[0], opened_values[i]),
                 "RandomShare G2 test failed: parties disagree");
  }

  // Record end time and stats
  auto end_time = std::chrono::high_resolution_clock::now();
  auto end_stats = GetTotalStats(contexts);

  std::cout << "  RandomShare G2 (" << mode << ", " << world_size << " parties)..." << std::endl;
  PrintStats(start_stats, end_stats, start_time, end_time, "RandomShareG2");
}

// Test Add for G2
void TestAddG2(bool malicious_security, size_t world_size = 2) {
  std::string mode = malicious_security ? "Malicious" : "Semi-Honest";
  std::cout << "Testing Add G2 (" << mode << ", " << world_size << " parties)..." << std::endl;

  auto contexts = yacl::link::test::SetupBrpcWorld(world_size);
  std::vector<std::unique_ptr<PairingMpcSystem>> mpc_systems(world_size);
  std::vector<std::thread> threads;

  // Use MclPGFactory directly to avoid library registration issues
  auto pairing_group = yacl::crypto::MclPGFactory::CreateByName("bls12-381");
  std::shared_ptr<yacl::crypto::PairingGroup> pairing_group_shared(
      pairing_group.release());
  auto g2 = pairing_group_shared->GetGroup2();
  // Record start time and stats
  auto start_time = std::chrono::high_resolution_clock::now();
  auto start_stats = GetTotalStats(contexts);

  for (size_t i = 0; i < world_size; ++i) {
    threads.emplace_back([&, i]() {
      std::vector<std::shared_ptr<yacl::link::Context>> ctx_vec = {contexts[i]};
      mpc_systems[i] = std::make_unique<PairingMpcSystem>(
          i, world_size, ctx_vec, pairing_group_shared, malicious_security);
    });
  }
  for (auto& t : threads) {
    t.join();
  }

  // Party 0 shares point P (100 * G), Party 1 shares point Q (200 * G)
  yacl::math::MPInt scalar_a("100");
  yacl::math::MPInt scalar_b("200");
  yacl::crypto::EcPoint point_a = g2->MulBase(scalar_a);
  yacl::crypto::EcPoint point_b = g2->MulBase(scalar_b);
  yacl::crypto::EcPoint expected = g2->Add(point_a, point_b);

  std::vector<EcPointShare> share_a(world_size), share_b(world_size);
  threads.clear();
  for (size_t i = 0; i < world_size; ++i) {
    threads.emplace_back([&, i]() {
      if (i == 0) {
        share_a[i] = mpc_systems[i]->ShareValueG2(point_a, 0);
      } else {
        yacl::math::MPInt zero;
        zero.SetZero();
        yacl::crypto::EcPoint infinity = g2->MulBase(zero);
        share_a[i] = mpc_systems[i]->ShareValueG2(infinity, 0);
      }
      std::this_thread::sleep_for(std::chrono::milliseconds(10));
      if (i == 1 || (world_size > 2 && i == 1)) {
        share_b[i] = mpc_systems[i]->ShareValueG2(point_b, 1);
      } else {
        yacl::math::MPInt zero;
        zero.SetZero();
        yacl::crypto::EcPoint infinity = g2->MulBase(zero);
        share_b[i] = mpc_systems[i]->ShareValueG2(infinity, 1);
      }
    });
  }
  for (auto& t : threads) {
    t.join();
  }

  // Compute [P] + [Q]
  std::vector<EcPointShare> result_shares(world_size);
  threads.clear();
  for (size_t i = 0; i < world_size; ++i) {
    threads.emplace_back([&, i]() {
      result_shares[i] = mpc_systems[i]->AddG2(share_a[i], share_b[i]);
    });
  }
  for (auto& t : threads) {
    t.join();
  }

  // Open result
  std::vector<yacl::crypto::EcPoint> results(world_size);
  threads.clear();
  for (size_t i = 0; i < world_size; ++i) {
    threads.emplace_back([&, i]() {
      results[i] = mpc_systems[i]->OpenG2(result_shares[i]);
    });
  }
  for (auto& t : threads) {
    t.join();
  }

  // All parties should agree and result should be P + Q
  for (size_t i = 1; i < world_size; ++i) {
    YACL_ENFORCE(g2->PointEqual(results[0], results[i]),
                 "Add G2 test failed: parties disagree");
    YACL_ENFORCE(g2->PointEqual(results[i], expected),
                 "Add G2 test failed: result != expected");
  }

  // Record end time and stats
  auto end_time = std::chrono::high_resolution_clock::now();
  auto end_stats = GetTotalStats(contexts);

  // Verify: opened result matches plaintext computation
  bool matches = g2->PointEqual(results[0], expected);
  YACL_ENFORCE(matches, "Add G2 test failed: MPC result != plaintext computation");
  
  std::cout << "  Add G2 (" << mode << ", " << world_size
            << " parties) test PASSED (opened value matches plaintext: " << std::endl;
  PrintStats(start_stats, end_stats, start_time, end_time, "AddG2");
}

// Test MulScalarG1: k * [P] = [k*P] in G1 (k is public)
void TestMulScalarG1(bool malicious_security, size_t world_size = 2) {
  std::string mode = malicious_security ? "Malicious" : "Semi-Honest";
  std::cout << "Testing MulScalarG1 k[P] (" << mode << ", " << world_size << " parties)..." << std::endl;

  auto contexts = yacl::link::test::SetupBrpcWorld(world_size);
  std::vector<std::unique_ptr<PairingMpcSystem>> mpc_systems(world_size);
  std::vector<std::thread> threads;

  auto pairing_group = yacl::crypto::MclPGFactory::CreateByName("bls12-381");
  std::shared_ptr<yacl::crypto::PairingGroup> pairing_group_shared(
      pairing_group.release());
  auto g1 = pairing_group_shared->GetGroup1();

  auto start_time = std::chrono::high_resolution_clock::now();
  auto start_stats = GetTotalStats(contexts);

  for (size_t i = 0; i < world_size; ++i) {
    threads.emplace_back([&, i]() {
      std::vector<std::shared_ptr<yacl::link::Context>> ctx_vec = {contexts[i]};
      mpc_systems[i] = std::make_unique<PairingMpcSystem>(
          i, world_size, ctx_vec, pairing_group_shared, malicious_security);
    });
  }
  for (auto& t : threads) {
    t.join();
  }

  yacl::math::MPInt scalar_k("5");
  yacl::math::MPInt scalar_p("100");
  yacl::crypto::EcPoint point_p = g1->MulBase(scalar_p);
  yacl::crypto::EcPoint expected = g1->Mul(point_p, scalar_k);

  std::vector<EcPointShare> share_p(world_size);
  threads.clear();
  for (size_t i = 0; i < world_size; ++i) {
    threads.emplace_back([&, i]() {
      if (i == 0) {
        share_p[i] = mpc_systems[i]->ShareValueG1(point_p, 0);
      } else {
        yacl::math::MPInt zero(0);
        yacl::crypto::EcPoint infinity = g1->MulBase(zero);
        share_p[i] = mpc_systems[i]->ShareValueG1(infinity, 0);
      }
    });
  }
  for (auto& t : threads) {
    t.join();
  }

  std::vector<EcPointShare> result_shares(world_size);
  threads.clear();
  for (size_t i = 0; i < world_size; ++i) {
    threads.emplace_back([&, i]() {
      result_shares[i] = mpc_systems[i]->MulScalarG1(scalar_k, share_p[i]);
    });
  }
  for (auto& t : threads) {
    t.join();
  }

  std::vector<yacl::crypto::EcPoint> results(world_size);
  threads.clear();
  for (size_t i = 0; i < world_size; ++i) {
    threads.emplace_back([&, i]() {
      results[i] = mpc_systems[i]->OpenG1(result_shares[i]);
    });
  }
  for (auto& t : threads) {
    t.join();
  }

  for (size_t i = 1; i < world_size; ++i) {
    YACL_ENFORCE(g1->PointEqual(results[0], results[i]),
                 "MulScalarG1 test failed: parties disagree");
    YACL_ENFORCE(g1->PointEqual(results[i], expected),
                 "MulScalarG1 test failed: result != expected");
  }

  auto end_time = std::chrono::high_resolution_clock::now();
  auto end_stats = GetTotalStats(contexts);

  bool matches = g1->PointEqual(results[0], expected);
  YACL_ENFORCE(matches, "MulScalarG1 test failed: MPC result != plaintext computation");
  
  std::cout << "  MulScalarG1 k[P] (" << mode << ", " << world_size
            << " parties) test PASSED (opened value matches plaintext: " << std::endl;
  PrintStats(start_stats, end_stats, start_time, end_time, "MulScalarG1");
}

// Test MulSecretScalarPublicPointG1: [k] * P = [k*P] in G1 ([k] is secret, P is public)
void TestMulSecretScalarPublicPointG1(bool malicious_security, size_t world_size = 2) {
  std::string mode = malicious_security ? "Malicious" : "Semi-Honest";
  std::cout << "Testing MulSecretScalarPublicPointG1 [k]P (" << mode << ", " << world_size << " parties)..." << std::endl;

  auto contexts = yacl::link::test::SetupBrpcWorld(world_size);
  std::vector<std::unique_ptr<PairingMpcSystem>> mpc_systems(world_size);
  std::vector<std::unique_ptr<SpdzMpcSystem>> fp_mpc_systems(world_size);
  std::vector<std::thread> threads;

  auto pairing_group = yacl::crypto::MclPGFactory::CreateByName("bls12-381");
  std::shared_ptr<yacl::crypto::PairingGroup> pairing_group_shared(
      pairing_group.release());
  auto g1 = pairing_group_shared->GetGroup1();
  yacl::math::MPInt order = pairing_group_shared->GetOrder();

  auto start_time = std::chrono::high_resolution_clock::now();
  auto start_stats = GetTotalStats(contexts);

  for (size_t i = 0; i < world_size; ++i) {
    threads.emplace_back([&, i]() {
      std::vector<std::shared_ptr<yacl::link::Context>> ctx_vec = {contexts[i]};
      mpc_systems[i] = std::make_unique<PairingMpcSystem>(
          i, world_size, ctx_vec, pairing_group_shared, malicious_security);
      fp_mpc_systems[i] = std::make_unique<SpdzMpcSystem>(
          i, world_size, ctx_vec, malicious_security, &order);
    });
  }
  for (auto& t : threads) {
    t.join();
  }

  yacl::math::MPInt scalar_k("123");
  yacl::math::MPInt scalar_p("100");
  yacl::crypto::EcPoint public_point = g1->MulBase(scalar_p);
  yacl::crypto::EcPoint expected = g1->Mul(public_point, scalar_k);

  std::vector<SecretShare> share_k(world_size);
  threads.clear();
  for (size_t i = 0; i < world_size; ++i) {
    threads.emplace_back([&, i]() {
      if (i == 0) {
        share_k[i] = fp_mpc_systems[i]->ShareMyValue(scalar_k);
      } else {
        share_k[i] = fp_mpc_systems[i]->ShareValue(yacl::math::MPInt(0), 0);
      }
    });
  }
  for (auto& t : threads) {
    t.join();
  }

  std::vector<EcPointShare> result_shares(world_size);
  threads.clear();
  for (size_t i = 0; i < world_size; ++i) {
    threads.emplace_back([&, i]() {
      result_shares[i] = mpc_systems[i]->MulSecretScalarPublicPointG1(share_k[i], public_point);
    });
  }
  for (auto& t : threads) {
    t.join();
  }

  std::vector<yacl::crypto::EcPoint> results(world_size);
  threads.clear();
  for (size_t i = 0; i < world_size; ++i) {
    threads.emplace_back([&, i]() {
      results[i] = mpc_systems[i]->OpenG1(result_shares[i]);
    });
  }
  for (auto& t : threads) {
    t.join();
  }

  for (size_t i = 1; i < world_size; ++i) {
    YACL_ENFORCE(g1->PointEqual(results[0], results[i]),
                 "MulSecretScalarPublicPointG1 test failed: parties disagree");
    YACL_ENFORCE(g1->PointEqual(results[i], expected),
                 "MulSecretScalarPublicPointG1 test failed: result != expected");
  }

  auto end_time = std::chrono::high_resolution_clock::now();
  auto end_stats = GetTotalStats(contexts);

  bool matches = g1->PointEqual(results[0], expected);
  YACL_ENFORCE(matches, "MulSecretScalarPublicPointG1 test failed: MPC result != plaintext computation");
  
  std::cout << "  MulSecretScalarPublicPointG1 [k]P (" << mode << ", " << world_size
            << " parties) test PASSED (opened value matches plaintext: " << std::endl;
  PrintStats(start_stats, end_stats, start_time, end_time, "MulSecretScalarPublicPointG1");
}

// Test MulSecretScalarG1: [k] * [P] = [k*P] in G1 (both [k] and [P] are secret)
void TestMulSecretScalarG1(bool malicious_security, size_t world_size = 2) {
  std::string mode = malicious_security ? "Malicious" : "Semi-Honest";
  std::cout << "Testing MulSecretScalarG1 [k][P] (" << mode << ", " << world_size << " parties)..." << std::endl;

  auto contexts = yacl::link::test::SetupBrpcWorld(world_size);
  std::vector<std::unique_ptr<PairingMpcSystem>> mpc_systems(world_size);
  std::vector<std::unique_ptr<SpdzMpcSystem>> fp_mpc_systems(world_size);
  std::vector<std::thread> threads;

  auto pairing_group = yacl::crypto::MclPGFactory::CreateByName("bls12-381");
  std::shared_ptr<yacl::crypto::PairingGroup> pairing_group_shared(
      pairing_group.release());
  auto g1 = pairing_group_shared->GetGroup1();
  yacl::math::MPInt order = pairing_group_shared->GetOrder();

  auto start_time = std::chrono::high_resolution_clock::now();
  auto start_stats = GetTotalStats(contexts);

  for (size_t i = 0; i < world_size; ++i) {
    threads.emplace_back([&, i]() {
      std::vector<std::shared_ptr<yacl::link::Context>> ctx_vec = {contexts[i]};
      mpc_systems[i] = std::make_unique<PairingMpcSystem>(
          i, world_size, ctx_vec, pairing_group_shared, malicious_security);
      fp_mpc_systems[i] = std::make_unique<SpdzMpcSystem>(
          i, world_size, ctx_vec, malicious_security, &order);
    });
  }
  for (auto& t : threads) {
    t.join();
  }

  yacl::math::MPInt scalar_k("123");
  yacl::math::MPInt scalar_p("100");
  yacl::crypto::EcPoint point_p = g1->MulBase(scalar_p);
  yacl::crypto::EcPoint expected = g1->Mul(point_p, scalar_k);

  std::vector<SecretShare> share_k(world_size);
  std::vector<EcPointShare> share_p(world_size);
  threads.clear();
  for (size_t i = 0; i < world_size; ++i) {
    threads.emplace_back([&, i]() {
      if (i == 0) {
        share_k[i] = fp_mpc_systems[i]->ShareMyValue(scalar_k);
        yacl::math::MPInt zero(0);
        yacl::crypto::EcPoint infinity = g1->MulBase(zero);
        share_p[i] = mpc_systems[i]->ShareValueG1(infinity, 1);
      } else if (i == 1) {
        share_k[i] = fp_mpc_systems[i]->ShareValue(yacl::math::MPInt(0), 0);
        share_p[i] = mpc_systems[i]->ShareMyValueG1(point_p);
      } else {
        share_k[i] = fp_mpc_systems[i]->ShareValue(yacl::math::MPInt(0), 0);
        yacl::math::MPInt zero(0);
        yacl::crypto::EcPoint infinity = g1->MulBase(zero);
        share_p[i] = mpc_systems[i]->ShareValueG1(infinity, 1);
      }
    });
  }
  for (auto& t : threads) {
    t.join();
  }

  std::vector<EcPointShare> result_shares(world_size);
  threads.clear();
  for (size_t i = 0; i < world_size; ++i) {
    threads.emplace_back([&, i]() {
      result_shares[i] = mpc_systems[i]->MulSecretScalarG1(share_k[i], share_p[i], fp_mpc_systems[i].get());
    });
  }
  for (auto& t : threads) {
    t.join();
  }

  std::vector<yacl::crypto::EcPoint> results(world_size);
  threads.clear();
  for (size_t i = 0; i < world_size; ++i) {
    threads.emplace_back([&, i]() {
      results[i] = mpc_systems[i]->OpenG1(result_shares[i]);
    });
  }
  for (auto& t : threads) {
    t.join();
  }

  for (size_t i = 1; i < world_size; ++i) {
    YACL_ENFORCE(g1->PointEqual(results[0], results[i]),
                 "MulSecretScalarG1 test failed: parties disagree");
    YACL_ENFORCE(g1->PointEqual(results[i], expected),
                 "MulSecretScalarG1 test failed: result != expected");
  }

  auto end_time = std::chrono::high_resolution_clock::now();
  auto end_stats = GetTotalStats(contexts);

  bool matches = g1->PointEqual(results[0], expected);
  YACL_ENFORCE(matches, "MulSecretScalarG1 test failed: MPC result != plaintext computation");
  
  std::cout << "  MulSecretScalarG1 [k][P] (" << mode << ", " << world_size
            << " parties) test PASSED (opened value matches plaintext: " << std::endl;
  PrintStats(start_stats, end_stats, start_time, end_time, "MulSecretScalarG1");
}

// Test MulScalarG2: k * [P] = [k*P] in G2 (k is public)
void TestMulScalarG2(bool malicious_security, size_t world_size = 2) {
  std::string mode = malicious_security ? "Malicious" : "Semi-Honest";
  std::cout << "Testing MulScalarG2 k[P] (" << mode << ", " << world_size << " parties)..." << std::endl;

  auto contexts = yacl::link::test::SetupBrpcWorld(world_size);
  std::vector<std::unique_ptr<PairingMpcSystem>> mpc_systems(world_size);
  std::vector<std::thread> threads;

  auto pairing_group = yacl::crypto::MclPGFactory::CreateByName("bls12-381");
  std::shared_ptr<yacl::crypto::PairingGroup> pairing_group_shared(
      pairing_group.release());
  auto g2 = pairing_group_shared->GetGroup2();

  auto start_time = std::chrono::high_resolution_clock::now();
  auto start_stats = GetTotalStats(contexts);

  for (size_t i = 0; i < world_size; ++i) {
    threads.emplace_back([&, i]() {
      std::vector<std::shared_ptr<yacl::link::Context>> ctx_vec = {contexts[i]};
      mpc_systems[i] = std::make_unique<PairingMpcSystem>(
          i, world_size, ctx_vec, pairing_group_shared, malicious_security);
    });
  }
  for (auto& t : threads) {
    t.join();
  }

  yacl::math::MPInt scalar_k("5");
  yacl::math::MPInt scalar_p("100");
  yacl::crypto::EcPoint point_p = g2->MulBase(scalar_p);
  yacl::crypto::EcPoint expected = g2->Mul(point_p, scalar_k);

  std::vector<EcPointShare> share_p(world_size);
  threads.clear();
  for (size_t i = 0; i < world_size; ++i) {
    threads.emplace_back([&, i]() {
      if (i == 0) {
        share_p[i] = mpc_systems[i]->ShareValueG2(point_p, 0);
      } else {
        yacl::math::MPInt zero(0);
        yacl::crypto::EcPoint infinity = g2->MulBase(zero);
        share_p[i] = mpc_systems[i]->ShareValueG2(infinity, 0);
      }
    });
  }
  for (auto& t : threads) {
    t.join();
  }

  std::vector<EcPointShare> result_shares(world_size);
  threads.clear();
  for (size_t i = 0; i < world_size; ++i) {
    threads.emplace_back([&, i]() {
      result_shares[i] = mpc_systems[i]->MulScalarG2(scalar_k, share_p[i]);
    });
  }
  for (auto& t : threads) {
    t.join();
  }

  std::vector<yacl::crypto::EcPoint> results(world_size);
  threads.clear();
  for (size_t i = 0; i < world_size; ++i) {
    threads.emplace_back([&, i]() {
      results[i] = mpc_systems[i]->OpenG2(result_shares[i]);
    });
  }
  for (auto& t : threads) {
    t.join();
  }

  for (size_t i = 1; i < world_size; ++i) {
    YACL_ENFORCE(g2->PointEqual(results[0], results[i]),
                 "MulScalarG2 test failed: parties disagree");
    YACL_ENFORCE(g2->PointEqual(results[i], expected),
                 "MulScalarG2 test failed: result != expected");
  }

  auto end_time = std::chrono::high_resolution_clock::now();
  auto end_stats = GetTotalStats(contexts);

  bool matches = g2->PointEqual(results[0], expected);
  YACL_ENFORCE(matches, "MulScalarG2 test failed: MPC result != plaintext computation");
  
  std::cout << "  MulScalarG2 k[P] (" << mode << ", " << world_size
            << " parties) test PASSED (opened value matches plaintext: " << std::endl;
  PrintStats(start_stats, end_stats, start_time, end_time, "MulScalarG2");
}

// Test MulSecretScalarPublicPointG2: [k] * P = [k*P] in G2 ([k] is secret, P is public)
void TestMulSecretScalarPublicPointG2(bool malicious_security, size_t world_size = 2) {
  std::string mode = malicious_security ? "Malicious" : "Semi-Honest";
  std::cout << "Testing MulSecretScalarPublicPointG2 [k]P (" << mode << ", " << world_size << " parties)..." << std::endl;

  auto contexts = yacl::link::test::SetupBrpcWorld(world_size);
  std::vector<std::unique_ptr<PairingMpcSystem>> mpc_systems(world_size);
  std::vector<std::unique_ptr<SpdzMpcSystem>> fp_mpc_systems(world_size);
  std::vector<std::thread> threads;

  auto pairing_group = yacl::crypto::MclPGFactory::CreateByName("bls12-381");
  std::shared_ptr<yacl::crypto::PairingGroup> pairing_group_shared(
      pairing_group.release());
  auto g2 = pairing_group_shared->GetGroup2();
  yacl::math::MPInt order = pairing_group_shared->GetOrder();

  auto start_time = std::chrono::high_resolution_clock::now();
  auto start_stats = GetTotalStats(contexts);

  for (size_t i = 0; i < world_size; ++i) {
    threads.emplace_back([&, i]() {
      std::vector<std::shared_ptr<yacl::link::Context>> ctx_vec = {contexts[i]};
      mpc_systems[i] = std::make_unique<PairingMpcSystem>(
          i, world_size, ctx_vec, pairing_group_shared, malicious_security);
      fp_mpc_systems[i] = std::make_unique<SpdzMpcSystem>(
          i, world_size, ctx_vec, malicious_security, &order);
    });
  }
  for (auto& t : threads) {
    t.join();
  }

  yacl::math::MPInt scalar_k("123");
  yacl::math::MPInt scalar_p("100");
  yacl::crypto::EcPoint public_point = g2->MulBase(scalar_p);
  yacl::crypto::EcPoint expected = g2->Mul(public_point, scalar_k);

  std::vector<SecretShare> share_k(world_size);
  threads.clear();
  for (size_t i = 0; i < world_size; ++i) {
    threads.emplace_back([&, i]() {
      if (i == 0) {
        share_k[i] = fp_mpc_systems[i]->ShareMyValue(scalar_k);
      } else {
        share_k[i] = fp_mpc_systems[i]->ShareValue(yacl::math::MPInt(0), 0);
      }
    });
  }
  for (auto& t : threads) {
    t.join();
  }

  std::vector<EcPointShare> result_shares(world_size);
  threads.clear();
  for (size_t i = 0; i < world_size; ++i) {
    threads.emplace_back([&, i]() {
      result_shares[i] = mpc_systems[i]->MulSecretScalarPublicPointG2(share_k[i], public_point);
    });
  }
  for (auto& t : threads) {
    t.join();
  }

  std::vector<yacl::crypto::EcPoint> results(world_size);
  threads.clear();
  for (size_t i = 0; i < world_size; ++i) {
    threads.emplace_back([&, i]() {
      results[i] = mpc_systems[i]->OpenG2(result_shares[i]);
    });
  }
  for (auto& t : threads) {
    t.join();
  }

  for (size_t i = 1; i < world_size; ++i) {
    YACL_ENFORCE(g2->PointEqual(results[0], results[i]),
                 "MulSecretScalarPublicPointG2 test failed: parties disagree");
    YACL_ENFORCE(g2->PointEqual(results[i], expected),
                 "MulSecretScalarPublicPointG2 test failed: result != expected");
  }

  auto end_time = std::chrono::high_resolution_clock::now();
  auto end_stats = GetTotalStats(contexts);

  bool matches = g2->PointEqual(results[0], expected);
  YACL_ENFORCE(matches, "MulSecretScalarPublicPointG2 test failed: MPC result != plaintext computation");
  
  std::cout << "  MulSecretScalarPublicPointG2 [k]P (" << mode << ", " << world_size
            << " parties) test PASSED (opened value matches plaintext: " << std::endl;
  PrintStats(start_stats, end_stats, start_time, end_time, "MulSecretScalarPublicPointG2");
}

// Test MulSecretScalarG2: [k] * [P] = [k*P] in G2 (both [k] and [P] are secret)
void TestMulSecretScalarG2(bool malicious_security, size_t world_size = 2) {
  std::string mode = malicious_security ? "Malicious" : "Semi-Honest";
  std::cout << "Testing MulSecretScalarG2 [k][P] (" << mode << ", " << world_size << " parties)..." << std::endl;

  auto contexts = yacl::link::test::SetupBrpcWorld(world_size);
  std::vector<std::unique_ptr<PairingMpcSystem>> mpc_systems(world_size);
  std::vector<std::unique_ptr<SpdzMpcSystem>> fp_mpc_systems(world_size);
  std::vector<std::thread> threads;

  auto pairing_group = yacl::crypto::MclPGFactory::CreateByName("bls12-381");
  std::shared_ptr<yacl::crypto::PairingGroup> pairing_group_shared(
      pairing_group.release());
  auto g2 = pairing_group_shared->GetGroup2();
  yacl::math::MPInt order = pairing_group_shared->GetOrder();

  auto start_time = std::chrono::high_resolution_clock::now();
  auto start_stats = GetTotalStats(contexts);

  for (size_t i = 0; i < world_size; ++i) {
    threads.emplace_back([&, i]() {
      std::vector<std::shared_ptr<yacl::link::Context>> ctx_vec = {contexts[i]};
      mpc_systems[i] = std::make_unique<PairingMpcSystem>(
          i, world_size, ctx_vec, pairing_group_shared, malicious_security);
      fp_mpc_systems[i] = std::make_unique<SpdzMpcSystem>(
          i, world_size, ctx_vec, malicious_security, &order);
    });
  }
  for (auto& t : threads) {
    t.join();
  }

  yacl::math::MPInt scalar_k("123");
  yacl::math::MPInt scalar_p("100");
  yacl::crypto::EcPoint point_p = g2->MulBase(scalar_p);
  yacl::crypto::EcPoint expected = g2->Mul(point_p, scalar_k);

  std::vector<SecretShare> share_k(world_size);
  std::vector<EcPointShare> share_p(world_size);
  threads.clear();
  for (size_t i = 0; i < world_size; ++i) {
    threads.emplace_back([&, i]() {
      if (i == 0) {
        share_k[i] = fp_mpc_systems[i]->ShareMyValue(scalar_k);
        yacl::math::MPInt zero(0);
        yacl::crypto::EcPoint infinity = g2->MulBase(zero);
        share_p[i] = mpc_systems[i]->ShareValueG2(infinity, 1);
      } else if (i == 1) {
        share_k[i] = fp_mpc_systems[i]->ShareValue(yacl::math::MPInt(0), 0);
        share_p[i] = mpc_systems[i]->ShareMyValueG2(point_p);
      } else {
        share_k[i] = fp_mpc_systems[i]->ShareValue(yacl::math::MPInt(0), 0);
        yacl::math::MPInt zero(0);
        yacl::crypto::EcPoint infinity = g2->MulBase(zero);
        share_p[i] = mpc_systems[i]->ShareValueG2(infinity, 1);
      }
    });
  }
  for (auto& t : threads) {
    t.join();
  }

  std::vector<EcPointShare> result_shares(world_size);
  threads.clear();
  for (size_t i = 0; i < world_size; ++i) {
    threads.emplace_back([&, i]() {
      result_shares[i] = mpc_systems[i]->MulSecretScalarG2(share_k[i], share_p[i], fp_mpc_systems[i].get());
    });
  }
  for (auto& t : threads) {
    t.join();
  }

  std::vector<yacl::crypto::EcPoint> results(world_size);
  threads.clear();
  for (size_t i = 0; i < world_size; ++i) {
    threads.emplace_back([&, i]() {
      results[i] = mpc_systems[i]->OpenG2(result_shares[i]);
    });
  }
  for (auto& t : threads) {
    t.join();
  }

  for (size_t i = 1; i < world_size; ++i) {
    YACL_ENFORCE(g2->PointEqual(results[0], results[i]),
                 "MulSecretScalarG2 test failed: parties disagree");
    YACL_ENFORCE(g2->PointEqual(results[i], expected),
                 "MulSecretScalarG2 test failed: result != expected");
  }

  auto end_time = std::chrono::high_resolution_clock::now();
  auto end_stats = GetTotalStats(contexts);

  bool matches = g2->PointEqual(results[0], expected);
  YACL_ENFORCE(matches, "MulSecretScalarG2 test failed: MPC result != plaintext computation");
  
  std::cout << "  MulSecretScalarG2 [k][P] (" << mode << ", " << world_size
            << " parties) test PASSED (opened value matches plaintext: " << std::endl;
  PrintStats(start_stats, end_stats, start_time, end_time, "MulSecretScalarG2");
}

// Test Mul for GT
void TestMulGT(bool malicious_security, size_t world_size = 2) {
  std::string mode = malicious_security ? "Malicious" : "Semi-Honest";
  std::cout << "Testing Mul GT (" << mode << ", " << world_size << " parties)..." << std::endl;

  auto contexts = yacl::link::test::SetupBrpcWorld(world_size);
  std::vector<std::unique_ptr<PairingMpcSystem>> mpc_systems(world_size);
  std::vector<std::thread> threads;

  // Use MclPGFactory directly to avoid library registration issues
  auto pairing_group = yacl::crypto::MclPGFactory::CreateByName("bls12-381");
  std::shared_ptr<yacl::crypto::PairingGroup> pairing_group_shared(
      pairing_group.release());
  auto gt = pairing_group_shared->GetGroupT();
  // Record start time and stats
  auto start_time = std::chrono::high_resolution_clock::now();
  auto start_stats = GetTotalStats(contexts);

  for (size_t i = 0; i < world_size; ++i) {
    threads.emplace_back([&, i]() {
      std::vector<std::shared_ptr<yacl::link::Context>> ctx_vec = {contexts[i]};
      mpc_systems[i] = std::make_unique<PairingMpcSystem>(
          i, world_size, ctx_vec, pairing_group_shared, malicious_security);
    });
  }
  for (auto& t : threads) {
    t.join();
  }

  // Party 0 shares element g, Party 1 shares element h
  yacl::Item element_g = gt->Random();
  yacl::Item element_h = gt->Random();
  yacl::Item expected = gt->Mul(element_g, element_h);

  // Pre-allocate vectors with identity elements
  yacl::Item identity = gt->GetIdentityOne();
  yacl::math::MPInt zero(0);
  GtElementShare init_share(identity, identity, zero);
  std::vector<GtElementShare> share_g(world_size, init_share);
  std::vector<GtElementShare> share_h(world_size, init_share);

  threads.clear();
  
  // Use reference capture for element_g and element_h to avoid copying Item objects
  for (size_t i = 0; i < world_size; ++i) {
    YACL_ENFORCE(mpc_systems[i] != nullptr, "mpc_systems[{}] is null", i);
    // Capture gt by value (shared_ptr) to avoid lifetime issues
    auto gt_ptr = gt;
    // Use reference capture for element_g and element_h since Item cannot be copied
    threads.push_back(std::thread([&share_g, &share_h, &mpc_systems, gt_ptr, &element_g, &element_h, i, world_size]() {
      YACL_ENFORCE(mpc_systems[i] != nullptr, "mpc_systems[{}] is null in thread", i);
      if (i == 0) {
        share_g[i] = mpc_systems[i]->ShareValueGT(element_g, 0);
      } else {
        yacl::Item id = gt_ptr->GetIdentityOne();
        share_g[i] = mpc_systems[i]->ShareValueGT(id, 0);
      }
      std::this_thread::sleep_for(std::chrono::milliseconds(10));
      if (i == 1 || (world_size > 2 && i == 1)) {
        share_h[i] = mpc_systems[i]->ShareValueGT(element_h, 1);
      } else {
        yacl::Item id = gt_ptr->GetIdentityOne();
        share_h[i] = mpc_systems[i]->ShareValueGT(id, 1);
      }
    }));
  }
  for (auto& t : threads) {
    t.join();
  }

  // Compute [g] * [h]
  std::vector<GtElementShare> result_shares(world_size, init_share);
  threads.clear();
  for (size_t i = 0; i < world_size; ++i) {
    threads.emplace_back([&, i]() {
      result_shares[i] = mpc_systems[i]->MulGT(share_g[i], share_h[i]);
    });
  }
  for (auto& t : threads) {
    t.join();
  }

  // Open result
  std::vector<yacl::Item> results(world_size, identity);
  threads.clear();
  for (size_t i = 0; i < world_size; ++i) {
    threads.emplace_back([&, i]() {
      results[i] = mpc_systems[i]->OpenGT(result_shares[i]);
    });
  }
  for (auto& t : threads) {
    t.join();
  }

  // All parties should agree and result should be g * h
  for (size_t i = 1; i < world_size; ++i) {
    YACL_ENFORCE(gt->Equal(results[0], results[i]),
                 "Mul GT test failed: parties disagree");
    YACL_ENFORCE(gt->Equal(results[i], expected),
                 "Mul GT test failed: result != expected");
  }

  // Record end time and stats
  auto end_time = std::chrono::high_resolution_clock::now();
  auto end_stats = GetTotalStats(contexts);

  // Verify: opened result matches plaintext computation
  bool matches = gt->Equal(results[0], expected);
  YACL_ENFORCE(matches, "Mul GT test failed: MPC result != plaintext computation");
  
  std::cout << "  Mul GT (" << mode << ", " << world_size
            << " parties) test PASSED (opened value matches plaintext: " << std::endl;
  PrintStats(start_stats, end_stats, start_time, end_time, "MulGT");
}

// Test PowGT: g^k in GT (k is public)
void TestPowGT(bool malicious_security, size_t world_size = 2) {
  std::string mode = malicious_security ? "Malicious" : "Semi-Honest";
  std::cout << "Testing PowGT g^k (" << mode << ", " << world_size << " parties)..." << std::endl;

  auto contexts = yacl::link::test::SetupBrpcWorld(world_size);
  std::vector<std::unique_ptr<PairingMpcSystem>> mpc_systems(world_size);
  std::vector<std::thread> threads;

  auto pairing_group = yacl::crypto::MclPGFactory::CreateByName("bls12-381");
  std::shared_ptr<yacl::crypto::PairingGroup> pairing_group_shared(
      pairing_group.release());
  auto gt = pairing_group_shared->GetGroupT();

  auto start_time = std::chrono::high_resolution_clock::now();
  auto start_stats = GetTotalStats(contexts);

  for (size_t i = 0; i < world_size; ++i) {
    threads.emplace_back([&, i]() {
      std::vector<std::shared_ptr<yacl::link::Context>> ctx_vec = {contexts[i]};
      mpc_systems[i] = std::make_unique<PairingMpcSystem>(
          i, world_size, ctx_vec, pairing_group_shared, malicious_security);
    });
  }
  for (auto& t : threads) {
    t.join();
  }

  yacl::math::MPInt exponent_k("5");
  // Use Pairing(g1, g2) to get a generator of GT group, not a random element
  // This ensures g^order = 1, which is required for the protocol to work correctly
  auto g1 = pairing_group_shared->GetGroup1()->GetGenerator();
  auto g2 = pairing_group_shared->GetGroup2()->GetGenerator();
  yacl::Item element_g = pairing_group_shared->Pairing(g1, g2);
  yacl::Item expected = gt->Pow(element_g, exponent_k);

  yacl::Item identity = gt->GetIdentityOne();
  yacl::math::MPInt zero(0);
  GtElementShare init_share(identity, identity, zero);
  std::vector<GtElementShare> share_g(world_size, init_share);

  threads.clear();
  for (size_t i = 0; i < world_size; ++i) {
    threads.emplace_back([&, i]() {
      if (i == 0) {
        share_g[i] = mpc_systems[i]->ShareMyValueGT(element_g);
      } else {
        share_g[i] = mpc_systems[i]->ShareValueGT(identity, 0);
      }
    });
  }
  for (auto& t : threads) {
    t.join();
  }

  std::vector<GtElementShare> result_shares(world_size, init_share);
  threads.clear();
  for (size_t i = 0; i < world_size; ++i) {
    threads.emplace_back([&, i]() {
      result_shares[i] = mpc_systems[i]->PowGT(exponent_k, share_g[i]);
    });
  }
  for (auto& t : threads) {
    t.join();
  }

  std::vector<yacl::Item> results;
  results.reserve(world_size);
  threads.clear();
  for (size_t i = 0; i < world_size; ++i) {
    threads.emplace_back([&, i]() {
      yacl::Item result = mpc_systems[i]->OpenGT(result_shares[i]);
      if (i == 0) {
        results.push_back(result);
      } else {
        results.push_back(gt->DeepCopy(result));
      }
    });
  }
  for (auto& t : threads) {
    t.join();
  }

  for (size_t i = 1; i < world_size; ++i) {
    YACL_ENFORCE(gt->Equal(results[0], results[i]),
                 "PowGT test failed: parties disagree");
    YACL_ENFORCE(gt->Equal(results[i], expected),
                 "PowGT test failed: result != expected");
  }

  auto end_time = std::chrono::high_resolution_clock::now();
  auto end_stats = GetTotalStats(contexts);

  bool matches = gt->Equal(results[0], expected);
  YACL_ENFORCE(matches, "PowGT test failed: MPC result != plaintext computation");
  
  std::cout << "  PowGT g^k (" << mode << ", " << world_size
            << " parties) test PASSED (opened value matches plaintext: " << std::endl;
  PrintStats(start_stats, end_stats, start_time, end_time, "PowGT");
}

// Test MulSecretScalarPublicElementGT: [k] * g = [g^k] in GT ([k] is secret, g is public)
void TestMulSecretScalarPublicElementGT(bool malicious_security, size_t world_size = 2) {
  std::string mode = malicious_security ? "Malicious" : "Semi-Honest";
  std::cout << "Testing MulSecretScalarPublicElementGT [k]g (" << mode << ", " << world_size << " parties)..." << std::endl;

  auto contexts = yacl::link::test::SetupBrpcWorld(world_size);
  std::vector<std::unique_ptr<PairingMpcSystem>> mpc_systems(world_size);
  std::vector<std::unique_ptr<SpdzMpcSystem>> fp_mpc_systems(world_size);
  std::vector<std::thread> threads;

  auto pairing_group = yacl::crypto::MclPGFactory::CreateByName("bls12-381");
  std::shared_ptr<yacl::crypto::PairingGroup> pairing_group_shared(
      pairing_group.release());
  auto gt = pairing_group_shared->GetGroupT();
  yacl::math::MPInt order = pairing_group_shared->GetOrder();

  auto start_time = std::chrono::high_resolution_clock::now();
  auto start_stats = GetTotalStats(contexts);

  for (size_t i = 0; i < world_size; ++i) {
    threads.emplace_back([&, i]() {
      std::vector<std::shared_ptr<yacl::link::Context>> ctx_vec = {contexts[i]};
      mpc_systems[i] = std::make_unique<PairingMpcSystem>(
          i, world_size, ctx_vec, pairing_group_shared, malicious_security);
      fp_mpc_systems[i] = std::make_unique<SpdzMpcSystem>(
          i, world_size, ctx_vec, malicious_security, &order);
    });
  }
  for (auto& t : threads) {
    t.join();
  }

  yacl::math::MPInt scalar_k("123");
  // Use Pairing(g1, g2) to get a generator of GT group, not a random element
  // This ensures g^order = 1, which is required for the protocol to work correctly
  auto g1 = pairing_group_shared->GetGroup1()->GetGenerator();
  auto g2 = pairing_group_shared->GetGroup2()->GetGenerator();
  yacl::Item public_element = pairing_group_shared->Pairing(g1, g2);
  yacl::Item expected = gt->Pow(public_element, scalar_k);
  
  yacl::math::MPInt prime = fp_mpc_systems[0]->GetPrime();

  std::vector<SecretShare> share_k(world_size);
  threads.clear();
  for (size_t i = 0; i < world_size; ++i) {
    threads.emplace_back([&, i]() {
      if (i == 0) {
        share_k[i] = fp_mpc_systems[i]->ShareMyValue(scalar_k);
      } else {
        share_k[i] = fp_mpc_systems[i]->ShareValue(yacl::math::MPInt(0), 0);
      }
    });
  }
  for (auto& t : threads) {
    t.join();
  }
  
  // Verify sum of shares
  yacl::math::MPInt sum_shares(0);
  for (size_t i = 0; i < world_size; ++i) {
    sum_shares = (sum_shares + share_k[i].value_share) % prime;
  }
  
  // Compute expected using sum_shares (mod GT order) to verify
  yacl::math::MPInt k_for_exponent = sum_shares % order;
  yacl::Item expected_from_shares = gt->Pow(public_element, k_for_exponent);  // Verify: g^(k_0) * g^(k_1) should equal g^(k_0 + k_1)
  yacl::math::MPInt k0_mod_order = share_k[0].value_share % order;
  yacl::math::MPInt k1_mod_order = share_k[1].value_share % order;
  yacl::math::MPInt k0_plus_k1 = (share_k[0].value_share + share_k[1].value_share) % order;
  yacl::math::MPInt k0_mod_plus_k1_mod = (k0_mod_order + k1_mod_order) % order;
  
  yacl::math::MPInt k0_mod_plus_k1_mod_raw = k0_mod_order + k1_mod_order;
  
  // Check if we should use GetMulGroupOrder() instead of GetOrder()
  yacl::math::MPInt mul_group_order = gt->GetMulGroupOrder();
  
  yacl::Item g_k0 = gt->Pow(public_element, k0_mod_order);
  yacl::Item g_k1 = gt->Pow(public_element, k1_mod_order);
  yacl::Item g_k0_times_g_k1 = gt->Mul(g_k0, g_k1);
  yacl::Item g_k0_plus_k1 = gt->Pow(public_element, k0_plus_k1);
  yacl::Item g_k0_mod_plus_k1_mod = gt->Pow(public_element, k0_mod_plus_k1_mod);  // Test: Does Pow automatically reduce exponent modulo order?
  yacl::Item g_k0_raw = gt->Pow(public_element, share_k[0].value_share);
  yacl::Item g_k0_mod = gt->Pow(public_element, k0_mod_order);  // Test: Try using k_0 + k_1 directly (without mod) to see if that works
  yacl::math::MPInt k0_plus_k1_raw = share_k[0].value_share + share_k[1].value_share;
  yacl::Item g_k0_plus_k1_raw = gt->Pow(public_element, k0_plus_k1_raw);  // Test: Simple test - does g^a * g^b = g^(a+b) for small values?
  yacl::math::MPInt test_a("10");
  yacl::math::MPInt test_b("20");
  yacl::math::MPInt test_a_plus_b("30");
  yacl::Item g_test_a = gt->Pow(public_element, test_a);
  yacl::Item g_test_b = gt->Pow(public_element, test_b);
  yacl::Item g_test_a_times_b = gt->Mul(g_test_a, g_test_b);
  yacl::Item g_test_a_plus_b = gt->Pow(public_element, test_a_plus_b);  // Test: Does g^(a mod order) * g^(b mod order) = g^((a+b) mod order) for small values?
  yacl::math::MPInt test_a_mod = test_a % order;
  yacl::math::MPInt test_b_mod = test_b % order;
  yacl::math::MPInt test_a_plus_b_mod = (test_a + test_b) % order;
  yacl::Item g_test_a_mod = gt->Pow(public_element, test_a_mod);
  yacl::Item g_test_b_mod = gt->Pow(public_element, test_b_mod);
  yacl::Item g_test_a_mod_times_b_mod = gt->Mul(g_test_a_mod, g_test_b_mod);
  yacl::Item g_test_a_plus_b_mod = gt->Pow(public_element, test_a_plus_b_mod);  // Test: Does g^(a mod order) * g^(b mod order) = g^((a mod order + b mod order) mod order) when a+b >= order?
  // Use values similar to k_0 mod order and k_1 mod order
  yacl::math::MPInt test_large_a = k0_mod_order;
  yacl::math::MPInt test_large_b = k1_mod_order;
  yacl::math::MPInt test_large_sum = (test_large_a + test_large_b) % order;
  yacl::Item g_test_large_a = gt->Pow(public_element, test_large_a);
  yacl::Item g_test_large_b = gt->Pow(public_element, test_large_b);
  yacl::Item g_test_large_a_times_b = gt->Mul(g_test_large_a, g_test_large_b);
  yacl::Item g_test_large_sum = gt->Pow(public_element, test_large_sum);  // Test: When a + b = order + c, does g^a * g^b = g^c?
  // This tests if MCL's pow automatically reduces exponent modulo order
  yacl::math::MPInt test_a_equals_order_minus_10 = order - yacl::math::MPInt("10");
  yacl::math::MPInt test_b_equals_20("20");
  yacl::math::MPInt test_c_equals_10("10");
  yacl::Item g_test_a_order = gt->Pow(public_element, test_a_equals_order_minus_10);
  yacl::Item g_test_b_order = gt->Pow(public_element, test_b_equals_20);
  yacl::Item g_test_a_times_b_order = gt->Mul(g_test_a_order, g_test_b_order);
  yacl::Item g_test_c_order = gt->Pow(public_element, test_c_equals_10);  // Test: Does g^order = 1?
  yacl::Item g_order = gt->Pow(public_element, order);
  yacl::Item identity_one = gt->GetIdentityOne();  // Test: Does g^(order + c) = g^c?
  yacl::math::MPInt test_order_plus_c = order + test_c_equals_10;
  yacl::Item g_order_plus_c = gt->Pow(public_element, test_order_plus_c);  yacl::Item identity = gt->GetIdentityOne();
  yacl::math::MPInt zero(0);
  GtElementShare init_share(identity, identity, zero);
  std::vector<GtElementShare> result_shares(world_size, init_share);
  threads.clear();
  for (size_t i = 0; i < world_size; ++i) {
    threads.emplace_back([&, i]() {
      result_shares[i] = mpc_systems[i]->MulSecretScalarPublicElementGT(share_k[i], public_element);
    });
  }
  for (auto& t : threads) {
    t.join();
  }

  std::vector<yacl::Item> results;
  yacl::Item identity_temp = gt->GetIdentityOne();
  for (size_t i = 0; i < world_size; ++i) {
    results.push_back(gt->DeepCopy(identity_temp));
  }
  threads.clear();
  for (size_t i = 0; i < world_size; ++i) {
    threads.emplace_back([&, i]() {
      results[i] = mpc_systems[i]->OpenGT(result_shares[i]);
    });
  }
    for (auto& t : threads) {
    t.join();
  }

  for (size_t i = 1; i < world_size; ++i) {
    YACL_ENFORCE(gt->Equal(results[0], results[i]),
                 "MulSecretScalarPublicElementGT test failed: parties disagree");
    
        YACL_ENFORCE(gt->Equal(results[i], expected),
                 "MulSecretScalarPublicElementGT test failed: result != expected");
  }

  auto end_time = std::chrono::high_resolution_clock::now();
  auto end_stats = GetTotalStats(contexts);

  bool matches = gt->Equal(results[0], expected);
  YACL_ENFORCE(matches, "MulSecretScalarPublicElementGT test failed: MPC result != plaintext computation");
  
  std::cout << "  MulSecretScalarPublicElementGT [k]g (" << mode << ", " << world_size
            << " parties) test PASSED (opened value matches plaintext: " << std::endl;
  PrintStats(start_stats, end_stats, start_time, end_time, "MulSecretScalarPublicElementGT");
}

// Test MulSecretScalarGT: [k] * [g] = [g^k] in GT (both [k] and [g] are secret)
void TestMulSecretScalarGT(bool malicious_security, size_t world_size = 2) {
  std::string mode = malicious_security ? "Malicious" : "Semi-Honest";
  std::cout << "Testing MulSecretScalarGT [k][g] (" << mode << ", " << world_size << " parties)..." << std::endl;

  auto contexts = yacl::link::test::SetupBrpcWorld(world_size);
  std::vector<std::unique_ptr<PairingMpcSystem>> mpc_systems(world_size);
  std::vector<std::unique_ptr<SpdzMpcSystem>> fp_mpc_systems(world_size);
  std::vector<std::thread> threads;

  auto pairing_group = yacl::crypto::MclPGFactory::CreateByName("bls12-381");
  std::shared_ptr<yacl::crypto::PairingGroup> pairing_group_shared(
      pairing_group.release());
  auto gt = pairing_group_shared->GetGroupT();
  yacl::math::MPInt order = pairing_group_shared->GetOrder();

  auto start_time = std::chrono::high_resolution_clock::now();
  auto start_stats = GetTotalStats(contexts);

  for (size_t i = 0; i < world_size; ++i) {
    threads.emplace_back([&, i]() {
      std::vector<std::shared_ptr<yacl::link::Context>> ctx_vec = {contexts[i]};
      mpc_systems[i] = std::make_unique<PairingMpcSystem>(
          i, world_size, ctx_vec, pairing_group_shared, malicious_security);
      fp_mpc_systems[i] = std::make_unique<SpdzMpcSystem>(
          i, world_size, ctx_vec, malicious_security, &order);
    });
  }
  for (auto& t : threads) {
    t.join();
  }

  yacl::math::MPInt scalar_k("123");
  yacl::Item element_g = gt->Random();
  yacl::Item expected = gt->Pow(element_g, scalar_k);

  std::vector<SecretShare> share_k(world_size);
  yacl::Item identity = gt->GetIdentityOne();
  yacl::math::MPInt zero(0);
  GtElementShare init_share(identity, identity, zero);
  std::vector<GtElementShare> share_g(world_size, init_share);

  threads.clear();
  for (size_t i = 0; i < world_size; ++i) {
    threads.emplace_back([&, i]() {
      if (i == 0) {
        share_k[i] = fp_mpc_systems[i]->ShareMyValue(scalar_k);
        share_g[i] = mpc_systems[i]->ShareValueGT(identity, 1);
      } else if (i == 1) {
        share_k[i] = fp_mpc_systems[i]->ShareValue(yacl::math::MPInt(0), 0);
        share_g[i] = mpc_systems[i]->ShareMyValueGT(element_g);
      } else {
        share_k[i] = fp_mpc_systems[i]->ShareValue(yacl::math::MPInt(0), 0);
        share_g[i] = mpc_systems[i]->ShareValueGT(identity, 1);
      }
    });
  }
  for (auto& t : threads) {
    t.join();
  }

  std::vector<GtElementShare> result_shares(world_size, init_share);
  threads.clear();
  for (size_t i = 0; i < world_size; ++i) {
    threads.emplace_back([&, i]() {
      result_shares[i] = mpc_systems[i]->MulSecretScalarGT(share_k[i], share_g[i], fp_mpc_systems[i].get());
    });
  }
  for (auto& t : threads) {
    t.join();
  }

  std::vector<yacl::Item> results;
  yacl::Item identity_temp = gt->GetIdentityOne();
  for (size_t i = 0; i < world_size; ++i) {
    results.push_back(gt->DeepCopy(identity_temp));
  }
  threads.clear();
  for (size_t i = 0; i < world_size; ++i) {
    threads.emplace_back([&, i]() {
      results[i] = mpc_systems[i]->OpenGT(result_shares[i]);
    });
  }
  for (auto& t : threads) {
    t.join();
  }

  for (size_t i = 1; i < world_size; ++i) {
    YACL_ENFORCE(gt->Equal(results[0], results[i]),
                 "MulSecretScalarGT test failed: parties disagree");
    YACL_ENFORCE(gt->Equal(results[i], expected),
                 "MulSecretScalarGT test failed: result != expected");
  }

  auto end_time = std::chrono::high_resolution_clock::now();
  auto end_stats = GetTotalStats(contexts);

  bool matches = gt->Equal(results[0], expected);
  YACL_ENFORCE(matches, "MulSecretScalarGT test failed: MPC result != plaintext computation");
  
  std::cout << "  MulSecretScalarGT [k][g] (" << mode << ", " << world_size
            << " parties) test PASSED (opened value matches plaintext: " << std::endl;
  PrintStats(start_stats, end_stats, start_time, end_time, "MulSecretScalarGT");
}

// Test SecPair1: e([P], Q) where [P] ∈ G1 is secret-shared, Q ∈ G2 is public
void TestPairingSecretG1(bool malicious_security, size_t world_size = 2) {
  std::string mode = malicious_security ? "Malicious" : "Semi-Honest";
  std::cout << "Testing SecPair1 e([P], Q) (" << mode << ", " << world_size << " parties)..." << std::endl;

  auto contexts = yacl::link::test::SetupBrpcWorld(world_size);
  std::vector<std::unique_ptr<PairingMpcSystem>> mpc_systems(world_size);
  std::vector<std::thread> threads;

  auto pairing_group = yacl::crypto::MclPGFactory::CreateByName("bls12-381");
  std::shared_ptr<yacl::crypto::PairingGroup> pairing_group_shared(
      pairing_group.release());
  auto g1 = pairing_group_shared->GetGroup1();
  auto g2 = pairing_group_shared->GetGroup2();
  auto gt = pairing_group_shared->GetGroupT();
  // Record start time and stats
  auto start_time = std::chrono::high_resolution_clock::now();
  auto start_stats = GetTotalStats(contexts);

  for (size_t i = 0; i < world_size; ++i) {
    threads.emplace_back([&, i]() {
      std::vector<std::shared_ptr<yacl::link::Context>> ctx_vec = {contexts[i]};
      mpc_systems[i] = std::make_unique<PairingMpcSystem>(
          i, world_size, ctx_vec, pairing_group_shared, malicious_security);
    });
  }
  for (auto& t : threads) {
    t.join();
  }

  // Party 0 shares point P in G1, Q in G2 is public
  yacl::math::MPInt scalar_p("123");
  yacl::crypto::EcPoint point_p = g1->MulBase(scalar_p);
  yacl::crypto::EcPoint point_q = g2->MulBase(yacl::math::MPInt("456"));
  
  // Expected: e(P, Q)
  yacl::Item expected = pairing_group_shared->Pairing(point_p, point_q);

  // Share P in G1
  std::vector<EcPointShare> share_p(world_size);
  threads.clear();
  for (size_t i = 0; i < world_size; ++i) {
    threads.emplace_back([&, i]() {
      if (i == 0) {
        share_p[i] = mpc_systems[i]->ShareValueG1(point_p, 0);
      } else {
        yacl::math::MPInt zero;
        zero.SetZero();
        yacl::crypto::EcPoint infinity = g1->MulBase(zero);
        share_p[i] = mpc_systems[i]->ShareValueG1(infinity, 0);
      }
    });
  }
  for (auto& t : threads) {
    t.join();
  }

  // Compute e([P], Q)
  yacl::Item identity = gt->GetIdentityOne();
  yacl::math::MPInt zero(0);
  GtElementShare init_share(identity, identity, zero);
  std::vector<GtElementShare> result_shares(world_size, init_share);
  threads.clear();
  for (size_t i = 0; i < world_size; ++i) {
    threads.emplace_back([&, i]() {
      result_shares[i] = mpc_systems[i]->PairingSecretG1(share_p[i], point_q);
    });
  }
  for (auto& t : threads) {
    t.join();
  }

  // Open result
  std::vector<yacl::Item> results(world_size, identity);
  threads.clear();
  for (size_t i = 0; i < world_size; ++i) {
    threads.emplace_back([&, i]() {
      results[i] = mpc_systems[i]->OpenGT(result_shares[i]);
    });
  }
  for (auto& t : threads) {
    t.join();
  }

  // All parties should agree and result should be e(P, Q)

  // All parties should agree and result should be e(P, Q)
  for (size_t i = 1; i < world_size; ++i) {
    bool equal = gt->Equal(results[0], results[i]);
    YACL_ENFORCE(equal,
                 "SecPair1 test failed: parties disagree");
    bool matches_expected = gt->Equal(results[i], expected);
    YACL_ENFORCE(matches_expected,
                 "SecPair1 test failed: result != expected");
  }

  // Record end time and stats
  auto end_time = std::chrono::high_resolution_clock::now();
  auto end_stats = GetTotalStats(contexts);

  bool matches = gt->Equal(results[0], expected);
  YACL_ENFORCE(matches, "SecPair1 test failed: MPC result != plaintext computation");

  std::cout << "  SecPair1 e([P], Q) (" << mode << ", " << world_size
            << " parties) test PASSED (opened value matches plaintext: " << std::endl;
  PrintStats(start_stats, end_stats, start_time, end_time, "PairingSecretG1");
}

// Test SecPair2: e(P, [Q]) where P ∈ G1 is public, [Q] ∈ G2 is secret-shared
void TestPairingSecretG2(bool malicious_security, size_t world_size = 2) {
  std::string mode = malicious_security ? "Malicious" : "Semi-Honest";
  std::cout << "Testing SecPair2 e(P, [Q]) (" << mode << ", " << world_size << " parties)..." << std::endl;

  auto contexts = yacl::link::test::SetupBrpcWorld(world_size);
  std::vector<std::unique_ptr<PairingMpcSystem>> mpc_systems(world_size);
  std::vector<std::thread> threads;

  auto pairing_group = yacl::crypto::MclPGFactory::CreateByName("bls12-381");
  std::shared_ptr<yacl::crypto::PairingGroup> pairing_group_shared(
      pairing_group.release());
  auto g1 = pairing_group_shared->GetGroup1();
  auto g2 = pairing_group_shared->GetGroup2();
  auto gt = pairing_group_shared->GetGroupT();
  // Record start time and stats
  auto start_time = std::chrono::high_resolution_clock::now();
  auto start_stats = GetTotalStats(contexts);

  for (size_t i = 0; i < world_size; ++i) {
    threads.emplace_back([&, i]() {
      std::vector<std::shared_ptr<yacl::link::Context>> ctx_vec = {contexts[i]};
      mpc_systems[i] = std::make_unique<PairingMpcSystem>(
          i, world_size, ctx_vec, pairing_group_shared, malicious_security);
    });
  }
  for (auto& t : threads) {
    t.join();
  }

  // P in G1 is public, Party 0 shares point Q in G2
  yacl::crypto::EcPoint point_p = g1->MulBase(yacl::math::MPInt("123"));
  yacl::math::MPInt scalar_q("456");
  yacl::crypto::EcPoint point_q = g2->MulBase(scalar_q);
  
  // Expected: e(P, Q)
  yacl::Item expected = pairing_group_shared->Pairing(point_p, point_q);

  // Share Q in G2
  std::vector<EcPointShare> share_q(world_size);
  threads.clear();
  for (size_t i = 0; i < world_size; ++i) {
    threads.emplace_back([&, i]() {
      if (i == 0) {
        share_q[i] = mpc_systems[i]->ShareValueG2(point_q, 0);
      } else {
        yacl::math::MPInt zero;
        zero.SetZero();
        yacl::crypto::EcPoint infinity = g2->MulBase(zero);
        share_q[i] = mpc_systems[i]->ShareValueG2(infinity, 0);
      }
    });
  }
  for (auto& t : threads) {
    t.join();
  }

  // Compute e(P, [Q])
  yacl::Item identity = gt->GetIdentityOne();
  yacl::math::MPInt zero(0);
  GtElementShare init_share(identity, identity, zero);
  std::vector<GtElementShare> result_shares(world_size, init_share);
  threads.clear();
  for (size_t i = 0; i < world_size; ++i) {
    threads.emplace_back([&, i]() {
      result_shares[i] = mpc_systems[i]->PairingSecretG2(point_p, share_q[i]);
    });
  }
  for (auto& t : threads) {
    t.join();
  }

  // Open result
  std::vector<yacl::Item> results(world_size, identity);
  threads.clear();
  for (size_t i = 0; i < world_size; ++i) {
    threads.emplace_back([&, i]() {
      results[i] = mpc_systems[i]->OpenGT(result_shares[i]);
    });
  }
  for (auto& t : threads) {
    t.join();
  }

  // Record end time and stats
  auto end_time = std::chrono::high_resolution_clock::now();
  auto end_stats = GetTotalStats(contexts);

  // All parties should agree and result should be e(P, Q)
  for (size_t i = 1; i < world_size; ++i) {
    YACL_ENFORCE(gt->Equal(results[0], results[i]),
                 "SecPair2 test failed: parties disagree");
    YACL_ENFORCE(gt->Equal(results[i], expected),
                 "SecPair2 test failed: result != expected");
  }

  bool matches = gt->Equal(results[0], expected);
  YACL_ENFORCE(matches, "SecPair2 test failed: MPC result != plaintext computation");
  
  std::cout << "  SecPair2 e(P, [Q]) (" << mode << ", " << world_size
            << " parties) test PASSED (opened value matches plaintext: " << std::endl;
  PrintStats(start_stats, end_stats, start_time, end_time, "PairingSecretG2");
}

// Test SecPair3: e([P], [Q]) where both [P] ∈ G1 and [Q] ∈ G2 are secret-shared
void TestPairingSecret(bool malicious_security, size_t world_size = 2) {
  std::string mode = malicious_security ? "Malicious" : "Semi-Honest";
  std::cout << "Testing SecPair3 e([P], [Q]) (" << mode << ", " << world_size << " parties)..." << std::endl;

  auto contexts = yacl::link::test::SetupBrpcWorld(world_size);
  std::vector<std::unique_ptr<PairingMpcSystem>> mpc_systems(world_size);
  std::vector<std::unique_ptr<SpdzMpcSystem>> fp_mpc_systems(world_size);
  std::vector<std::thread> threads;

  auto pairing_group = yacl::crypto::MclPGFactory::CreateByName("bls12-381");
  std::shared_ptr<yacl::crypto::PairingGroup> pairing_group_shared(
      pairing_group.release());
  auto g1 = pairing_group_shared->GetGroup1();
  auto g2 = pairing_group_shared->GetGroup2();
  auto gt = pairing_group_shared->GetGroupT();
  auto order = pairing_group_shared->GetOrder();
  // Record start time and stats
  auto start_time = std::chrono::high_resolution_clock::now();
  auto start_stats = GetTotalStats(contexts);

  for (size_t i = 0; i < world_size; ++i) {
    threads.emplace_back([&, i]() {
      std::vector<std::shared_ptr<yacl::link::Context>> ctx_vec = {contexts[i]};
      mpc_systems[i] = std::make_unique<PairingMpcSystem>(
          i, world_size, ctx_vec, pairing_group_shared, malicious_security);
      fp_mpc_systems[i] = std::make_unique<SpdzMpcSystem>(
          i, world_size, ctx_vec, malicious_security, &order);
    });
  }
  for (auto& t : threads) {
    t.join();
  }

  // Party 0 shares point P in G1, Party 1 shares point Q in G2
  yacl::math::MPInt scalar_p("123");
  yacl::math::MPInt scalar_q("456");
  yacl::crypto::EcPoint point_p = g1->MulBase(scalar_p);
  yacl::crypto::EcPoint point_q = g2->MulBase(scalar_q);
  
  // Expected: e(P, Q)
  yacl::Item expected = pairing_group_shared->Pairing(point_p, point_q);

  // Share P in G1
  std::vector<EcPointShare> share_p(world_size);
  threads.clear();
  for (size_t i = 0; i < world_size; ++i) {
    threads.emplace_back([&, i]() {
      if (i == 0) {
        share_p[i] = mpc_systems[i]->ShareValueG1(point_p, 0);
      } else {
        yacl::math::MPInt zero;
        zero.SetZero();
        yacl::crypto::EcPoint infinity = g1->MulBase(zero);
        share_p[i] = mpc_systems[i]->ShareValueG1(infinity, 0);
      }
    });
  }
  for (auto& t : threads) {
    t.join();
  }

  // Share Q in G2
  std::vector<EcPointShare> share_q(world_size);
  threads.clear();
  for (size_t i = 0; i < world_size; ++i) {
    threads.emplace_back([&, i]() {
      if (i == 1 || (world_size > 2 && i == 1)) {
        share_q[i] = mpc_systems[i]->ShareValueG2(point_q, 1);
      } else {
        yacl::math::MPInt zero;
        zero.SetZero();
        yacl::crypto::EcPoint infinity = g2->MulBase(zero);
        share_q[i] = mpc_systems[i]->ShareValueG2(infinity, 1);
      }
    });
  }
  for (auto& t : threads) {
    t.join();
  }

  // Compute e([P], [Q])
  yacl::Item identity = gt->GetIdentityOne();
  yacl::math::MPInt zero(0);
  GtElementShare init_share(identity, identity, zero);
  std::vector<GtElementShare> result_shares(world_size, init_share);
  threads.clear();
  for (size_t i = 0; i < world_size; ++i) {
    threads.emplace_back([&, i]() {
      result_shares[i] = mpc_systems[i]->PairingSecret(share_p[i], share_q[i], fp_mpc_systems[i].get());
    });
  }
  for (auto& t : threads) {
    t.join();
  }

  // Open result
  std::vector<yacl::Item> results(world_size, identity);
  threads.clear();
  for (size_t i = 0; i < world_size; ++i) {
    threads.emplace_back([&, i]() {
      results[i] = mpc_systems[i]->OpenGT(result_shares[i]);
    });
  }
  for (auto& t : threads) {
    t.join();
  }

  // All parties should agree and result should be e(P, Q)
  for (size_t i = 1; i < world_size; ++i) {
    YACL_ENFORCE(gt->Equal(results[0], results[i]),
                 "SecPair3 test failed: parties disagree");
    YACL_ENFORCE(gt->Equal(results[i], expected),
                 "SecPair3 test failed: result != expected");
  }

  // Record end time and stats
  auto end_time = std::chrono::high_resolution_clock::now();
  auto end_stats = GetTotalStats(contexts);

  bool matches = gt->Equal(results[0], expected);
  YACL_ENFORCE(matches, "SecPair3 test failed: MPC result != plaintext computation");

  std::cout << "  SecPair3 e([P], [Q]) (" << mode << ", " << world_size
            << " parties) test PASSED (opened value matches plaintext: " << std::endl;
  PrintStats(start_stats, end_stats, start_time, end_time, "PairingSecret");
}

}  // namespace yacl::examples::pii

int main() {

  // Test with different world sizes
  std::vector<size_t> world_sizes = {2, 3, 4};

  for (size_t world_size : world_sizes) {

    // Semi-Honest Security Tests
    std::cout << "--- Semi-Honest Security Tests (" << world_size << " parties) ---" << std::endl << std::endl;
    yacl::examples::pii::TestRandomShareG1(false, world_size);
    yacl::examples::pii::TestAddG1(false, world_size);
    yacl::examples::pii::TestMulScalarG1(false, world_size);
    yacl::examples::pii::TestMulSecretScalarPublicPointG1(false, world_size);
    yacl::examples::pii::TestMulSecretScalarG1(false, world_size);
    yacl::examples::pii::TestRandomShareG2(false, world_size);
    yacl::examples::pii::TestAddG2(false, world_size);
    yacl::examples::pii::TestMulScalarG2(false, world_size);
    yacl::examples::pii::TestMulSecretScalarPublicPointG2(false, world_size);
    yacl::examples::pii::TestMulSecretScalarG2(false, world_size);
    yacl::examples::pii::TestMulGT(false, world_size);
    yacl::examples::pii::TestPowGT(false, world_size);
    yacl::examples::pii::TestMulSecretScalarPublicElementGT(false, world_size);
    yacl::examples::pii::TestMulSecretScalarGT(false, world_size);
    yacl::examples::pii::TestPairingSecretG1(false, world_size);
    yacl::examples::pii::TestPairingSecretG2(false, world_size);
    yacl::examples::pii::TestPairingSecret(false, world_size);

    // Malicious Security Tests
    std::cout << "--- Malicious Security Tests (" << world_size << " parties) ---" << std::endl << std::endl;
    yacl::examples::pii::TestRandomShareG1(true, world_size);
    yacl::examples::pii::TestAddG1(true, world_size);
    yacl::examples::pii::TestMulScalarG1(true, world_size);
    yacl::examples::pii::TestMulSecretScalarPublicPointG1(true, world_size);
    yacl::examples::pii::TestMulSecretScalarG1(true, world_size);
    yacl::examples::pii::TestRandomShareG2(true, world_size);
    yacl::examples::pii::TestAddG2(true, world_size);
    yacl::examples::pii::TestMulScalarG2(true, world_size);
    yacl::examples::pii::TestMulSecretScalarPublicPointG2(true, world_size);
    yacl::examples::pii::TestMulSecretScalarG2(true, world_size);
    yacl::examples::pii::TestMulGT(true, world_size);
    yacl::examples::pii::TestPowGT(true, world_size);
    yacl::examples::pii::TestMulSecretScalarPublicElementGT(true, world_size);
    yacl::examples::pii::TestMulSecretScalarGT(true, world_size);
    yacl::examples::pii::TestPairingSecretG1(true, world_size);
    yacl::examples::pii::TestPairingSecretG2(true, world_size);
    yacl::examples::pii::TestPairingSecret(true, world_size);
  }

  return 0;
}
