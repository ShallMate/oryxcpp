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

#include "examples/oryxcpp/ec_mpc.h"

#include <chrono>
#include <iostream>
#include <thread>
#include <vector>

#include "examples/oryxcpp/spdz_mpc.h"
#include "yacl/base/exception.h"
#include "yacl/crypto/ecc/ecc_spi.h"
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
                const std::string& test_name) {
  auto duration_ms = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time);
  auto duration_us = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time);
  size_t sent_bytes = end_stats.sent_bytes - start_stats.sent_bytes;
  size_t sent_actions = end_stats.sent_actions - start_stats.sent_actions;
  size_t recv_bytes = end_stats.recv_bytes - start_stats.recv_bytes;
  size_t recv_actions = end_stats.recv_actions - start_stats.recv_actions;
  
  std::cout << "  [" << test_name << " Statistics]" << std::endl;
  if (duration_ms.count() > 0) {
    std::cout << "    Time: " << duration_ms.count() << " ms (" << duration_us.count() << " μs)" << std::endl;
  } else {
    std::cout << "    Time: " << duration_us.count() << " μs" << std::endl;
  }
  std::cout << "    Communication:" << std::endl;
  std::cout << "      Sent: " << sent_bytes << " bytes (" << sent_actions << " actions)" << std::endl;
  std::cout << "      Received: " << recv_bytes << " bytes (" << recv_actions << " actions)" << std::endl;
  std::cout << "      Total: " << (sent_bytes + recv_bytes) << " bytes (" 
            << (sent_actions + recv_actions) << " actions)" << std::endl;
}

// Test RandomShare: Generate random shared point
void TestRandomShare(bool malicious_security, size_t world_size = 2) {
  std::string mode = malicious_security ? "Malicious" : "Semi-Honest";
  std::cout << "Testing RandomShare (" << mode << ", " << world_size
            << " parties)..." << std::endl;

  auto contexts = yacl::link::test::SetupBrpcWorld(world_size);
  std::vector<std::unique_ptr<EcMpcSystem>> mpc_systems(world_size);
  std::vector<std::thread> threads;

  // Create EC group (use secp256k1 as example)
  auto ec_group_unique = yacl::crypto::EcGroupFactory::Instance().Create("secp256k1");
  std::shared_ptr<yacl::crypto::EcGroup> ec_group(ec_group_unique.release());

  // Record start time and stats
  auto start_time = std::chrono::high_resolution_clock::now();
  auto start_stats = GetTotalStats(contexts);

  // Initialize MPC systems in parallel
  for (size_t i = 0; i < world_size; ++i) {
    threads.emplace_back([&, i]() {
      std::vector<std::shared_ptr<yacl::link::Context>> ctx_vec = {contexts[i]};
      mpc_systems[i] = std::make_unique<EcMpcSystem>(
          i, world_size, ctx_vec, ec_group, malicious_security);
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
      shares[i] = mpc_systems[i]->RandomShare();
    });
  }
  for (auto& t : threads) {
    t.join();
  }

  // Open shares
  std::vector<yacl::crypto::EcPoint> opened_values(world_size);
  threads.clear();
  for (size_t i = 0; i < world_size; ++i) {
    threads.emplace_back([&, i]() {
      opened_values[i] = mpc_systems[i]->PartialOpen(shares[i]);
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
    YACL_ENFORCE(ec_group->PointEqual(opened_values[0], opened_values[i]),
                 "RandomShare test failed: parties disagree on opened value");
  }

  std::cout << "  RandomShare (" << mode << ", " << world_size
            << " parties) test PASSED" << std::endl;
  PrintStats(start_stats, end_stats, start_time, end_time, "RandomShare");
}

// Test ShareValue: Share a point
void TestShareValue(bool malicious_security, size_t world_size = 2) {
  std::string mode = malicious_security ? "Malicious" : "Semi-Honest";
  std::cout << "Testing ShareValue (" << mode << ", " << world_size
            << " parties)..." << std::endl;

  auto contexts = yacl::link::test::SetupBrpcWorld(world_size);
  std::vector<std::unique_ptr<EcMpcSystem>> mpc_systems(world_size);
  std::vector<std::thread> threads;

  auto ec_group_unique = yacl::crypto::EcGroupFactory::Instance().Create("secp256k1");
  std::shared_ptr<yacl::crypto::EcGroup> ec_group(ec_group_unique.release());

  // Record start time and stats
  auto start_time = std::chrono::high_resolution_clock::now();
  auto start_stats = GetTotalStats(contexts);

  for (size_t i = 0; i < world_size; ++i) {
    threads.emplace_back([&, i]() {
      std::vector<std::shared_ptr<yacl::link::Context>> ctx_vec = {contexts[i]};
      mpc_systems[i] = std::make_unique<EcMpcSystem>(
          i, world_size, ctx_vec, ec_group, malicious_security);
    });
  }
  for (auto& t : threads) {
    t.join();
  }

  // Party 0 shares a point (scalar * G where scalar = 123456789)
  yacl::math::MPInt test_scalar("123456789");
  yacl::crypto::EcPoint test_point = ec_group->MulBase(test_scalar);

  std::vector<EcPointShare> shares(world_size);
  threads.clear();
  for (size_t i = 0; i < world_size; ++i) {
    threads.emplace_back([&, i]() {
      if (i == 0) {
        shares[i] = mpc_systems[i]->ShareValue(test_point, 0);
      } else {
        // Other parties receive
        yacl::math::MPInt zero(0);
        yacl::crypto::EcPoint infinity = ec_group->MulBase(zero);
        shares[i] = mpc_systems[i]->ShareValue(infinity, 0);
      }
    });
  }
  for (auto& t : threads) {
    t.join();
  }

  // Open shares
  std::vector<yacl::crypto::EcPoint> opened_values(world_size);
  threads.clear();
  for (size_t i = 0; i < world_size; ++i) {
    threads.emplace_back([&, i]() {
      opened_values[i] = mpc_systems[i]->Open(shares[i]);
    });
  }
  for (auto& t : threads) {
    t.join();
  }

  // Record end time and stats
  auto end_time = std::chrono::high_resolution_clock::now();
  auto end_stats = GetTotalStats(contexts);

  // All parties should get the same opened value, equal to test_point
  for (size_t i = 1; i < world_size; ++i) {
    YACL_ENFORCE(ec_group->PointEqual(opened_values[0], opened_values[i]),
                 "ShareValue test failed: parties disagree");
    YACL_ENFORCE(ec_group->PointEqual(opened_values[i], test_point),
                 "ShareValue test failed: opened value != test point");
  }

  std::cout << "  ShareValue (" << mode << ", " << world_size
            << " parties) test PASSED" << std::endl;
  PrintStats(start_stats, end_stats, start_time, end_time, "ShareValue");
}

// Test Add: [P] + [Q] = [P+Q]
void TestAdd(bool malicious_security, size_t world_size = 2) {
  std::string mode = malicious_security ? "Malicious" : "Semi-Honest";
  std::cout << "Testing Add (" << mode << ", " << world_size << " parties)..."
            << std::endl;

  auto contexts = yacl::link::test::SetupBrpcWorld(world_size);
  std::vector<std::unique_ptr<EcMpcSystem>> mpc_systems(world_size);
  std::vector<std::thread> threads;

  auto ec_group_unique = yacl::crypto::EcGroupFactory::Instance().Create("secp256k1");
  std::shared_ptr<yacl::crypto::EcGroup> ec_group(ec_group_unique.release());

  // Record start time and stats
  auto start_time = std::chrono::high_resolution_clock::now();
  auto start_stats = GetTotalStats(contexts);

  for (size_t i = 0; i < world_size; ++i) {
    threads.emplace_back([&, i]() {
      std::vector<std::shared_ptr<yacl::link::Context>> ctx_vec = {contexts[i]};
      mpc_systems[i] = std::make_unique<EcMpcSystem>(
          i, world_size, ctx_vec, ec_group, malicious_security);
    });
  }
  for (auto& t : threads) {
    t.join();
  }

  // Party 0 shares point P (100 * G), Party 1 shares point Q (200 * G)
  yacl::math::MPInt scalar_a("100");
  yacl::math::MPInt scalar_b("200");
  yacl::crypto::EcPoint point_a = ec_group->MulBase(scalar_a);
  yacl::crypto::EcPoint point_b = ec_group->MulBase(scalar_b);
  yacl::crypto::EcPoint expected = ec_group->Add(point_a, point_b);

  std::vector<EcPointShare> share_a(world_size), share_b(world_size);
  threads.clear();
  for (size_t i = 0; i < world_size; ++i) {
    threads.emplace_back([&, i]() {
      if (i == 0) {
        share_a[i] = mpc_systems[i]->ShareValue(point_a, 0);
      } else {
        yacl::math::MPInt zero(0);
        yacl::crypto::EcPoint infinity = ec_group->MulBase(zero);
        share_a[i] = mpc_systems[i]->ShareValue(infinity, 0);
      }
      std::this_thread::sleep_for(std::chrono::milliseconds(10));
      if (i == 1 || (world_size > 2 && i == 1)) {
        share_b[i] = mpc_systems[i]->ShareValue(point_b, 1);
      } else {
        yacl::math::MPInt zero(0);
        yacl::crypto::EcPoint infinity = ec_group->MulBase(zero);
        share_b[i] = mpc_systems[i]->ShareValue(infinity, 1);
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
      result_shares[i] = mpc_systems[i]->Add(share_a[i], share_b[i]);
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
      results[i] = mpc_systems[i]->Open(result_shares[i]);
    });
  }
  for (auto& t : threads) {
    t.join();
  }

  // Record end time and stats
  auto end_time = std::chrono::high_resolution_clock::now();
  auto end_stats = GetTotalStats(contexts);

  // All parties should agree and result should be P + Q
  for (size_t i = 1; i < world_size; ++i) {
    YACL_ENFORCE(ec_group->PointEqual(results[0], results[i]),
                 "Add test failed: parties disagree");
    YACL_ENFORCE(ec_group->PointEqual(results[i], expected),
                 "Add test failed: result != expected");
  }

  // Verify: opened result matches plaintext computation
  bool matches = ec_group->PointEqual(results[0], expected);
  YACL_ENFORCE(matches, "Add test failed: MPC result != plaintext computation");
  
  std::cout << "  Add (" << mode << ", " << world_size
            << " parties) test PASSED (opened value matches plaintext: "
            << (matches ? "YES" : "NO") << ")" << std::endl;
  PrintStats(start_stats, end_stats, start_time, end_time, "Add");
}

// Test Sub: [P] - [Q] = [P-Q]
void TestSub(bool malicious_security, size_t world_size = 2) {
  std::string mode = malicious_security ? "Malicious" : "Semi-Honest";
  std::cout << "Testing Sub (" << mode << ", " << world_size << " parties)..."
            << std::endl;

  auto contexts = yacl::link::test::SetupBrpcWorld(world_size);
  std::vector<std::unique_ptr<EcMpcSystem>> mpc_systems(world_size);
  std::vector<std::thread> threads;

  auto ec_group_unique = yacl::crypto::EcGroupFactory::Instance().Create("secp256k1");
  std::shared_ptr<yacl::crypto::EcGroup> ec_group(ec_group_unique.release());

  // Record start time and stats
  auto start_time = std::chrono::high_resolution_clock::now();
  auto start_stats = GetTotalStats(contexts);

  for (size_t i = 0; i < world_size; ++i) {
    threads.emplace_back([&, i]() {
      std::vector<std::shared_ptr<yacl::link::Context>> ctx_vec = {contexts[i]};
      mpc_systems[i] = std::make_unique<EcMpcSystem>(
          i, world_size, ctx_vec, ec_group, malicious_security);
    });
  }
  for (auto& t : threads) {
    t.join();
  }

  // Party 0 shares point P (500 * G), Party 1 shares point Q (200 * G)
  yacl::math::MPInt scalar_a("500");
  yacl::math::MPInt scalar_b("200");
  yacl::crypto::EcPoint point_a = ec_group->MulBase(scalar_a);
  yacl::crypto::EcPoint point_b = ec_group->MulBase(scalar_b);
  yacl::crypto::EcPoint expected = ec_group->Sub(point_a, point_b);

  std::vector<EcPointShare> share_a(world_size), share_b(world_size);
  threads.clear();
  for (size_t i = 0; i < world_size; ++i) {
    threads.emplace_back([&, i]() {
      if (i == 0) {
        share_a[i] = mpc_systems[i]->ShareValue(point_a, 0);
      } else {
        yacl::math::MPInt zero(0);
        yacl::crypto::EcPoint infinity = ec_group->MulBase(zero);
        share_a[i] = mpc_systems[i]->ShareValue(infinity, 0);
      }
      std::this_thread::sleep_for(std::chrono::milliseconds(10));
      if (i == 1 || (world_size > 2 && i == 1)) {
        share_b[i] = mpc_systems[i]->ShareValue(point_b, 1);
      } else {
        yacl::math::MPInt zero(0);
        yacl::crypto::EcPoint infinity = ec_group->MulBase(zero);
        share_b[i] = mpc_systems[i]->ShareValue(infinity, 1);
      }
    });
  }
  for (auto& t : threads) {
    t.join();
  }

  // Compute [P] - [Q]
  std::vector<EcPointShare> result_shares(world_size);
  threads.clear();
  for (size_t i = 0; i < world_size; ++i) {
    threads.emplace_back([&, i]() {
      result_shares[i] = mpc_systems[i]->Sub(share_a[i], share_b[i]);
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
      results[i] = mpc_systems[i]->Open(result_shares[i]);
    });
  }
  for (auto& t : threads) {
    t.join();
  }

  // All parties should agree and result should be P - Q
  for (size_t i = 1; i < world_size; ++i) {
    YACL_ENFORCE(ec_group->PointEqual(results[0], results[i]),
                 "Sub test failed: parties disagree");
    YACL_ENFORCE(ec_group->PointEqual(results[i], expected),
                 "Sub test failed: result != expected");
  }

  // Verify: opened result matches plaintext computation
  bool matches = ec_group->PointEqual(results[0], expected);
  YACL_ENFORCE(matches, "Sub test failed: MPC result != plaintext computation");
  
  // Record end time and stats
  auto end_time = std::chrono::high_resolution_clock::now();
  auto end_stats = GetTotalStats(contexts);

  std::cout << "  Sub (" << mode << ", " << world_size
            << " parties) test PASSED (opened value matches plaintext: "
            << (matches ? "YES" : "NO") << ")" << std::endl;
  PrintStats(start_stats, end_stats, start_time, end_time, "Sub");
}

// Test MulScalar: k * [P] = [k*P]
void TestMulScalar(bool malicious_security, size_t world_size = 2) {
  std::string mode = malicious_security ? "Malicious" : "Semi-Honest";
  std::cout << "Testing MulScalar (" << mode << ", " << world_size
            << " parties)..." << std::endl;

  auto contexts = yacl::link::test::SetupBrpcWorld(world_size);
  std::vector<std::unique_ptr<EcMpcSystem>> mpc_systems(world_size);
  std::vector<std::thread> threads;

  auto ec_group_unique = yacl::crypto::EcGroupFactory::Instance().Create("secp256k1");
  std::shared_ptr<yacl::crypto::EcGroup> ec_group(ec_group_unique.release());

  // Record start time and stats
  auto start_time = std::chrono::high_resolution_clock::now();
  auto start_stats = GetTotalStats(contexts);

  for (size_t i = 0; i < world_size; ++i) {
    threads.emplace_back([&, i]() {
      std::vector<std::shared_ptr<yacl::link::Context>> ctx_vec = {contexts[i]};
      mpc_systems[i] = std::make_unique<EcMpcSystem>(
          i, world_size, ctx_vec, ec_group, malicious_security);
    });
  }
  for (auto& t : threads) {
    t.join();
  }

  // Party 0 shares point P (100 * G)
  yacl::math::MPInt scalar_p("100");
  yacl::math::MPInt scalar_k("5");
  yacl::crypto::EcPoint point_p = ec_group->MulBase(scalar_p);
  yacl::crypto::EcPoint expected = ec_group->Mul(point_p, scalar_k);

  std::vector<EcPointShare> share_p(world_size);
  threads.clear();
  for (size_t i = 0; i < world_size; ++i) {
    threads.emplace_back([&, i]() {
      if (i == 0) {
        share_p[i] = mpc_systems[i]->ShareValue(point_p, 0);
      } else {
        yacl::math::MPInt zero(0);
        yacl::crypto::EcPoint infinity = ec_group->MulBase(zero);
        share_p[i] = mpc_systems[i]->ShareValue(infinity, 0);
      }
    });
  }
  for (auto& t : threads) {
    t.join();
  }

  // Compute k * [P]
  std::vector<EcPointShare> result_shares(world_size);
  threads.clear();
  for (size_t i = 0; i < world_size; ++i) {
    threads.emplace_back([&, i]() {
      result_shares[i] = mpc_systems[i]->MulScalar(scalar_k, share_p[i]);
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
      results[i] = mpc_systems[i]->Open(result_shares[i]);
    });
  }
  for (auto& t : threads) {
    t.join();
  }

  // All parties should agree and result should be k * P
  for (size_t i = 1; i < world_size; ++i) {
    YACL_ENFORCE(ec_group->PointEqual(results[0], results[i]),
                 "MulScalar test failed: parties disagree");
    YACL_ENFORCE(ec_group->PointEqual(results[i], expected),
                 "MulScalar test failed: result != expected");
  }

  // Verify: opened result matches plaintext computation
  bool matches = ec_group->PointEqual(results[0], expected);
  YACL_ENFORCE(matches, "MulScalar test failed: MPC result != plaintext computation");
  
  // Record end time and stats
  auto end_time = std::chrono::high_resolution_clock::now();
  auto end_stats = GetTotalStats(contexts);

  std::cout << "  MulScalar (" << mode << ", " << world_size
            << " parties) test PASSED (opened value matches plaintext: "
            << (matches ? "YES" : "NO") << ")" << std::endl;
  PrintStats(start_stats, end_stats, start_time, end_time, "MulScalar");
}

// Test MulSecretScalarPublicPoint: [k] * P = [k*P] (secret scalar [k] * public point P)
void TestMulSecretScalarPublicPoint(bool malicious_security, size_t world_size = 2) {
  std::string mode = malicious_security ? "Malicious" : "Semi-Honest";
  std::cout << "Testing MulSecretScalarPublicPoint [k]P (" << mode << ", " << world_size
            << " parties)..." << std::endl;

  auto contexts = yacl::link::test::SetupBrpcWorld(world_size);
  std::vector<std::unique_ptr<EcMpcSystem>> mpc_systems(world_size);
  std::vector<std::unique_ptr<SpdzMpcSystem>> fp_mpc_systems(world_size);
  std::vector<std::thread> threads;

  auto ec_group_unique = yacl::crypto::EcGroupFactory::Instance().Create("secp256k1");
  std::shared_ptr<yacl::crypto::EcGroup> ec_group(ec_group_unique.release());
  yacl::math::MPInt order = ec_group->GetOrder();

  // Record start time and stats
  auto start_time = std::chrono::high_resolution_clock::now();
  auto start_stats = GetTotalStats(contexts);

  for (size_t i = 0; i < world_size; ++i) {
    threads.emplace_back([&, i]() {
      std::vector<std::shared_ptr<yacl::link::Context>> ctx_vec = {contexts[i]};
      mpc_systems[i] = std::make_unique<EcMpcSystem>(
          i, world_size, ctx_vec, ec_group, malicious_security);
      fp_mpc_systems[i] = std::make_unique<SpdzMpcSystem>(
          i, world_size, ctx_vec, malicious_security, &order);
    });
  }
  for (auto& t : threads) {
    t.join();
  }

  // Party 0 shares scalar k (secret scalar [k])
  yacl::math::MPInt scalar_k("123");
  yacl::crypto::EcPoint public_point = ec_group->MulBase(yacl::math::MPInt("100"));  // Public point P = 100 * G
  yacl::crypto::EcPoint expected = ec_group->Mul(public_point, scalar_k);  // Expected: k * P

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

  // Compute [k] * P = [k*P] using MulSecretScalarPublicPoint
  // This is more efficient than MulSecretScalar since P is public
  std::vector<EcPointShare> result_shares(world_size);
  threads.clear();
  for (size_t i = 0; i < world_size; ++i) {
    threads.emplace_back([&, i]() {
      result_shares[i] = mpc_systems[i]->MulSecretScalarPublicPoint(share_k[i], public_point);
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
      results[i] = mpc_systems[i]->Open(result_shares[i]);
    });
  }
  for (auto& t : threads) {
    t.join();
  }

  // All parties should agree and result should be k * P
  for (size_t i = 1; i < world_size; ++i) {
    YACL_ENFORCE(ec_group->PointEqual(results[0], results[i]),
                 "MulSecretScalarPublicPoint test failed: parties disagree");
    YACL_ENFORCE(ec_group->PointEqual(results[i], expected),
                 "MulSecretScalarPublicPoint test failed: result != expected");
  }

  // Record end time and stats
  auto end_time = std::chrono::high_resolution_clock::now();
  auto end_stats = GetTotalStats(contexts);

  // Verify: opened result matches plaintext computation
  bool matches = ec_group->PointEqual(results[0], expected);
  YACL_ENFORCE(matches, "MulSecretScalarPublicPoint test failed: MPC result != plaintext computation");
  
  std::cout << "  MulSecretScalarPublicPoint [k]P (" << mode << ", " << world_size
            << " parties) test PASSED (opened value matches plaintext: "
            << (matches ? "YES" : "NO") << ")" << std::endl;
  PrintStats(start_stats, end_stats, start_time, end_time, "MulSecretScalarPublicPoint");
}

// Test MulSecretScalar: [k] * [P] = [k*P] (secret scalar [k] * secret point [P])
void TestMulSecretScalar(bool malicious_security, size_t world_size = 2) {
  std::string mode = malicious_security ? "Malicious" : "Semi-Honest";
  std::cout << "Testing MulSecretScalar [k][P] (" << mode << ", " << world_size
            << " parties)..." << std::endl;

  auto contexts = yacl::link::test::SetupBrpcWorld(world_size);
  std::vector<std::unique_ptr<EcMpcSystem>> mpc_systems(world_size);
  std::vector<std::unique_ptr<SpdzMpcSystem>> fp_mpc_systems(world_size);
  std::vector<std::thread> threads;

  auto ec_group_unique = yacl::crypto::EcGroupFactory::Instance().Create("secp256k1");
  std::shared_ptr<yacl::crypto::EcGroup> ec_group(ec_group_unique.release());
  yacl::math::MPInt order = ec_group->GetOrder();

  // Record start time and stats
  auto start_time = std::chrono::high_resolution_clock::now();
  auto start_stats = GetTotalStats(contexts);

  for (size_t i = 0; i < world_size; ++i) {
    threads.emplace_back([&, i]() {
      std::vector<std::shared_ptr<yacl::link::Context>> ctx_vec = {contexts[i]};
      mpc_systems[i] = std::make_unique<EcMpcSystem>(
          i, world_size, ctx_vec, ec_group, malicious_security);
      fp_mpc_systems[i] = std::make_unique<SpdzMpcSystem>(
          i, world_size, ctx_vec, malicious_security, &order);
    });
  }
  for (auto& t : threads) {
    t.join();
  }

  // Party 0 shares scalar k (secret scalar [k])
  yacl::math::MPInt scalar_k("123");
  // Party 1 shares point P (secret point [P])
  yacl::math::MPInt scalar_p("456");
  yacl::crypto::EcPoint point_p = ec_group->MulBase(scalar_p);
  yacl::crypto::EcPoint expected = ec_group->Mul(point_p, scalar_k);  // Expected: k * P

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

  std::vector<EcPointShare> share_p(world_size);
  threads.clear();
  for (size_t i = 0; i < world_size; ++i) {
    threads.emplace_back([&, i]() {
      if (i == 1 || (world_size > 2 && i == 1)) {
        share_p[i] = mpc_systems[i]->ShareValue(point_p, 1);
      } else {
        yacl::math::MPInt zero(0);
        yacl::crypto::EcPoint infinity = ec_group->MulBase(zero);
        share_p[i] = mpc_systems[i]->ShareValue(infinity, 1);
      }
    });
  }
  for (auto& t : threads) {
    t.join();
  }

  // Compute [k] * [P] = [k*P]
  std::vector<EcPointShare> result_shares(world_size);
  threads.clear();
  for (size_t i = 0; i < world_size; ++i) {
    threads.emplace_back([&, i]() {
      result_shares[i] = mpc_systems[i]->MulSecretScalar(share_k[i], share_p[i], fp_mpc_systems[i].get());
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
      results[i] = mpc_systems[i]->Open(result_shares[i]);
    });
  }
  for (auto& t : threads) {
    t.join();
  }

  // All parties should agree and result should be k * P
  for (size_t i = 1; i < world_size; ++i) {
    YACL_ENFORCE(ec_group->PointEqual(results[0], results[i]),
                 "MulSecretScalar test failed: parties disagree");
    YACL_ENFORCE(ec_group->PointEqual(results[i], expected),
                 "MulSecretScalar test failed: result != expected");
  }

  // Record end time and stats
  auto end_time = std::chrono::high_resolution_clock::now();
  auto end_stats = GetTotalStats(contexts);

  // Verify: opened result matches plaintext computation
  bool matches = ec_group->PointEqual(results[0], expected);
  YACL_ENFORCE(matches, "MulSecretScalar test failed: MPC result != plaintext computation");
  
  std::cout << "  MulSecretScalar [k][P] (" << mode << ", " << world_size
            << " parties) test PASSED (opened value matches plaintext: "
            << (matches ? "YES" : "NO") << ")" << std::endl;
  PrintStats(start_stats, end_stats, start_time, end_time, "MulSecretScalar");
}

// Test Open and PartialOpen
void TestOpen(bool malicious_security, size_t world_size = 2) {
  std::string mode = malicious_security ? "Malicious" : "Semi-Honest";
  std::cout << "Testing Open (" << mode << ", " << world_size
            << " parties)..." << std::endl;

  auto contexts = yacl::link::test::SetupBrpcWorld(world_size);
  std::vector<std::unique_ptr<EcMpcSystem>> mpc_systems(world_size);
  std::vector<std::thread> threads;

  auto ec_group_unique = yacl::crypto::EcGroupFactory::Instance().Create("secp256k1");
  std::shared_ptr<yacl::crypto::EcGroup> ec_group(ec_group_unique.release());

  // Record start time and stats
  auto start_time = std::chrono::high_resolution_clock::now();
  auto start_stats = GetTotalStats(contexts);

  for (size_t i = 0; i < world_size; ++i) {
    threads.emplace_back([&, i]() {
      std::vector<std::shared_ptr<yacl::link::Context>> ctx_vec = {contexts[i]};
      mpc_systems[i] = std::make_unique<EcMpcSystem>(
          i, world_size, ctx_vec, ec_group, malicious_security);
    });
  }
  for (auto& t : threads) {
    t.join();
  }

  // Party 0 shares a point
  yacl::math::MPInt test_scalar("999999");
  yacl::crypto::EcPoint test_point = ec_group->MulBase(test_scalar);

  std::vector<EcPointShare> shares(world_size);
  threads.clear();
  for (size_t i = 0; i < world_size; ++i) {
    threads.emplace_back([&, i]() {
      if (i == 0) {
        shares[i] = mpc_systems[i]->ShareValue(test_point, 0);
      } else {
        yacl::math::MPInt zero(0);
        yacl::crypto::EcPoint infinity = ec_group->MulBase(zero);
        shares[i] = mpc_systems[i]->ShareValue(infinity, 0);
      }
    });
  }
  for (auto& t : threads) {
    t.join();
  }

  // Open shares
  std::vector<yacl::crypto::EcPoint> opened_values(world_size);
  threads.clear();
  for (size_t i = 0; i < world_size; ++i) {
    threads.emplace_back([&, i]() {
      opened_values[i] = mpc_systems[i]->Open(shares[i]);
    });
  }
  for (auto& t : threads) {
    t.join();
  }

  // All parties should get the same opened value
  for (size_t i = 1; i < world_size; ++i) {
    YACL_ENFORCE(ec_group->PointEqual(opened_values[0], opened_values[i]),
                 "Open test failed: parties disagree");
    YACL_ENFORCE(ec_group->PointEqual(opened_values[i], test_point),
                 "Open test failed: opened value != test point");
  }

  // Record end time and stats
  auto end_time = std::chrono::high_resolution_clock::now();
  auto end_stats = GetTotalStats(contexts);

  // Verify: opened value matches plaintext (original shared point)
  bool matches = ec_group->PointEqual(opened_values[0], test_point);
  YACL_ENFORCE(matches, "Open test failed: opened value != plaintext");
  
  std::string security_msg = malicious_security
                                 ? " (MAC verification successful)"
                                 : " (semi-honest, no MAC)";
  std::cout << "  Open (" << mode << ", " << world_size
            << " parties) test PASSED" << security_msg
            << " (opened value matches plaintext: " << (matches ? "YES" : "NO") << ")"
            << std::endl;
  PrintStats(start_stats, end_stats, start_time, end_time, "Open");
}

}  // namespace yacl::examples::pii

int main() {
  std::cout << "=== EC Group G MPC Tests ===" << std::endl;
  std::cout << std::endl;

  // Test with different world sizes
  std::vector<size_t> world_sizes = {2, 3, 4};

  for (size_t world_size : world_sizes) {
    std::cout << "=== Testing with " << world_size << " parties ===" << std::endl;
    std::cout << std::endl;

    // Semi-Honest Security Tests
    std::cout << "--- Semi-Honest Security Tests (" << world_size
              << " parties) ---" << std::endl;
    yacl::examples::pii::TestRandomShare(false, world_size);
    yacl::examples::pii::TestShareValue(false, world_size);
    yacl::examples::pii::TestAdd(false, world_size);
    yacl::examples::pii::TestSub(false, world_size);
      yacl::examples::pii::TestMulScalar(false, world_size);
      yacl::examples::pii::TestMulSecretScalarPublicPoint(false, world_size);
      yacl::examples::pii::TestMulSecretScalar(false, world_size);
      yacl::examples::pii::TestOpen(false, world_size);
    std::cout << std::endl;

    // Malicious Security Tests
    std::cout << "--- Malicious Security Tests (" << world_size
              << " parties) ---" << std::endl;
    yacl::examples::pii::TestRandomShare(true, world_size);
    yacl::examples::pii::TestShareValue(true, world_size);
    yacl::examples::pii::TestAdd(true, world_size);
    yacl::examples::pii::TestSub(true, world_size);
      yacl::examples::pii::TestMulScalar(true, world_size);
      yacl::examples::pii::TestMulSecretScalarPublicPoint(true, world_size);
      yacl::examples::pii::TestMulSecretScalar(true, world_size);
      yacl::examples::pii::TestOpen(true, world_size);
    std::cout << std::endl;
  }

  std::cout << "=== All EC Group G MPC Tests PASSED ===" << std::endl;
  return 0;
}
