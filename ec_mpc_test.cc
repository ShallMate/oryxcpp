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

#include <iostream>
#include <thread>
#include <vector>

#include "yacl/base/exception.h"
#include "yacl/crypto/ecc/ecc_spi.h"
#include "yacl/link/test_util.h"

namespace yacl::examples::pii {

// Test RandomShare: Generate random shared point
void TestRandomShare(bool malicious_security, size_t world_size = 2) {
  std::string mode = malicious_security ? "Malicious" : "Semi-Honest";
  std::cout << "Testing RandomShare (" << mode << ", " << world_size
            << " parties)..." << std::endl;

  auto contexts = yacl::link::test::SetupWorld(world_size);
  std::vector<std::unique_ptr<EcMpcSystem>> mpc_systems(world_size);
  std::vector<std::thread> threads;

  // Create EC group (use secp256k1 as example)
  auto ec_group_unique = yacl::crypto::EcGroupFactory::Instance().Create("secp256k1");
  std::shared_ptr<yacl::crypto::EcGroup> ec_group(ec_group_unique.release());

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

  // All parties should get the same opened value
  for (size_t i = 1; i < world_size; ++i) {
    YACL_ENFORCE(ec_group->PointEqual(opened_values[0], opened_values[i]),
                 "RandomShare test failed: parties disagree on opened value");
  }

  std::cout << "  RandomShare (" << mode << ", " << world_size
            << " parties) test PASSED" << std::endl;
}

// Test ShareValue: Share a point
void TestShareValue(bool malicious_security, size_t world_size = 2) {
  std::string mode = malicious_security ? "Malicious" : "Semi-Honest";
  std::cout << "Testing ShareValue (" << mode << ", " << world_size
            << " parties)..." << std::endl;

  auto contexts = yacl::link::test::SetupWorld(world_size);
  std::vector<std::unique_ptr<EcMpcSystem>> mpc_systems(world_size);
  std::vector<std::thread> threads;

  auto ec_group_unique = yacl::crypto::EcGroupFactory::Instance().Create("secp256k1");
  std::shared_ptr<yacl::crypto::EcGroup> ec_group(ec_group_unique.release());

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

  // All parties should get the same opened value, equal to test_point
  for (size_t i = 1; i < world_size; ++i) {
    YACL_ENFORCE(ec_group->PointEqual(opened_values[0], opened_values[i]),
                 "ShareValue test failed: parties disagree");
    YACL_ENFORCE(ec_group->PointEqual(opened_values[i], test_point),
                 "ShareValue test failed: opened value != test point");
  }

  std::cout << "  ShareValue (" << mode << ", " << world_size
            << " parties) test PASSED" << std::endl;
}

// Test Add: [P] + [Q] = [P+Q]
void TestAdd(bool malicious_security, size_t world_size = 2) {
  std::string mode = malicious_security ? "Malicious" : "Semi-Honest";
  std::cout << "Testing Add (" << mode << ", " << world_size << " parties)..."
            << std::endl;

  auto contexts = yacl::link::test::SetupWorld(world_size);
  std::vector<std::unique_ptr<EcMpcSystem>> mpc_systems(world_size);
  std::vector<std::thread> threads;

  auto ec_group_unique = yacl::crypto::EcGroupFactory::Instance().Create("secp256k1");
  std::shared_ptr<yacl::crypto::EcGroup> ec_group(ec_group_unique.release());

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
}

// Test Sub: [P] - [Q] = [P-Q]
void TestSub(bool malicious_security, size_t world_size = 2) {
  std::string mode = malicious_security ? "Malicious" : "Semi-Honest";
  std::cout << "Testing Sub (" << mode << ", " << world_size << " parties)..."
            << std::endl;

  auto contexts = yacl::link::test::SetupWorld(world_size);
  std::vector<std::unique_ptr<EcMpcSystem>> mpc_systems(world_size);
  std::vector<std::thread> threads;

  auto ec_group_unique = yacl::crypto::EcGroupFactory::Instance().Create("secp256k1");
  std::shared_ptr<yacl::crypto::EcGroup> ec_group(ec_group_unique.release());

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
  
  std::cout << "  Sub (" << mode << ", " << world_size
            << " parties) test PASSED (opened value matches plaintext: "
            << (matches ? "YES" : "NO") << ")" << std::endl;
}

// Test MulScalar: k * [P] = [k*P]
void TestMulScalar(bool malicious_security, size_t world_size = 2) {
  std::string mode = malicious_security ? "Malicious" : "Semi-Honest";
  std::cout << "Testing MulScalar (" << mode << ", " << world_size
            << " parties)..." << std::endl;

  auto contexts = yacl::link::test::SetupWorld(world_size);
  std::vector<std::unique_ptr<EcMpcSystem>> mpc_systems(world_size);
  std::vector<std::thread> threads;

  auto ec_group_unique = yacl::crypto::EcGroupFactory::Instance().Create("secp256k1");
  std::shared_ptr<yacl::crypto::EcGroup> ec_group(ec_group_unique.release());

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
  
  std::cout << "  MulScalar (" << mode << ", " << world_size
            << " parties) test PASSED (opened value matches plaintext: "
            << (matches ? "YES" : "NO") << ")" << std::endl;
}

// Test Open and PartialOpen
void TestOpen(bool malicious_security, size_t world_size = 2) {
  std::string mode = malicious_security ? "Malicious" : "Semi-Honest";
  std::cout << "Testing Open (" << mode << ", " << world_size
            << " parties)..." << std::endl;

  auto contexts = yacl::link::test::SetupWorld(world_size);
  std::vector<std::unique_ptr<EcMpcSystem>> mpc_systems(world_size);
  std::vector<std::thread> threads;

  auto ec_group_unique = yacl::crypto::EcGroupFactory::Instance().Create("secp256k1");
  std::shared_ptr<yacl::crypto::EcGroup> ec_group(ec_group_unique.release());

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
    yacl::examples::pii::TestOpen(true, world_size);
    std::cout << std::endl;
  }

  std::cout << "=== All EC Group G MPC Tests PASSED ===" << std::endl;
  return 0;
}
