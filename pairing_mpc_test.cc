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

#include <iostream>
#include <thread>
#include <vector>

#include "examples/oryxcpp/spdz_mpc.h"
#include "yacl/base/exception.h"
#include "yacl/crypto/pairing/factory/mcl_pairing_group.h"
#include "yacl/crypto/pairing/pairing.h"
#include "yacl/link/test_util.h"

namespace yacl::examples::pii {

// Test RandomShare for G1
void TestRandomShareG1(bool malicious_security, size_t world_size = 2) {
  std::string mode = malicious_security ? "Malicious" : "Semi-Honest";
  std::cout << "Testing RandomShare G1 (" << mode << ", " << world_size
            << " parties)..." << std::endl;

  auto contexts = yacl::link::test::SetupWorld(world_size);
  std::vector<std::unique_ptr<PairingMpcSystem>> mpc_systems(world_size);
  std::vector<std::thread> threads;

  // Create pairing group (use BLS12_381 as example)
  // Use MclPGFactory directly to avoid library registration issues
  auto pairing_group = yacl::crypto::MclPGFactory::CreateByName("bls12-381");
  std::shared_ptr<yacl::crypto::PairingGroup> pairing_group_shared(
      pairing_group.release());

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

  // All parties should get the same opened value
  for (size_t i = 1; i < world_size; ++i) {
    YACL_ENFORCE(g1->PointEqual(opened_values[0], opened_values[i]),
                 "RandomShare G1 test failed: parties disagree");
  }

  std::cout << "  RandomShare G1 (" << mode << ", " << world_size
            << " parties) test PASSED" << std::endl;
}

// Test Add for G1
void TestAddG1(bool malicious_security, size_t world_size = 2) {
  std::string mode = malicious_security ? "Malicious" : "Semi-Honest";
  std::cout << "Testing Add G1 (" << mode << ", " << world_size
            << " parties)..." << std::endl;

  auto contexts = yacl::link::test::SetupWorld(world_size);
  std::vector<std::unique_ptr<PairingMpcSystem>> mpc_systems(world_size);
  std::vector<std::thread> threads;

  // Use MclPGFactory directly to avoid library registration issues
  auto pairing_group = yacl::crypto::MclPGFactory::CreateByName("bls12-381");
  std::shared_ptr<yacl::crypto::PairingGroup> pairing_group_shared(
      pairing_group.release());
  auto g1 = pairing_group_shared->GetGroup1();

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

  std::cout << "  Add G1 (" << mode << ", " << world_size
            << " parties) test PASSED (opened value matches plaintext: "
            << (matches ? "YES" : "NO") << ")" << std::endl;
}

// Test RandomShare for G2
void TestRandomShareG2(bool malicious_security, size_t world_size = 2) {
  std::string mode = malicious_security ? "Malicious" : "Semi-Honest";
  std::cout << "Testing RandomShare G2 (" << mode << ", " << world_size
            << " parties)..." << std::endl;

  auto contexts = yacl::link::test::SetupWorld(world_size);
  std::vector<std::unique_ptr<PairingMpcSystem>> mpc_systems(world_size);
  std::vector<std::thread> threads;

  // Create pairing group (use BLS12_381 as example)
  auto pairing_group = yacl::crypto::MclPGFactory::CreateByName("bls12-381");
  std::shared_ptr<yacl::crypto::PairingGroup> pairing_group_shared(
      pairing_group.release());

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

  std::cout << "  RandomShare G2 (" << mode << ", " << world_size
            << " parties) test PASSED" << std::endl;
}

// Test Add for G2
void TestAddG2(bool malicious_security, size_t world_size = 2) {
  std::string mode = malicious_security ? "Malicious" : "Semi-Honest";
  std::cout << "Testing Add G2 (" << mode << ", " << world_size
            << " parties)..." << std::endl;

  auto contexts = yacl::link::test::SetupWorld(world_size);
  std::vector<std::unique_ptr<PairingMpcSystem>> mpc_systems(world_size);
  std::vector<std::thread> threads;

  // Use MclPGFactory directly to avoid library registration issues
  auto pairing_group = yacl::crypto::MclPGFactory::CreateByName("bls12-381");
  std::shared_ptr<yacl::crypto::PairingGroup> pairing_group_shared(
      pairing_group.release());
  auto g2 = pairing_group_shared->GetGroup2();

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

  // Verify: opened result matches plaintext computation
  bool matches = g2->PointEqual(results[0], expected);
  YACL_ENFORCE(matches, "Add G2 test failed: MPC result != plaintext computation");

  std::cout << "  Add G2 (" << mode << ", " << world_size
            << " parties) test PASSED (opened value matches plaintext: "
            << (matches ? "YES" : "NO") << ")" << std::endl;
}

// Test Mul for GT
void TestMulGT(bool malicious_security, size_t world_size = 2) {
  std::string mode = malicious_security ? "Malicious" : "Semi-Honest";
  std::cout << "Testing Mul GT (" << mode << ", " << world_size
            << " parties)..." << std::endl;

  auto contexts = yacl::link::test::SetupWorld(world_size);
  std::vector<std::unique_ptr<PairingMpcSystem>> mpc_systems(world_size);
  std::vector<std::thread> threads;

  // Use MclPGFactory directly to avoid library registration issues
  auto pairing_group = yacl::crypto::MclPGFactory::CreateByName("bls12-381");
  std::shared_ptr<yacl::crypto::PairingGroup> pairing_group_shared(
      pairing_group.release());
  auto gt = pairing_group_shared->GetGroupT();

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

  // Verify: opened result matches plaintext computation
  bool matches = gt->Equal(results[0], expected);
  YACL_ENFORCE(matches, "Mul GT test failed: MPC result != plaintext computation");

  std::cout << "  Mul GT (" << mode << ", " << world_size
            << " parties) test PASSED (opened value matches plaintext: "
            << (matches ? "YES" : "NO") << ")" << std::endl;
}

// Test SecPair1: e([P], Q) where [P] ∈ G1 is secret-shared, Q ∈ G2 is public
void TestPairingSecretG1(bool malicious_security, size_t world_size = 2) {
  std::string mode = malicious_security ? "Malicious" : "Semi-Honest";
  std::cout << "Testing SecPair1 e([P], Q) (" << mode << ", " << world_size
            << " parties)..." << std::endl;

  auto contexts = yacl::link::test::SetupWorld(world_size);
  std::vector<std::unique_ptr<PairingMpcSystem>> mpc_systems(world_size);
  std::vector<std::thread> threads;

  auto pairing_group = yacl::crypto::MclPGFactory::CreateByName("bls12-381");
  std::shared_ptr<yacl::crypto::PairingGroup> pairing_group_shared(
      pairing_group.release());
  auto g1 = pairing_group_shared->GetGroup1();
  auto g2 = pairing_group_shared->GetGroup2();
  auto gt = pairing_group_shared->GetGroupT();

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

  bool matches = gt->Equal(results[0], expected);
  YACL_ENFORCE(matches, "SecPair1 test failed: MPC result != plaintext computation");

  std::cout << "  SecPair1 e([P], Q) (" << mode << ", " << world_size
            << " parties) test PASSED (opened value matches plaintext: "
            << (matches ? "YES" : "NO") << ")" << std::endl;
}

// Test SecPair2: e(P, [Q]) where P ∈ G1 is public, [Q] ∈ G2 is secret-shared
void TestPairingSecretG2(bool malicious_security, size_t world_size = 2) {
  std::string mode = malicious_security ? "Malicious" : "Semi-Honest";
  std::cout << "Testing SecPair2 e(P, [Q]) (" << mode << ", " << world_size
            << " parties)..." << std::endl;

  auto contexts = yacl::link::test::SetupWorld(world_size);
  std::vector<std::unique_ptr<PairingMpcSystem>> mpc_systems(world_size);
  std::vector<std::thread> threads;

  auto pairing_group = yacl::crypto::MclPGFactory::CreateByName("bls12-381");
  std::shared_ptr<yacl::crypto::PairingGroup> pairing_group_shared(
      pairing_group.release());
  auto g1 = pairing_group_shared->GetGroup1();
  auto g2 = pairing_group_shared->GetGroup2();
  auto gt = pairing_group_shared->GetGroupT();

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
            << " parties) test PASSED (opened value matches plaintext: "
            << (matches ? "YES" : "NO") << ")" << std::endl;
}

// Test SecPair3: e([P], [Q]) where both [P] ∈ G1 and [Q] ∈ G2 are secret-shared
void TestPairingSecret(bool malicious_security, size_t world_size = 2) {
  std::string mode = malicious_security ? "Malicious" : "Semi-Honest";
  std::cout << "Testing SecPair3 e([P], [Q]) (" << mode << ", " << world_size
            << " parties)..." << std::endl;

  auto contexts = yacl::link::test::SetupWorld(world_size);
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

  bool matches = gt->Equal(results[0], expected);
  YACL_ENFORCE(matches, "SecPair3 test failed: MPC result != plaintext computation");

  std::cout << "  SecPair3 e([P], [Q]) (" << mode << ", " << world_size
            << " parties) test PASSED (opened value matches plaintext: "
            << (matches ? "YES" : "NO") << ")" << std::endl;
}

}  // namespace yacl::examples::pii

int main() {
  std::cout << "=== Bilinear Pairing Groups MPC Tests ===" << std::endl;
  std::cout << std::endl;

  // Test with different world sizes
  std::vector<size_t> world_sizes = {2, 3, 4};

  for (size_t world_size : world_sizes) {
    std::cout << "=== Testing with " << world_size << " parties ===" << std::endl;
    std::cout << std::endl;

    // Semi-Honest Security Tests
    std::cout << "--- Semi-Honest Security Tests (" << world_size
              << " parties) ---" << std::endl;
    yacl::examples::pii::TestRandomShareG1(false, world_size);
    yacl::examples::pii::TestAddG1(false, world_size);
    yacl::examples::pii::TestRandomShareG2(false, world_size);
    yacl::examples::pii::TestAddG2(false, world_size);
    yacl::examples::pii::TestMulGT(false, world_size);
    yacl::examples::pii::TestPairingSecretG1(false, world_size);
    yacl::examples::pii::TestPairingSecretG2(false, world_size);
    yacl::examples::pii::TestPairingSecret(false, world_size);
    std::cout << std::endl;

    // Malicious Security Tests
    std::cout << "--- Malicious Security Tests (" << world_size
              << " parties) ---" << std::endl;
    yacl::examples::pii::TestRandomShareG1(true, world_size);
    yacl::examples::pii::TestAddG1(true, world_size);
    yacl::examples::pii::TestRandomShareG2(true, world_size);
    yacl::examples::pii::TestAddG2(true, world_size);
    yacl::examples::pii::TestMulGT(true, world_size);
    yacl::examples::pii::TestPairingSecretG1(true, world_size);
    yacl::examples::pii::TestPairingSecretG2(true, world_size);
    yacl::examples::pii::TestPairingSecret(true, world_size);
    std::cout << std::endl;
  }

  std::cout << "=== All Bilinear Pairing Groups MPC Tests PASSED ===" << std::endl;
  return 0;
}
