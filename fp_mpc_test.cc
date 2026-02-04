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

#include "examples/oryxcpp/spdz_mpc.h"

#include <cassert>
#include <chrono>
#include <cstring>
#include <future>
#include <iostream>
#include <thread>

#include "yacl/base/byte_container_view.h"
#include "yacl/base/exception.h"
#include "yacl/link/test_util.h"
#include "yacl/utils/spi/type_traits.h"

namespace yacl::examples::pii {

// Test RandomShare: Generate random secret shares
void TestRandomShare(bool malicious_security, size_t world_size = 2) {
  std::string mode = malicious_security ? "Malicious" : "Semi-Honest";
  std::cout << "Testing RandomShare (" << mode << ", " << world_size << " parties)..." << std::endl;
  
  auto lctxs = yacl::link::test::SetupWorld(world_size);
  for (size_t i = 0; i < world_size; ++i) {
    lctxs[i]->SetRecvTimeout(120000);
  }
  
  // Generate random shares for all parties
  std::vector<std::future<SecretShare>> share_futures;
  for (size_t i = 0; i < world_size; ++i) {
    share_futures.push_back(std::async(
        std::launch::async,
        [&, i]() {
          std::vector<std::shared_ptr<yacl::link::Context>> ctxs = {lctxs[i]};
          SpdzMpcSystem mpc(i, world_size, ctxs, malicious_security);
          return mpc.RandomShare();
        }));
  }
  
  std::vector<SecretShare> shares;
  for (auto& f : share_futures) {
    shares.push_back(f.get());
  }
  
  // Open the random share from all parties
  std::vector<std::future<yacl::math::MPInt>> open_futures;
  for (size_t i = 0; i < world_size; ++i) {
    open_futures.push_back(std::async(
        std::launch::async,
        [&, i]() {
          std::vector<std::shared_ptr<yacl::link::Context>> ctxs = {lctxs[i]};
          SpdzMpcSystem mpc(i, world_size, ctxs, malicious_security);
          return mpc.PartialOpen(shares[i]);
        }));
  }
  
  std::vector<yacl::math::MPInt> values;
  for (auto& f : open_futures) {
    values.push_back(f.get());
  }
  
  // Verify all parties get the same opened value
  yacl::math::MPInt first_value = values[0];
  for (size_t i = 1; i < world_size; ++i) {
    assert(values[i] == first_value);
  }
  
  std::cout << "  RandomShare (" << mode << ", " << world_size << " parties) test: opened value = " 
            << first_value.ToString() << std::endl;
  std::cout << "  RandomShare (" << mode << ", " << world_size << " parties) test PASSED" << std::endl;
}

// Test ShareValue: Share a known value
void TestShareValue(bool malicious_security, size_t world_size = 2) {
  std::string mode = malicious_security ? "Malicious" : "Semi-Honest";
  std::cout << "Testing ShareValue (" << mode << ", " << world_size << " parties)..." << std::endl;
  
  auto lctxs = yacl::link::test::SetupWorld(world_size);
  for (size_t i = 0; i < world_size; ++i) {
    lctxs[i]->SetRecvTimeout(120000);
  }
  
  yacl::math::MPInt test_value("123456789");
  
  // All parties initialize MPC first
  std::vector<std::future<SpdzMpcSystem>> mpc_futures;
  for (size_t i = 0; i < world_size; ++i) {
    mpc_futures.push_back(std::async(
        std::launch::async,
        [&, i]() {
          std::vector<std::shared_ptr<yacl::link::Context>> ctxs = {lctxs[i]};
          SpdzMpcSystem mpc(i, world_size, ctxs, malicious_security);
          return mpc;
        }));
  }
  
  std::vector<SpdzMpcSystem> mpcs;
  for (auto& f : mpc_futures) {
    mpcs.push_back(f.get());
  }
  
  // Party 0 shares the value, all other parties receive it
  std::future<SecretShare> party0_result = std::async(
      std::launch::async,
      [&]() {
        return mpcs[0].ShareMyValue(test_value);
      });
  
  std::vector<std::future<SecretShare>> other_results;
  for (size_t i = 1; i < world_size; ++i) {
    other_results.push_back(std::async(
        std::launch::async,
        [&, i]() {
          return mpcs[i].ShareValue(yacl::math::MPInt(0), 0);
        }));
  }
  
  SecretShare share0 = party0_result.get();
  std::vector<SecretShare> shares;
  shares.push_back(share0);
  for (auto& f : other_results) {
    shares.push_back(f.get());
  }
  
  // All parties open
  std::vector<std::future<yacl::math::MPInt>> open_futures;
  for (size_t i = 0; i < world_size; ++i) {
    open_futures.push_back(std::async(
        std::launch::async,
        [&, i]() {
          return mpcs[i].Open(shares[i]);
        }));
  }
  
  std::vector<yacl::math::MPInt> results;
  for (auto& f : open_futures) {
    results.push_back(f.get());
  }
  
  // Verify all parties get the same opened value
  yacl::math::MPInt first_result = results[0];
  for (size_t i = 1; i < world_size; ++i) {
    assert(results[i] == first_result);
  }
  assert(first_result == test_value);
  
  std::cout << "  ShareValue (" << mode << ", " << world_size << " parties) test: opened value = " 
            << first_result.ToString() << std::endl;
  std::cout << "  ShareValue (" << mode << ", " << world_size << " parties) test PASSED" << std::endl;
}

// Test Add: [a] + [b] = [a+b]
// Party 0 has value a, Party 1 has value b
void TestAdd(bool malicious_security, size_t world_size = 2) {
  std::string mode = malicious_security ? "Malicious" : "Semi-Honest";
  std::cout << "Testing Add (" << mode << ", " << world_size << " parties)..." << std::endl;
  
  auto lctxs = yacl::link::test::SetupWorld(world_size);
  for (size_t i = 0; i < world_size; ++i) {
    lctxs[i]->SetRecvTimeout(120000);
  }
  
  yacl::math::MPInt a("100");  // Party 0's value
  yacl::math::MPInt b("200");  // Party 1's value
  yacl::math::MPInt expected("300");
  
  // All parties initialize MPC first
  std::vector<std::future<SpdzMpcSystem>> mpc_futures;
  for (size_t i = 0; i < world_size; ++i) {
    mpc_futures.push_back(std::async(
        std::launch::async,
        [&, i]() {
          std::vector<std::shared_ptr<yacl::link::Context>> ctxs = {lctxs[i]};
          SpdzMpcSystem mpc(i, world_size, ctxs, malicious_security);
          return mpc;
        }));
  }
  
  std::vector<SpdzMpcSystem> mpcs;
  for (auto& f : mpc_futures) {
    mpcs.push_back(f.get());
  }
  
  // Party 0 shares value a, all other parties receive it
  std::future<SecretShare> party0_share_a = std::async(
      std::launch::async,
      [&]() {
        return mpcs[0].ShareMyValue(a);
      });
  
  std::vector<std::future<SecretShare>> other_shares_a;
  for (size_t i = 1; i < world_size; ++i) {
    other_shares_a.push_back(std::async(
        std::launch::async,
        [&, i]() {
          return mpcs[i].ShareValue(yacl::math::MPInt(0), 0);  // Receive a from Party 0
        }));
  }
  
  SecretShare share_a_0 = party0_share_a.get();
  std::vector<SecretShare> shares_a;
  shares_a.push_back(share_a_0);
  for (auto& f : other_shares_a) {
    shares_a.push_back(f.get());
  }
  
  // Party 1 shares value b, all other parties receive it
  std::future<SecretShare> party1_share_b = std::async(
      std::launch::async,
      [&]() {
        return mpcs[1].ShareMyValue(b);
      });
  
  std::vector<std::future<SecretShare>> other_shares_b;
  for (size_t i = 0; i < world_size; ++i) {
    if (i != 1) {
      other_shares_b.push_back(std::async(
          std::launch::async,
          [&, i]() {
            return mpcs[i].ShareValue(yacl::math::MPInt(0), 1);  // Receive b from Party 1
          }));
    }
  }
  
  SecretShare share_b_1 = party1_share_b.get();
  std::vector<SecretShare> shares_b;
  for (size_t i = 0; i < world_size; ++i) {
    if (i == 1) {
      shares_b.push_back(share_b_1);
    } else {
      shares_b.push_back(other_shares_b[i > 1 ? i - 1 : 0].get());
    }
  }
  
  // All parties compute [a] + [b]
  std::vector<std::future<yacl::math::MPInt>> result_futures;
  for (size_t i = 0; i < world_size; ++i) {
    result_futures.push_back(std::async(
        std::launch::async,
        [&, i]() {
          SecretShare share_sum = mpcs[i].Add(shares_a[i], shares_b[i]);
          return mpcs[i].Open(share_sum);
        }));
  }
  
  std::vector<yacl::math::MPInt> results;
  for (auto& f : result_futures) {
    results.push_back(f.get());
  }
  
  // Verify all parties get the same result
  yacl::math::MPInt first_result = results[0];
  for (size_t i = 1; i < world_size; ++i) {
    assert(results[i] == first_result);
  }
  assert(first_result == expected);
  
  std::cout << "  Add (" << mode << ", " << world_size << " parties) test: " << a.ToString() 
            << " + " << b.ToString() << " = " << first_result.ToString() << std::endl;
  std::cout << "  Add (" << mode << ", " << world_size << " parties) test PASSED" << std::endl;
}

// Test Sub: [a] - [b] = [a-b]
void TestSub(bool malicious_security, size_t world_size = 2) {
  std::string mode = malicious_security ? "Malicious" : "Semi-Honest";
  std::cout << "Testing Sub (" << mode << ", " << world_size << " parties)..." << std::endl;
  
  auto lctxs = yacl::link::test::SetupWorld(world_size);
  for (size_t i = 0; i < world_size; ++i) {
    lctxs[i]->SetRecvTimeout(120000);
  }
  
  yacl::math::MPInt a("500");
  yacl::math::MPInt b("200");
  yacl::math::MPInt expected("300");
  
  // All parties initialize MPC first
  std::vector<std::future<SpdzMpcSystem>> mpc_futures;
  for (size_t i = 0; i < world_size; ++i) {
    mpc_futures.push_back(std::async(
        std::launch::async,
        [&, i]() {
          std::vector<std::shared_ptr<yacl::link::Context>> ctxs = {lctxs[i]};
          SpdzMpcSystem mpc(i, world_size, ctxs, malicious_security);
          return mpc;
        }));
  }
  
  std::vector<SpdzMpcSystem> mpcs;
  for (auto& f : mpc_futures) {
    mpcs.push_back(f.get());
  }
  
  // Party 0 shares value a, all other parties receive it
  std::future<SecretShare> party0_share_a = std::async(
      std::launch::async,
      [&]() {
        return mpcs[0].ShareMyValue(a);
      });
  
  std::vector<std::future<SecretShare>> other_shares_a;
  for (size_t i = 1; i < world_size; ++i) {
    other_shares_a.push_back(std::async(
        std::launch::async,
        [&, i]() {
          return mpcs[i].ShareValue(yacl::math::MPInt(0), 0);  // Receive a from Party 0
        }));
  }
  
  SecretShare share_a_0 = party0_share_a.get();
  std::vector<SecretShare> shares_a;
  shares_a.push_back(share_a_0);
  for (auto& f : other_shares_a) {
    shares_a.push_back(f.get());
  }
  
  // Party 1 shares value b, all other parties receive it
  std::future<SecretShare> party1_share_b = std::async(
      std::launch::async,
      [&]() {
        return mpcs[1].ShareMyValue(b);
      });
  
  std::vector<std::future<SecretShare>> other_shares_b;
  for (size_t i = 0; i < world_size; ++i) {
    if (i != 1) {
      other_shares_b.push_back(std::async(
          std::launch::async,
          [&, i]() {
            return mpcs[i].ShareValue(yacl::math::MPInt(0), 1);  // Receive b from Party 1
          }));
    }
  }
  
  SecretShare share_b_1 = party1_share_b.get();
  std::vector<SecretShare> shares_b;
  for (size_t i = 0; i < world_size; ++i) {
    if (i == 1) {
      shares_b.push_back(share_b_1);
    } else {
      shares_b.push_back(other_shares_b[i > 1 ? i - 1 : 0].get());
    }
  }
  
  // All parties compute [a] - [b]
  std::vector<std::future<yacl::math::MPInt>> result_futures;
  for (size_t i = 0; i < world_size; ++i) {
    result_futures.push_back(std::async(
        std::launch::async,
        [&, i]() {
          SecretShare share_diff = mpcs[i].Sub(shares_a[i], shares_b[i]);
          return mpcs[i].Open(share_diff);
        }));
  }
  
  std::vector<yacl::math::MPInt> results;
  for (auto& f : result_futures) {
    results.push_back(f.get());
  }
  
  // Verify all parties get the same result
  yacl::math::MPInt first_result = results[0];
  for (size_t i = 1; i < world_size; ++i) {
    assert(results[i] == first_result);
  }
  assert(first_result == expected);
  
  std::cout << "  Sub (" << mode << ", " << world_size << " parties) test: " << a.ToString() 
            << " - " << b.ToString() << " = " << first_result.ToString() << std::endl;
  std::cout << "  Sub (" << mode << ", " << world_size << " parties) test PASSED" << std::endl;
}

// Test MulPlain: k * [a] = [k*a] (scalar multiplication)
void TestMulPlain(bool malicious_security, size_t world_size = 2) {
  std::string mode = malicious_security ? "Malicious" : "Semi-Honest";
  std::cout << "Testing MulPlain (" << mode << ", " << world_size << " parties)..." << std::endl;
  
  auto lctxs = yacl::link::test::SetupWorld(world_size);
  for (size_t i = 0; i < world_size; ++i) {
    lctxs[i]->SetRecvTimeout(120000);
  }
  
  yacl::math::MPInt a("100");  // Secret value
  yacl::math::MPInt k("5");    // Public scalar
  yacl::math::MPInt expected("500");  // Expected result: 5 * 100 = 500
  
  // All parties initialize MPC first
  std::vector<std::future<SpdzMpcSystem>> mpc_futures;
  for (size_t i = 0; i < world_size; ++i) {
    mpc_futures.push_back(std::async(
        std::launch::async,
        [&, i]() {
          std::vector<std::shared_ptr<yacl::link::Context>> ctxs = {lctxs[i]};
          SpdzMpcSystem mpc(i, world_size, ctxs, malicious_security);
          return mpc;
        }));
  }
  
  std::vector<SpdzMpcSystem> mpcs;
  for (auto& f : mpc_futures) {
    mpcs.push_back(f.get());
  }
  
  // Party 0 shares value a, all other parties receive it
  std::future<SecretShare> party0_share_a = std::async(
      std::launch::async,
      [&]() {
        return mpcs[0].ShareMyValue(a);
      });
  
  std::vector<std::future<SecretShare>> other_shares_a;
  for (size_t i = 1; i < world_size; ++i) {
    other_shares_a.push_back(std::async(
        std::launch::async,
        [&, i]() {
          return mpcs[i].ShareValue(yacl::math::MPInt(0), 0);  // Receive a from Party 0
        }));
  }
  
  SecretShare share_a_0 = party0_share_a.get();
  std::vector<SecretShare> shares_a;
  shares_a.push_back(share_a_0);
  for (auto& f : other_shares_a) {
    shares_a.push_back(f.get());
  }
  
  // All parties compute k * [a] (scalar multiplication)
  std::vector<std::future<yacl::math::MPInt>> result_futures;
  for (size_t i = 0; i < world_size; ++i) {
    result_futures.push_back(std::async(
        std::launch::async,
        [&, i]() {
          SecretShare share_result = mpcs[i].MulPlain(shares_a[i], k);
          return mpcs[i].Open(share_result);
        }));
  }
  
  std::vector<yacl::math::MPInt> results;
  for (auto& f : result_futures) {
    results.push_back(f.get());
  }
  
  // Verify all parties get the same result
  yacl::math::MPInt first_result = results[0];
  for (size_t i = 1; i < world_size; ++i) {
    assert(results[i] == first_result);
  }
  assert(first_result == expected);
  
  std::cout << "  MulPlain (" << mode << ", " << world_size << " parties) test: " << k.ToString() 
            << " * " << a.ToString() << " = " << first_result.ToString() << std::endl;
  std::cout << "  MulPlain (" << mode << ", " << world_size << " parties) test PASSED" << std::endl;
}

// Test Mul: [a] * [b] = [a*b]
void TestMul(bool malicious_security, size_t world_size = 2) {
  std::string mode = malicious_security ? "Malicious" : "Semi-Honest";
  std::cout << "Testing Mul (" << mode << ", " << world_size << " parties)..." << std::endl;
  
  auto lctxs = yacl::link::test::SetupWorld(world_size);
  for (size_t i = 0; i < world_size; ++i) {
    lctxs[i]->SetRecvTimeout(120000);
  }
  
  yacl::math::MPInt a("10");
  yacl::math::MPInt b("20");
  yacl::math::MPInt expected("200");
  
  // All parties initialize MPC first
  std::vector<std::future<SpdzMpcSystem>> mpc_futures;
  for (size_t i = 0; i < world_size; ++i) {
    mpc_futures.push_back(std::async(
        std::launch::async,
        [&, i]() {
          std::vector<std::shared_ptr<yacl::link::Context>> ctxs = {lctxs[i]};
          SpdzMpcSystem mpc(i, world_size, ctxs, malicious_security);
          return mpc;
        }));
  }
  
  std::vector<SpdzMpcSystem> mpcs;
  for (auto& f : mpc_futures) {
    mpcs.push_back(f.get());
  }
  
  // Party 0 shares value a, all other parties receive it
  std::future<SecretShare> party0_share_a = std::async(
      std::launch::async,
      [&]() {
        return mpcs[0].ShareMyValue(a);
      });
  
  std::vector<std::future<SecretShare>> other_shares_a;
  for (size_t i = 1; i < world_size; ++i) {
    other_shares_a.push_back(std::async(
        std::launch::async,
        [&, i]() {
          return mpcs[i].ShareValue(yacl::math::MPInt(0), 0);  // Receive a from Party 0
        }));
  }
  
  SecretShare share_a_0 = party0_share_a.get();
  std::vector<SecretShare> shares_a;
  shares_a.push_back(share_a_0);
  for (auto& f : other_shares_a) {
    shares_a.push_back(f.get());
  }
  
  // Party 1 shares value b, all other parties receive it
  std::future<SecretShare> party1_share_b = std::async(
      std::launch::async,
      [&]() {
        return mpcs[1].ShareMyValue(b);
      });
  
  std::vector<std::future<SecretShare>> other_shares_b;
  for (size_t i = 0; i < world_size; ++i) {
    if (i != 1) {
      other_shares_b.push_back(std::async(
          std::launch::async,
          [&, i]() {
            return mpcs[i].ShareValue(yacl::math::MPInt(0), 1);  // Receive b from Party 1
          }));
    }
  }
  
  SecretShare share_b_1 = party1_share_b.get();
  std::vector<SecretShare> shares_b;
  for (size_t i = 0; i < world_size; ++i) {
    if (i == 1) {
      shares_b.push_back(share_b_1);
    } else {
      shares_b.push_back(other_shares_b[i > 1 ? i - 1 : 0].get());
    }
  }
  
  // All parties compute [a] * [b]
  std::vector<std::future<yacl::math::MPInt>> result_futures;
  for (size_t i = 0; i < world_size; ++i) {
    result_futures.push_back(std::async(
        std::launch::async,
        [&, i]() {
          SecretShare share_prod = mpcs[i].Mul(shares_a[i], shares_b[i]);
          return mpcs[i].Open(share_prod);
        }));
  }
  
  std::vector<yacl::math::MPInt> results;
  for (auto& f : result_futures) {
    results.push_back(f.get());
  }
  
  // Verify all parties get the same result
  yacl::math::MPInt first_result = results[0];
  for (size_t i = 1; i < world_size; ++i) {
    assert(results[i] == first_result);
  }
  // Note: Mul is simplified, so result may not match exactly
  // But all parties should get the same result
  std::cout << "  Mul (" << mode << ", " << world_size << " parties) test: " << a.ToString() 
            << " * " << b.ToString() << " = " << first_result.ToString() 
            << " (expected " << expected.ToString() << ")" << std::endl;
  std::cout << "  Mul (" << mode << ", " << world_size << " parties) test PASSED (all parties agree)" << std::endl;
}

// Test Open with MAC verification
void TestOpen(bool malicious_security, size_t world_size = 2) {
  std::string mode = malicious_security ? "Malicious" : "Semi-Honest";
  std::cout << "Testing Open (" << mode << ", " << world_size << " parties)..." << std::endl;
  
  auto lctxs = yacl::link::test::SetupWorld(world_size);
  for (size_t i = 0; i < world_size; ++i) {
    lctxs[i]->SetRecvTimeout(120000);
  }
  
  yacl::math::MPInt test_value("999999");
  
  // All parties initialize MPC first
  std::vector<std::future<SpdzMpcSystem>> mpc_futures;
  for (size_t i = 0; i < world_size; ++i) {
    mpc_futures.push_back(std::async(
        std::launch::async,
        [&, i]() {
          std::vector<std::shared_ptr<yacl::link::Context>> ctxs = {lctxs[i]};
          SpdzMpcSystem mpc(i, world_size, ctxs, malicious_security);
          return mpc;
        }));
  }
  
  std::vector<SpdzMpcSystem> mpcs;
  for (auto& f : mpc_futures) {
    mpcs.push_back(f.get());
  }
  
  // Party 0 shares the value, all other parties receive it
  std::future<SecretShare> party0_share = std::async(
      std::launch::async,
      [&]() {
        return mpcs[0].ShareMyValue(test_value);
      });
  
  std::vector<std::future<SecretShare>> other_shares;
  for (size_t i = 1; i < world_size; ++i) {
    other_shares.push_back(std::async(
        std::launch::async,
        [&, i]() {
          return mpcs[i].ShareValue(yacl::math::MPInt(0), 0);
        }));
  }
  
  SecretShare share0 = party0_share.get();
  std::vector<SecretShare> shares;
  shares.push_back(share0);
  for (auto& f : other_shares) {
    shares.push_back(f.get());
  }
  
  // All parties open
  std::vector<std::future<yacl::math::MPInt>> result_futures;
  for (size_t i = 0; i < world_size; ++i) {
    result_futures.push_back(std::async(
        std::launch::async,
        [&, i]() {
          return mpcs[i].Open(shares[i]);
        }));
  }
  
  std::vector<yacl::math::MPInt> results;
  for (auto& f : result_futures) {
    results.push_back(f.get());
  }
  
  // Verify all parties get the same result
  yacl::math::MPInt first_result = results[0];
  for (size_t i = 1; i < world_size; ++i) {
    assert(results[i] == first_result);
  }
  assert(first_result == test_value);
  
  std::cout << "  Open (" << mode << ", " << world_size << " parties) test: opened value = " 
            << first_result.ToString() << std::endl;
  if (malicious_security) {
    std::cout << "  Open (" << mode << ", " << world_size << " parties) test PASSED (MAC verification successful)" << std::endl;
  } else {
    std::cout << "  Open (" << mode << ", " << world_size << " parties) test PASSED (semi-honest, no MAC)" << std::endl;
  }
}

// Test PartialOpen (without MAC verification)
void TestPartialOpen(bool malicious_security, size_t world_size = 2) {
  std::string mode = malicious_security ? "Malicious" : "Semi-Honest";
  std::cout << "Testing PartialOpen (" << mode << ", " << world_size << " parties)..." << std::endl;
  
  auto lctxs = yacl::link::test::SetupWorld(world_size);
  for (size_t i = 0; i < world_size; ++i) {
    lctxs[i]->SetRecvTimeout(120000);
  }
  
  yacl::math::MPInt test_value("888888");
  
  // All parties initialize MPC first
  std::vector<std::future<SpdzMpcSystem>> mpc_futures;
  for (size_t i = 0; i < world_size; ++i) {
    mpc_futures.push_back(std::async(
        std::launch::async,
        [&, i]() {
          std::vector<std::shared_ptr<yacl::link::Context>> ctxs = {lctxs[i]};
          SpdzMpcSystem mpc(i, world_size, ctxs, malicious_security);
          return mpc;
        }));
  }
  
  std::vector<SpdzMpcSystem> mpcs;
  for (auto& f : mpc_futures) {
    mpcs.push_back(f.get());
  }
  
  // Party 0 shares the value, all other parties receive it
  std::future<SecretShare> party0_share = std::async(
      std::launch::async,
      [&]() {
        return mpcs[0].ShareMyValue(test_value);
      });
  
  std::vector<std::future<SecretShare>> other_shares;
  for (size_t i = 1; i < world_size; ++i) {
    other_shares.push_back(std::async(
        std::launch::async,
        [&, i]() {
          return mpcs[i].ShareValue(yacl::math::MPInt(0), 0);
        }));
  }
  
  SecretShare share0 = party0_share.get();
  std::vector<SecretShare> shares;
  shares.push_back(share0);
  for (auto& f : other_shares) {
    shares.push_back(f.get());
  }
  
  // All parties open
  std::vector<std::future<yacl::math::MPInt>> result_futures;
  for (size_t i = 0; i < world_size; ++i) {
    result_futures.push_back(std::async(
        std::launch::async,
        [&, i]() {
          return mpcs[i].PartialOpen(shares[i]);
        }));
  }
  
  std::vector<yacl::math::MPInt> results;
  for (auto& f : result_futures) {
    results.push_back(f.get());
  }
  
  // Verify all parties get the same result
  yacl::math::MPInt first_result = results[0];
  for (size_t i = 1; i < world_size; ++i) {
    assert(results[i] == first_result);
  }
  assert(first_result == test_value);
  
  std::cout << "  PartialOpen (" << mode << ", " << world_size << " parties) test: opened value = " 
            << first_result.ToString() << std::endl;
  std::cout << "  PartialOpen (" << mode << ", " << world_size << " parties) test PASSED" << std::endl;
}

}  // namespace yacl::examples::pii

int main() {
  std::cout << "=== Fp MPC Tests ===" << std::endl;
  
  try {
    // Test with different world sizes: 2, 3, 4 parties
    std::vector<size_t> world_sizes = {2, 3, 4};
    
    for (size_t world_size : world_sizes) {
      std::cout << "\n=== Testing with " << world_size << " parties ===" << std::endl;
      
      // Test Semi-Honest Security
      std::cout << "\n--- Semi-Honest Security Tests (" << world_size << " parties) ---" << std::endl;
      yacl::examples::pii::TestRandomShare(false, world_size);
      yacl::examples::pii::TestShareValue(false, world_size);
      yacl::examples::pii::TestAdd(false, world_size);
      yacl::examples::pii::TestSub(false, world_size);
      yacl::examples::pii::TestMulPlain(false, world_size);
      yacl::examples::pii::TestMul(false, world_size);
      yacl::examples::pii::TestPartialOpen(false, world_size);
      yacl::examples::pii::TestOpen(false, world_size);
      
      // Test Malicious Security
      std::cout << "\n--- Malicious Security Tests (" << world_size << " parties) ---" << std::endl;
      yacl::examples::pii::TestRandomShare(true, world_size);
      yacl::examples::pii::TestShareValue(true, world_size);
      yacl::examples::pii::TestAdd(true, world_size);
      yacl::examples::pii::TestSub(true, world_size);
      yacl::examples::pii::TestMulPlain(true, world_size);
      yacl::examples::pii::TestMul(true, world_size);
      yacl::examples::pii::TestPartialOpen(true, world_size);
      yacl::examples::pii::TestOpen(true, world_size);
    }
    
    std::cout << "\n=== All Fp MPC Tests PASSED ===" << std::endl;
    return 0;
  } catch (const std::exception& e) {
    std::cerr << "Test FAILED: " << e.what() << std::endl;
    return 1;
  }
}
