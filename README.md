# Multi-Party Computation (MPC) Library

This directory contains a comprehensive MPC library implementation supporting secure computation over multiple algebraic structures:

- **F_p**: Finite prime field arithmetic
- **G1**: Elliptic curve group G1 (from bilinear pairing groups)
- **G2**: Elliptic curve group G2 (from bilinear pairing groups)
- **GT**: Target group of bilinear pairing (multiplicative group)
- **Pairing**: Secure pairing computation protocols

## Overview

This MPC library implements SPDZ-style secure multi-party computation protocols with support for:

- **Additive Secret Sharing**: Secret values are shared additively across parties
- **Malicious Security**: Message Authentication Codes (MAC) for security against malicious adversaries
- **Semi-Honest Security**: Efficient protocols for semi-honest security model
- **N-Party Support**: Extends naturally from 2-party to N-party settings
- **Bilinear Pairing**: Secure computation of pairings e([P], Q), e(P, [Q]), and e([P], [Q])

## Implementation Details

### F_p MPC (`spdz_mpc.h`, `spdz_mpc.cc`)

Finite prime field arithmetic with the following operations:
- `RandomShare()`: Generate a random secret-shared value
- `ShareValue()`: Share a value from a specific party
- `ShareMyValue()`: Share my own value
- `Add()`: Secure addition of two secret shares
- `Sub()`: Secure subtraction of two secret shares
- `Mul()`: Secure multiplication using Beaver triples
- `MulPlain()`: Multiply a secret share by a public plaintext value
- `Open()`: Open a secret share (with MAC verification in malicious mode)
- `PartialOpen()`: Partially open a secret share (without MAC verification)

### G1/G2 MPC (`ec_mpc.h`, `ec_mpc.cc`)

Elliptic curve point operations over groups G1 and G2:
- `RandomShare()`: Generate a random secret-shared point
- `ShareValue()`: Share a point from a specific party
- `ShareMyValue()`: Share my own point
- `Add()`: Secure point addition
- `Sub()`: Secure point subtraction
- `MulScalar()`: Multiply a secret-shared point by a public scalar
- `MulSecretScalar()`: Multiply a secret-shared point by a secret-shared scalar [k] * [P]
- `Open()`: Open a secret-shared point (with MAC verification in malicious mode)
- `PartialOpen()`: Partially open a secret-shared point

### GT MPC (`pairing_mpc.h`, `pairing_mpc.cc`)

Multiplicative group operations in the target group GT:
- `RandomShareGT()`: Generate a random secret-shared GT element
- `ShareValueGT()`: Share a GT element from a specific party
- `ShareMyValueGT()`: Share my own GT element
- `MulGT()`: Secure multiplication of two GT element shares
- `DivGT()`: Secure division of two GT element shares
- `PowGT()`: Secure exponentiation of a GT element share
- `OpenGT()`: Open a secret-shared GT element (with MAC verification in malicious mode)
- `PartialOpenGT()`: Partially open a secret-shared GT element

### Secure Pairing Protocols

Three secure pairing protocols are implemented:

1. **SecPair1: e([P], Q)**
   - Computes pairing where P ∈ G1 is secret-shared and Q ∈ G2 is public
   - Each party computes e(P_i, Q) locally, exchanges values, multiplies, then shares the result

2. **SecPair2: e(P, [Q])**
   - Computes pairing where P ∈ G1 is public and Q ∈ G2 is secret-shared
   - Each party computes e(P, Q_i) locally, exchanges values, multiplies, then shares the result

3. **SecPair3: e([P], [Q])**
   - Computes pairing where both P ∈ G1 and Q ∈ G2 are secret-shared
   - Uses Beaver triples over F_p and secure scalar-point multiplication

## Building

```bash
cd /home/lgw/yacl
bazel build //examples/oryxcpp:fp_mpc_test
bazel build //examples/oryxcpp:ec_mpc_test
bazel build //examples/oryxcpp:pairing_mpc_test
```

## Running Tests

### F_p MPC Tests
```bash
cd /home/lgw/yacl
bazel-bin/examples/oryxcpp/fp_mpc_test
```

Tests cover:
- Random share generation
- Value sharing
- Addition, subtraction, multiplication
- Plaintext multiplication
- Opening and partial opening
- Support for 2, 3, and 4 parties
- Both semi-honest and malicious security modes

### EC MPC Tests (G1/G2)
```bash
cd /home/lgw/yacl
bazel-bin/examples/oryxcpp/ec_mpc_test
```

Tests cover:
- Random point sharing
- Point sharing
- Point addition and subtraction
- Scalar multiplication (public and secret scalars)
- Opening and partial opening
- Support for 2, 3, and 4 parties
- Both semi-honest and malicious security modes

### Pairing MPC Tests
```bash
cd /home/lgw/yacl
bazel-bin/examples/oryxcpp/pairing_mpc_test
```

Tests cover:
- G1 operations (random share, addition)
- G2 operations (random share, addition)
- GT operations (random share, multiplication)
- Secure pairing protocols (SecPair1, SecPair2, SecPair3)
- Support for 2, 3, and 4 parties
- Both semi-honest and malicious security modes

## Usage Example

### F_p MPC
```cpp
#include "examples/oryxcpp/spdz_mpc.h"

// Setup network for 3 parties
auto lctxs = yacl::link::test::SetupWorld(3);
yacl::math::MPInt prime("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F");

// Create MPC systems
std::vector<std::unique_ptr<yacl::examples::pii::SpdzMpcSystem>> mpc_systems;
for (size_t i = 0; i < 3; ++i) {
  mpc_systems.push_back(std::make_unique<yacl::examples::pii::SpdzMpcSystem>(
      i, 3, lctxs, true, &prime));  // malicious_security = true
}

// Share a value
yacl::math::MPInt value(12345);
auto share0 = mpc_systems[0]->ShareMyValue(value);
auto share1 = mpc_systems[1]->ShareValue(yacl::math::MPInt(0), 0);
auto share2 = mpc_systems[2]->ShareValue(yacl::math::MPInt(0), 0);

// Add two shares
auto sum_share = mpc_systems[0]->Add(share0, share1);

// Open the result
auto result = mpc_systems[0]->Open(sum_share);
```

### EC MPC (G1/G2)
```cpp
#include "examples/oryxcpp/ec_mpc.h"

// Setup EC group
auto ec_group = yacl::crypto::EcGroup::Create("sm2", yacl::ArgLib = "mcl");

// Create MPC systems
std::vector<std::unique_ptr<yacl::examples::pii::EcMpcSystem>> mpc_systems;
for (size_t i = 0; i < 2; ++i) {
  mpc_systems.push_back(std::make_unique<yacl::examples::pii::EcMpcSystem>(
      i, 2, lctxs, ec_group, true));  // malicious_security = true
}

// Share a point
yacl::crypto::EcPoint point = ec_group->GetGenerator();
auto share0 = mpc_systems[0]->ShareMyValue(point);
auto share1 = mpc_systems[1]->ShareValue(ec_group->GetInfinity(), 0);

// Add two point shares
auto sum_share = mpc_systems[0]->Add(share0, share1);

// Open the result
auto result = mpc_systems[0]->Open(sum_share);
```

### Pairing MPC
```cpp
#include "examples/oryxcpp/pairing_mpc.h"

// Setup pairing group
auto pairing_group = yacl::crypto::MclPGFactory::CreateByName("bls12-381");

// Create MPC systems
std::vector<std::unique_ptr<yacl::examples::pii::PairingMpcSystem>> mpc_systems;
for (size_t i = 0; i < 2; ++i) {
  mpc_systems.push_back(std::make_unique<yacl::examples::pii::PairingMpcSystem>(
      i, 2, lctxs, pairing_group, true));  // malicious_security = true
}

// Share a G1 point
auto g1_point = pairing_group->GetGroup1()->GetGenerator();
auto g1_share0 = mpc_systems[0]->ShareMyValueG1(g1_point);
auto g1_share1 = mpc_systems[1]->ShareValueG1(pairing_group->GetGroup1()->GetInfinity(), 0);

// Share a G2 point
auto g2_point = pairing_group->GetGroup2()->GetGenerator();
auto g2_share0 = mpc_systems[0]->ShareMyValueG2(g2_point);
auto g2_share1 = mpc_systems[1]->ShareValueG2(pairing_group->GetGroup2()->GetInfinity(), 0);

// Compute secure pairing e([P], Q) where P is secret-shared in G1, Q is public in G2
auto gt_share = mpc_systems[0]->PairingSecretG1(g1_share0, g2_point);

// Open the result
auto result = mpc_systems[0]->OpenGT(gt_share);
```

## Architecture

### Core Components

- **`spdz_mpc.h/cc`**: SPDZ-style MPC for finite prime field F_p
- **`ec_mpc.h/cc`**: MPC for elliptic curve groups G1 and G2
- **`pairing_mpc.h/cc`**: MPC for bilinear pairing groups (G1, G2, GT) and secure pairing protocols

### Test Files

- **`fp_mpc_test.cc`**: Comprehensive tests for F_p MPC operations
- **`ec_mpc_test.cc`**: Comprehensive tests for EC MPC operations
- **`pairing_mpc_test.cc`**: Comprehensive tests for pairing MPC operations

## Security Models

### Semi-Honest Security
- Parties follow the protocol but may try to learn information from messages
- More efficient, suitable for trusted environments
- No MAC verification required

### Malicious Security
- Parties may deviate arbitrarily from the protocol
- Uses Message Authentication Codes (MAC) to detect cheating
- More expensive but provides stronger security guarantees

## Features

- ✅ N-party support (tested with 2, 3, and 4 parties)
- ✅ Both semi-honest and malicious security modes
- ✅ Beaver triple generation for secure multiplication
- ✅ MAC-based verification for malicious security
- ✅ Secret scalar-secret point multiplication [k] * [P]
- ✅ Secure pairing protocols for all three cases
- ✅ Comprehensive test coverage

## References

- SPDZ Protocol: "Multiparty computation from somewhat homomorphic encryption" (Crypto 2012)
- Bilinear Pairings: "Pairings for cryptographers" (Discrete Applied Mathematics, 2006)
- Secure Pairing Computation: Based on bilinearity property e(P + Q, R) = e(P, R) * e(Q, R)
