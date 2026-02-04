# Private Identity Intersection (PII) Implementation

This directory contains an implementation of the Private Identity Intersection (PII) protocol based on the paper:

**"Privacy-Preserving Authorized Set Matching via Dishonest Majority Multiparty Computation"**
by Guowei Ling, Peng Tang, Fei Tang, et al. (IEEE TDSC 2025)

## Overview

PII is an extension of Private Set Intersection (PSI) that provides:
- **Input Authenticity**: Verifies that each input identifier is authorized via digital signatures
- **Output Integrity**: Ensures the complete intersection is outputted to all parties
- **Multi-party Support**: Naturally extends from two-party to multi-party settings
- **Collusion Resistance**: Resistant to collusion attacks

## Protocol Description

PII takes as input:
- Each party has a set of `(identifier, message, signature)` tuples
- The identifier can be a public key, email address, phone number, etc.
- The message is a payload attached to the identifier
- The signature verifies the authenticity of the identifier

PII outputs:
- The intersection of identifiers that pass verification from all parties
- Verification results for each input

## Implementation Status

### Completed
- ✅ Basic two-party PII protocol structure
- ✅ Signature verification framework (simplified for demo)
- ✅ Input serialization/deserialization
- ✅ Intersection computation
- ✅ Multi-party PII protocol skeleton

### TODO
- ⏳ Full ECDSA signature verification (currently uses hash-based demo)
- ⏳ AIBS (Anonymous Identity-Based Signature) support
- ⏳ Output integrity verification mechanism
- ⏳ Secure PSI integration (currently uses simple set intersection)
- ⏳ Performance optimizations

## Building

```bash
cd /home/lgw/yacl
bazel build //examples/oryxcpp:pii_demo
```

## Running

```bash
cd /home/lgw/yacl
bazel-bin/examples/oryxcpp/pii_demo
```

## Usage Example

```cpp
#include "examples/oryxcpp/pii.h"

// Setup network
auto lctxs = yacl::link::test::SetupWorld(2);

// Prepare inputs
std::vector<yacl::examples::pii::PiiInput> party0_inputs = {
    {"alice@example.com", "claim1", signature1},
    {"bob@example.com", "claim2", signature2},
};

std::vector<yacl::examples::pii::PiiInput> party1_inputs = {
    {"bob@example.com", "claim2", signature2},
    {"charlie@example.com", "claim3", signature3},
};

// Run PII protocol
auto result0 = yacl::examples::pii::Pii2Party(
    lctxs[0], party0_inputs, party1_inputs);
auto result1 = yacl::examples::pii::Pii2Party(
    lctxs[1], party1_inputs, party0_inputs);

// result0.intersection and result1.intersection should be the same
```

## Architecture

- `pii.h`: Main PII protocol interface
- `pii.cc`: PII protocol implementation
- `main.cc`: Demo program
- `BUILD.bazel`: Bazel build configuration

## Notes

This is an initial implementation based on the paper. The current version uses a simplified signature verification scheme for demonstration purposes. For production use, you should:

1. Implement proper ECDSA signature verification using yacl's ECC primitives
2. Implement AIBS (Anonymous Identity-Based Signature) scheme
3. Integrate with yacl's secure PSI protocols for privacy-preserving intersection
4. Add output integrity verification to detect malicious behavior
5. Add comprehensive error handling and security checks

## References

- Paper: "Privacy-Preserving Authorized Set Matching via Dishonest Majority Multiparty Computation" (IEEE TDSC 2025)
- Original Oryx implementation: https://github.com/ShallMate/Oryx
# oryxcpp
