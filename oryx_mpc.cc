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

#include "examples/oryxcpp/oryx_mpc.h"

#include <cstring>
#include <random>

#include "yacl/base/byte_container_view.h"
#include "yacl/base/exception.h"
#include "yacl/crypto/rand/rand_secret.h"

namespace yacl::examples::oryx {

// ========== Constructor ==========

OryxMpcSystem::OryxMpcSystem(
    size_t rank, size_t world_size,
    const std::vector<std::shared_ptr<yacl::link::Context>>& ctxs,
    std::shared_ptr<yacl::crypto::EcGroup> ec_group,
    std::shared_ptr<yacl::crypto::PairingGroup> pairing_group)
    : rank_(rank),
      world_size_(world_size),
      ec_group_(ec_group),
      pairing_group_(pairing_group) {
  YACL_ENFORCE(!ctxs.empty(), "Contexts vector cannot be empty");
  YACL_ENFORCE(rank < ctxs.size(), "Rank out of bounds");
  ctx_ = ctxs[rank];

  // Use a large prime for Fp (256-bit security)
  // If we have an EC group, use its order; otherwise use a default prime
  if (ec_group_) {
    prime_ = ec_group_->GetOrder();
  } else if (pairing_group_) {
    prime_ = pairing_group_->GetOrder();
  } else {
    prime_ = yacl::math::MPInt(
        "115792089237316195423570985008687907853269984665640564039457584007913129639747");
  }

  // Generate MAC key share αi (in full implementation, this would be
  // generated via a secure key generation protocol)
  yacl::math::MPInt::RandomLtN(prime_, &mac_key_share_);
}

// ========== Fp Operations ==========

FpShare OryxMpcSystem::GenerateRandomFpShare() {
  FpShare share;
  yacl::math::MPInt::RandomLtN(prime_, &share.delta);
  yacl::math::MPInt::RandomLtN(prime_, &share.value_share);
  share.mac_share = yacl::math::MPInt(0);
  return share;
}

FpShare OryxMpcSystem::FpRandom() {
  FpShare share = GenerateRandomFpShare();
  
  // In 2PC, exchange shares with the other party
  if (world_size_ == 2) {
    size_t other_rank = (rank_ == 0) ? 1 : 0;
    
    auto delta_buf = share.delta.ToMagBytes();
    auto value_buf = share.value_share.ToMagBytes();
    
    uint32_t delta_len = static_cast<uint32_t>(delta_buf.size());
    uint32_t value_len = static_cast<uint32_t>(value_buf.size());
    
    std::vector<uint8_t> data(sizeof(delta_len) + delta_buf.size() +
                             sizeof(value_len) + value_buf.size());
    size_t offset = 0;
    std::memcpy(data.data() + offset, &delta_len, sizeof(delta_len));
    offset += sizeof(delta_len);
    std::memcpy(data.data() + offset, delta_buf.data<uint8_t>(), delta_buf.size());
    offset += delta_buf.size();
    std::memcpy(data.data() + offset, &value_len, sizeof(value_len));
    offset += sizeof(value_len);
    std::memcpy(data.data() + offset, value_buf.data<uint8_t>(), value_buf.size());
    
    ctx_->SendAsync(other_rank, yacl::ByteContainerView(data), "fp_random");
    
    // Receive from other party
    auto recv_data = ctx_->Recv(other_rank, "fp_random");
    // Process received share if needed
  }
  
  // Compute MAC share
  yacl::math::MPInt x_plus_delta = (share.value_share + share.delta) % prime_;
  share.mac_share = (mac_key_share_ * x_plus_delta) % prime_;
  
  return share;
}

FpShare OryxMpcSystem::FpShare(const yacl::math::MPInt& value) {
  FpShare share;
  yacl::math::MPInt::RandomLtN(prime_, &share.delta);
  
  // Generate random shares
  yacl::math::MPInt sum(0);
  std::vector<yacl::math::MPInt> all_value_shares(world_size_);
  
  for (size_t i = 0; i < world_size_ - 1; ++i) {
    yacl::math::MPInt::RandomLtN(prime_, &all_value_shares[i]);
    sum += all_value_shares[i];
    sum %= prime_;
  }
  
  all_value_shares[world_size_ - 1] = (value - sum + prime_) % prime_;
  share.value_share = all_value_shares[rank_];
  
  // Distribute shares
  if (world_size_ == 2) {
    size_t other_rank = (rank_ == 0) ? 1 : 0;
    
    auto delta_buf = share.delta.ToMagBytes();
    auto value_buf = all_value_shares[other_rank].ToMagBytes();
    
    uint32_t delta_len = static_cast<uint32_t>(delta_buf.size());
    uint32_t value_len = static_cast<uint32_t>(value_buf.size());
    
    std::vector<uint8_t> data(sizeof(delta_len) + delta_buf.size() +
                             sizeof(value_len) + value_buf.size());
    size_t offset = 0;
    std::memcpy(data.data() + offset, &delta_len, sizeof(delta_len));
    offset += sizeof(delta_len);
    std::memcpy(data.data() + offset, delta_buf.data<uint8_t>(), delta_buf.size());
    offset += delta_buf.size();
    std::memcpy(data.data() + offset, &value_len, sizeof(value_len));
    offset += sizeof(value_len);
    std::memcpy(data.data() + offset, value_buf.data<uint8_t>(), value_buf.size());
    
    ctx_->SendAsync(other_rank, yacl::ByteContainerView(data), "fp_share");
  }
  
  // Compute MAC share
  yacl::math::MPInt x_plus_delta = (share.value_share + share.delta) % prime_;
  share.mac_share = (mac_key_share_ * x_plus_delta) % prime_;
  
  return share;
}

FpShare OryxMpcSystem::FpAdd(const FpShare& a, const FpShare& b) {
  FpShare result;
  result.delta = (a.delta + b.delta) % prime_;
  result.value_share = (a.value_share + b.value_share) % prime_;
  result.mac_share = (a.mac_share + b.mac_share) % prime_;
  return result;
}

FpShare OryxMpcSystem::FpSub(const FpShare& a, const FpShare& b) {
  FpShare result;
  result.delta = (a.delta - b.delta + prime_) % prime_;
  result.value_share = (a.value_share - b.value_share + prime_) % prime_;
  result.mac_share = (a.mac_share - b.mac_share + prime_) % prime_;
  return result;
}

FpShare OryxMpcSystem::FpMul(const FpShare& a, const FpShare& b) {
  // Simplified multiplication (insecure for production)
  // Full implementation would use Beaver triples
  FpShare result;
  result.delta = (a.delta * b.delta) % prime_;
  result.value_share = (a.value_share * b.value_share) % prime_;
  result.mac_share = (a.mac_share * b.mac_share) % prime_;
  return result;
}

yacl::math::MPInt OryxMpcSystem::FpOpen(const FpShare& share) {
  yacl::math::MPInt value = share.value_share;
  
  if (world_size_ == 2) {
    size_t other_rank = (rank_ == 0) ? 1 : 0;
    
    auto value_buf = share.value_share.ToMagBytes();
    uint32_t value_len = static_cast<uint32_t>(value_buf.size());
    std::vector<uint8_t> data(sizeof(value_len) + value_buf.size());
    std::memcpy(data.data(), &value_len, sizeof(value_len));
    std::memcpy(data.data() + sizeof(value_len), value_buf.data<uint8_t>(),
                value_buf.size());
    ctx_->SendAsync(other_rank, yacl::ByteContainerView(data), "fp_open");
    
    auto recv_data = ctx_->Recv(other_rank, "fp_open");
    uint32_t recv_value_len;
    std::memcpy(&recv_value_len, recv_data.data(), sizeof(recv_value_len));
    yacl::math::MPInt other_share;
    other_share.FromMagBytes(
        yacl::ByteContainerView(recv_data.data() + sizeof(recv_value_len),
                               recv_value_len),
        yacl::Endian::native);
    
    value = (value + other_share) % prime_;
  }
  
  // Verify MAC
  if (!VerifyFpMac(share, value)) {
    YACL_THROW("MAC verification failed, aborting protocol");
  }
  
  return value;
}

bool OryxMpcSystem::VerifyFpMac(const FpShare& share,
                                const yacl::math::MPInt& opened_value) {
  yacl::math::MPInt x_plus_delta = (opened_value + share.delta) % prime_;
  yacl::math::MPInt expected_mac = (mac_key_share_ * x_plus_delta) % prime_;
  return (share.mac_share == expected_mac);
}

// ========== Elliptic Curve Operations ==========

std::vector<uint8_t> OryxMpcSystem::SerializeEcPoint(
    const yacl::crypto::EcPoint& point) {
  if (!ec_group_) {
    YACL_THROW("EC group not initialized");
  }
  auto buf = ec_group_->SerializePoint(point, yacl::crypto::PointOctetFormat::X962Compressed);
  return std::vector<uint8_t>(buf.data<uint8_t>(), buf.data<uint8_t>() + buf.size());
}

yacl::crypto::EcPoint OryxMpcSystem::DeserializeEcPoint(
    const std::vector<uint8_t>& data) {
  if (!ec_group_) {
    YACL_THROW("EC group not initialized");
  }
  return ec_group_->DeserializePoint(yacl::ByteContainerView(data),
                                     yacl::crypto::PointOctetFormat::X962Compressed);
}

EcPointShare OryxMpcSystem::EcShare(const yacl::crypto::EcPoint& point) {
  if (!ec_group_) {
    YACL_THROW("EC group not initialized");
  }
  
  EcPointShare share;
  
  // Generate random point shares
  // For additive secret sharing: P = P1 + ... + Pn
  if (rank_ == 0) {
    // Party 0: generate random shares for all parties
    std::vector<yacl::crypto::EcPoint> all_shares(world_size_);
    yacl::crypto::EcPoint sum = ec_group_->GetInfinity();
    
    // Generate random shares for parties 0 to n-2
    for (size_t i = 0; i < world_size_ - 1; ++i) {
      yacl::math::MPInt r;
      yacl::math::MPInt::RandomLtN(ec_group_->GetOrder(), &r);
      all_shares[i] = ec_group_->MulBase(r);
      sum = ec_group_->Add(sum, all_shares[i]);
    }
    
    // Last share makes sum equal to point
    all_shares[world_size_ - 1] = ec_group_->Sub(point, sum);
    share.point_share = all_shares[0];
    
    // Distribute shares to other parties
    for (size_t i = 1; i < world_size_; ++i) {
      auto serialized = SerializeEcPoint(all_shares[i]);
      uint32_t len = static_cast<uint32_t>(serialized.size());
      std::vector<uint8_t> data(sizeof(len) + serialized.size());
      std::memcpy(data.data(), &len, sizeof(len));
      std::memcpy(data.data() + sizeof(len), serialized.data(), serialized.size());
      ctx_->SendAsync(i, yacl::ByteContainerView(data), "ec_share");
    }
  } else {
    // Other parties: receive share from party 0
    auto recv_data = ctx_->Recv(0, "ec_share");
    uint32_t len;
    std::memcpy(&len, recv_data.data(), sizeof(len));
    std::vector<uint8_t> point_data(recv_data.data() + sizeof(len),
                                    recv_data.data() + sizeof(len) + len);
    share.point_share = DeserializeEcPoint(point_data);
  }
  
  return share;
}

EcPointShare OryxMpcSystem::EcAdd(const EcPointShare& a,
                                  const EcPointShare& b) {
  if (!ec_group_) {
    YACL_THROW("EC group not initialized");
  }
  EcPointShare result;
  result.point_share = ec_group_->Add(a.point_share, b.point_share);
  return result;
}

EcPointShare OryxMpcSystem::EcMul(const FpShare& scalar,
                                   const EcPointShare& point) {
  if (!ec_group_) {
    YACL_THROW("EC group not initialized");
  }
  
  // First open the scalar
  yacl::math::MPInt k = FpOpen(scalar);
  
  // Then compute k * point_share
  EcPointShare result;
  result.point_share = ec_group_->Mul(point.point_share, k);
  
  return result;
}

EcPointShare OryxMpcSystem::EcMulPublic(const yacl::math::MPInt& scalar,
                                        const EcPointShare& point) {
  if (!ec_group_) {
    YACL_THROW("EC group not initialized");
  }
  EcPointShare result;
  result.point_share = ec_group_->Mul(point.point_share, scalar);
  return result;
}

yacl::crypto::EcPoint OryxMpcSystem::EcOpen(const EcPointShare& share) {
  if (!ec_group_) {
    YACL_THROW("EC group not initialized");
  }
  
  yacl::crypto::EcPoint result = share.point_share;
  
  if (world_size_ == 2) {
    size_t other_rank = (rank_ == 0) ? 1 : 0;
    
    auto serialized = SerializeEcPoint(share.point_share);
    uint32_t len = static_cast<uint32_t>(serialized.size());
    std::vector<uint8_t> data(sizeof(len) + serialized.size());
    std::memcpy(data.data(), &len, sizeof(len));
    std::memcpy(data.data() + sizeof(len), serialized.data(), serialized.size());
    ctx_->SendAsync(other_rank, yacl::ByteContainerView(data), "ec_open");
    
    auto recv_data = ctx_->Recv(other_rank, "ec_open");
    uint32_t recv_len;
    std::memcpy(&recv_len, recv_data.data(), sizeof(recv_len));
    std::vector<uint8_t> point_data(recv_data.data() + sizeof(recv_len),
                                    recv_data.data() + sizeof(recv_len) + recv_len);
    yacl::crypto::EcPoint other_share = DeserializeEcPoint(point_data);
    
    result = ec_group_->Add(result, other_share);
  }
  
  return result;
}

// ========== G1 Operations ==========

G1Share OryxMpcSystem::G1Share(const yacl::crypto::EcPoint& point) {
  if (!pairing_group_) {
    YACL_THROW("Pairing group not initialized");
  }
  
  auto g1 = pairing_group_->GetGroup1();
  G1Share share;
  
  // Similar to EcShare, but using G1 group
  if (rank_ == 0) {
    std::vector<yacl::crypto::EcPoint> all_shares(world_size_);
    yacl::crypto::EcPoint sum = g1->GetInfinity();
    
    for (size_t i = 0; i < world_size_ - 1; ++i) {
      yacl::math::MPInt r;
      yacl::math::MPInt::RandomLtN(g1->GetOrder(), &r);
      all_shares[i] = g1->MulBase(r);
      sum = g1->Add(sum, all_shares[i]);
    }
    
    all_shares[world_size_ - 1] = g1->Sub(point, sum);
    share.point_share = all_shares[0];
    
    for (size_t i = 1; i < world_size_; ++i) {
      auto serialized = g1->SerializePoint(all_shares[i], yacl::crypto::PointOctetFormat::X962Compressed);
      uint32_t len = static_cast<uint32_t>(serialized.size());
      std::vector<uint8_t> data(sizeof(len) + serialized.size());
      std::memcpy(data.data(), &len, sizeof(len));
      std::memcpy(data.data() + sizeof(len), serialized.data<uint8_t>(), serialized.size());
      ctx_->SendAsync(i, yacl::ByteContainerView(data), "g1_share");
    }
  } else {
    auto recv_data = ctx_->Recv(0, "g1_share");
    uint32_t len;
    std::memcpy(&len, recv_data.data(), sizeof(len));
    yacl::ByteContainerView point_data(recv_data.data() + sizeof(len), len);
    share.point_share = g1->DeserializePoint(point_data, yacl::crypto::PointOctetFormat::X962Compressed);
  }
  
  return share;
}

G1Share OryxMpcSystem::G1Add(const G1Share& a, const G1Share& b) {
  if (!pairing_group_) {
    YACL_THROW("Pairing group not initialized");
  }
  auto g1 = pairing_group_->GetGroup1();
  G1Share result;
  result.point_share = g1->Add(a.point_share, b.point_share);
  return result;
}

G1Share OryxMpcSystem::G1Mul(const FpShare& scalar, const G1Share& point) {
  if (!pairing_group_) {
    YACL_THROW("Pairing group not initialized");
  }
  auto g1 = pairing_group_->GetGroup1();
  yacl::math::MPInt k = FpOpen(scalar);
  G1Share result;
  result.point_share = g1->Mul(point.point_share, k);
  return result;
}

yacl::crypto::EcPoint OryxMpcSystem::G1Open(const G1Share& share) {
  if (!pairing_group_) {
    YACL_THROW("Pairing group not initialized");
  }
  auto g1 = pairing_group_->GetGroup1();
  yacl::crypto::EcPoint result = share.point_share;
  
  if (world_size_ == 2) {
    size_t other_rank = (rank_ == 0) ? 1 : 0;
    auto serialized = g1->SerializePoint(share.point_share, yacl::crypto::PointOctetFormat::X962Compressed);
    uint32_t len = static_cast<uint32_t>(serialized.size());
    std::vector<uint8_t> data(sizeof(len) + serialized.size());
    std::memcpy(data.data(), &len, sizeof(len));
    std::memcpy(data.data() + sizeof(len), serialized.data<uint8_t>(), serialized.size());
    ctx_->SendAsync(other_rank, yacl::ByteContainerView(data), "g1_open");
    
    auto recv_data = ctx_->Recv(other_rank, "g1_open");
    uint32_t recv_len;
    std::memcpy(&recv_len, recv_data.data(), sizeof(recv_len));
    yacl::ByteContainerView point_data(recv_data.data() + sizeof(recv_len), recv_len);
    yacl::crypto::EcPoint other_share = g1->DeserializePoint(point_data, yacl::crypto::PointOctetFormat::X962Compressed);
    result = g1->Add(result, other_share);
  }
  
  return result;
}

// ========== G2 Operations ==========

G2Share OryxMpcSystem::G2Share(const yacl::crypto::EcPoint& point) {
  if (!pairing_group_) {
    YACL_THROW("Pairing group not initialized");
  }
  auto g2 = pairing_group_->GetGroup2();
  G2Share share;
  
  if (rank_ == 0) {
    std::vector<yacl::crypto::EcPoint> all_shares(world_size_);
    yacl::crypto::EcPoint sum = g2->GetInfinity();
    
    for (size_t i = 0; i < world_size_ - 1; ++i) {
      yacl::math::MPInt r;
      yacl::math::MPInt::RandomLtN(g2->GetOrder(), &r);
      all_shares[i] = g2->MulBase(r);
      sum = g2->Add(sum, all_shares[i]);
    }
    
    all_shares[world_size_ - 1] = g2->Sub(point, sum);
    share.point_share = all_shares[0];
    
    for (size_t i = 1; i < world_size_; ++i) {
      auto serialized = g2->SerializePoint(all_shares[i], yacl::crypto::PointOctetFormat::X962Compressed);
      uint32_t len = static_cast<uint32_t>(serialized.size());
      std::vector<uint8_t> data(sizeof(len) + serialized.size());
      std::memcpy(data.data(), &len, sizeof(len));
      std::memcpy(data.data() + sizeof(len), serialized.data<uint8_t>(), serialized.size());
      ctx_->SendAsync(i, yacl::ByteContainerView(data), "g2_share");
    }
  } else {
    auto recv_data = ctx_->Recv(0, "g2_share");
    uint32_t len;
    std::memcpy(&len, recv_data.data(), sizeof(len));
    yacl::ByteContainerView point_data(recv_data.data() + sizeof(len), len);
    share.point_share = g2->DeserializePoint(point_data, yacl::crypto::PointOctetFormat::X962Compressed);
  }
  
  return share;
}

G2Share OryxMpcSystem::G2Add(const G2Share& a, const G2Share& b) {
  if (!pairing_group_) {
    YACL_THROW("Pairing group not initialized");
  }
  auto g2 = pairing_group_->GetGroup2();
  G2Share result;
  result.point_share = g2->Add(a.point_share, b.point_share);
  return result;
}

G2Share OryxMpcSystem::G2Mul(const FpShare& scalar, const G2Share& point) {
  if (!pairing_group_) {
    YACL_THROW("Pairing group not initialized");
  }
  auto g2 = pairing_group_->GetGroup2();
  yacl::math::MPInt k = FpOpen(scalar);
  G2Share result;
  result.point_share = g2->Mul(point.point_share, k);
  return result;
}

yacl::crypto::EcPoint OryxMpcSystem::G2Open(const G2Share& share) {
  if (!pairing_group_) {
    YACL_THROW("Pairing group not initialized");
  }
  auto g2 = pairing_group_->GetGroup2();
  yacl::crypto::EcPoint result = share.point_share;
  
  if (world_size_ == 2) {
    size_t other_rank = (rank_ == 0) ? 1 : 0;
    auto serialized = g2->SerializePoint(share.point_share, yacl::crypto::PointOctetFormat::X962Compressed);
    uint32_t len = static_cast<uint32_t>(serialized.size());
    std::vector<uint8_t> data(sizeof(len) + serialized.size());
    std::memcpy(data.data(), &len, sizeof(len));
    std::memcpy(data.data() + sizeof(len), serialized.data<uint8_t>(), serialized.size());
    ctx_->SendAsync(other_rank, yacl::ByteContainerView(data), "g2_open");
    
    auto recv_data = ctx_->Recv(other_rank, "g2_open");
    uint32_t recv_len;
    std::memcpy(&recv_len, recv_data.data(), sizeof(recv_len));
    yacl::ByteContainerView point_data(recv_data.data() + sizeof(recv_len), recv_len);
    yacl::crypto::EcPoint other_share = g2->DeserializePoint(point_data, yacl::crypto::PointOctetFormat::X962Compressed);
    result = g2->Add(result, other_share);
  }
  
  return result;
}

// ========== GT Operations ==========

std::vector<uint8_t> OryxMpcSystem::SerializeGtElement(
    const yacl::crypto::GtElement& element) {
  if (!pairing_group_) {
    YACL_THROW("Pairing group not initialized");
  }
  auto gt = pairing_group_->GetGroupT();
  // GT elements are serialized as field elements
  // Wrap element as Item for serialization
  yacl::math::GaloisField::Item element_item(element);
  auto buf = gt->Serialize(element_item);
  return std::vector<uint8_t>(buf.data<uint8_t>(), buf.data<uint8_t>() + buf.size());
}

yacl::crypto::GtElement OryxMpcSystem::DeserializeGtElement(
    const std::vector<uint8_t>& data) {
  if (!pairing_group_) {
    YACL_THROW("Pairing group not initialized");
  }
  auto gt = pairing_group_->GetGroupT();
  auto deserialized = gt->Deserialize(yacl::ByteContainerView(data));
  return deserialized.As<yacl::crypto::GtElement>();
}

GTShare OryxMpcSystem::GTShare(const yacl::crypto::GtElement& element) {
  if (!pairing_group_) {
    YACL_THROW("Pairing group not initialized");
  }
  auto gt = pairing_group_->GetGroupT();
  GTShare share;
  
  // Multiplicative secret sharing: g = g1 * ... * gn
  if (rank_ == 0) {
    std::vector<yacl::crypto::GtElement> all_shares(world_size_);
    auto one_item = gt->GetIdentityOne();
    yacl::math::GaloisField::Item product = one_item;
    
    // Generate random shares
    for (size_t i = 0; i < world_size_ - 1; ++i) {
      // Generate random GT element by pairing random G1 and G2 points
      auto g1 = pairing_group_->GetGroup1();
      auto g2 = pairing_group_->GetGroup2();
      yacl::math::MPInt r1, r2;
      yacl::math::MPInt::RandomLtN(g1->GetOrder(), &r1);
      yacl::math::MPInt::RandomLtN(g2->GetOrder(), &r2);
      auto g1_point = g1->MulBase(r1);
      auto g2_point = g2->MulBase(r2);
      yacl::crypto::GtElement random_gt = pairing_group_->Pairing(g1_point, g2_point);
      all_shares[i] = random_gt;
      yacl::math::GaloisField::Item share_item(random_gt);
      product = gt->Mul(product, share_item);
    }
    
    // Last share makes product equal to element
    yacl::math::GaloisField::Item element_item(element);
    auto last_share_item = gt->Div(element_item, product);
    all_shares[world_size_ - 1] = last_share_item.As<yacl::crypto::GtElement>();
    share.element_share = all_shares[0];
    
    for (size_t i = 1; i < world_size_; ++i) {
      auto serialized = SerializeGtElement(all_shares[i]);
      uint32_t len = static_cast<uint32_t>(serialized.size());
      std::vector<uint8_t> data(sizeof(len) + serialized.size());
      std::memcpy(data.data(), &len, sizeof(len));
      std::memcpy(data.data() + sizeof(len), serialized.data(), serialized.size());
      ctx_->SendAsync(i, yacl::ByteContainerView(data), "gt_share");
    }
  } else {
    auto recv_data = ctx_->Recv(0, "gt_share");
    uint32_t len;
    std::memcpy(&len, recv_data.data(), sizeof(len));
    std::vector<uint8_t> element_data(recv_data.data() + sizeof(len),
                                       recv_data.data() + sizeof(len) + len);
    share.element_share = DeserializeGtElement(element_data);
  }
  
  return share;
}

GTShare OryxMpcSystem::GTMul(const GTShare& a, const GTShare& b) {
  if (!pairing_group_) {
    YACL_THROW("Pairing group not initialized");
  }
  auto gt = pairing_group_->GetGroupT();
  GTShare result;
  yacl::math::GaloisField::Item a_item(a.element_share);
  yacl::math::GaloisField::Item b_item(b.element_share);
  result.element_share = gt->Mul(a_item, b_item).As<yacl::crypto::GtElement>();
  return result;
}

GTShare OryxMpcSystem::GTPow(const GTShare& base, const FpShare& exponent) {
  if (!pairing_group_) {
    YACL_THROW("Pairing group not initialized");
  }
  auto gt = pairing_group_->GetGroupT();
  yacl::math::MPInt k = FpOpen(exponent);
  GTShare result;
  yacl::math::GaloisField::Item base_item(base.element_share);
  result.element_share = gt->Pow(base_item, k).As<yacl::crypto::GtElement>();
  return result;
}

yacl::crypto::GtElement OryxMpcSystem::GTOpen(const GTShare& share) {
  if (!pairing_group_) {
    YACL_THROW("Pairing group not initialized");
  }
  auto gt = pairing_group_->GetGroupT();
  yacl::crypto::GtElement result = share.element_share;
  
  if (world_size_ == 2) {
    size_t other_rank = (rank_ == 0) ? 1 : 0;
    auto serialized = SerializeGtElement(share.element_share);
    uint32_t len = static_cast<uint32_t>(serialized.size());
    std::vector<uint8_t> data(sizeof(len) + serialized.size());
    std::memcpy(data.data(), &len, sizeof(len));
    std::memcpy(data.data() + sizeof(len), serialized.data(), serialized.size());
    ctx_->SendAsync(other_rank, yacl::ByteContainerView(data), "gt_open");
    
    auto recv_data = ctx_->Recv(other_rank, "gt_open");
    uint32_t recv_len;
    std::memcpy(&recv_len, recv_data.data(), sizeof(recv_len));
    std::vector<uint8_t> element_data(recv_data.data() + sizeof(recv_len),
                                       recv_data.data() + sizeof(recv_len) + recv_len);
    yacl::crypto::GtElement other_share = DeserializeGtElement(element_data);
    yacl::math::GaloisField::Item result_item(result);
    yacl::math::GaloisField::Item other_item(other_share);
    result = gt->Mul(result_item, other_item).As<yacl::crypto::GtElement>();
  }
  
  return result;
}

// ========== Pairing Operations ==========

GTShare OryxMpcSystem::Pairing(const G1Share& g1_point,
                               const G2Share& g2_point) {
  if (!pairing_group_) {
    YACL_THROW("Pairing group not initialized");
  }
  
  // Open both shares
  yacl::crypto::EcPoint p1 = G1Open(g1_point);
  yacl::crypto::EcPoint p2 = G2Open(g2_point);
  
  // Compute pairing
  yacl::crypto::GtElement result = pairing_group_->Pairing(p1, p2);
  
  // Share the result
  return GTShare(result);
}

GTShare OryxMpcSystem::PairingPublicG1(
    const yacl::crypto::EcPoint& g1_point, const G2Share& g2_point) {
  if (!pairing_group_) {
    YACL_THROW("Pairing group not initialized");
  }
  
  yacl::crypto::EcPoint p2 = G2Open(g2_point);
  yacl::crypto::GtElement result = pairing_group_->Pairing(g1_point, p2);
  
  return GTShare(result);
}

GTShare OryxMpcSystem::PairingPublicG2(
    const G1Share& g1_point, const yacl::crypto::EcPoint& g2_point) {
  if (!pairing_group_) {
    YACL_THROW("Pairing group not initialized");
  }
  
  yacl::crypto::EcPoint p1 = G1Open(g1_point);
  yacl::crypto::GtElement result = pairing_group_->Pairing(p1, g2_point);
  
  return GTShare(result);
}

}  // namespace yacl::examples::oryx
