#pragma once

#include "openfhe.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <vector>

namespace fheconv {

using lbcrypto::Ciphertext;
using lbcrypto::CryptoContext;
using lbcrypto::DCRTPoly;
using lbcrypto::KeyPair;
using lbcrypto::Plaintext;

constexpr std::size_t kInputRows = 4;
constexpr std::size_t kInputCols = 4;
constexpr std::size_t kKernelRows = 3;
constexpr std::size_t kKernelCols = 3;
constexpr std::size_t kOutputRows = 2;
constexpr std::size_t kOutputCols = 2;
constexpr std::size_t kSlotCount = 16;
constexpr std::uint64_t kPlaintextModulus = 65537;

using InputMatrix = std::array<std::int64_t, kSlotCount>;
using KernelMatrix = std::array<std::int64_t, kKernelRows * kKernelCols>;
using OutputMatrix = std::array<std::int64_t, kOutputRows * kOutputCols>;

struct OperationStats {
    std::size_t rotations = 0;
    std::size_t plaintextMultiplications = 0;
    std::size_t additions = 0;
};

struct FheEnvironment {
    CryptoContext<DCRTPoly> context;
    KeyPair<DCRTPoly> keys;
};

FheEnvironment CreateEnvironment();

std::vector<std::int64_t> ToVector(const InputMatrix& input);
std::vector<std::int64_t> MakeMask(
    const std::vector<std::size_t>& activeSlots,
    std::int64_t value);

OutputMatrix PlainConvolution(
    const InputMatrix& input,
    const KernelMatrix& kernel);

Ciphertext<DCRTPoly> EncryptedConvolutionNaive(
    const CryptoContext<DCRTPoly>& context,
    const Ciphertext<DCRTPoly>& encryptedInput,
    const KernelMatrix& kernel,
    OperationStats* stats = nullptr);

Ciphertext<DCRTPoly> EncryptedConvolutionOptimized(
    const CryptoContext<DCRTPoly>& context,
    const Ciphertext<DCRTPoly>& encryptedInput,
    const KernelMatrix& kernel,
    OperationStats* stats = nullptr);

std::vector<std::int64_t> DecryptSlots(
    const FheEnvironment& env,
    const Ciphertext<DCRTPoly>& ciphertext,
    std::size_t length = kSlotCount);

OutputMatrix ExtractOutput(const std::vector<std::int64_t>& slots);

bool EqualOutput(const OutputMatrix& lhs, const OutputMatrix& rhs);

}  // namespace fheconv
