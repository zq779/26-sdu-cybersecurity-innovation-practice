#include "fhe_convolution.hpp"

#include <algorithm>
#include <stdexcept>
#include <utility>

namespace fheconv {
namespace {

constexpr std::array<std::size_t, 4> kOutputSlots = {0, 1, 4, 5};
constexpr std::array<std::int32_t, 8> kRequiredRotations = {
    1, 2, 4, 5, 6, 8, 9, 10};

void CountRotation(OperationStats* stats) {
    if (stats != nullptr) {
        ++stats->rotations;
    }
}

void CountMultiplication(OperationStats* stats) {
    if (stats != nullptr) {
        ++stats->plaintextMultiplications;
    }
}

void CountAddition(OperationStats* stats) {
    if (stats != nullptr) {
        ++stats->additions;
    }
}

Ciphertext<DCRTPoly> AddTerm(
    const CryptoContext<DCRTPoly>& context,
    Ciphertext<DCRTPoly> accumulator,
    const Ciphertext<DCRTPoly>& term,
    bool initialized,
    OperationStats* stats) {
    if (!initialized) {
        return term;
    }
    CountAddition(stats);
    return context->EvalAdd(accumulator, term);
}

}  // namespace

FheEnvironment CreateEnvironment() {
    using namespace lbcrypto;

    CCParams<CryptoContextBFVRNS> parameters;
    parameters.SetPlaintextModulus(kPlaintextModulus);
    parameters.SetBatchSize(kSlotCount);
    parameters.SetMultiplicativeDepth(1);
    parameters.SetSecurityLevel(HEStd_128_classic);
    parameters.SetKeySwitchTechnique(HYBRID);
    parameters.SetKeySwitchCount(kRequiredRotations.size());
    parameters.SetEvalAddCount(16);

    CryptoContext<DCRTPoly> context = GenCryptoContext(parameters);
    context->Enable(PKE);
    context->Enable(KEYSWITCH);
    context->Enable(LEVELEDSHE);
    context->Enable(ADVANCEDSHE);

    auto keys = context->KeyGen();
    if (!keys.good()) {
        throw std::runtime_error("OpenFHE key generation failed");
    }

    std::vector<std::int32_t> rotations(
        kRequiredRotations.begin(), kRequiredRotations.end());
    context->EvalRotateKeyGen(keys.secretKey, rotations);

    return {context, keys};
}

std::vector<std::int64_t> ToVector(const InputMatrix& input) {
    return {input.begin(), input.end()};
}

std::vector<std::int64_t> MakeMask(
    const std::vector<std::size_t>& activeSlots,
    std::int64_t value) {
    std::vector<std::int64_t> mask(kSlotCount, 0);
    for (const std::size_t slot : activeSlots) {
        if (slot >= kSlotCount) {
            throw std::out_of_range("mask slot is outside the 16-slot layout");
        }
        mask[slot] = value;
    }
    return mask;
}

OutputMatrix PlainConvolution(
    const InputMatrix& input,
    const KernelMatrix& kernel) {
    OutputMatrix output{};

    for (std::size_t outRow = 0; outRow < kOutputRows; ++outRow) {
        for (std::size_t outCol = 0; outCol < kOutputCols; ++outCol) {
            std::int64_t sum = 0;
            for (std::size_t kernelRow = 0; kernelRow < kKernelRows; ++kernelRow) {
                for (std::size_t kernelCol = 0; kernelCol < kKernelCols; ++kernelCol) {
                    const std::size_t inputIndex =
                        (outRow + kernelRow) * kInputCols + outCol + kernelCol;
                    const std::size_t kernelIndex =
                        kernelRow * kKernelCols + kernelCol;
                    sum += input[inputIndex] * kernel[kernelIndex];
                }
            }
            output[outRow * kOutputCols + outCol] = sum;
        }
    }

    return output;
}

Ciphertext<DCRTPoly> EncryptedConvolutionNaive(
    const CryptoContext<DCRTPoly>& context,
    const Ciphertext<DCRTPoly>& encryptedInput,
    const KernelMatrix& kernel,
    OperationStats* stats) {
    if (stats != nullptr) {
        *stats = {};
    }

    Ciphertext<DCRTPoly> result;
    bool initialized = false;

    for (std::size_t kernelRow = 0; kernelRow < kKernelRows; ++kernelRow) {
        for (std::size_t kernelCol = 0; kernelCol < kKernelCols; ++kernelCol) {
            const std::size_t kernelIndex = kernelRow * kKernelCols + kernelCol;
            const std::int32_t offset = static_cast<std::int32_t>(
                kernelRow * kInputCols + kernelCol);

            Ciphertext<DCRTPoly> shifted = encryptedInput;
            if (offset != 0) {
                shifted = context->EvalRotate(encryptedInput, offset);
                CountRotation(stats);
            }

            const std::vector<std::size_t> activeSlots(
                kOutputSlots.begin(), kOutputSlots.end());
            Plaintext mask = context->MakePackedPlaintext(
                MakeMask(activeSlots, kernel[kernelIndex]));

            Ciphertext<DCRTPoly> term = context->EvalMult(shifted, mask);
            CountMultiplication(stats);
            result = AddTerm(context, result, term, initialized, stats);
            initialized = true;
        }
    }

    return result;
}

Ciphertext<DCRTPoly> EncryptedConvolutionOptimized(
    const CryptoContext<DCRTPoly>& context,
    const Ciphertext<DCRTPoly>& encryptedInput,
    const KernelMatrix& kernel,
    OperationStats* stats) {
    if (stats != nullptr) {
        *stats = {};
    }

    // Baby steps: only two horizontal rotations are materialized.
    const Ciphertext<DCRTPoly> horizontal0 = encryptedInput;
    const Ciphertext<DCRTPoly> horizontal1 =
        context->EvalRotate(encryptedInput, 1);
    CountRotation(stats);
    const Ciphertext<DCRTPoly> horizontal2 =
        context->EvalRotate(encryptedInput, 2);
    CountRotation(stats);

    const std::array<Ciphertext<DCRTPoly>, 3> horizontal = {
        horizontal0, horizontal1, horizontal2};

    std::array<Ciphertext<DCRTPoly>, 3> rowTerms;

    for (std::size_t kernelRow = 0; kernelRow < kKernelRows; ++kernelRow) {
        // The row term is first stored at S + 4*kernelRow.  A later giant-step
        // rotation by 4*kernelRow moves it back to S={0,1,4,5}.
        const std::size_t base = kernelRow * kInputCols;
        const std::vector<std::size_t> activeSlots = {
            base,
            base + 1,
            base + kInputCols,
            base + kInputCols + 1};

        Ciphertext<DCRTPoly> rowAccumulator;
        bool rowInitialized = false;

        for (std::size_t kernelCol = 0; kernelCol < kKernelCols; ++kernelCol) {
            const std::size_t kernelIndex = kernelRow * kKernelCols + kernelCol;
            Plaintext mask = context->MakePackedPlaintext(
                MakeMask(activeSlots, kernel[kernelIndex]));

            Ciphertext<DCRTPoly> term =
                context->EvalMult(horizontal[kernelCol], mask);
            CountMultiplication(stats);
            rowAccumulator = AddTerm(
                context, rowAccumulator, term, rowInitialized, stats);
            rowInitialized = true;
        }

        rowTerms[kernelRow] = rowAccumulator;
    }

    // Giant steps: align the second and third kernel rows with output slots.
    const Ciphertext<DCRTPoly> alignedRow0 = rowTerms[0];
    const Ciphertext<DCRTPoly> alignedRow1 =
        context->EvalRotate(rowTerms[1], 4);
    CountRotation(stats);
    const Ciphertext<DCRTPoly> alignedRow2 =
        context->EvalRotate(rowTerms[2], 8);
    CountRotation(stats);

    Ciphertext<DCRTPoly> result = context->EvalAdd(alignedRow0, alignedRow1);
    CountAddition(stats);
    result = context->EvalAdd(result, alignedRow2);
    CountAddition(stats);

    return result;
}

std::vector<std::int64_t> DecryptSlots(
    const FheEnvironment& env,
    const Ciphertext<DCRTPoly>& ciphertext,
    std::size_t length) {
    Plaintext plaintext;
    const auto decryptResult =
        env.context->Decrypt(env.keys.secretKey, ciphertext, &plaintext);
    if (!decryptResult.isValid) {
        throw std::runtime_error("OpenFHE decryption failed");
    }

    plaintext->SetLength(length);
    std::vector<std::int64_t> values = plaintext->GetPackedValue();
    values.resize(length);
    return values;
}

OutputMatrix ExtractOutput(const std::vector<std::int64_t>& slots) {
    if (slots.size() < kSlotCount) {
        throw std::invalid_argument("at least 16 decrypted slots are required");
    }
    return {slots[0], slots[1], slots[4], slots[5]};
}

bool EqualOutput(const OutputMatrix& lhs, const OutputMatrix& rhs) {
    return std::equal(lhs.begin(), lhs.end(), rhs.begin());
}

}  // namespace fheconv
