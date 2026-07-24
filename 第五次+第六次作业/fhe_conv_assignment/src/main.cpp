#include "fhe_convolution.hpp"

#include <chrono>
#include <cstdlib>
#include <iomanip>
#include <iostream>
#include <random>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

using Clock = std::chrono::steady_clock;
using fheconv::Ciphertext;
using fheconv::DCRTPoly;
using fheconv::InputMatrix;
using fheconv::KernelMatrix;
using fheconv::OperationStats;
using fheconv::OutputMatrix;

void PrintInput(const InputMatrix& matrix) {
    for (std::size_t row = 0; row < fheconv::kInputRows; ++row) {
        for (std::size_t col = 0; col < fheconv::kInputCols; ++col) {
            std::cout << std::setw(6)
                      << matrix[row * fheconv::kInputCols + col];
        }
        std::cout << '\n';
    }
}

void PrintKernel(const KernelMatrix& matrix) {
    for (std::size_t row = 0; row < fheconv::kKernelRows; ++row) {
        for (std::size_t col = 0; col < fheconv::kKernelCols; ++col) {
            std::cout << std::setw(6)
                      << matrix[row * fheconv::kKernelCols + col];
        }
        std::cout << '\n';
    }
}

void PrintOutput(const OutputMatrix& matrix) {
    for (std::size_t row = 0; row < fheconv::kOutputRows; ++row) {
        for (std::size_t col = 0; col < fheconv::kOutputCols; ++col) {
            std::cout << std::setw(8)
                      << matrix[row * fheconv::kOutputCols + col];
        }
        std::cout << '\n';
    }
}

void PrintSlots(const std::vector<std::int64_t>& slots) {
    for (std::size_t row = 0; row < fheconv::kInputRows; ++row) {
        for (std::size_t col = 0; col < fheconv::kInputCols; ++col) {
            std::cout << std::setw(8)
                      << slots[row * fheconv::kInputCols + col];
        }
        std::cout << '\n';
    }
}

void Require(bool condition, const std::string& message) {
    if (!condition) {
        throw std::runtime_error(message);
    }
}

Ciphertext<DCRTPoly> EncryptInput(
    const fheconv::FheEnvironment& env,
    const InputMatrix& input) {
    auto plaintext = env.context->MakePackedPlaintext(fheconv::ToVector(input));
    return env.context->Encrypt(env.keys.publicKey, plaintext);
}

struct EvaluationResult {
    OutputMatrix plain{};
    OutputMatrix naive{};
    OutputMatrix optimized{};
    std::vector<std::int64_t> naiveSlots;
    std::vector<std::int64_t> optimizedSlots;
    OperationStats naiveStats{};
    OperationStats optimizedStats{};
};

EvaluationResult EvaluateCase(
    const fheconv::FheEnvironment& env,
    const InputMatrix& input,
    const KernelMatrix& kernel) {
    EvaluationResult result;
    result.plain = fheconv::PlainConvolution(input, kernel);

    const auto encryptedInput = EncryptInput(env, input);
    const auto naiveCiphertext = fheconv::EncryptedConvolutionNaive(
        env.context, encryptedInput, kernel, &result.naiveStats);
    const auto optimizedCiphertext = fheconv::EncryptedConvolutionOptimized(
        env.context, encryptedInput, kernel, &result.optimizedStats);

    result.naiveSlots = fheconv::DecryptSlots(env, naiveCiphertext);
    result.optimizedSlots = fheconv::DecryptSlots(env, optimizedCiphertext);
    result.naive = fheconv::ExtractOutput(result.naiveSlots);
    result.optimized = fheconv::ExtractOutput(result.optimizedSlots);

    Require(
        fheconv::EqualOutput(result.plain, result.naive),
        "naive encrypted convolution differs from plaintext convolution");
    Require(
        fheconv::EqualOutput(result.plain, result.optimized),
        "optimized encrypted convolution differs from plaintext convolution");
    Require(result.naiveStats.rotations == 8, "naive rotation count must be 8");
    Require(
        result.optimizedStats.rotations == 4,
        "optimized rotation count must be 4");

    return result;
}

template <typename Function>
double AverageMilliseconds(Function&& function, int rounds) {
    function();  // warm-up
    const auto start = Clock::now();
    for (int i = 0; i < rounds; ++i) {
        function();
    }
    const auto finish = Clock::now();
    const auto elapsed =
        std::chrono::duration<double, std::milli>(finish - start).count();
    return elapsed / static_cast<double>(rounds);
}

void RunRandomTests(const fheconv::FheEnvironment& env, int testCount) {
    std::mt19937_64 generator(20260724ULL);
    std::uniform_int_distribution<std::int64_t> inputDistribution(-20, 20);
    std::uniform_int_distribution<std::int64_t> kernelDistribution(-7, 7);

    for (int test = 0; test < testCount; ++test) {
        InputMatrix input{};
        KernelMatrix kernel{};
        for (auto& value : input) {
            value = inputDistribution(generator);
        }
        for (auto& value : kernel) {
            value = kernelDistribution(generator);
        }
        EvaluateCase(env, input, kernel);
    }

    std::cout << "Random correctness tests: " << testCount << "/"
              << testCount << " passed\n";
}

int ParsePositiveInt(const char* text, const char* name) {
    const int value = std::atoi(text);
    if (value <= 0) {
        throw std::invalid_argument(std::string(name) + " must be positive");
    }
    return value;
}

}  // namespace

int main(int argc, char** argv) {
    try {
        int benchmarkRounds = 5;
        int randomTests = 5;
        for (int i = 1; i < argc; ++i) {
            const std::string argument = argv[i];
            if (argument == "--rounds" && i + 1 < argc) {
                benchmarkRounds = ParsePositiveInt(argv[++i], "rounds");
            } else if (argument == "--random-tests" && i + 1 < argc) {
                randomTests = ParsePositiveInt(argv[++i], "random-tests");
            } else if (argument == "--help") {
                std::cout << "Usage: fhe_conv [--rounds N] [--random-tests N]\n";
                return 0;
            } else {
                throw std::invalid_argument("unknown command-line argument: " + argument);
            }
        }

        const InputMatrix input = {
            1,  2,  3,  4,
            5,  6,  7,  8,
            9, 10, 11, 12,
           13, 14, 15, 16};
        const KernelMatrix kernel = {
            1, 2, 3,
            4, 5, 6,
            7, 8, 9};

        std::cout << "Creating OpenFHE BFV-RNS context and rotation keys...\n";
        const fheconv::FheEnvironment env = fheconv::CreateEnvironment();
        std::cout << "Ring dimension: " << env.context->GetRingDimension() << '\n';
        std::cout << "Plaintext modulus: "
                  << env.context->GetCryptoParameters()->GetPlaintextModulus()
                  << "\n\n";

        const EvaluationResult fixed = EvaluateCase(env, input, kernel);

        std::cout << "Input 4x4:\n";
        PrintInput(input);
        std::cout << "\nKernel 3x3:\n";
        PrintKernel(kernel);
        std::cout << "\nPlain convolution 2x2:\n";
        PrintOutput(fixed.plain);
        std::cout << "\nNaive decrypted slots:\n";
        PrintSlots(fixed.naiveSlots);
        std::cout << "\nOptimized decrypted slots:\n";
        PrintSlots(fixed.optimizedSlots);

        std::cout << "\nOperation counts\n";
        std::cout << "method,rotations,ct-pt multiplications,additions\n";
        std::cout << "naive," << fixed.naiveStats.rotations << ','
                  << fixed.naiveStats.plaintextMultiplications << ','
                  << fixed.naiveStats.additions << '\n';
        std::cout << "optimized," << fixed.optimizedStats.rotations << ','
                  << fixed.optimizedStats.plaintextMultiplications << ','
                  << fixed.optimizedStats.additions << '\n';

        RunRandomTests(env, randomTests);

        const auto encryptedInput = EncryptInput(env, input);
        const double naiveMs = AverageMilliseconds(
            [&] {
                OperationStats stats;
                auto result = fheconv::EncryptedConvolutionNaive(
                    env.context, encryptedInput, kernel, &stats);
                (void)result;
            },
            benchmarkRounds);
        const double optimizedMs = AverageMilliseconds(
            [&] {
                OperationStats stats;
                auto result = fheconv::EncryptedConvolutionOptimized(
                    env.context, encryptedInput, kernel, &stats);
                (void)result;
            },
            benchmarkRounds);

        std::cout << std::fixed << std::setprecision(3);
        std::cout << "\nAverage encrypted convolution time over "
                  << benchmarkRounds << " rounds\n";
        std::cout << "naive_ms=" << naiveMs << '\n';
        std::cout << "optimized_ms=" << optimizedMs << '\n';
        std::cout << "speedup=" << naiveMs / optimizedMs << "x\n";

        std::cout << "\nAll correctness checks passed.\n";
        return 0;
    } catch (const std::exception& exception) {
        std::cerr << "ERROR: " << exception.what() << '\n';
        return 1;
    }
}
