# 验证结果说明

- `correctness.txt`：当前 x86-64 验证环境的标准向量、边界、随机差分与自动分发结果。
- `openssl-differential.txt`：128 个文件与 OpenSSL SM3 的逐字节比较结果。
- `sanitizer.txt`：ASan/UBSan 构建及测试输出。
- `disassembly-summary.txt`：AVX2 YMM 与 AVX-512 ZMM 目标指令摘要。
- `benchmark-validation.txt`：支持 AVX-512 的独立验证环境性能，供确认 AVX-512 路径可真实运行。
- `environment.txt`：独立验证环境信息。
- `arm64-cross/`：ARM64 NEON 交叉编译对象、对象类型和反汇编摘要。它证明目标 ISA 生成，不等同于 ARM64 原生运行测试。

报告中的 AMD Ryzen 5 5600U / WSL2 AVX2 多长度数据来自用户原有实验运行记录，未伪造为当前容器数据。
