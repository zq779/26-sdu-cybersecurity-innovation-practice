# 作业3：AES 软件实现与优化

本工程以 **AES-128/AES-256** 为对象，从基础字节实现出发，完成多种软件优化，并在统一接口上实现 CTR、GCM、XTS 三种工作模式。

## 1. 已完成内容

### AES 分组算法后端

| 后端 | 方法 | 主要技术 |
|---|---|---|
| `baseline` | 基础实现 | SubBytes、ShiftRows、MixColumns、AddRoundKey 分步骤实现 |
| `ttable` | T-table | 将 SubBytes 与 MixColumns 合并为 4 组 32 位查表 |
| `shuffle` | Shuffle | SSSE3 `PSHUFB` 完成 16×16 S 盒行查找、ShiftRows 和向量化 MixColumns |
| `aesni` | 指令集优化一 | AES-NI `AESENC/AESDEC/AESIMC`，4 路并行处理 |
| `vaes` | 指令集优化二 | VAES + AVX2，使用 256 位寄存器并行处理多个 AES 分组 |

### 工作模式

- **CTR**：批量生成计数器，一次调用后端的多分组加密接口；支持任意长度尾块。
- **GCM**：96 位 IV 快速路径；CTR 批处理；GHASH 在支持的 CPU 上使用 `PCLMULQDQ`，否则回退到 4-bit 软件乘法；支持 AAD 和 128 位认证标签。
- **XTS**：双密钥、GF(2^128) tweak 更新、批量多分组处理，并支持最后不满 16 字节时的 ciphertext stealing。

## 2. 目录结构

```text
.
├── include/aeslab.h          # 公共接口
├── src/
│   ├── aes_common.c          # S 盒、密钥扩展、后端注册和运行时检测
│   ├── aes_baseline.c        # 基础实现
│   ├── aes_ttable.c          # T-table 实现
│   ├── aes_shuffle.c         # SSSE3 shuffle 实现
│   ├── aes_aesni.c           # AES-NI 实现
│   ├── aes_vaes.c            # VAES/AVX2 实现
│   └── modes.c               # CTR/GCM/XTS
├── tests/test_aeslab.c       # 标准测试向量
├── bench/bench.c             # 性能测试
├── scripts/run_all.sh        # 一键构建、测试、跑分
└── report/
    ├── 实验报告.md
    └── benchmark.csv
```

## 3. 环境要求

推荐环境：

- Ubuntu 22.04/24.04 或 WSL2 Ubuntu
- GCC 11 及以上或 Clang 14 及以上
- CMake 3.16 及以上
- x86-64 CPU

程序使用运行时 CPU 特性检测。CPU 不支持 SSSE3、AES-NI 或 VAES 时，对应后端会显示为 `unavailable`，不会非法执行指令。

## 4. 编译与运行

### 一键运行

```bash
cd aes_software_optimization
./scripts/run_all.sh
```

### 手动运行

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
ctest --test-dir build --output-on-failure
./build/aeslab_test
./build/aeslab_bench --bytes $((16*1024*1024)) --iters 8
```

输出 CSV：

```bash
./build/aeslab_bench --bytes $((16*1024*1024)) --iters 8 --csv \
  > report/benchmark.csv
```

### Sanitizer 检查

```bash
cmake -S . -B build-asan -DAESLAB_SANITIZE=ON -DCMAKE_BUILD_TYPE=Debug
cmake --build build-asan -j
./build-asan/aeslab_test
```

## 5. 测试覆盖

测试程序覆盖：

- FIPS 197 AES-128 单分组加密/解密向量；
- FIPS 197 AES-256 单分组加密/解密向量；
- NIST SP 800-38A CTR-AES128 四分组向量；
- NIST SP 800-38D GCM-AES128 密文与标签向量；
- AES-XTS 37 字节 ciphertext stealing 向量；
- 每一种可用后端均执行相同测试。

正确运行时会看到：

```text
[TEST] baseline
[ OK ] baseline
...
[TEST] vaes
[ OK ] vaes
```

## 6. 性能测试说明

基准程序对同一缓冲区重复执行 ECB、CTR、GCM 和 XTS，输出 MiB/s。为了减少误差，正式报告建议：

1. 关闭其他高负载程序；
2. 使用 Release 构建；
3. 每种配置至少运行 5 次；
4. 取中位数；
5. 记录 CPU 型号、编译器版本和 CPU flags；
6. 在自己的电脑上重新生成 `report/benchmark.csv`。

## 7. 安全性说明

这是教学和性能实验代码，不应直接用于生产系统。

- T-table 和本工程的 shuffle 查找路径都可能产生与秘密数据相关的缓存访问或执行特征，不保证常数时间。
- AES-NI/VAES 路径更适合实际使用，但完整密码库还需要密钥清零、错误处理、API 防误用、并发上下文、认证失败策略等工程措施。
- GCM 中同一密钥下不得重复使用 IV。
- XTS 的两个 AES 密钥必须独立，且 XTS 只提供存储加密的保密性，不提供完整性认证。

## 8. 参考标准

- FIPS 197: Advanced Encryption Standard (AES)
- NIST SP 800-38A: CTR mode
- NIST SP 800-38D: GCM/GMAC
- NIST SP 800-38E: XTS-AES
- Intel Intrinsics Guide: AES-NI、VAES、PCLMULQDQ
