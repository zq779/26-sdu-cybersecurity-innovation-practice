# 作业4：SM3 软件实现与优化

本工程实现 SM3 标量基线，以及基于 **SIMD 寄存器 + 通用寄存器混合分工** 的三种批量后端：

| 架构 | 后端 | 并行宽度 | 核心指令/机制 |
|---|---|---:|---|
| x86-64 | AVX2 | 8 条消息 | YMM、`VPADDD`、`VPXOR`、移位拼接、`VPBLENDVB` |
| x86-64 | AVX-512F | 16 条消息 | ZMM、`VPTERNLOGD`、`VPROLD`、opmask 掩码更新 |
| ARM64 | NEON | 4 条消息 | `uint32x4_t`、`EOR`、`ADD`、向量移位、`BSL` |

通用寄存器负责消息指针、长度、循环计数、活跃 lane 位图、填充尾块和后端调度；SIMD 寄存器负责 A-H 状态、W/W' 消息字、P0/P1、FF/GG、模加和循环移位。

## 目录结构

```text
.
├── include/sm3.h              # 公共 API
├── src/
│   ├── sm3_internal.h         # SM3 常量、端序、填充工具
│   ├── sm3_scalar.c           # 标量参考实现
│   ├── sm3_avx2.c             # AVX2 八路实现
│   ├── sm3_avx512.c           # AVX-512 十六路实现
│   ├── sm3_neon.c             # ARM64 NEON 四路实现
│   └── sm3_dispatch.c         # CPU 检测与运行时分发
├── tests/test_sm3.c           # 标准向量、边界和随机差分测试
├── bench/bench_sm3.c          # 中位数吞吐率基准
├── tools/sm3_cli.c            # 文件摘要命令行工具
├── scripts/
│   ├── verify_openssl.py      # 与 OpenSSL 差分验证
│   └── run_validation.sh      # 一键收集验收证据
├── report/report.tex          # LaTeX 报告源文件
└── Makefile
```

## x86-64 编译与验证

```bash
make clean
make -j"$(nproc)" all
make test
make verify-openssl
make asm-check
./build/sm3_bench 4096 256
```

Sanitizer：

```bash
make sanitize
```

恢复 Release 构建：

```bash
make clean
make -j"$(nproc)" all
```

一键收集全部证据：

```bash
./scripts/run_validation.sh
```

结果写入 `results/`。

## ARM64 原生编译

在 AArch64 Linux、RK3588、树莓派 5、Apple Silicon Linux VM 等环境：

```bash
make clean
make -j"$(nproc)" all
make test
make asm-check
./build/sm3_bench 4096 256
```

从 x86 主机交叉编译（需要交叉工具链和 sysroot）：

```bash
sudo apt install gcc-aarch64-linux-gnu binutils-aarch64-linux-gnu
make arm64
```

交叉编译只能证明 ARM64 对象可生成；正确性和性能应在真实 ARM64 设备运行测试程序后确认。

## 生成报告

系统需安装 XeLaTeX/TeX Live：

```bash
make report
```

输出：

```text
report/SM3软件实现与优化实验报告.pdf
```

## 设计说明

### SoA 数据布局

每个向量保存多条消息的同一个 32 位状态字：

```text
A_vec = {A_msg0, A_msg1, ..., A_msgN-1}
Wj_vec = {Wj_msg0, Wj_msg1, ..., Wj_msgN-1}
```

这不是把一条 SM3 消息内部的连续字直接塞进宽向量，而是并行计算多条彼此独立的 SM3 消息。因此它主要提高批量吞吐率，不保证降低单条短消息延迟。

### 不同长度消息

1. 通用寄存器计算每个 lane 的完整分组数；
2. 每轮构造活跃 lane 位图；
3. 所有 lane 统一执行 SIMD 压缩；
4. AVX2 用 `_mm256_blendv_epi8`、AVX-512 用 `_mm512_mask_mov_epi32`、NEON 用 `vbslq_u32` 只提交活跃 lane；
5. 每条消息独立构造一或两个填充分组。

### 运行时分发

- x86：优先 `AVX-512 16 路 -> AVX2 8 路 -> scalar`；
- ARM64：优先 `NEON 4 路 -> scalar`；
- 高级指令仅用于对应目标文件，避免旧 CPU 在程序启动阶段触发非法指令。

## 已验证内容

- 空消息、`abc`、`abcd` 重复 16 次标准向量；
- 0、1、55、56、63、64、65、119、120、121、128、1024 等边界长度；
- AVX2/AVX-512/自动分发随机差分；
- OpenSSL SM3 文件差分；
- ASan/UBSan；
- x86 目标指令反汇编；
- ARM64 NEON 对象交叉编译与反汇编。
