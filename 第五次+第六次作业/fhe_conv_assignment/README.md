# OpenFHE 密文卷积：作业5与作业6

本工程使用 OpenFHE 1.5.1 的 BFV-RNS 方案，完成：

1. 单输入单输出 4×4 输入、3×3 卷积核、步长1、无填充的密文卷积；
2. 基线算法使用8次旋转；
3. “打包→旋转→累加”优化算法使用4次旋转；
4. 固定样例、随机样例和明文卷积三方比对；
5. 输出旋转、密文-明文乘法和加法次数，并测量执行时间。

## 1. 固定测试数据

输入：

```text
1   2   3   4
5   6   7   8
9  10  11  12
13 14  15  16
```

卷积核：

```text
1 2 3
4 5 6
7 8 9
```

期望输出：

```text
348 393
528 573
```

输出被放置在槽位 `{0,1,4,5}`，所以解密后的前16槽为：

```text
348 393 0 0
528 573 0 0
0   0   0 0
0   0   0 0
```

## 2. 算法说明

### 作业5：基线算法

行优先打包后，3×3卷积所需的线性偏移为：

```text
0, 1, 2, 4, 5, 6, 8, 9, 10
```

偏移0直接使用原密文，其余8个偏移分别调用一次 `EvalRotate`，所以旋转次数为8。
每个旋转结果与一个明文权重掩码执行 `EvalMult`，最后累加。

### 作业6：4次旋转算法

将偏移集合分解为：

```text
{0,1,2,4,5,6,8,9,10} = {0,1,2} + {0,4,8}
```

先生成水平 baby steps：

```text
C, Rot(C,1), Rot(C,2)
```

需要2次旋转。随后分别构造卷积核三行的加权和，再将第二、三行执行：

```text
Rot(H1,4), Rot(H2,8)
```

再用2次旋转，总旋转次数为4。

对一般稠密3×3卷积，一个输出位置依赖9个不同输入槽位。在只允许明文对角乘、加法和旋转的线性计算模型中，执行 `r` 次旋转后，一个输出槽最多形成 `2^r` 条不同槽位依赖路径。因此 `2^3<9`，至少需要4次旋转；本实现达到该下界。

## 3. 依赖

- OpenFHE 1.5.1
- CMake 3.16+
- GCC 9+ 或 Clang 10+
- C++17

OpenFHE需先完成 `make install`。若安装在非默认位置，配置时传入：

```bash
cmake -S . -B build -DCMAKE_PREFIX_PATH=/path/to/openfhe/install
```

## 4. 编译运行

```bash
mkdir build
cd build
cmake ..
cmake --build . -j
./fhe_conv --rounds 5 --random-tests 5
```

或者：

```bash
./run.sh
```

## 5. 预期关键输出

```text
Plain convolution 2x2:
     348     393
     528     573

method,rotations,ct-pt multiplications,additions
naive,8,9,8
optimized,4,9,8

Random correctness tests: 5/5 passed
All correctness checks passed.
```

实际运行时间由CPU、编译选项和OpenFHE参数决定，不应在未运行的情况下预填。

## 6. 文件说明

```text
include/fhe_convolution.hpp     接口和数据结构
src/fhe_convolution.cpp         两种密文卷积实现
src/main.cpp                    测试、计数和基准测试
scripts/verify_reference.py     不依赖OpenFHE的槽位逻辑验证
report/report.tex               可提交的实验报告LaTeX源码
```
