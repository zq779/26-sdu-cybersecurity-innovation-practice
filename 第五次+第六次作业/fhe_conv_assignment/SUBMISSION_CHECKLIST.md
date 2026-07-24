# 提交前检查

1. 在 `report/report.tex` 首页填写姓名和学号。
2. 安装 OpenFHE 1.5.1 后运行：

   ```bash
   ./run.sh
   ```

3. 将程序输出的 `naive_ms`、`optimized_ms` 和 `speedup` 填入报告第6.3节表格。
4. 截图至少保留以下内容：
   - 明文卷积输出；
   - 两种密文卷积解密槽位；
   - `naive,8,9,8` 与 `optimized,4,9,8`；
   - 随机测试全部通过；
   - 两种方案平均运行时间。
5. 再次编译报告：

   ```bash
   cd report
   xelatex report.tex
   xelatex report.tex
   ```

除姓名、学号和本机实测时间外，作业算法、代码、证明和报告正文均已完成。
