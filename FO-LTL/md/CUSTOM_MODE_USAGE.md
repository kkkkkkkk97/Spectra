# Custom Mode 使用指南

## 概述

Custom模式允许你指定**任意组合的属性**同时违反，用于生成特定的测试场景。

---

## 基本用法

```bash
python3 main.py --mode custom --properties <属性列表> [选项]
```

### 参数说明

- `--mode custom`: 启用自定义模式（必需）
- `--properties <列表>`: 逗号分隔的属性名称（必需）
  - 例如: `C1,C5` 或 `C11,C17,C19`
- `--max-steps <数字>`: 最大消息序列长度（默认10）
- `--output-dir <目录>`: 输出目录（默认examples）

---

## 使用示例

### 1. 违反两个属性

```bash
# 同时违反 C1（初始消息）和 C5（SH→EE顺序）
python3 main.py --mode custom --properties C1,C5
```

**生成结果示例**:
```
SH -> CF -> App -> App -> SCV -> SF -> App
```
- ✗ C1: 初始消息是SH而非CH
- ✗ C5: SH后是CF而非EE

---

### 2. 违反三个属性

```bash
# 同时违反 C11（CCert→CCV）、C17（legacy_version）、C19（comp_method）
python3 main.py --mode custom --properties C11,C17,C19 --max-steps 10
```

**生成结果示例**:
```
CH(legacy_version=0x304, comp_method=1) -> SH -> EE -> SCert -> SCV -> SF -> App -> CCert
```
- ✗ C11: CCert后缺少CCV
- ✗ C17: legacy_version=0x304（应为0x0303）
- ✗ C19: comp_method=1（应为0）

---

### 3. 违反时序属性组合

```bash
# 同时违反 C2（CH响应）和 C7（CRq→SCert）
python3 main.py --mode custom --properties C2,C7
```

**生成结果示例**:
```
CH -> CH -> SH -> EE -> SCert -> SCV -> SF -> CF -> CRq -> CCert
```
- ✗ C2: 第一个CH后是CH而非SH/HRR
- ✗ C7: CRq后是CCert而非SCert

---

### 4. 违反字段约束组合

```bash
# 同时违反所有ClientHello字段约束
python3 main.py --mode custom --properties C17,C18,C19 --max-steps 8
```

**可能生成**:
```
CH(legacy_version=0x304, KeyShareY=0, comp_method=1) -> ...
```
- ✗ C17: legacy_version错误
- ✗ C18: KeyShareY超出范围
- ✗ C19: comp_method错误

---

## 可用属性列表

### 时序约束（C1-C13, C16）
- **C1**: 初始消息必须是ClientHello
- **C2**: CH后必须是SH或HRR
- **C3**: HRR只能出现一次 ⚠️ 可能UNSAT
- **C4**: HRR后必须是CH
- **C5**: SH后立即是EE
- **C6**: EE后是CRq或SCert
- **C7**: CRq后必须是SCert
- **C8**: SCert后必须是SCV
- **C9**: SCV后必须是SF
- **C10**: CRq不能在EE之前 ⚠️ 可能UNSAT
- **C11**: CCert后必须是CCV
- **C12**: CCV后必须是CF
- **C13**: 发送CRq则必有CCert
- **C16**: 应用数据必须在Finished之后 ⚠️ 可能UNSAT

### 字段约束（C17-C19）
- **C17**: ClientHello的legacy_version必须为0x0303
- **C18**: KeyShareY必须在有效范围：1 < Y < p-1
- **C19**: ClientHello的压缩方法必须为0

### 其他（C20）
- **C20**: 关键消息必须在记录边界（简化实现）

---

## 注意事项

### ⚠️ UNSAT（无法满足）情况

某些属性组合可能无法生成违规，因为约束冲突：

**常见UNSAT组合**:
1. **C3 + 其他**：C3要求HRR≤1次，但模型基本约束也限制≤1，无法违反
2. **C10 + C6/C7**：逻辑冲突
3. **C16 + C1**：App在Finished前 vs 初始消息不是CH

**如果生成失败**:
```
[FAIL] Could not generate violation for C3, C10
```
说明这个组合在当前约束下无法同时违反。

---

### ✅ 推荐组合

**易于生成的组合**（成功率高）:

1. **时序组合**:
   - `C1,C5`（初始消息 + SH顺序）
   - `C2,C4`（CH响应 + HRR顺序）
   - `C11,C12`（客户端认证顺序）

2. **字段组合**:
   - `C17,C19`（ClientHello字段）
   - `C17,C18,C19`（所有字段约束）

3. **混合组合**:
   - `C11,C17`（认证顺序 + 字段）
   - `C5,C19`（服务器顺序 + 字段）

---

## 输出文件命名

生成的文件名格式：`violation_<属性1>_<属性2>_...txt`

**示例**:
- `violation_C1_C5.txt`
- `violation_C11_C17_C19.txt`
- `violation_C2_C7.txt`

---

## 高级技巧

### 1. 增加序列长度

某些复杂组合需要更长的序列：

```bash
python3 main.py --mode custom --properties C2,C7,C13 --max-steps 15
```

### 2. 批量测试多个组合

使用Shell脚本批量生成：

```bash
#!/bin/bash
# test_combinations.sh

combinations=(
    "C1,C5"
    "C11,C17"
    "C2,C7"
    "C8,C19"
)

for combo in "${combinations[@]}"; do
    echo "Testing: $combo"
    python3 main.py --mode custom --properties "$combo" --max-steps 10
done
```

### 3. 验证生成质量

生成后检查trace是否确实只违反了指定属性：

```bash
# 查看生成的文件
cat examples/violation_C1_C5.txt

# 验证：
# 1. "Violated Properties" 部分是否只列出 C1 和 C5
# 2. 序列是否符合其他所有属性
```

---

## 问题排查

### Q1: 为什么某些组合生成失败？

**A**: 约束冲突导致。例如：
- C3要求违反"HRR只能1次"，但基本约束限制HRR≤1
- 解决：尝试不同的属性组合

### Q2: 如何知道哪些组合可行？

**A**:
1. 先尝试单个属性：`--mode single`
2. 成功的单属性可以尝试组合
3. 避免逻辑冲突的组合（如C3 + C10）

### Q3: 生成的序列是随机的吗？

**A**: 是的！Z3求解器是非确定性的，每次运行可能生成不同的违规序列。多次运行可以得到不同的测试用例。

---

## 示例会话

```bash
$ python3 main.py --mode custom --properties C11,C17,C19

TLS 1.3 Violation Test Case Generator
Started at: 2025-12-22 22:43:59
Configuration:
  Mode: custom
  Max steps: 10
  Output directory: examples
  Properties to violate: C11,C17,C19

================================================================================
Generating Custom Violation: C11, C17, C19
================================================================================

  [OK] Success! Generated violation for C11, C17, C19
================================================================================
VIOLATION TEST CASE
================================================================================

Violated Properties:
  - C11: CCert后必须是CCV
  - C17: ClientHello的legacy_version必须为0x0303
  - C19: ClientHello的压缩方法必须为0

Message Sequence:
  CH(legacy_version=0x304, comp_method=1) -> SH -> EE -> SCert -> SCV -> SF -> App -> CCert

Message Trace (detailed):
--------------------------------------------------------------------------------
  [0] CH(legacy_version=0x304, comp_method=1) (ClientHello, from cl)
  [1] SH                             (ServerHello, from sr)
  [2] EE                             (EncryptedExtensions, from sr)
  [3] SCert                          (ServerCertificate, from sr)
  [4] SCV                            (ServerCertificateVerify, from sr)
  [5] SF                             (ServerFinished, from sr)
  [6] App                            (ApplicationData, from cl)
  [7] CCert                          (ClientCertificate, from cl)
--------------------------------------------------------------------------------
================================================================================
  Saved to: examples\violation_C11_C17_C19.txt

[OK] All test cases generated successfully!
```

---

## 总结

Custom模式提供了灵活的测试用例生成能力：
- ✅ 支持任意属性组合
- ✅ 生成纯粹违反（只违反指定属性）
- ✅ 符合TLS 1.3协议约束（消息重复限制）
- ✅ 非确定性生成（每次运行可能不同）

这使得你可以针对特定的测试场景生成精确的违规案例！
