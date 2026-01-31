# Corrected System Architecture (Based on Actual Implementation)
## Modular Design for Academic Paper

---

## 1. System Overview (Input-Processing-Output)

### 1.1 Complete I/O Specification

```
┌─────────────────────────────────────────────────────────────────┐
│                    SYSTEM INPUT/OUTPUT                           │
└─────────────────────────────────────────────────────────────────┘

INPUT:
┌────────────────────────────────────────┐
│ • Security Properties: P = {C₁,...,Cₙ} │
│ • Target Violations: V ⊆ P             │
│ • Max Steps: N (trace length limit)    │
└────────────────────────────────────────┘
                    ↓
              [PROCESSING]
                    ↓
OUTPUT (Two Components):
┌────────────────────────────────────────┐
│ 1. Trace: τ = ⟨m₀, m₁, ..., m_k⟩      │  ← Extracted by Trace Extractor
│    (structured message sequence)        │
│                                         │
│ 2. Violation Test Case Report          │  ← Formatted test case
│    • Violated properties list           │
│    • Message sequence (compact)         │
│    • Detailed trace (with senders)      │
│    • Saved to file                      │
└────────────────────────────────────────┘
```

**Key Insight:** Trace Extractor和Violation Test Case是**两个阶段**的输出：
- **Trace (τ)**: 原始结构化数据（中间输出）
- **Test Case Report**: 人类可读的格式化报告（最终输出）

---

## 2. System Architecture (4 Core Modules)

```
┌─────────────────────────────────────────────────────────────────┐
│                   ACTUAL SYSTEM ARCHITECTURE                     │
└─────────────────────────────────────────────────────────────────┘

Input Layer:
┌──────────────┐  ┌──────────────┐  ┌──────────────┐
│ Properties   │  │ Violation    │  │   Config     │
│   P={C_i}    │  │   Targets V  │  │   (N, ...)   │
└──────────────┘  └──────────────┘  └──────────────┘
       │                  │                  │
       └──────────────────┼──────────────────┘
                          ↓
┌──────────────────────────────────────────────────────────────┐
│  MODULE ① : Protocol Model (TLSModel)                        │
│  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━  │
│  • Creates SMT variables (msg_type[t], sender[t], fields[t]) │
│  • Encodes protocol constraints (sender binding, limits)     │
│  • Wraps Z3 Solver instance                                  │
│  • Provides: solver.add(), solver.check(), get_model()       │
└──────────────────────────────────────────────────────────────┘
                          ↓
┌──────────────────────────────────────────────────────────────┐
│  MODULE ② : Property Encoder (TLSProperties)                 │
│  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━  │
│  • Takes TLSModel instance                                   │
│  • Encodes each C_i as SMT formula φ_i                       │
│  • Handles LTL operators (G, X, F)                           │
│  • Returns: get_all_properties() → {C_i: φ_i}                │
└──────────────────────────────────────────────────────────────┘
                          ↓
┌──────────────────────────────────────────────────────────────┐
│  MODULE ③ : Violation Generator (ViolationGenerator)        │
│  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━  │
│  • Implements constraint separation strategy                 │
│  • Adds satisfy constraints: ⋀_{C∈P\V} φ_C                   │
│  • Adds violate constraints: ⋀_{C∈V} ¬φ_C                    │
│  • Invokes solver.check() (uses Z3 underneath)               │
│  • Returns: (TLSModel, Z3_Model, violated_list)              │
└──────────────────────────────────────────────────────────────┘
                          ↓
                    [Z3 SMT Solver]
                    (embedded in Module ①)
                          ↓
                   SAT / UNSAT
                          ↓
                   [if SAT: Model M]
                          ↓
┌──────────────────────────────────────────────────────────────┐
│  MODULE ④ : Trace Extractor & Formatter (TestCaseFormatter) │
│  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━  │
│  Step 1: Extract Trace                                       │
│    • extract_trace(z3_model, tls_model) → τ                  │
│    • Evaluates: M(msg_count), M(msg_type[t]), M(sender[t])  │
│    • Builds: τ = [                                           │
│        {time: 0, msg_type: 'CH', sender: 'cl', ...},         │
│        {time: 1, msg_type: 'SH', sender: 'sr', ...},         │
│        ...                                                   │
│      ]                                                       │
│                                                              │
│  Step 2: Format Test Case                                   │
│    • format_violation_report(z3_model, tls_model, violated) │
│    • Generates human-readable report                         │
│    • Returns: formatted string                               │
│                                                              │
│  Step 3: Save to File                                        │
│    • save_to_file(report, filename)                          │
│    • Writes to disk: violation_C1_C5.txt                     │
└──────────────────────────────────────────────────────────────┘
                          ↓
        ┌─────────────────────────────────┐
        │   OUTPUT 1: Trace (τ)           │
        │   (structured data)             │
        └─────────────────────────────────┘
                          ↓
        ┌─────────────────────────────────┐
        │   OUTPUT 2: Violation Report    │
        │   (formatted test case)         │
        └─────────────────────────────────┘
```

---

## 3. Module Detailed Specifications

### MODULE ① : Protocol Model (model.py → TLSModel)

**What is it?**
Protocol Model是**协议的形式化建模类**，它不是输入，而是**系统的核心组件**。

**Purpose:**
- 定义SMT变量（消息类型、发送方、字段）
- 编码协议级约束（基本规则）
- 包装Z3求解器

**Key Components:**

```python
class TLSModel:
    # 1. Variable Declaration (时域变量定义)
    msg_type[t]: MsgType    # t时刻的消息类型
    sender[t]: Sender       # t时刻的发送方
    fields[t]: {...}        # t时刻的消息字段
    msg_count: Int          # 实际消息数量

    # 2. Solver Instance (内嵌求解器)
    solver: Z3_Solver       # Z3求解器实例

    # 3. Protocol Constraints (协议约束)
    _add_basic_constraints():
        - Sender binding: CH/CCert/CCV/CF → client
                         SH/HRR/EE/... → server
        - Occurrence limits: CH≤2, SH≤1, SF≤1, ...
        - Field validity: prime[t] > 2

    # 4. Solver Interface (求解器接口)
    add_constraint(φ):      # 添加约束到solver
    check_sat():            # 调用solver.check()
    get_model():            # 获取满足模型
```

**How Z3 is Used:**

```python
# Inside TLSModel.__init__():
self.solver = Solver()                    # 创建Z3求解器实例
self.solver.add(self.msg_count >= 1)      # 添加约束
self.solver.add(self.msg_count <= N)

# Later usage:
model.add_constraint(some_formula)        # 外部添加约束
if model.check_sat() == sat:              # 检查可满足性
    z3_model = model.get_model()          # 获取模型
```

**Why it's a Module:**
它是系统的**建模层**，封装了：
- 变量声明
- 约束管理
- 求解器调用

---

### MODULE ② : Property Encoder (properties.py → TLSProperties)

**Purpose:** 将LTL安全属性编码为SMT约束

**Interface:**

```python
class TLSProperties:
    def __init__(self, model: TLSModel):
        self.m = model  # 引用Protocol Model

    def C1_initial_client_hello(self) -> SMT_Formula:
        return self.m.msg_type[0] == self.m.CH

    def C5_sh_then_ee(self) -> SMT_Formula:
        constraints = []
        for t in range(self.m.N - 1):
            sh_at_t = And(t < self.m.msg_count,
                         self.m.msg_type[t] == self.m.SH)
            next_is_ee = And(t + 1 < self.m.msg_count,
                            self.m.msg_type[t + 1] == self.m.EE)
            constraints.append(Implies(sh_at_t, next_is_ee))
        return And(constraints)

    def get_all_properties(self) -> Dict[str, SMT_Formula]:
        return {
            'C1': self.C1_initial_client_hello(),
            'C5': self.C5_sh_then_ee(),
            ...
        }
```

**Key Point:** 它使用`TLSModel`中的变量来构造约束！

---

### MODULE ③ : Violation Generator (generator.py → ViolationGenerator)

**Purpose:** 实现约束分离策略，生成纯粹违反

**Core Algorithm:**

```python
class ViolationGenerator:
    def generate_single_violation(self, property_name):
        # Step 1: 创建新的Protocol Model实例
        model = TLSModel(self.max_steps)

        # Step 2: 创建Property Encoder
        props = TLSProperties(model)
        all_props = props.get_all_properties()

        # Step 3: 约束分离
        # 3a. 满足所有其他属性
        for name, constraint in all_props.items():
            if name != property_name:
                model.add_constraint(constraint)  # φ_i

        # 3b. 违反目标属性
        model.add_constraint(Not(all_props[property_name]))  # ¬φ_target

        # Step 4: 调用求解器（通过Protocol Model）
        if model.check_sat() == sat:
            z3_model = model.get_model()
            return (model, z3_model, [property_name])
        else:
            return None
```

**How Z3 Solver is Used (Implicitly):**
```
ViolationGenerator
    └─> model.add_constraint(φ)
            └─> self.solver.add(φ)   # Z3内部
    └─> model.check_sat()
            └─> self.solver.check()  # Z3求解
```

Z3求解器**不是独立模块**，而是嵌入在`TLSModel`中！

---

### MODULE ④ : Trace Extractor & Formatter (formatter.py → TestCaseFormatter)

**Purpose:** 从SMT模型提取轨迹并格式化为测试报告

**Two-Phase Output:**

#### Phase 1: Trace Extraction (中间输出)

```python
def extract_trace(self, z3_model, tls_model):
    """
    提取原始轨迹数据
    """
    trace = []
    msg_count = z3_model.eval(tls_model.msg_count).as_long()

    for t in range(msg_count):
        msg_info = {
            'time': t,
            'msg_type': str(z3_model.eval(tls_model.msg_type[t])),
            'sender': str(z3_model.eval(tls_model.sender[t])),
            'msg_type_full': self.msg_type_names[...],
        }

        # 提取字段（如果是ClientHello）
        if z3_model.eval(tls_model.msg_type[t]) == tls_model.CH:
            msg_info['legacy_version'] = z3_model.eval(
                tls_model.legacy_version[t]
            )
            # ... 其他字段

        trace.append(msg_info)

    return trace  # ← OUTPUT 1: 结构化轨迹
```

**Output 1 Example:**
```python
trace = [
    {'time': 0, 'msg_type': 'CH', 'sender': 'cl',
     'legacy_version': 0x303, 'keyshare_Y': 2, ...},
    {'time': 1, 'msg_type': 'SH', 'sender': 'sr'},
    {'time': 2, 'msg_type': 'EE', 'sender': 'sr'},
    ...
]
```

#### Phase 2: Test Case Formatting (最终输出)

```python
def format_violation_report(self, z3_model, tls_model, violated):
    """
    格式化为人类可读的测试报告
    """
    # 1. 提取轨迹
    trace = self.extract_trace(z3_model, tls_model)

    # 2. 构建报告
    report = "=" * 80 + "\n"
    report += "VIOLATION TEST CASE\n"
    report += "=" * 80 + "\n\n"

    # 3. 列出违反的属性
    report += "Violated Properties:\n"
    for prop in violated:
        desc = self.get_property_description(prop)
        report += f"  - {prop}: {desc}\n"

    # 4. 紧凑序列
    report += "\nMessage Sequence:\n  "
    report += " -> ".join([self.format_message(m) for m in trace])

    # 5. 详细轨迹（含发送方）
    report += "\n\nMessage Trace (detailed):\n"
    report += "-" * 80 + "\n"
    for msg in trace:
        report += f"  [{msg['time']}] {msg['msg_type']:30} "
        report += f"({msg['msg_type_full']}, from {msg['sender']})\n"
    report += "-" * 80 + "\n"

    return report  # ← OUTPUT 2: 格式化报告字符串
```

**Output 2 Example:**
```
================================================================================
VIOLATION TEST CASE
================================================================================

Violated Properties:
  - C1: 初始消息必须是ClientHello
  - C5: SH后立即是EE

Message Sequence:
  SH -> CF -> App -> SCV -> SF

Message Trace (detailed):
--------------------------------------------------------------------------------
  [0] SH                             (ServerHello, from sr)
  [1] CF                             (ClientFinished, from cl)
  [2] App                            (ApplicationData, from cl)
  [3] SCV                            (ServerCertificateVerify, from sr)
  [4] SF                             (ServerFinished, from sr)
--------------------------------------------------------------------------------
================================================================================
```

---

## 4. Data Flow (Corrected)

```
┌────────┐
│  用户   │ Input: {P, V, N}
└───┬────┘
    │
    ↓
┌─────────────────────────────────────────┐
│ ① Protocol Model (TLSModel)             │
│    • 声明变量: msg_type[t], sender[t]    │
│    • 内嵌Z3: self.solver = Solver()      │
│    • 添加基本约束                         │
└───────────────┬─────────────────────────┘
                │ (model instance)
                ↓
┌─────────────────────────────────────────┐
│ ② Property Encoder (TLSProperties)      │
│    • props = TLSProperties(model)        │
│    • 生成: {C1: φ₁, C5: φ₅, ...}         │
└───────────────┬─────────────────────────┘
                │ (property formulas)
                ↓
┌─────────────────────────────────────────┐
│ ③ Violation Generator                   │
│    • 约束分离:                            │
│      - model.add_constraint(φ_i) for i≠V │
│      - model.add_constraint(¬φ_v) for v∈V│
│    • 求解: model.check_sat()             │
│      (内部调用 Z3 Solver)                 │
└───────────────┬─────────────────────────┘
                │
                ↓
        ┌───────────────┐
        │  Z3 Solver    │ (嵌入在TLSModel中)
        │  SAT / UNSAT  │
        └───────┬───────┘
                │ [if SAT]
                ↓
        ┌───────────────┐
        │  Z3 Model M   │ (变量赋值)
        └───────┬───────┘
                │
                ↓
┌─────────────────────────────────────────┐
│ ④ Trace Extractor & Formatter          │
│                                         │
│  Phase 1: extract_trace()               │
│    • M(msg_count) = 5                   │
│    • M(msg_type[0]) = SH                │
│    • M(sender[0]) = sr                  │
│    • ...                                │
│    → τ = [{time:0, type:'SH', ...}, ...]│ ← OUTPUT 1
│                                         │
│  Phase 2: format_violation_report()     │
│    • 构建人类可读报告                     │
│    → report_string                      │ ← OUTPUT 2
│                                         │
│  Phase 3: save_to_file()                │
│    → violation_C1_C5.txt                │
└─────────────────────────────────────────┘
```

---

## 5. Key Clarifications

### 5.1 What is "Protocol Model"?

**Answer:** `TLSModel`类 - 不是输入，而是**系统组件**

```python
# 它的作用:
TLSModel = {
    变量定义层,          # msg_type[t], sender[t], fields
    约束管理层,          # _add_basic_constraints()
    求解器包装层,        # solver.add(), solver.check()
}
```

在论文中可以表述为：
> The **Protocol Model** module encapsulates the formal representation of the protocol, defining temporal variables, encoding structural invariants, and wrapping the SMT solver interface.

### 5.2 How is SMT Solver Used?

**Answer:** Z3求解器**嵌入**在`TLSModel`中，不是独立模块

```python
# 实际代码:
class TLSModel:
    def __init__(self):
        self.solver = Solver()  # ← Z3求解器实例

# 使用流程:
model = TLSModel(10)                    # 创建模型（内含Z3）
model.add_constraint(some_formula)      # 添加约束
if model.check_sat() == sat:            # 调用Z3求解
    z3_model = model.get_model()        # 获取Z3模型
```

在论文中可以表述为：
> We employ the Z3 SMT solver (version 4.8+) as the underlying constraint solving engine. The solver is encapsulated within the Protocol Model module, providing a clean interface for constraint addition and satisfiability checking.

### 5.3 What is Trace Extractor?

**Answer:** 它是**Formatter模块的第一阶段功能**，而非独立模块

```python
# TestCaseFormatter内部:
class TestCaseFormatter:
    def extract_trace(self, z3_model, tls_model):
        # Phase 1: 从Z3模型提取结构化数据
        return trace  # [{time:0, type:'CH', ...}, ...]

    def format_violation_report(self, z3_model, tls_model, violated):
        # Phase 2: 格式化为人类可读报告
        trace = self.extract_trace(...)  # 内部调用Phase 1
        return report_string
```

在论文中可以表述为：
> The **Trace Extractor** (implemented within the `TestCaseFormatter` module) evaluates SMT variables against the satisfying model to reconstruct concrete message sequences.

### 5.4 Why Two Outputs?

**Answer:** 两阶段处理，分离关注点

```
Z3 Model (变量赋值)
    ↓ [extract_trace]
Structured Trace (程序可用)  ← OUTPUT 1 (中间输出)
    ↓ [format_violation_report]
Test Case Report (人类可读)  ← OUTPUT 2 (最终输出)
```

**Rationale:**
- **Trace (τ)**: 供程序进一步处理（如自动化测试）
- **Report**: 供人类阅读和验证

在论文中可以表述为：
> The system produces two outputs: (1) a structured trace $\tau$ for programmatic consumption, and (2) a formatted violation report for human inspection. This separation enables both automated testing and manual verification.

---

## 6. Simplified Architecture for Paper

```
┌────────────────────────────────────────────────────────────┐
│              SIMPLIFIED ARCHITECTURE (For Paper)            │
└────────────────────────────────────────────────────────────┘

Input:  𝒫, 𝒱, N
  │
  ↓
┌──────────────────────┐
│ ① Protocol Model     │  Formal modeling + Z3 wrapper
│    (TLSModel)        │
└──────────────────────┘
  │
  ↓
┌──────────────────────┐
│ ② Property Encoder   │  LTL → SMT translation
│    (TLSProperties)   │
└──────────────────────┘
  │
  ↓
┌──────────────────────┐
│ ③ Violation          │  Constraint separation
│    Generator         │  + SMT solving
└──────────────────────┘
  │
  ↓
┌──────────────────────┐
│ ④ Trace Formatter    │  Extraction + Formatting
│    (TestCaseFormatter│
└──────────────────────┘
  │
  ↓
Output: τ (trace) + Report (test case)
```

这是**4个模块**，不是5个！Z3求解器是嵌入式组件。

---

## 7. Paper-Ready Description

### For "System Design" Section:

> Our system consists of four core modules:
>
> **Module 1: Protocol Model** (`TLSModel`) formalizes the protocol as an SMT problem. It declares temporal variables $\text{msg\_type}[t]$, $\text{sender}[t]$, and message fields for each time step $t \in [0, N)$. The module encodes protocol-level invariants such as sender bindings and message occurrence constraints. Internally, it maintains a Z3 Solver instance and provides methods for constraint addition (`add_constraint`) and satisfiability checking (`check_sat`).
>
> **Module 2: Property Encoder** (`TLSProperties`) translates high-level LTL security properties into SMT constraints. Given a Protocol Model instance, it encodes each property $C_i$ as a formula $\phi_i$ over the model's variables. The encoding handles temporal operators ($\mathbf{G}$, $\mathbf{X}$, $\mathbf{F}$) using finite-trace semantics, and field constraints using implication-based guards.
>
> **Module 3: Violation Generator** (`ViolationGenerator`) implements our constraint separation strategy. Given target violations $\mathcal{V}$, it asserts $\bigwedge_{C \in \mathcal{P} \setminus \mathcal{V}} \phi_C$ (satisfy non-targets) and $\bigwedge_{C \in \mathcal{V}} \neg \phi_C$ (violate targets) to the Protocol Model's solver. It then invokes satisfiability checking and returns the TLSModel, Z3 model, and violated property list upon success.
>
> **Module 4: Trace Formatter** (`TestCaseFormatter`) extracts and formats concrete test cases. It first evaluates model variables against the Z3 satisfying assignment to produce a structured trace $\tau$. It then generates a human-readable violation report including violated properties, message sequences with sender annotations, and field values. The final report is persisted to disk.
>
> The Z3 SMT solver (version 4.8+) serves as the underlying constraint solving engine, embedded within Module 1. Data flows sequentially from modeling to encoding to generation to formatting, with the SMT solver invoked in Module 3.

---

This corrected architecture matches your actual implementation!
