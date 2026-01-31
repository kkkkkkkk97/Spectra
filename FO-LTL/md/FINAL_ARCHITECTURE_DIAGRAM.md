# Final System Architecture Diagram
## Complete Module Relationships and Data Flow

---

## 系统架构图（最终版本）

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         SYSTEM ARCHITECTURE                              │
│                    (Based on Actual Implementation)                      │
└─────────────────────────────────────────────────────────────────────────┘

                            ┌──────────────┐
                            │    INPUT     │
                            │  • P={C₁..Cₙ}│  Security Properties
                            │  • V⊆P       │  Target Violations
                            │  • N         │  Max Steps
                            └──────┬───────┘
                                   │
                                   ▼
        ╔══════════════════════════════════════════════════════════╗
        ║          MODULE 1: Protocol Model (TLSModel)             ║
        ║  ┌────────────────────────────────────────────────────┐  ║
        ║  │ Components:                                        │  ║
        ║  │  • Variable Declarations (msg_type[t], sender[t]) │  ║
        ║  │  • Embedded Z3 Solver ← self.solver = Solver()    │  ║
        ║  │  • Protocol Constraints (sender binding, limits)  │  ║
        ║  │                                                    │  ║
        ║  │ Key Methods:                                       │  ║
        ║  │  • add_constraint(φ) → self.solver.add(φ)         │  ║
        ║  │  • check_sat() → self.solver.check()              │  ║
        ║  │  • get_model() → self.solver.model()              │  ║
        ║  └────────────────────────────────────────────────────┘  ║
        ╚═══════════════════════════╦══════════════════════════════╝
                                    │ Output: TLSModel instance
                                    │         (with Z3 solver inside)
                                    ▼
        ╔══════════════════════════════════════════════════════════╗
        ║        MODULE 2: Property Encoder (TLSProperties)        ║
        ║  ┌────────────────────────────────────────────────────┐  ║
        ║  │ Input: TLSModel instance                           │  ║
        ║  │                                                    │  ║
        ║  │ Function: Encode LTL → SMT                         │  ║
        ║  │  • C1_initial_client_hello() → φ₁                  │  ║
        ║  │  • C5_sh_then_ee() → φ₅                            │  ║
        ║  │  • ... (18 properties total)                       │  ║
        ║  │                                                    │  ║
        ║  │ Output: get_all_properties()                       │  ║
        ║  │         → {C1: φ₁, C2: φ₂, ..., C20: φ₂₀}          │  ║
        ║  └────────────────────────────────────────────────────┘  ║
        ╚═══════════════════════════╦══════════════════════════════╝
                                    │ Output: Property Dictionary
                                    │         {Ci: φᵢ}
                                    ▼
        ╔══════════════════════════════════════════════════════════╗
        ║      MODULE 3: Violation Generator                       ║
        ║      (包含 Constraint Manager 功能)                       ║
        ║  ┌────────────────────────────────────────────────────┐  ║
        ║  │ Input:                                             │  ║
        ║  │  • TLSModel instance (from Module 1)               │  ║
        ║  │  • Property Dict (from Module 2)                   │  ║
        ║  │  • Target Violations V                             │  ║
        ║  │                                                    │  ║
        ║  │ Function: Constraint Separation                    │  ║
        ║  │  ┌──────────────────────────────────────────────┐  │  ║
        ║  │  │ A. Satisfy Non-Targets (P \ V)              │  │  ║
        ║  │  │    for C in P \ V:                           │  │  ║
        ║  │  │        model.add_constraint(φ_C)             │  │  ║
        ║  │  │        └─> solver.add(φ_C)                   │  │  ║
        ║  │  │                                               │  │  ║
        ║  │  │ B. Violate Targets (V)                       │  │  ║
        ║  │  │    for C in V:                               │  │  ║
        ║  │  │        model.add_constraint(Not(φ_C))        │  │  ║
        ║  │  │        └─> solver.add(Not(φ_C))              │  │  ║
        ║  │  │                                               │  │  ║
        ║  │  │ C. Invoke Solver                             │  │  ║
        ║  │  │    result = model.check_sat()                │  │  ║
        ║  │  │    └─> solver.check()  [Z3 Solving]          │  │  ║
        ║  │  └──────────────────────────────────────────────┘  │  ║
        ║  │                                                    │  ║
        ║  │ Output:                                            │  ║
        ║  │  • (TLSModel, Z3_Model, violated_list)             │  ║
        ║  │    or None (if UNSAT)                              │  ║
        ║  └────────────────────────────────────────────────────┘  ║
        ╚═══════════════════════════╦══════════════════════════════╝
                                    │ Output: (TLSModel, Z3_Model, V)
                                    │
                                    ▼
                            ┌───────────────┐
                            │  Z3 Solver    │ (Embedded in Module 1)
                            │  SAT / UNSAT  │
                            └───────┬───────┘
                                    │ if SAT
                                    ▼
                            ┌───────────────┐
                            │  Z3 Model M   │ Variable Assignments
                            │  {msg_count:5,│
                            │   msg_type[]:,│
                            │   sender[],...}│
                            └───────┬───────┘
                                    │ Output: Z3_Model + TLSModel
                                    │
                                    ▼
        ╔══════════════════════════════════════════════════════════╗
        ║   MODULE 4: Formatter (TestCaseFormatter)                ║
        ║   (包含 Trace Extractor 功能)                             ║
        ║  ┌────────────────────────────────────────────────────┐  ║
        ║  │ Input:                                             │  ║
        ║  │  • Z3_Model (from Module 3)                        │  ║
        ║  │  • TLSModel (from Module 3)                        │  ║
        ║  │  • violated_list (from Module 3)                   │  ║
        ║  │                                                    │  ║
        ║  │ Phase 1: Trace Extraction                          │  ║
        ║  │  ┌──────────────────────────────────────────────┐  │  ║
        ║  │  │ extract_trace(Z3_Model, TLSModel)            │  │  ║
        ║  │  │   • n = Z3_Model.eval(msg_count)             │  │  ║
        ║  │  │   • for t in range(n):                       │  │  ║
        ║  │  │       msg = Z3_Model.eval(msg_type[t])       │  │  ║
        ║  │  │       sender = Z3_Model.eval(sender[t])      │  │  ║
        ║  │  │       trace.append({time, type, sender...})  │  │  ║
        ║  │  │                                               │  │  ║
        ║  │  │   Output: τ = [                              │  │  ║
        ║  │  │     {time:0, msg_type:'SH', sender:'sr'},    │  │  ║
        ║  │  │     {time:1, msg_type:'CF', sender:'cl'},    │  │  ║
        ║  │  │     ...                                       │  │  ║
        ║  │  │   ]                                           │  │  ║
        ║  │  └──────────────────────────────────────────────┘  │  ║
        ║  │         │                                          │  ║
        ║  │         │ Output 1: Structured Trace τ             │  ║
        ║  │         ▼                                          │  ║
        ║  │  ┌──────────────────────────────────────────────┐  │  ║
        ║  │  │ Phase 2: Report Formatting                   │  │  ║
        ║  │  │ format_violation_report(...)                 │  │  ║
        ║  │  │   • Build header: "VIOLATION TEST CASE"      │  │  ║
        ║  │  │   • List violated: "- C1: ..."               │  │  ║
        ║  │  │   • Compact sequence: "SH -> CF -> ..."      │  │  ║
        ║  │  │   • Detailed trace: "[0] SH (from sr)"       │  │  ║
        ║  │  │                                               │  │  ║
        ║  │  │   Output: report_string                      │  │  ║
        ║  │  └──────────────────────────────────────────────┘  │  ║
        ║  │         │                                          │  ║
        ║  │         │ Output 2: Formatted Report               │  ║
        ║  │         ▼                                          │  ║
        ║  │  ┌──────────────────────────────────────────────┐  │  ║
        ║  │  │ Phase 3: File Saving                         │  │  ║
        ║  │  │ save_to_file(report, filename)               │  │  ║
        ║  │  │   → violation_C1_C5.txt                      │  │  ║
        ║  │  └──────────────────────────────────────────────┘  │  ║
        ║  └────────────────────────────────────────────────────┘  ║
        ╚═══════════════════════════╦══════════════════════════════╝
                                    │
                                    ▼
                            ┌──────────────┐
                            │   OUTPUT     │
                            │  • τ (trace) │  Structured
                            │  • Report    │  Human-readable
                            │  • File      │  Saved on disk
                            └──────────────┘


═══════════════════════════════════════════════════════════════════════
                        MODULE RELATIONSHIPS
═══════════════════════════════════════════════════════════════════════

Protocol Model (Module 1)
    └─── Contains: Z3 Solver (embedded)

Property Encoder (Module 2)
    └─── Uses: Protocol Model (references variables)

Violation Generator (Module 3)
    ├─── Uses: Protocol Model (for constraint management)
    ├─── Uses: Property Encoder (gets property formulas)
    └─── Implements: Constraint Manager functionality
                     (constraint separation logic)

Formatter (Module 4)
    ├─── Uses: Z3 Model (from Module 3)
    ├─── Uses: TLSModel (from Module 3)
    └─── Implements: Trace Extractor functionality
                     (model → trace conversion)

═══════════════════════════════════════════════════════════════════════
                          DATA FLOW
═══════════════════════════════════════════════════════════════════════

Flow 1: Initialization
   User Input {P, V, N}
       → Module 1 (Protocol Model)
           Output: TLSModel instance (with solver)
       → Module 2 (Property Encoder)
           Input: TLSModel
           Output: {Ci: φᵢ}

Flow 2: Constraint Assembly
   {Ci: φᵢ} + V + TLSModel
       → Module 3 (Violation Generator)
           Process:
               - Add constraints to solver via TLSModel
               - Φ_satisfy = ⋀_{C∈P\V} φ_C
               - Φ_violate = ⋀_{C∈V} ¬φ_C
           Output: (TLSModel, Z3_Model, V) or None

Flow 3: Solving
   TLSModel.check_sat()
       → Z3 Solver (embedded in Module 1)
           Input: All accumulated constraints Φ
           Process: DPLL(T) algorithm
           Output: SAT + Model or UNSAT

Flow 4: Extraction & Formatting
   Z3_Model + TLSModel + V
       → Module 4 (Formatter)
           Phase 1: extract_trace()
               Input: Z3_Model, TLSModel
               Output: τ (structured trace)
           Phase 2: format_violation_report()
               Input: τ, V
               Output: Report string
           Phase 3: save_to_file()
               Output: violation_Ci_Cj.txt
```

---

## 模块包含关系（层次结构）

```
System
├── Protocol Model (TLSModel)
│   ├── Z3 Solver ◄─── [Embedded Component]
│   ├── Variable Declarations
│   ├── Protocol Constraints
│   └── Solver Interface Methods
│
├── Property Encoder (TLSProperties)
│   ├── References: Protocol Model
│   └── LTL Encoding Methods (C1..C20)
│
├── Violation Generator (ViolationGenerator)
│   ├── Uses: Protocol Model
│   ├── Uses: Property Encoder
│   └── Contains: Constraint Manager Logic ◄─── [Functional Component]
│       ├── Constraint Separation
│       ├── Solver Invocation
│       └── Result Management
│
└── Formatter (TestCaseFormatter)
    ├── Uses: Z3 Model
    ├── Uses: TLSModel
    └── Contains: Trace Extractor Logic ◄─── [Functional Component]
        ├── Model Evaluation
        ├── Trace Construction
        └── Report Generation
```

---

## 数据类型与接口

```python
# Core Data Types

TLSModel:
    - solver: Z3 Solver
    - msg_type: Array[Const]
    - sender: Array[Const]
    - msg_count: Int
    - methods: add_constraint(), check_sat(), get_model()

Property_Dict:
    - type: Dict[str, SMT_Formula]
    - example: {'C1': φ₁, 'C5': φ₅, ...}

Z3_Model:
    - type: Z3 Model Object
    - contains: Variable assignments
    - method: eval(variable) → value

Trace:
    - type: List[Dict]
    - structure: [
        {'time': 0, 'msg_type': 'SH', 'sender': 'sr', ...},
        {'time': 1, 'msg_type': 'CF', 'sender': 'cl', ...},
        ...
      ]

Report:
    - type: String
    - format: Human-readable violation test case
```

---

## 模块交互时序图

```
User                Module 3           Module 1           Z3 Solver    Module 4
 │                  (Generator)        (Protocol)                      (Formatter)
 │
 │ generate()           │                   │                              │
 ├───────────────────>  │                   │                              │
 │                      │                   │                              │
 │                      │ TLSModel()        │                              │
 │                      ├──────────────────>│                              │
 │                      │                   │ Solver()                     │
 │                      │                   ├─────────────>                │
 │                      │                   │               │              │
 │                      │ <─────────────────┤               │              │
 │                      │   model           │               │              │
 │                      │                   │               │              │
 │                      │ TLSProperties(m)  │               │              │
 │                      ├──────────────────>│               │              │
 │                      │ <─────────────────┤               │              │
 │                      │   props           │               │              │
 │                      │                   │               │              │
 │                      │ add_constraint()  │               │              │
 │                      ├──────────────────>│ add(φ)        │              │
 │                      │                   ├──────────────>│              │
 │                      │                   │               │              │
 │                      │ (repeat 16x)      │               │              │
 │                      │ add_constraint()  │               │              │
 │                      ├──────────────────>│ add(¬φ)       │              │
 │                      │                   ├──────────────>│              │
 │                      │                   │               │              │
 │                      │ check_sat()       │               │              │
 │                      ├──────────────────>│ check()       │              │
 │                      │                   ├──────────────>│              │
 │                      │                   │               │ [Solving]    │
 │                      │                   │               │ DPLL(T)      │
 │                      │                   │               │ ~35ms        │
 │                      │                   │ <─────────────┤              │
 │                      │                   │   SAT         │              │
 │                      │ <─────────────────┤               │              │
 │                      │   sat             │               │              │
 │                      │                   │               │              │
 │                      │ get_model()       │               │              │
 │                      ├──────────────────>│ model()       │              │
 │                      │                   ├──────────────>│              │
 │                      │                   │ <─────────────┤              │
 │                      │ <─────────────────┤   Model       │              │
 │                      │   z3_model        │               │              │
 │                      │                   │               │              │
 │ <────────────────────┤                   │               │              │
 │   (model,z3_m,V)     │                   │               │              │
 │                      │                   │               │              │
 │ format_report()      │                   │               │              │
 ├─────────────────────────────────────────────────────────────────────> │
 │                      │                   │               │              │
 │                      │                   │               │  extract()   │
 │                      │                   │               │  format()    │
 │                      │                   │               │              │
 │ <───────────────────────────────────────────────────────────────────── │
 │   report_string      │                   │               │              │
 │                      │                   │               │              │
```

---

## 关键澄清

### ❌ 不存在的独立模块

1. **"Constraint Assembler"** - 不是独立模块
   - 功能分布在 Module 1 (添加协议约束) 和 Module 3 (约束分离)

2. **"Constraint Manager"** - 不是独立模块
   - 功能包含在 Module 3 (Violation Generator) 内部
   - 实现约束分离逻辑

3. **"Solver"** - 不是独立模块
   - Z3求解器嵌入在 Module 1 (Protocol Model) 中
   - 通过 `self.solver` 访问

4. **"Trace Extractor"** - 不是独立模块
   - 功能包含在 Module 4 (Formatter) 的 Phase 1
   - 实现为 `extract_trace()` 方法

### ✅ 实际的4个模块

1. **Protocol Model** (model.py)
2. **Property Encoder** (properties.py)
3. **Violation Generator** (generator.py) - 包含约束管理逻辑
4. **Formatter** (formatter.py) - 包含轨迹提取逻辑

---

## 论文中推荐的表述

> Our system comprises **four core modules** organized in a sequential pipeline:
>
> **Module 1 (Protocol Model)** encapsulates the formal protocol representation, including SMT variable declarations, protocol-level constraints, and an embedded Z3 solver instance.
>
> **Module 2 (Property Encoder)** translates high-level LTL security properties into SMT constraints, operating over the variables defined in Module 1.
>
> **Module 3 (Violation Generator)** implements our constraint separation strategy. It partitions properties into satisfaction and violation sets, asserts corresponding constraints to the solver, and invokes satisfiability checking.
>
> **Module 4 (Formatter)** extracts concrete message traces from satisfying Z3 models and generates human-readable violation reports.
>
> Data flows sequentially through these modules: user input → protocol modeling → property encoding → constraint-based generation → trace formatting → test case output.

---

这就是**最终的、准确的**系统架构图！
