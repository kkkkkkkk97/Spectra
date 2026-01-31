# SMT-based Test Case Generation for Protocol Security Properties
## Abstract Algorithm for Academic Paper

---

## Algorithm 1: Pure Violation Generation

**Input:**
- $\mathcal{P} = \{C_1, C_2, \ldots, C_n\}$: Set of all security properties
- $\mathcal{V} \subseteq \mathcal{P}$: Target properties to violate
- $N$: Maximum trace length
- $\mathcal{M}$: Message type domain
- $\mathcal{S}$: Sender domain $\{client, server\}$

**Output:**
- A trace $\tau = \langle m_0, m_1, \ldots, m_k \rangle$ violating exactly $\mathcal{V}$, or UNSAT

---

```
Algorithm: GenerateViolation(𝒫, 𝒱, N)

1:  Initialize SMT solver Φ
2:
3:  // Define temporal domain and variables
4:  T ← {0, 1, ..., N-1}
5:  for each t ∈ T do
6:      Declare msg_type[t] ∈ ℳ, sender[t] ∈ 𝒮, fields[t]
7:  Declare msg_count ∈ [1, N]
8:
9:  // Add protocol-level constraints
10: Φ ← Φ ∧ ProtocolConstraints(T, msg_count)
11:
12: // Satisfy all properties except targets
13: for each C ∈ (𝒫 \ 𝒱) do
14:     Φ ← Φ ∧ Encode_LTL(C, T, msg_count)
15:
16: // Violate target properties
17: for each C ∈ 𝒱 do
18:     Φ ← Φ ∧ ¬Encode_LTL(C, T, msg_count)
19:
20: // Solve and extract trace
21: if SAT(Φ) then
22:     M ← GetModel(Φ)
23:     τ ← ExtractTrace(M, msg_count)
24:     return τ
25: else
26:     return UNSAT
```

---

## Algorithm 2: LTL to SMT Encoding

**Input:**
- $\varphi$: LTL formula over finite trace
- $T = \{0, \ldots, N-1\}$: Temporal domain
- $n$: Actual trace length variable

**Output:** SMT constraint $\psi$

---

```
Function: Encode_LTL(φ, T, n)

1:  match φ with
2:
3:  | CH₀                           // Atomic: initial message
4:      return (msg_type[0] = CH)
5:
6:  | G(P → X Q)                    // Global implication with next
7:      return ⋀_{t=0}^{|T|-2} ((t < n ∧ P(t)) → (t+1 < n ∧ Q(t+1)))
8:
9:  | G(P → F Q)                    // Global implication with eventually
10:     return ⋀_{t∈T} ((t < n ∧ P(t)) → ⋁_{t'=t}^{|T|-1} (t' < n ∧ Q(t')))
11:
12: | G(¬P → ¬Q)                   // Global negative implication
13:     return ⋀_{t∈T} ((t < n ∧ Q(t)) → ⋁_{t'=0}^{t-1} (t' < n ∧ P(t')))
14:
15: | count(M) ≤ k                 // Cardinality constraint
16:     return Σ_{t∈T} [t < n ∧ msg_type[t] = M] ≤ k
17:
18: | field = value                // Field constraint
19:     return ⋀_{t∈T} ((t < n ∧ msg_type[t] = M) → field[t] = value)
20:
21: | lower < field < upper        // Range constraint
22:     return ⋀_{t∈T} ((t < n ∧ msg_type[t] = M) →
23:                      (lower < field[t] ∧ field[t] < upper))
```

---

## Algorithm 3: Protocol Constraints

```
Function: ProtocolConstraints(T, n)

1:  Ψ ← ∅
2:
3:  // Sender binding constraints
4:  for each t ∈ T do
5:      for each M ∈ ClientMessages do
6:          Ψ ← Ψ ∧ (msg_type[t] = M → sender[t] = client)
7:      for each M ∈ ServerMessages do
8:          Ψ ← Ψ ∧ (msg_type[t] = M → sender[t] = server)
9:
10: // Message occurrence constraints
11: for each (M, k) ∈ OccurrenceLimits do
12:     Ψ ← Ψ ∧ (Σ_{t∈T} [t < n ∧ msg_type[t] = M] ≤ k)
13:
14: return Ψ
```

---

## Key Definitions

**Temporal Logic Operators (Finite Trace Semantics):**

Given a finite trace $\tau = \langle m_0, \ldots, m_{k-1} \rangle$ of length $k$:

$$
\begin{aligned}
\tau, i &\models p &&\text{iff } p \text{ holds at position } i \\
\tau, i &\models \mathbf{X} \varphi &&\text{iff } i+1 < k \text{ and } \tau, i+1 \models \varphi \\
\tau, i &\models \mathbf{G} \varphi &&\text{iff } \forall j \in [i, k). \; \tau, j \models \varphi \\
\tau, i &\models \mathbf{F} \varphi &&\text{iff } \exists j \in [i, k). \; \tau, j \models \varphi \\
\tau &\models \varphi &&\text{iff } \tau, 0 \models \varphi
\end{aligned}
$$

**SMT Encoding Translation:**

| LTL Formula | SMT Constraint |
|-------------|----------------|
| $\mathbf{G}(\varphi)$ | $\bigwedge_{t=0}^{N-1} (t < n) \to \varphi(t)$ |
| $\mathbf{X}(\varphi)$ | $(t+1 < n) \land \varphi(t+1)$ |
| $\mathbf{F}(\varphi)$ | $\bigvee_{t'=t}^{N-1} (t' < n) \land \varphi(t')$ |
| $\varphi \to \psi$ | $\varphi(t) \to \psi(t)$ |

---

## Theorem 1: Soundness

**Theorem:** If $\text{GenerateViolation}(\mathcal{P}, \mathcal{V}, N)$ returns a trace $\tau$, then:
1. $\tau$ violates all properties in $\mathcal{V}$: $\forall C \in \mathcal{V}. \; \tau \not\models C$
2. $\tau$ satisfies all other properties: $\forall C \in \mathcal{P} \setminus \mathcal{V}. \; \tau \models C$

**Proof sketch:** By construction, the SMT formula $\Phi$ encodes:
- $\bigwedge_{C \in \mathcal{P} \setminus \mathcal{V}} \text{Encode\_LTL}(C, T, n)$ — satisfaction constraints
- $\bigwedge_{C \in \mathcal{V}} \neg \text{Encode\_LTL}(C, T, n)$ — violation constraints

Any satisfying model $M$ must respect both constraint sets. The encoding preserves LTL semantics (Lemma 1). □

---

## Complexity Analysis

**Theorem 2:** The decision problem is NP-complete.

**Proof:**
- **In NP:** Given a trace $\tau$, checking $\tau \models C$ for each property takes $O(|\tau| \cdot |C|)$.
- **NP-hard:** Reduction from SAT. A propositional formula $\phi$ over variables $\{p_1, \ldots, p_k\}$ can be encoded as a single-step trace problem where $\text{msg\_type}[0]$ encodes the truth assignment. □

**Space Complexity:** $O(N \cdot |\mathcal{M}| + N \cdot |\mathcal{P}|)$ variables and constraints.

**Time Complexity:** Worst-case exponential in $N$ (SMT solving), but practical instances with $N \leq 15$ and $|\mathcal{P}| = 18$ solve in seconds.

---

## Example Application

**Input:**
- $\mathcal{P} = \{C_1, \ldots, C_{18}\}$ (TLS 1.3 properties)
- $\mathcal{V} = \{C_1, C_5\}$ (violate initial message and SH→EE order)
- $N = 10$

**Properties:**
- $C_1: \text{msg\_type}[0] = \text{CH}$
- $C_5: \mathbf{G}(\text{SH} \to \mathbf{X} \text{EE})$

**Generated Trace:**
$$\tau = \langle \text{SH}, \text{CF}, \text{App}, \text{SCV}, \text{SF} \rangle$$

**Verification:**
- ✗ $\tau \not\models C_1$ (first message is SH, not CH)
- ✗ $\tau \not\models C_5$ (SH at position 0 followed by CF at position 1)
- ✓ $\tau \models C_i$ for all $i \in \{2, 3, 4, 6, \ldots, 18\}$

---

## Extensions

1. **Probabilistic Generation:** Sample uniformly from all satisfying assignments
2. **Minimality:** Add objective function $\min(n)$ to find shortest violations
3. **Witness Extraction:** Return specific positions violating each property
4. **Incremental Solving:** Reuse solver state for related queries

---

## Implementation Notes

- **SMT Solver:** Z3 4.8+ with theories of integers and uninterpreted functions
- **Optimization:** Use push/pop for batch generation
- **Timeout:** Set per-query timeout (default: 30s) for decidability
