# MSS Advance Revenge — picoCTF 2026

**Category:** Cryptography
**Flag:** `picoCTF{MSS_Advance_but_we_brought_it_back_and_made_it_harder!!!}`

---

## Challenge Overview

> *"Last time we went easy on you. You'll never get the flag this time!"*

Files: `chall.py`, `output.txt`

A Shamir's Secret Sharing-inspired scheme. A degree-29 polynomial is constructed with 30 coefficients derived from a SHA256 hash chain seeded by the flag. The flag is AES-CBC encrypted using `MASTER_KEY = SHA256(flag)` as the key, and 20 evaluation points `(xᵢ, yᵢ)` are given.

---

## Understanding the Challenge

```python
p = getPrime(1024)

MASTER_KEY = hashlib.sha256(flag).digest()
coeffs = [bytes_to_long(MASTER_KEY)]
for i in range(29):
    co = hashlib.sha256(long_to_bytes(coeffs[-1])).digest()
    coeffs.append(bytes_to_long(co))

pairs = []
for i in range(20):
    x = random.randint(0, p)
    y = eval_poly(x, coeffs)
    pairs.append((x, y))
```

The hash chain structure means all coefficients are determined by `coeffs[0]` alone:
```
coeffs[0] = bytes_to_long(SHA256(flag))
coeffs[i] = bytes_to_long(SHA256(long_to_bytes(coeffs[i-1])))
```

The polynomial has **degree 29**, requiring **30 points** to recover via standard SSS. We only have **20 points** — the system is underdetermined with 10 degrees of freedom.

---

## The Key Insight: Small Coefficients

Each coefficient is a SHA256 output: exactly **256 bits**.
The prime `p` is **1024 bits**.

This 4× size disparity is the vulnerability. The 30 unknowns are **anomalously small** compared to `p`:

- Random solution entries have size ~`p` ≈ 2¹⁰²⁴
- The *actual* solution has entries of size ~2²⁵⁶
- The ratio: **2²⁵⁶ vs. 2¹⁰²⁴** — the real solution is astronomically shorter

---

## The Lattice Attack

### Step 1: Set Up the Linear System

The 20 evaluation points give 20 equations in 30 unknowns over 𝔽ₚ:

```
A · c ≡ y  (mod p)
```

where `A[i][j] = xᵢ^(29-j) mod p` (Vandermonde-like), `c = (coeffs[0], …, coeffs[29])`, and `y = (y₀, …, y₁₉)`.

The solution space is a 10-dimensional affine subspace of 𝔽ₚ³⁰.

### Step 2: Lift to an Integer Lattice

The homogeneous lattice `L_hom = { c ∈ ℤ³⁰ : A·c ≡ 0 (mod p) }` has basis:
- **10 nullspace vectors**: from Gaussian elimination over 𝔽ₚ
- **20 multiples of p**: `p·eⱼ` for each pivot column `j`

```
det(L_hom) = p²⁰ ≈ 2²⁰⁴⁸⁰
Expected λ₁(L_hom) ≈ p^(2/3) ≈ 2⁶⁸³
Actual target norm ≈ √30 · 2²⁵⁶ ≈ 2²⁵⁸
Gap: 2⁴²⁵
```

Since **2²⁵⁸ ≪ 2⁶⁸³**, LLL finds the real solution immediately.

### Step 3: Kannan Embedding (CVP → SVP)

Build a 31×31 matrix:

```
M = [ L_hom_basis | 0 ]   ← 30 rows (the lattice basis)
    [     c₀      | 1 ]   ← 1 row  (the coset target)
```

Any vector in the generated lattice with last coordinate = 1 has the form `(c₀ + v, 1)` where `v ∈ L_hom`. LLL minimizes the norm, finding the `v` that makes `c₀ + v` as small as possible — exactly the real coefficient vector.

---

## Complete Solve Script

```python
from fpylll import IntegerMatrix, LLL
from Crypto.Util.number import long_to_bytes, bytes_to_long
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import hashlib

# [p, pairs, iv, ct from output.txt]

def gauss_fp(A_in, b_in, p):
    """Gaussian elimination over Fp; returns (particular_solution, nullspace, pivot_cols)."""
    m, n = len(A_in), len(A_in[0])
    M = [A_in[i][:] + [b_in[i] % p] for i in range(m)]
    pivot_rows, cur_row = {}, 0
    for col in range(n):
        piv = next((i for i in range(cur_row, m) if M[i][col] % p), None)
        if piv is None: continue
        M[cur_row], M[piv] = M[piv], M[cur_row]
        inv = pow(M[cur_row][col], p - 2, p)
        M[cur_row] = [v * inv % p for v in M[cur_row]]
        for i in range(m):
            if i != cur_row and M[i][col]:
                f = M[i][col]
                M[i] = [(M[i][k] - f * M[cur_row][k]) % p for k in range(n + 1)]
        pivot_rows[col], cur_row = cur_row, cur_row + 1
    x_part = [0] * n
    for col, row in pivot_rows.items(): x_part[col] = M[row][-1]
    free_cols = [c for c in range(n) if c not in pivot_rows]
    null_basis = []
    for fc in free_cols:
        v = [0] * n; v[fc] = 1
        for col, row in pivot_rows.items(): v[col] = (-M[row][fc]) % p
        null_basis.append(v)
    return x_part, null_basis, sorted(pivot_rows.keys())

n, m = 30, 20
xs = [pair[0] for pair in pairs]
ys = [pair[1] for pair in pairs]
A = [[pow(xs[i], n - 1 - j, p) for j in range(n)] for i in range(m)]
c0, null_basis, pivot_cols = gauss_fp(A, list(ys), p)

# Build 30×30 lattice basis
basis = [nv[:] for nv in null_basis]
for pc in pivot_cols:
    row = [0] * n; row[pc] = p
    basis.append(row)

# Kannan embedding (31×31)
kannan = [row + [0] for row in basis] + [c0 + [1]]
M_int = IntegerMatrix(31, 31)
for i in range(31):
    for j in range(31):
        M_int[i, j] = kannan[i][j]
LLL.reduction(M_int)

for i in range(31):
    row = [M_int[i, j] for j in range(31)]
    if abs(row[-1]) == 1:
        coeffs = [row[-1] * x for x in row[:-1]]
        if all(0 <= c < 2**260 for c in coeffs): break

master_key = long_to_bytes(coeffs[0], 32)
cipher = AES.new(master_key, AES.MODE_CBC, iv)
print(unpad(cipher.decrypt(ct), 16).decode())
# → picoCTF{MSS_Advance_but_we_brought_it_back_and_made_it_harder!!!}
```

---

## Why This Works: The Math

| Quantity | Value |
|---|---|
| Prime `p` | ~2¹⁰²⁴ |
| Coefficient size | ~2²⁵⁶ |
| Lattice dimension | 30 |
| `det(L_hom)` | `p²⁰ ≈ 2²⁰⁴⁸⁰` |
| Expected `λ₁` | `≈ 2⁶⁸³` |
| Actual target norm | `≈ 2²⁵⁸` |
| **Gap** | **2⁴²⁵** |

LLL runs in polynomial time. With a gap of `2⁴²⁵` in 30 dimensions, even basic LLL finds the solution immediately (in practice, under a second).

---

## Key Takeaways

1. **Underdetermined ≠ Unsolvable.** A linear system with more unknowns than equations can still be uniquely solved if the solution has extra structure — here, anomalously small coefficients.
2. **Small coefficient polynomials are dangerous.** SSS is only secure when coefficients are uniformly random in 𝔽ₚ. Deriving them from SHA256 (256-bit) into a 1024-bit field breaks the scheme.
3. **LLL is a powerful general-purpose attack.** Anytime you see "small values modulo a large prime," think lattice reduction. The Kannan embedding is the standard technique for reducing CVP to an SVP that LLL can solve.
4. **The hash chain doesn't help.** The lattice attack treats them as 30 independent small unknowns and finds them all at once.
