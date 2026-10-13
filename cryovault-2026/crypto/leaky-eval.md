### Summary

The scheme is Ring-LWE in `Z_Q[X]/(X^64 + 1)` with `Q = 2^61 - 1` and a ternary secret `s`. Each of the 72 samples publishes `b = a*s + e` together with one coefficient `leak = e[idx] mod Q` of the noise. Knowing that coefficient removes the LWE error at that position, so each sample gives one exact linear equation in the 64 unknowns `s_j` modulo a prime. Gaussian elimination mod `Q` recovers `s`, the key is `SHA256` of its comma-joined coefficients, and that key opens the flag.

### Steps

1. Read `files/output.json`. It holds `N = 64`, `Q`, `E_BOUND`, 72 samples (each with `a`, `b`, `idx`, `leak`), and the sealed flag (`flag_ct`, `flag_tag`, `flag_nonce`). The generator in `files/chall.py` confirms the key rule (`key = SHA256(",".join(map(str, s)))`) and that every sample has message `m = 0`, so `b = a*s + e` exactly.

2. Turn each sample into one linear equation. In `Z_Q[X]/(X^N + 1)`, the coefficient of `X^k` in `a*s` is `sum_j s_j * (X^j a)_k`, where the negacyclic wrap gives `(X^j a)_k = a[(k - j) mod N]` for `j <= k` and `-a[(k - j) mod N]` for `j > k`. Since `leak = e[k] mod Q`, the equation `sum_j (X^j a)_k * s_j = b[k] - leak (mod Q)` holds with no error.
   ```python
   def sample_row(a, k, Q):
       N = len(a)
       return [a[(k - j) % N] if j <= k else (-a[(k - j) % N]) % Q for j in range(N)]

   rows.append(sample_row(a, idx, Q))
   rhs.append((b[idx] - leak) % Q)
   ```

3. Solve the 72 x 64 system mod `Q`. `Q` is prime, so Gauss-Jordan elimination with modular inverses gives the unique solution. Each solved value must be `0`, `1`, or `Q - 1`, which map to `0`, `1`, and `-1`. The solver aborts if any value is outside the ternary set.

4. Verify all samples. Recompute `(a*s)[idx]` for every sample and compare it with `b[idx] - leak mod Q`. The solver reports 72/72 samples verified.

5. Derive the key and decrypt. `key = SHA256(",".join(map(str, s)))`, and `decrypt_and_verify` with the stored nonce and tag returns the flag.

6. Run the solver from `work/` with `pycryptodome` installed (see `scripts/requirements.txt`).
   ```sh
   cd work
   python3 scripts/solve.py ../files/output.json
   ```
   ```text
   [*] N=64 Q~2^61 samples=72
   [*] recovered secret (ternary, 45 nonzero coeffs)
   [*] samples verified: 72/72
   [+] FLAG: isfcr{REDACTED}
   ```

### Scripts

#### scripts/requirements.txt

Pins the one dependency the solver needs, `pycryptodome`, for AES-GCM.

```text
pycryptodome
```

#### scripts/solve.py

Builds the 72 x 64 system from the samples, solves it mod `Q`, verifies every sample, and decrypts the flag; run it from `work/` as shown in step 6.

```python
#!/usr/bin/env python3
"""
leaky-eval: recover the ternary Ring-LWE secret and decrypt the flag.

Scheme (files/chall.py): in R_Q = Z_Q[X]/(X^N+1), b = a*s + e mod Q with e small,
and each sample publishes one noise coefficient `leak = e[idx] mod Q`. Because that
coefficient of e is known exactly, the equation

    (a*s)[idx] == b[idx] - leak   (mod Q)

holds with no error, giving exact modular linear equations in the unknown s. With
72 samples and 64 ternary unknowns, Gaussian elimination mod Q recovers s, and
key = SHA256(",".join(map(str, s))) decrypts the flag.

Requires: pycryptodome.
Run: python3 scripts/solve.py [../files/output.json]
"""
import argparse
import json
import sys
from hashlib import sha256
from pathlib import Path

from Crypto.Cipher import AES


def sample_row(a, k, Q):
    # row_j = coefficient of X^j in X^j*a mod (X^N+1), evaluated at index k:
    # (a*s)_k = sum_j s_j * (X^j a)_k ; X^j a wraps with a sign flip past N.
    N = len(a)
    return [a[(k - j) % N] if j <= k else (-a[(k - j) % N]) % Q for j in range(N)]


def solve_mod(rows, rhs, n, Q):
    # Gaussian elimination over Z_Q (Q prime); returns unique solution or None
    m = len(rows)
    mat = [[x % Q for x in rows[i]] + [rhs[i] % Q] for i in range(m)]
    piv = []
    r = 0
    for c in range(n):
        p = next((i for i in range(r, m) if mat[i][c] % Q), None)
        if p is None:
            continue
        mat[r], mat[p] = mat[p], mat[r]
        inv = pow(mat[r][c], -1, Q)
        mat[r] = [(x * inv) % Q for x in mat[r]]
        for i in range(m):
            if i != r and mat[i][c] % Q:
                f = mat[i][c] % Q
                mat[i] = [(mat[i][j] - f * mat[r][j]) % Q for j in range(n + 1)]
        piv.append(c)
        r += 1
        if r == n:
            break
    if len(piv) < n:
        return None
    s = [0] * n
    for i, c in enumerate(piv):
        s[c] = mat[i][n]
    return s


def main():
    default = Path(__file__).resolve().parents[2] / "files" / "output.json"
    ap = argparse.ArgumentParser()
    ap.add_argument("path", nargs="?", default=str(default))
    args = ap.parse_args()

    d = json.loads(Path(args.path).read_text())
    N, Q = d["N"], d["Q"]
    samples = d["samples"]
    print(f"[*] N={N} Q~2^{Q.bit_length()} samples={len(samples)}")

    rows, rhs = [], []
    for sm in samples:
        a, b, idx, leak = sm["a"], sm["b"], sm["idx"], sm["leak"]
        rows.append(sample_row(a, idx, Q))
        rhs.append((b[idx] - leak) % Q)

    sol = solve_mod(rows, rhs, N, Q)
    if sol is None:
        print("[!] system not full rank")
        sys.exit(1)

    # map residues back to ternary representatives
    s = []
    for v in sol:
        v %= Q
        if v == 0 or v == 1:
            s.append(v)
        elif v == Q - 1:
            s.append(-1)
        else:
            print(f"[!] non-ternary coefficient: {v}")
            sys.exit(1)
    print(f"[*] recovered secret (ternary, {sum(1 for x in s if x)} nonzero coeffs)")

    # verify every sample
    bad = 0
    for sm in samples:
        a, b, idx, leak = sm["a"], sm["b"], sm["idx"], sm["leak"]
        row = sample_row(a, idx, Q)
        lhs = sum(row[j] * s[j] for j in range(N)) % Q
        if lhs != (b[idx] - leak) % Q:
            bad += 1
    print(f"[*] samples verified: {len(samples) - bad}/{len(samples)}")
    if bad:
        sys.exit(1)

    key = sha256((",".join(map(str, s))).encode()).digest()
    cipher = AES.new(key, AES.MODE_GCM, nonce=bytes.fromhex(d["flag_nonce"]))
    try:
        pt = cipher.decrypt_and_verify(bytes.fromhex(d["flag_ct"]), bytes.fromhex(d["flag_tag"]))
        print("[+] FLAG:", pt.decode())
    except ValueError:
        print("[!] GCM tag verification failed")
        sys.exit(1)


if __name__ == "__main__":
    main()
```

### Notes

- The `E_BOUND` value and the bound on `e` are never used. The leak is exact, so no lattice reduction is needed.
- The secret is ternary, so after solving mod `Q` the solver maps `Q - 1` back to `-1`. Any other residue makes the solver exit with a non-ternary error.
- The vault's `work/artifacts/recovered.txt` holds the recovered secret and the flag. It is not needed to reproduce the solve and is not reproduced here.
- The printed value is the flag. This write-up redacts it. `chall.py` only holds the placeholder default `isfcr{REDACTED}`.
