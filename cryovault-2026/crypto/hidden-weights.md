### Summary

The challenge hides both the 10 weights `a_i` and the binary selection matrix `X`, and publishes only the 50 subset sums `h_j = sum_i a_i * x[i][j] mod M`. The vectors `y` with `h . y = 0 mod M` form a lattice whose shortest vectors lie in the integer kernel of `X`, so they span the orthogonal complement of the row space of `X` (Nguyen-Stern orthogonal lattice attack). Recovering that row space and enumerating its short binary vectors gives the 10 rows of `X`. Solving `X^T a = h mod M` gives the weights, and the sorted weights hash to the AES-GCM key that opens the flag.

### Steps

1. Read the instance in `files/output.json`: `M` (a 201-bit prime), `n = 10` weights, `m = 50` rounds, the list `h`, and the sealed flag (`flag_ct`, `flag_tag`, `flag_nonce`). The generator in `files/chall.py` states the scheme and the key rule, `key = SHA256(",".join(map(str, sorted(weights))))`.

2. Build a full-rank basis of the relation lattice `L = {y in Z^m : h . y = 0 mod M}`. The naive generating set `{M e_i} plus {h}` has `m + 1` rows in dimension `m` and is rank-deficient. Using `h[0]` (invertible mod `M`, as the solver assumes), the basis is `e_i - h_i h_0^{-1} e_0` for `i >= 1` together with `M e_0`. LLL-reduce it. The 40 shortest vectors (`m - n`) have a clear norm gap and span the orthogonal complement of the row space.
   ```python
   inv_h0 = pow(h[0], -1, M)
   rows = []
   for i in range(1, m):
       v = [0] * m
       v[i] = 1
       v[0] = (-h[i] * inv_h0) % M
       rows.append(v)
   v = [0] * m
   v[0] = M
   rows.append(v)
   ```

3. Recover a basis of the row-space lattice `V cap Z^m`, which has rank 10. Form the embedding lattice of pairs `(x, scale * A x)` for `x` in `Z^m`, where the rows of `A` are the 40 kernel vectors and `scale = 10^6`. LLL-reduce it and keep the rows whose tail is zero. Those rows span the integer vectors of the row space.

4. Enumerate short vectors of that rank-10 lattice with coefficients in `{-1, 0, 1}` (`3^10 = 59049` combinations) and keep the ones with entries in `{0, 1}`. Exactly 10 binary vectors are found, and they are the rows `x_i`. If fewer than 10 are found, the solver retries with coefficients in `{-2..2}`.

5. Solve `X^T a = h mod M` for the weights. The solver runs Gaussian elimination mod `M` on the 50 equations, one per round, and then verifies that the weights reproduce every `h_j`. The weights are sorted and hashed, and the GCM tag is checked by `decrypt_and_verify`.

6. Run the solver from `work/` with the dependencies from `scripts/requirements.txt` installed.
   ```sh
   cd work
   python3 scripts/solve.py ../files/output.json
   ```
   ```text
   [*] M~2^201 n=10 m=50
   [*] kernel basis rows: 40
   [*] row-space lattice basis: 10
   [*] binary vectors found (coef<=1): 10
   [*] recovered weights: [576188020389782795523019761813433658046470093878326404725827, ...]
   [+] FLAG: isfcr{REDACTED}
   ```

### Scripts

#### scripts/requirements.txt

Lists the Python packages the solver imports (`fpylll` and `cysignals` for LLL, `numpy`, and `pycryptodome` for AES-GCM). The vault pins no versions.

```text
fpylll
cysignals
numpy
pycryptodome
```

#### scripts/solve.py

Runs the orthogonal-lattice attack, recovers the weights, decrypts the flag, and prints both; run it from `work/` as shown in step 6.

```python
#!/usr/bin/env python3
"""
hidden-weights: recover the secret weights of a hidden subset-sum instance and
decrypt the flag.

Scheme (files/chall.py): h_j = sum_i a_i * x_{i,j} mod M, x binary, and
key = SHA256(",".join(map(str, sorted(weights)))).

Attack (Nguyen-Stern orthogonal lattice):
  1. Build the relation lattice L = { y in Z^m : h.y = 0 mod M } and LLL it.
     Its short vectors lie in the integer kernel of X, hence span the orthogonal
     complement of the row space V = span{x_1,...,x_n}.
  2. Recover a basis of the row-space lattice V cap Z^m.
  3. Enumerate short vectors of V cap Z^m; the binary ones are the rows x_i.
  4. Solve X^T a = h mod M for a and decrypt (AES-GCM authenticates the result).

Requires: fpylll (+ cysignals), numpy, pycryptodome.
Run: python3 work/scripts/solve.py [path/to/output.json]
"""
import argparse
import itertools
import json
import sys
from hashlib import sha256
from pathlib import Path

import numpy as np
from fpylll import IntegerMatrix, LLL
from Crypto.Cipher import AES


def lll_rows(rows, delta=0.99):
    k, dim = len(rows), len(rows[0])
    b = IntegerMatrix(k, dim)
    for i in range(k):
        for j in range(dim):
            b[i, j] = int(rows[i][j])
    LLL.reduction(b, delta=delta)
    return [[int(b[i, j]) for j in range(dim)] for i in range(k)]


def relation_lattice(M, m, h):
    # L = { y : h.y = 0 mod M }, rank m, det M. h[0] is invertible by construction.
    inv_h0 = pow(h[0], -1, M)
    rows = []
    for i in range(1, m):
        v = [0] * m
        v[i] = 1
        v[0] = (-h[i] * inv_h0) % M
        rows.append(v)
    v = [0] * m
    v[0] = M
    rows.append(v)
    return rows


def kernel_rows(M, n, m, h):
    red = lll_rows(relation_lattice(M, m, h))
    red.sort(key=lambda r: sum(x * x for x in r))
    # the 40 shortest span the orthogonal complement (clear gap after m-n vectors)
    return red[: m - n]


def row_space_basis(ker, m, scale=10 ** 6):
    # embedding {(x, scale*A x)}; short tail-zero vectors span V cap Z^m
    r = len(ker)
    dim = m + r
    rows = []
    for i in range(m):
        row = [0] * dim
        row[i] = 1
        for k in range(r):
            row[m + k] = scale * int(ker[k][i])
        rows.append(row)
    red = lll_rows(rows)
    basis = [row[:m] for row in red if all(x == 0 for x in row[m:]) and any(row[:m])]
    return basis


def enumerate_binary(basis, max_coef=1, max_norm2=80):
    b = np.array(basis, dtype=np.int64)
    k = b.shape[0]
    found = []
    seen = set()
    for coef in itertools.product(range(-max_coef, max_coef + 1), repeat=k):
        if not any(coef):
            continue
        v = np.asarray(coef, dtype=np.int64) @ b
        if int(v @ v) > max_norm2:
            continue
        if np.all((v == 0) | (v == 1)):
            t = tuple(int(x) for x in v)
            if t not in seen:
                seen.add(t)
                found.append(list(t))
    return found


def solve_weights(X_rows, M, h):
    # X_rows: list of n binary rows x_i over m rounds -> h_j = sum_i x_i[j]*a_i
    n = len(X_rows)
    m = len(X_rows[0])
    # gaussian elimination mod M over the m equations (one per round)
    rows = [[X_rows[i][j] % M for i in range(n)] + [h[j] % M] for j in range(m)]
    piv = []
    r = 0
    for c in range(n):
        p = next((i for i in range(r, m) if rows[i][c] % M), None)
        if p is None:
            continue
        rows[r], rows[p] = rows[p], rows[r]
        inv = pow(rows[r][c], -1, M)
        rows[r] = [(x * inv) % M for x in rows[r]]
        for i in range(m):
            if i != r and rows[i][c] % M:
                f = rows[i][c] % M
                rows[i] = [(rows[i][j] - f * rows[r][j]) % M for j in range(n + 1)]
        piv.append(c)
        r += 1
        if r == n:
            break
    if len(piv) < n:
        return None
    a = [0] * n
    for i, c in enumerate(piv):
        a[c] = rows[i][n]
    if any(sum(X_rows[i][j] * a[i] for i in range(n)) % M != h[j] % M for j in range(m)):
        return None
    return a


def main():
    default = Path(__file__).resolve().parents[2] / "files" / "output.json"
    ap = argparse.ArgumentParser()
    ap.add_argument("path", nargs="?", default=str(default))
    args = ap.parse_args()

    d = json.loads(Path(args.path).read_text())
    M, n, m, h = d["M"], d["n"], d["m"], d["h"]
    print(f"[*] M~2^{M.bit_length()} n={n} m={m}")

    ker = kernel_rows(M, n, m, h)
    print(f"[*] kernel basis rows: {len(ker)}")
    basis = row_space_basis(ker, m)
    print(f"[*] row-space lattice basis: {len(basis)}")

    weights = None
    for max_coef in (1, 2):
        bins = enumerate_binary(basis, max_coef=max_coef)
        print(f"[*] binary vectors found (coef<={max_coef}): {len(bins)}")
        if len(bins) < n:
            continue
        combos = itertools.combinations(range(len(bins)), n) if len(bins) > n else [tuple(range(len(bins)))]
        for idx in combos:
            Xr = [bins[i] for i in idx]
            a = solve_weights(Xr, M, h)
            if a is not None:
                weights = a
                break
        if weights is not None:
            break

    if weights is None:
        print("[!] failed to recover weights")
        sys.exit(1)

    print("[*] recovered weights:", weights)
    key = sha256(",".join(map(str, sorted(weights))).encode()).digest()
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

- A rank-deficient naive basis makes fpylll return useless vectors. The full-rank `m x m` basis from step 2 is required.
- The duplicate `h[19] == h[20]` is incidental and the attack does not use it.
- The solver also checks the GCM tag, so a wrong weight set cannot produce a plausible flag.
- The vault's `work/artifacts/recovered.txt` holds the sorted weights and the flag. It is not needed to reproduce the solve and is not reproduced here.
- The printed value is the flag. This write-up redacts it. `chall.py` only holds the placeholder default `isfcr{REDACTED}`.
