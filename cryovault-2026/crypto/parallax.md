### Summary

The 40 public samples are 0/1 subset sums of 14 hidden atoms modulo a 224-bit prime, so recovering the mask is a modular hidden-subset-sum problem. An orthogonal-lattice attack with LLL recovers the mask and then the atoms. Eight small integer relations cancel every quadratic term of the atom polynomials and leave linear equations in four 56-bit limbs, which lattice CVP solves. The limbs rebuild the ChaCha20Poly1305 key that opens the seal and reveals the flag.

### Steps

1. Read `files/model.py` and `files/observations.json`. Each sample is `sample[i] = Σ_j mask[i][j]·atom[j] mod p` for a hidden 40 by 14 binary mask whose column weights are published in `column_weights` (12 to 25). Each atom is `g(j, limbs) + e_j`, where `g` has degree 2 in four hidden limbs below `modulus = 2^56`, and `e_j` is a nonzero centered integer with `|e_j| <= error_limit`. The seal key is `sha256(b"parallax-v1\x00" + limbs)`, where each limb is encoded as 7 little-endian bytes. The decrypted payload is 28 ASCII bytes.

2. Recover the mask. Run LLL on the lattice of integer vectors `y` with `y · samples = 0 mod p`. The 26 shortest vectors are short exact integer relations among the samples. Their integer kernel (computed via Smith normal form) is a 14-dimensional lattice that contains the mask columns. Its 0/1 vectors with weight `w` give exactly one column for each published weight, which pins down the mask. The script asserts that each weight has a unique candidate.

3. Solve `M · atoms = samples (mod p)` for the 14 atoms with the recovered mask `M`. The script checks that the solution reproduces all 40 samples.

4. Recover the four limbs. The quadratic parts of the 14 atom polynomials span only 6 dimensions, so there are 8 small integer vectors `v` with `v^T Q = 0` exactly. Each gives a linear equation `v^T L x = v^T (atoms - const) - v^T e` in the limbs, with small error `|v^T e| << p`. The script builds a CVP lattice with weight `2^shift` over these equations and tries shifts 120, 100, 110, 90, 130 and 80. It accepts the first result where all four limbs lie in `[0, modulus)` and all 14 atom errors are nonzero and within `error_limit`. Then it opens the seal.

   Run the whole pipeline from the challenge directory:

   ```sh
   python3 work/scripts/solve_parallax.py
   ```

   The script prints the recovered limbs and the decrypted payload, which is the flag:

   ```
   limbs: [four integers below 2^56]
   payload: b'isfcr{REDACTED}'
   ```

### Scripts

#### scripts/solve_parallax.py

Recovers the mask, the 14 atoms and the 4 limbs, writes the evidence to `work/artifacts/parallax_recovered.json`, and prints the decrypted seal. Run it from the challenge directory (`python3 work/scripts/solve_parallax.py`), because it opens `files/observations.json` by a relative path. It needs `fpylll`, `sympy` and `cryptography`.

```python
#!/usr/bin/env python3
"""Parallax (id 49) solver.

Pipeline:
  1. Recover the 14 hidden atoms from the 40 public samples with the
     orthogonal-lattice hidden-subset-sum attack (Nguyen-Stern style), using
     the known column weights of the binary mask to select the columns.
  2. Recover the 4 limbs from the atoms: 8 small integer relations cancel the
     quadratic terms of the atom polynomials exactly, leaving 8 linear
     equations in the limbs with small errors, solved by lattice CVP.
  3. Rebuild the ChaCha20Poly1305 key from the limbs and open the seal.

Run from the challenge directory (challenges/crypto/parallax):
    python3 work/scripts/solve_parallax.py
"""
import json, math, hashlib
from fractions import Fraction

from fpylll import IntegerMatrix, LLL, CVP
from sympy import Matrix
from sympy.matrices.normalforms import smith_normal_decomp
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

N = 14
M = 40

D = json.load(open('files/observations.json'))
p = int(D['prime'])
modulus = int(D['modulus'])
err_limit = int(D['error_limit'])
WEIGHTS = [int(w) for w in D['column_weights']]
SAMPLES = [int(v) % p for v in D['samples']]


def lll_rows(rows):
    r, m = len(rows), len(rows[0])
    B = IntegerMatrix(r, m)
    for i in range(r):
        for j in range(m):
            B[i, j] = int(rows[i][j])
    LLL.reduction(B)
    return [[int(B[i, j]) for j in range(m)] for i in range(r)]


def integer_kernel(rows):
    """Basis of {z in Z^m : rows . z = 0} via Smith normal form."""
    S, U, V = smith_normal_decomp(Matrix(rows))
    m = Matrix(rows).cols
    diag = [S[i, i] for i in range(min(S.rows, S.cols))]
    zero_cols = [i for i in range(m) if (i >= len(diag) or S[i, i] == 0)]
    return [[int(V[r, i]) for r in range(m)] for i in zero_cols]


def gram_schmidt(basis):
    n, m = len(basis), len(basis[0])
    bstar, mu, Bn = [], [[Fraction(0)] * n for _ in range(n)], []
    for i in range(n):
        v = [Fraction(x) for x in basis[i]]
        for j in range(i):
            mu[i][j] = sum(Fraction(basis[i][k]) * bstar[j][k] for k in range(m)) / Bn[j]
            v = [v[k] - mu[i][j] * bstar[j][k] for k in range(m)]
        bstar.append(v)
        Bn.append(sum(x * x for x in v))
    return mu, Bn


def enum_short(basis, R2):
    """All nonzero lattice vectors with squared norm <= R2 (Fincke-Pohst)."""
    n, m = len(basis), len(basis[0])
    mu, Bn = gram_schmidt(basis)
    out, coeffs = [], [0] * n

    def rec(i, partial):
        if i < 0:
            out.append(coeffs[:])
            return
        center = Fraction(0)
        for j in range(i + 1, n):
            if coeffs[j]:
                center += coeffs[j] * mu[j][i]
        rem = R2 - partial
        if rem < 0:
            return
        rad = math.sqrt(max(0.0, float(rem / Bn[i])))
        c = float(center)
        for xi in range(math.floor(-rad - c - 1), math.ceil(rad - c + 1) + 1):
            term = Bn[i] * (Fraction(xi) + center) ** 2
            if term <= rem + Fraction(1, 10 ** 9):
                coeffs[i] = xi
                rec(i - 1, partial + term)
                coeffs[i] = 0

    rec(n - 1, Fraction(0))
    return out


def solve_mod(Amat, rhs):
    rows = [[Amat[i][j] % p for j in range(N)] + [rhs[i] % p] for i in range(M)]
    piv, r = [], 0
    for c in range(N):
        pr = next((i for i in range(r, M) if rows[i][c] % p), None)
        if pr is None:
            continue
        rows[r], rows[pr] = rows[pr], rows[r]
        inv = pow(rows[r][c], p - 2, p)
        rows[r] = [(v * inv) % p for v in rows[r]]
        for i in range(M):
            if i != r and rows[i][c] % p:
                f = rows[i][c]
                rows[i] = [(rows[i][k] - f * rows[r][k]) % p for k in range(N + 1)]
        piv.append(c)
        r += 1
    for i in range(r, M):
        if all(rows[i][k] == 0 for k in range(N)) and rows[i][N] % p != 0:
            return None
    sol = [0] * N
    for idx, c in enumerate(piv):
        sol[c] = rows[idx][N] % p
    return sol


def recover_atoms():
    inv = pow(SAMPLES[M - 1], p - 2, p)
    B = IntegerMatrix(M, M)
    for i in range(M - 1):
        B[i, i] = 1
        B[i, M - 1] = -((SAMPLES[i] * inv) % p)
    B[M - 1, M - 1] = p
    LLL.reduction(B)
    rows = [[int(B[i, j]) for j in range(M)] for i in range(M)]
    norms = [sum(v * v for v in r) for r in rows]
    order = sorted(range(M), key=lambda i: norms[i])
    relations = [rows[i] for i in order[:M - N]]          # 26 short exact relations
    Wb = lll_rows(integer_kernel(relations))              # column space lattice
    bins = {}
    for c in enum_short(Wb, 30):
        vec = [0] * M
        for k in range(len(Wb)):
            if c[k]:
                for t in range(M):
                    vec[t] += c[k] * Wb[k][t]
        if all(t in (0, 1) for t in vec):
            bins.setdefault(sum(vec), set()).add(tuple(vec))
    cols = {}
    for w in WEIGHTS:
        assert len(bins.get(w, ())) == 1, (w, len(bins.get(w, ())))
        cols[w] = next(iter(bins[w]))
    Amat = [[0] * N for _ in range(M)]
    for j in range(N):
        for i in range(M):
            Amat[i][j] = cols[WEIGHTS[j]][i]
    atoms = solve_mod(Amat, SAMPLES)
    assert atoms and all(sum(Amat[i][j] * atoms[j] for j in range(N)) % p == SAMPLES[i] for i in range(M))
    return atoms, Amat


def recover_limbs(atoms):
    Q = [[int(D['quad'][j][k]) for k in range(10)] for j in range(N)]
    rels = lll_rows(integer_kernel(Matrix(Q).T.tolist()))   # v with v^T Q = 0 exactly
    L = [[int(D['linear'][j][i]) for i in range(4)] for j in range(N)]
    const = [int(D['constant'][j]) for j in range(N)]
    b = [(atoms[j] - const[j]) % p for j in range(N)]
    k = len(rels)
    Alin = [[sum(rels[l][j] * L[j][i] for j in range(N)) % p for i in range(4)] for l in range(k)]
    w = [sum(rels[l][j] * b[j] for j in range(N)) % p for l in range(k)]

    def cvp(W):
        n = 4 + k
        B = IntegerMatrix(n, n)
        for i in range(4):
            B[i, i] = W
            for l in range(k):
                B[i, 4 + l] = Alin[l][i] % p
        for l in range(k):
            B[4 + l, 4 + l] = p
        LLL.reduction(B)
        cv = CVP.closest_vector(B, [0, 0, 0, 0] + [w[l] % p for l in range(k)])
        return [int(cv[i]) // W % modulus for i in range(4)]

    pos = D['positions']

    def errors(x):
        out = []
        for j in range(N):
            g = const[j]
            for i in range(4):
                g += L[j][i] * x[i]
            for k2, (a_, b_) in enumerate(pos):
                g += int(D['quad'][j][k2]) * x[a_] * x[b_]
            r = (atoms[j] - g) % p
            out.append(r - p if r > p // 2 else r)
        return out

    for shift in (120, 100, 110, 90, 130, 80):
        x = cvp(1 << shift)
        if all(0 <= v < modulus for v in x) and all(e != 0 and abs(e) <= err_limit for e in errors(x)):
            return x, errors(x)
    raise RuntimeError("limb recovery failed")


def open_seal(limbs):
    encoded = b"".join(int(v).to_bytes(7, "little") for v in limbs)
    key = hashlib.sha256(b"parallax-v1\x00" + encoded).digest()
    return ChaCha20Poly1305(key).decrypt(
        bytes.fromhex(D['nonce']), bytes.fromhex(D['ciphertext']), b"parallax-v1")


if __name__ == '__main__':
    atoms, Amat = recover_atoms()
    limbs, errs = recover_limbs(atoms)
    json.dump({"atoms": [str(a) for a in atoms],
               "columns": {str(w): [i for i in range(M) if Amat[i][WEIGHTS.index(w)]] for w in WEIGHTS},
               "limbs": [str(v) for v in limbs],
               "errors": [str(e) for e in errs]},
              open('work/artifacts/parallax_recovered.json', 'w'), indent=1)
    print("limbs:", limbs)
    print("payload:", open_seal(limbs))
```

### Notes

- A direct exact linearization of the atom system is inconsistent, because the atom errors are nonzero. The quadratic-cancelling relations are what make the limb recovery work.
- The mask has no simple structure. Recurrences and window or prefix families were checked and do not fit the samples, so the lattice attack is required.
- The script does not compare against the flag. The AEAD tag authenticates the payload, so a wrong limb vector raises an error instead of printing a plausible plaintext.
- Exploratory scripts in `work/scratch/` were not used for the final solve.
