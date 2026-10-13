### Summary

The 512 shares are points of a degree-39 polynomial `f` over `GF(2^31 - 1)`, but 327 of them were replaced by random values, so only 185 are honest. With 327 errors, the unique-decoding radius `(n-k)/2 = 236` and even the Sudan radius (about 312) are exceeded, so the attack needs list decoding. Guruswami-Sudan interpolation with multiplicity 2 finds a bivariate polynomial `Q(x, y)` that contains the factor `y - f(x)`, and Hensel lifting extracts `f`. The AES key is `SHA256` of the coefficients of `f`, and that key opens the flag.

### Steps

1. Read `files/output.json`. It holds `p = 2^31 - 1`, the threshold `k = 40` (so `deg f = 39`), the share count `n = 512`, the honest count `t = 185`, the 512 shares `[x, y]`, and the sealed flag (`flag_ct`, `flag_tag`, `flag_nonce`). The generator in `files/chall.py` confirms the key rule: the coefficients of `f`, low order first, decimal, comma-joined, hashed with SHA256.

2. Pick the list-decoding parameters. Multiplicity `m = 2` means every share is a double point, which gives `n * m(m+1)/2 = 1536` linear conditions (`Q = Q_x = Q_y = 0` at each point). The weighted degree is `i + 39 j <= D` for monomials `x^i y^j`. The solver chooses the smallest `D` whose monomial count exceeds 1536, then adds 4. For `D = 326` there are 1539 monomials, so the solver uses `D = 330` with 1575 monomials. The homogeneous system has a nonzero kernel (`STATE.md` records rank 1497 with 1536 constraints).
   ```text
   D = 330: 1575 monomials, 1536 constraints, nonzero kernel
   ```
   The kernel is found by Gaussian elimination mod `p` with `int64` numpy arithmetic. The free column is set to 1 and the pivot unknowns are back-substituted.

3. Extract `y - f(x)`. For a random `x0`, evaluate `U(y) = Q(x0, y)` and find its roots in `GF(p)`. A root `y0` lifts to a power series `Y(z)` with `Y(0) = y0` and `Q(x0 + z, Y(z)) = 0 mod z^40` (Hensel lifting, Newton iteration on the series). Converting `Y(x - x0)` back to ordinary coefficients gives a candidate `f`. The solver keeps the candidate only if it matches at least `t = 185` shares.

4. Derive the key and decrypt. The key is `SHA256` of the comma-joined coefficients of `f`, and the GCM tag authenticates the plaintext.
   ```python
   key = hashlib.sha256(",".join(map(str, f)).encode()).digest()
   pt = AESGCM(key).decrypt(bytes.fromhex(d["flag_nonce"]),
                            bytes.fromhex(d["flag_ct"]) + bytes.fromhex(d["flag_tag"]), None)
   ```

5. Run the solver from `work/`. It takes the path to `output.json` as an optional argument. The run takes about 22 seconds.
   ```sh
   python3 scripts/solve.py ../files/output.json
   ```
   ```text
   isfcr{REDACTED}
   ```

### Scripts

#### scripts/solve.py

Builds and solves the Guruswami-Sudan system, extracts `f` by Hensel lifting, checks it against the shares, and decrypts the flag; run it as shown in step 5 and it needs `numpy` and `cryptography`.

```python
#!/usr/bin/env python3
"""half-truths: recover the degree-39 polynomial from 512 shares, 327 of them lies.

List-decodes the Reed-Solomon word past the unique-decoding radius using the
Guruswami-Sudan algorithm with multiplicity 2 (every share is forced to be a
double point of the interpolation polynomial Q(x,y)); then extracts the factor
y - f(x) by Hensel lifting a power-series root and converting it back to a
polynomial. The key is sha256 of f's coefficients (low first, decimal, comma
joined); the flag is AES-GCM sealed under it.

Usage: python3 scripts/solve.py files/output.json
Depends on numpy and cryptography (AESGCM).
"""
import hashlib
import json
import random
import sys

import numpy as np
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

P = 2147483647          # field prime, 2^31 - 1
K = 40                  # threshold (deg f = 39)
W = K - 1               # y-weight for the (1,W) weighted degree
MULT = 2                # Guruswami-Sudan multiplicity


# interpolation
def build_and_solve(xs, ys, n):
    def nmono(D):
        return sum(D - W * j + 1 for j in range(D // W + 1))

    D = 1
    while nmono(D) <= n * MULT * (MULT + 1) // 2:
        D += 1
    D += 4
    assert MULT * n > 0
    monos = [(i, j) for j in range(D // W + 1) for i in range(D - W * j + 1)]
    mi = np.array([i for i, j in monos], dtype=np.int64)
    mj = np.array([j for i, j in monos], dtype=np.int64)
    rows = []
    for t in range(n):
        x, y = xs[t], ys[t]
        xp = np.empty(D + 1, dtype=np.int64); xp[0] = 1
        for e in range(1, D + 1):
            xp[e] = xp[e - 1] * x % P
        yp = np.empty(int(mj.max()) + 1, dtype=np.int64); yp[0] = 1
        for e in range(1, int(mj.max()) + 1):
            yp[e] = yp[e - 1] * y % P
        xi = xp[mi]; yj = yp[mj]
        rows.append(xi * yj % P)                                       # Q
        xi1 = np.where(mi >= 1, xp[np.maximum(mi - 1, 0)], 0)
        rows.append((mi % P) * xi1 % P * yj % P)                        # dQ/dx
        yj1 = np.where(mj >= 1, yp[np.maximum(mj - 1, 0)], 0)
        rows.append(xi * ((mj % P) * yj1 % P) % P)                      # dQ/dy
    A = np.array(rows, dtype=np.int64)
    r, c = A.shape
    pivots = []
    pr = 0
    for col in range(c):
        nz = np.nonzero(A[pr:, col])[0]
        if nz.size == 0:
            continue
        p2 = pr + int(nz[0])
        if p2 != pr:
            A[[pr, p2]] = A[[p2, pr]]
        inv = pow(int(A[pr, col]), P - 2, P)
        A[pr] = A[pr] * inv % P
        if A[pr + 1:].shape[0]:
            fac = A[pr + 1:, col].copy()
            A[pr + 1:] = (A[pr + 1:] - np.outer(fac, A[pr])) % P
        pivots.append((pr, col))
        pr += 1
        if pr == r:
            break
    pivotcols = set(c2 for _, c2 in pivots)
    freecols = [cc for cc in range(c) if cc not in pivotcols]
    xv = [0] * c
    xv[freecols[-1]] = 1
    for rr, cc in reversed(pivots):
        s = 0
        row = A[rr]
        for j in range(cc + 1, c):
            if xv[j] and row[j]:
                s += int(row[j]) * xv[j]
        xv[cc] = (-s) % P
    jmax = max(j for i, j in monos)
    qj = []
    for j in range(jmax + 1):
        poly = [0] * (D - W * j + 1)
        for idx, (i, jj) in enumerate(monos):
            if jj == j:
                poly[i] = xv[idx]
        qj.append(poly)
    return qj


# GF(p) polynomials
def trim(a):
    while len(a) > 1 and a[-1] % P == 0:
        a = a[:-1]
    return a


def pmul(a, b):
    r = [0] * (len(a) + len(b) - 1)
    for i, ai in enumerate(a):
        if ai:
            for j, bj in enumerate(b):
                r[i + j] = (r[i + j] + ai * bj) % P
    return trim(r)


def psub(a, b):
    n = max(len(a), len(b)); r = [0] * n
    for i in range(n):
        r[i] = ((a[i] if i < len(a) else 0) - (b[i] if i < len(b) else 0)) % P
    return trim(r)


def pdivmod(a, b):
    b = trim(b); inv = pow(b[-1], P - 2, P); a = list(a)
    q = [0] * max(1, len(a) - len(b) + 1)
    while len(a) >= len(b) and not (len(a) == 1 and a[0] == 0):
        deg = len(a) - len(b); coef = a[-1] * inv % P; q[deg] = coef
        for i in range(len(b)):
            a[deg + i] = (a[deg + i] - coef * b[i]) % P
        a = trim(a)
        if len(a) < len(b):
            break
    return trim(q), trim(a if a else [0])


def pgcd(a, b):
    a = trim(a); b = trim(b)
    while not (len(b) == 1 and b[0] == 0):
        _, r = pdivmod(a, b); a, b = b, r
    return trim([c * pow(a[-1], P - 2, P) % P for c in a])


def ppowmod(base, e, mod):
    res = [1]; base = pdivmod(base, mod)[1]
    while e:
        if e & 1:
            res = pdivmod(pmul(res, base), mod)[1]
        base = pdivmod(pmul(base, base), mod)[1]; e >>= 1
    return res


def proots(U):
    U = trim(U)
    if len(U) <= 1:
        return []
    g = pgcd(U, psub(ppowmod([0, 1], P, U), [0, 1]))
    rnd = random.Random(1234); out = []; stack = [g]
    while stack:
        f = stack.pop()
        if len(f) == 1:
            continue
        if len(f) == 2:
            out.append(-f[0] * pow(f[1], P - 2, P) % P); continue
        for _ in range(200):
            a = rnd.randrange(1, P)
            h = psub(ppowmod([a, 1], (P - 1) // 2, f), [1])
            dd = pgcd(f, h)
            if 0 < len(dd) - 1 < len(f) - 1:
                qq, _ = pdivmod(f, dd); stack += [dd, qq]; break
    return out


# truncated series
L = K
def smul(a, b):
    r = [0] * min(len(a) + len(b) - 1, L)
    for i, ai in enumerate(a):
        if ai:
            for j, bj in enumerate(b):
                if i + j < L:
                    r[i + j] = (r[i + j] + ai * bj) % P
    return r


def sadd(a, b):
    n = min(max(len(a), len(b)), L); r = [0] * n
    for i in range(n):
        r[i] = ((a[i] if i < len(a) else 0) + (b[i] if i < len(b) else 0)) % P
    return r


def sinv(a):
    r = [pow(a[0], P - 2, P)]; k = 1
    while k < L:
        k2 = min(2 * k, L)
        ar = smul(a, r)
        t = [(-ar[i]) % P if i < len(ar) else 0 for i in range(k2)]
        t[0] = (t[0] + 2) % P
        r = smul(r, t)[:k2]; k = k2
    return r


def shift_series(poly, x0):
    a = list(poly); out = []
    for _ in range(min(L, len(poly))):
        val = 0
        for c in reversed(a):
            val = (val * x0 + c) % P
        out.append(val)
        a = trim([(i * a[i]) % P for i in range(1, len(a))]) if len(a) > 1 else [0]
    out += [0] * (L - len(out))
    fact = 1
    for t in range(L):
        out[t] = out[t] * pow(fact, P - 2, P) % P
        fact = fact * (t + 1) % P
    return out


def hensel(qj, x0, y0):
    jmax = len(qj) - 1
    qs = [shift_series(qj[j], x0) for j in range(jmax + 1)]
    Y = [y0 % P] + [0] * (L - 1)
    prec = 1
    while prec < L:
        prec2 = min(2 * prec, L)
        Yp = [[1] + [0] * (L - 1)]
        for j in range(1, jmax + 1):
            Yp.append(smul(Yp[-1], Y))
        F = [0] * L; FY = [0] * L
        for j in range(jmax + 1):
            F = sadd(F, smul(qs[j], Yp[j]))
            if j >= 1:
                FY = sadd(FY, smul([j * qs[j][t] % P for t in range(L)], Yp[j - 1]))
        F = (F + [0] * (prec2 - len(F)))[:prec2]
        FY = (FY + [0] * (prec2 - len(FY)))[:prec2]
        if FY[0] % P == 0:
            return None
        corr = smul(F, sinv(FY))[:prec2]
        Y = [(Y[i] - (corr[i] if i < len(corr) else 0)) % P for i in range(L)]
        prec = prec2
    return Y


def series_to_poly(Y, x0):
    f = [0] * K
    for t in range(K):
        a = Y[t]
        if not a:
            continue
        c = 1
        for m in range(t + 1):
            f[m] = (f[m] + a * c % P * pow((-x0) % P, t - m, P)) % P
            c = c * (t - m) // (m + 1)
    return trim(f)


def main(path):
    d = json.load(open(path))
    shares = d["shares"]
    xs = [s[0] % P for s in shares]
    ys = [s[1] % P for s in shares]
    n = len(shares)
    qj = build_and_solve(xs, ys, n)
    rnd = random.Random(7)
    for _ in range(80):
        x0 = rnd.randrange(1, P)
        U = []
        for j in range(len(qj)):
            val = 0
            for c in reversed(qj[j]):
                val = (val * x0 + c) % P
            U.append(val)
        for y0 in proots(U):
            Y = hensel(qj, x0, y0)
            if Y is None:
                continue
            f = series_to_poly(Y, x0)
            good = sum(1 for i in range(n)
                       if sum(f[k] * pow(xs[i], k, P) for k in range(len(f))) % P == ys[i])
            if good >= d["t"]:
                key = hashlib.sha256(",".join(map(str, f)).encode()).digest()
                pt = AESGCM(key).decrypt(bytes.fromhex(d["flag_nonce"]),
                                         bytes.fromhex(d["flag_ct"]) + bytes.fromhex(d["flag_tag"]),
                                         None)
                print(pt.decode())
                return
    raise SystemExit("not found")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "files/output.json")
```

### Notes

- Berlekamp-Welch and other unique decoders cannot work here: with 327 errors, the system is underdetermined (the unique radius is 236).
- Sudan list decoding with `m = 1` corrects only about 312 errors, which is still short of 327. Multiplicity 2 raises the radius to about 339, which covers 327.
- The vault has no `requirements.txt` for this challenge. The script needs `numpy` and `cryptography` only.
- The solver tries random `x0` values and several roots, so the first candidate that matches 185 shares is the one it prints.
- The printed value is the flag. This write-up redacts it. `chall.py` only holds the placeholder default `isfcr{REDACTED}`.
