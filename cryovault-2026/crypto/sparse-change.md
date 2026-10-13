### Summary

The sweep log `log[j] = F(g^j) = Σ c_i·(g^{e_i})^j` is a sum of 24 geometric sequences, so it satisfies a linear recurrence of order 24 whose characteristic polynomial is `Π (X - g^{e_i})`, rather than a degree-10^18 polynomial that needs interpolation. With 48 = 2·24 values, Berlekamp-Massey over GF(p) recovers that polynomial. Its roots give `g^{e_i}`, discrete logs give the exponents, and a Vandermonde solve gives the coefficients. The reconstructed term list derives the AES-GCM key that opens the flag.

### Steps

1. Read `files/chall.py`. The hidden map is `F(X) = Σ c_i·X^{e_i} mod p` with `T = 24` terms, and the sweep recorded `log[j] = F(g^j)` for `j = 0..47`. Since `log[j] = Σ c_i·(g^{e_i})^j`, the sequence obeys a linear recurrence of order `T` with characteristic polynomial `Π (X - g^{e_i})`. The values needed are in `files/output.json`: `p`, `g`, `t`, `log`, `flag_nonce`, `flag_ct` and `flag_tag`.

2. Run Berlekamp-Massey over GF(p) on the 48 values. It returns recurrence length `L = 24`, which equals `T`, and the connection polynomial. Reversing its coefficients gives the characteristic polynomial `X^L + C_1·X^(L-1) + ... + C_L`.

3. Split that polynomial over GF(p). The script takes `gcd(f, X^p - X)` to keep only linear factors, then splits the result with Cantor-Zassenhaus. It must find 24 distinct roots `r_i = g^{e_i}`.

4. Take discrete logs of the roots to base `g`, which gives the exponents `e_i`. `p - 1` is built from small primes in `[2^14, 2^22]` and 2, so Pohlig-Hellman in sympy is fast.

5. Solve the Vandermonde system `Σ_i c_i·r_i^j = log[j]` for `j = 0..23` to get the coefficients `c_i`. Then check that the recovered terms reproduce all 48 published evaluations.

6. Rebuild the key as in `chall.py`: `sha256(";".join(f"{e}:{c}"))` over the terms sorted by exponent. Decrypt `flag_ct || flag_tag` with AES-GCM under `flag_nonce` and no AAD. Run the solver from the challenge directory:

   ```sh
   python3 work/scripts/solve.py
   ```

   Output:

   ```
   [+] Berlekamp-Massey order L = 24 (expected 24)
   [+] found 24 linear roots over GF(p)
   [+] exponents recovered: [...]
   [+] all 48 evaluations reproduced
   [+] FLAG: isfcr{REDACTED}
   ```

### Scripts

#### scripts/solve.py

Runs Berlekamp-Massey, GF(p) root finding, discrete logs, the Vandermonde solve, checks all 48 evaluations and decrypts the flag. Run it from the challenge directory as `python3 work/scripts/solve.py`, which finds `files/output.json` automatically, or pass the path to `output.json` as the argument. It needs `sympy` and `cryptography`.

```python
#!/usr/bin/env python3
"""Recover the sparse-change flag.

The log values a_j = F(g^j) = sum_i c_i (g^{e_i})^j form a linear recurrence of
order T=24 whose characteristic polynomial is prod(X - g^{e_i}).  With 2T=48
evaluations Berlekamp-Massey recovers it; its roots are g^{e_i}, whose discrete
logs give the exponents e_i.  Coefficients follow from a Vandermonde solve.

Usage: python3 solve.py [path/to/output.json]
"""
import hashlib
import json
import sys
from pathlib import Path
from random import SystemRandom

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from sympy.ntheory.residue_ntheory import discrete_log


# Polynomials are coefficient lists, lowest degree first.

def bm(seq, p):
    """Berlekamp-Massey over GF(p). Returns (C, L) with recurrence
    s[n] = -sum_{i=1..L} C[i] s[n-i]."""
    C, B = [1], [1]
    L, m, b = 0, 1, 1
    for n in range(len(seq)):
        d = seq[n]
        for i in range(1, L + 1):
            d = (d + C[i] * seq[n - i]) % p
        if d == 0:
            m += 1
            continue
        T = C[:]
        coef = d * pow(b, -1, p) % p
        if len(C) < len(B) + m:
            C += [0] * (len(B) + m - len(C))
        for i in range(len(B)):
            C[i + m] = (C[i + m] - coef * B[i]) % p
        if 2 * L <= n:
            L = n + 1 - L
            B, b, m = T, d, 1
        else:
            m += 1
    return C, L


def poly_trim(a):
    while len(a) > 1 and a[-1] == 0:
        a.pop()
    return a


def poly_mul(a, b, p):
    r = [0] * (len(a) + len(b) - 1)
    for i, x in enumerate(a):
        if x:
            for j, y in enumerate(b):
                r[i + j] = (r[i + j] + x * y) % p
    return poly_trim(r)


def poly_divmod(a, b, p):
    """Polynomial division: returns (quotient, remainder)."""
    inv = pow(b[-1], -1, p)
    db = len(b) - 1
    a = a[:]
    q = [0] * max(1, len(a) - db)
    for i in range(len(a) - 1, db - 1, -1):
        if a[i]:
            f = a[i] * inv % p
            q[i - db] = f
            for j in range(db + 1):
                a[i - db + j] = (a[i - db + j] - f * b[j]) % p
    return poly_trim(q), poly_trim(a[:db] or [0])


def poly_mod(a, m, p):
    return poly_divmod(a, m, p)[1]


def poly_powmod(a, e, m, p):
    r, a = [1], poly_mod(a, m, p)
    while e:
        if e & 1:
            r = poly_mod(poly_mul(r, a, p), m, p)
        a = poly_mod(poly_mul(a, a, p), m, p)
        e >>= 1
    return r


def poly_gcd(a, b, p):
    a, b = poly_trim(a[:]), poly_trim(b[:])
    while b != [0]:
        a, b = b, poly_mod(a, b, p)
    return poly_trim(a)


def poly_roots(f, p):
    """Distinct roots of squarefree f over GF(p) via Cantor-Zassenhaus."""
    rng = SystemRandom()
    x = [0, 1]
    # f = gcd(f, x^p - x): keep only factors whose roots lie in GF(p).
    xp = poly_powmod(x, p, f, p)
    while len(xp) < 2:
        xp.append(0)
    xp[1] = (xp[1] - 1) % p
    f = poly_gcd(f, poly_trim(xp), p)
    out = []
    stack = [f]
    while stack:
        g = poly_trim(stack.pop())
        if len(g) <= 1:
            continue
        if len(g) == 2:
            out.append((-g[0] * pow(g[1], -1, p)) % p)
            continue
        while True:
            a = rng.randrange(0, p)
            # A root splits g via gcd(g, (x+a)^((p-1)/2) - 1).
            t = poly_powmod([a, 1], (p - 1) // 2, g, p)
            t[0] = (t[0] - 1) % p
            h = poly_gcd(g, poly_trim(t), p)
            if 0 < len(h) - 1 < len(g) - 1:
                stack.append(h)
                stack.append(poly_divmod(g, h, p)[0])
                break
    return sorted(set(out))


def solve_vandermonde(roots, vals, p):
    """Solve sum_i c_i roots_i^j = vals[j], j=0..n-1, mod p."""
    n = len(roots)
    M = []
    for j in range(n):
        M.append([pow(roots[i], j, p) for i in range(n)] + [vals[j] % p])
    for col in range(n):
        piv = next(r for r in range(col, n) if M[r][col] % p)
        M[col], M[piv] = M[piv], M[col]
        inv = pow(M[col][col], -1, p)
        M[col] = [v * inv % p for v in M[col]]
        for r in range(n):
            if r != col and M[r][col]:
                f = M[r][col]
                M[r] = [(M[r][k] - f * M[col][k]) % p for k in range(n + 1)]
    return [M[i][n] for i in range(n)]


def main():
    out_path = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(
        __file__).resolve().parents[2] / "files" / "output.json"
    data = json.loads(out_path.read_text())
    p, g, T = data["p"], data["g"], data["t"]
    log = data["log"]

    C, L = bm(log, p)
    print(f"[+] Berlekamp-Massey order L = {L} (expected {T})")
    # Characteristic polynomial: X^L + C[1] X^(L-1) + ... + C[L], ascending coeffs.
    char = [C[L - i] for i in range(L + 1)]  # index d -> coeff of X^d
    assert L == T, "unexpected recurrence order"

    roots = poly_roots(char, p)
    print(f"[+] found {len(roots)} linear roots over GF(p)")
    assert len(roots) == T

    exps = [discrete_log(p, r, g) for r in roots]
    print(f"[+] exponents recovered: {sorted(exps)}")

    coeffs = solve_vandermonde(roots, log, p)
    terms = sorted(zip(exps, coeffs))
    key = hashlib.sha256(";".join(f"{e}:{c}" for e, c in terms).encode()).digest()

    # Verify the recovered polynomial reproduces every published evaluation.
    for j, val in enumerate(log):
        x = pow(g, j, p)
        assert sum(c * pow(x, e, p) for e, c in terms) % p == val, f"mismatch at j={j}"
    print("[+] all 48 evaluations reproduced")

    aes = AESGCM(key)
    pt = aes.decrypt(bytes.fromhex(data["flag_nonce"]),
                     bytes.fromhex(data["flag_ct"]) + bytes.fromhex(data["flag_tag"]),
                     None)
    print(f"[+] FLAG: {pt.decode()}")


if __name__ == "__main__":
    main()
```

### Notes

- The AES-GCM tag is the validation. The derived key either passes the tag check or raises, so a successful decrypt proves the recovered term list is correct.
- Two dead ends are ruled out by the challenge: interpolating the full degree `p - 2` polynomial needs `p - 1` evaluations, and brute forcing which exponents are live means searching `C(p-1, 24)`, about 10^421 candidates.
- The recurrence length is only 24 because the sweep provides exactly `2T = 48` values. Fewer than `2T` values would not determine the recurrence.
