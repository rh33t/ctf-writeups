### Summary

The two RSA moduli `N1 = p1*q1` and `N2 = p2*q2` use 1024-bit primes `p1`, `p2` that share their low `T = 530` bits, so `p1 = p2 mod 2^530`. Then `N1*q2 - N2*q1 = (p1 - p2)*q1*q2` is divisible by `2^530`, which places `(q1, q2)` on a 2-D lattice of determinant `2^530`. Because `q1*q2 < 2^530`, the vector `(q1, q2)` is far shorter than the lattice's typical vector, and Lagrange-Gauss reduction returns it directly. That reveals `q1`, which factors `N1`, and textbook RSA with `e = 65537` then decrypts the flag.

### Steps

1. Read `files/chall.py`. It sets `AP = 1024`, `AQ = 256`, `T = 530`, `E = 65537`. Each prime is `p = (randrange(1 << (AP - T)) << T) | low` with a shared `low`, and each `q` is a random 256-bit prime. The published data in `files/output.json` is `N1`, `N2`, `e`, and `ct` (the flag encrypted as a single integer under `N1`).

2. Derive the lattice. Let `M = 2^530`, `u = N1 mod M`, and `v = N2 mod M`. Because `p1 = p2 mod M`, the relation `N1*q2 - N2*q1 = 0 mod M` becomes `v*q1 - u*q2 = 0 mod M`. So `(q1, q2)` lies in the lattice `{(x, y) : v*x - u*y = 0 mod M}`, which has the basis `(M, 0)` and `(c, 1)` with `c = u * v^{-1} mod M`. Its determinant is `M`, so the typical shortest vector has norm about `2^265`, while `(q1, q2)` has norm about `2^256.5`.

3. Reduce the basis with Lagrange-Gauss reduction. This is the 2-D analogue of LLL, and it terminates with the short vector. Its components are the candidate factors up to sign.
   ```text
   short vector: |x| = 256 bits, |y| = 256 bits
   ```

4. Recover the factors. Try the four sign choices of each short component and keep the one that divides `N1` (or `N2`). This gives `q1` and `q2`, and then `p1 = N1 / q1` and `p2 = N2 / q2`. The solver checks that `p1 mod M == p2 mod M`, which confirms the twin property.
   ```text
   q1 = 64786187931412698251315414543156383486243083059864580047096727329372877393731  (256 bits)
   q2 = 101170715875140300554035433180998346142859797727066397463037064832869009328241  (256 bits)
   p1 and p2: 1024 bits each, p1 mod 2^530 == p2 mod 2^530
   ```

5. Decrypt. Compute `d = e^{-1} mod (p1 - 1)(q1 - 1)` and `m = ct^d mod N1`, then convert `m` to bytes. The result is the flag as ASCII text.
   ```python
   phi = (p1 - 1) * (q1 - 1)
   m = pow(ct, pow(e, -1, phi), N1)
   flag = m.to_bytes((m.bit_length() + 7) // 8, "big")
   ```

6. Run the solver from `work/`. It is pure Python standard library and runs in well under a second.
   ```sh
   python3 scripts/solve.py ../files/output.json
   ```
   ```text
   short vector: |x| = 256 bits, |y| = 256 bits
   q1 = 64786187931412698251315414543156383486243083059864580047096727329372877393731  (256 bits)
   q2 = 101170715875140300554035433180998346142859797727066397463037064832869009328241  (256 bits)
   shared low 530 bits match: True
   isfcr{REDACTED}
   ```

### Scripts

#### scripts/solve.py

Runs the full attack (2-D lattice reduction, factor recovery, RSA decryption) using only the standard library; run it from `work/` as shown in step 6.

```python
#!/usr/bin/env python3
"""Solve implicit-twins (crypto, id 9).

chall.py builds N1 = p1*q1 and N2 = p2*q2 with 256-bit q and 1024-bit p, where
p1 and p2 share their low T = 530 bits. Writing M = 2**T and p_i = x_i*M + l:

    N1*q2 - N2*q1 = (p1 - p2)*q1*q2 = (x1 - x2)*M*q1*q2  == 0 (mod M)

So with u = N1 mod M and v = N2 mod M, the point (q1, q2) lies on the 2-D
lattice {(x, y) : v*x - u*y == 0 (mod M)}, of determinant M. Its shortest vector
has norm ~2**(T/2) = 2**265, while ||(q1, q2)|| ~ 2**256.5, so Lagrange-Gauss
reduction recovers (q1, q2) exactly. Factoring N1 then decrypts the flag.

Run: python3 scripts/solve.py [files/output.json]
"""
import json
import math
import sys

T = 530  # shared low bits of p1, p2 (from chall.py)


def gauss(a, b):
    """Lagrange-Gauss reduction of the 2-D lattice basis (a, b)."""
    def norm2(w):
        return w[0] * w[0] + w[1] * w[1]

    while True:
        if norm2(b) < norm2(a):
            a, b = b, a
        dot = a[0] * b[0] + a[1] * b[1]
        den = norm2(a)
        # nearest integer to dot/den, with correct sign handling
        mu = (2 * dot + den) // (2 * den) if dot >= 0 else -((2 * -dot + den) // (2 * den))
        if mu == 0:
            return a
        b = (b[0] - mu * a[0], b[1] - mu * a[1])


def solve(path):
    d = json.load(open(path))
    N1, N2, e, ct = d["N1"], d["N2"], d["e"], d["ct"]
    M = 1 << T

    u, v = N1 % M, N2 % M
    c = (u * pow(v, -1, M)) % M
    x, y = gauss((M, 0), (c, 1))

    q1 = next(-s * x for s in (1, -1) if -s * x > 1 and N1 % (-s * x) == 0)
    q2 = next(-s * y for s in (1, -1) if -s * y > 1 and N2 % (-s * y) == 0)
    p1, p2 = N1 // q1, N2 // q2

    assert p1 % M == p2 % M, "twin property not reproduced"
    d1 = pow(e, -1, (p1 - 1) * (q1 - 1))
    m = pow(ct, d1, N1)
    flag = m.to_bytes((m.bit_length() + 7) // 8, "big")
    print(f"q1 = {q1}\nq2 = {q2}")
    print(f"shared low {T} bits: {p1 % M:#x}")
    print(flag.decode())
    return flag


if __name__ == "__main__":
    solve(sys.argv[1] if len(sys.argv) > 1 else "files/output.json")
```

### Notes

- The attack needs `T > 2 * AQ = 512`, so that `q1*q2 < 2^T`. With a smaller `T`, `(q1, q2)` is no longer a short vector and the reduction does not find it. The chosen `T = 530` exceeds this bound by 18 bits.
- The attack needs no factoring algorithm. ECM on the 256-bit factor was considered and rejected as unnecessary.
- The Lagrange-Gauss loop needs a correct nearest-integer rounding with sign handling. A naive rounding rule can loop forever.
- The solver prints the flag. This write-up redacts it. The text is 34 printable bytes.
- The `work/team/str1x/` directory holds an alternative script with the same logic. It is not reproduced here.
