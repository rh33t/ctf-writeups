# Related Messages — picoCTF 2026

**Category:** Cryptography
**Flag:** `picoCTF{m3ssage_w1th_typ0}`

---

## Overview

Two RSA ciphertexts for two related plaintexts — the same message, but the second has a typo corrected. The script leaks that `Message - Message_fixed = -3`, meaning `M_fixed = M + 3`. Both encrypted with the same key (`e = 17`, 2048-bit `N`). This is a textbook **Franklin-Reiter Related Message Attack**.

---

## Key observations

- `e = 0x11 = 17`
- `c1 = M^17 mod N`
- `c2 = (M + 3)^17 mod N`
- The difference `Message - Message_fixed = -3` is printed directly

The "typo" is that the original message ends with `z` (0x7a) instead of `}` (0x7d). The fixed message adds 3 to the last byte.

---

## Attack

The Franklin-Reiter attack exploits the fact that if two plaintexts are related by a known linear polynomial (`f(x) = x + 3`), then:

```
gcd(x^e - c1,  (x+3)^e - c2)  =  x - M   in Z_N[x]
```

Both polynomials share the root `x = M`, so their GCD is the linear factor `(x - M)`, from which `M` is trivially recovered.

### Steps

1. Build polynomial `p(x) = x^17 - c1`
2. Build polynomial `q(x) = (x+3)^17 - c2` via binomial expansion
3. Run the extended Euclidean algorithm on `p` and `q` in `Z_N[x]`
4. The result is a monic linear polynomial `x + a`; the root is `M = -a mod N`
5. `long_to_bytes(M)` gives the flag

---

## Solve Script

```python
from Crypto.Util.number import long_to_bytes
from math import comb

c1 = 34863...749   # from challenge output
c2 = 20198...124
N  = 17334...881
e  = 17

def poly_trim(f):
    while f and f[-1] == 0:
        f.pop()
    return f

def poly_mod_reduce(f, g, N):
    f = list(f)
    g = poly_trim(list(g))
    lc_inv = pow(g[-1], -1, N)
    while len(f) >= len(g):
        factor = f[-1] * lc_inv % N
        deg_diff = len(f) - len(g)
        for i, c in enumerate(g):
            f[deg_diff + i] = (f[deg_diff + i] - factor * c) % N
        f.pop()
        while f and f[-1] == 0:
            f.pop()
    return f if f else [0]

def poly_gcd(f, g, N):
    f, g = poly_trim(list(f)), poly_trim(list(g))
    while g and not (len(g) == 1 and g[0] == 0):
        f, g = g, poly_trim(poly_mod_reduce(f, g, N))
    lc_inv = pow(f[-1], -1, N)
    return [(c * lc_inv) % N for c in f]

p = [(-c1) % N] + [0] * (e - 1) + [1]
q = [0] * (e + 1)
for k in range(e + 1):
    q[k] = comb(e, k) * pow(3, e - k, N) % N
q[0] = (q[0] - c2) % N

gcd = poly_gcd(p, q, N)
M = (-gcd[0]) % N
print(long_to_bytes(M))  # b'picoCTF{m3ssage_w1th_typ0z'  (typo'd original)
# M_fixed = M + 3  =>  last byte 0x7a + 3 = 0x7d = '}'
# Flag: picoCTF{m3ssage_w1th_typ0}
```

---

## References

- Franklin, M., Reiter, M.: *The Simplest Protocol for Oblivious Transfer* (1996) — Section on related message attacks
- The attack runs in polynomial time via polynomial GCD over `Z_N[x]`
