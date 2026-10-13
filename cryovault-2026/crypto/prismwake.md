### Summary

The 6000 multipliers contain exactly 70 collisions `m_i + m_j = m_k + m_l (mod n)`, and each collision gives a relation of the 4th summation polynomial on the x-coordinates of the hidden points. The observations are those x-coordinates seen through an unknown Möbius map, so the relations are linear in the coefficients of a symmetric polynomial `G`, and 70 equations recover `G` up to scale without knowing the map. Roots of `G` at the torsion fixed points give the images of three known x-coordinates, which fixes the map, then `x(K)`, then the ChaCha20-Poly1305 key that opens the seal.

### Steps

Paths below are relative to the challenge directory unless noted.

1. Read `files/model.py`. The curve is `E: Y^2 = X^3 + b` over `F_p` with `#E = p + 1 = 6n`, and `p = 2 mod 3`, so cube roots are `x^(3^-1 mod (p-1))`. Each observation is `observation[i] = (A·x([m_i]K) + B) / (C·x([m_i]K) + D) mod p` for a hidden point `K` and a hidden invertible matrix. The inverse map is `x = (u·y + v) / (w·y + 1)`. The seal key is `sha256(b"prismwake-v1\x00" + x(K) || u || v || w)`, with each integer in a fixed big-endian width of `p`, and the cipher is ChaCha20Poly1305 with AAD `prismwake-v1`.

2. Find the collisions. Sum every pair of multipliers modulo `n` and keep the sums reached twice. There are exactly 70 collisions, with no negations, doublings or triples `m_i + m_j = m_k`. A collision means `±P_i ± P_j ± P_k ± P_l = O`, so the 4th summation polynomial `S4(x_i, x_j, x_k, x_l) = 0` for the x-coordinates of those points.

3. Eliminate the map. Substitute `x = (u·y + v) / (w·y + 1)` and multiply by `Π (w·y_i + 1)^4`. The result `G(y_1..y_4)` is still symmetric of degree at most 4 in each variable. Such polynomials have `C(8,4) = 70` coefficients. Each collision gives one linear equation on them. The 70 x 70 system over `F_p` has a kernel of dimension 1, so `G` is known up to scale without knowing `u`, `v` or `w`. The script asserts the kernel dimension.

4. Locate the torsion images. Write `G(t,t,t,s) = c·(s - t)^3·(s - T(t))`, where `T` is tripling seen through the map. `T(t) = t` exactly at the images of `x = infinity` and of the 2-torsion point `x = (-b)^(1/3)`, so the F_p roots of the third `s`-derivative of `G(t,t,t,s)` at `s = t` are those images. `G(t,t,t,t)` is identically zero, so it cannot be used for this. The script computes this polynomial as `g4`, and its roots as `r4`.

5. Fix the map. Let `s_inf` and `s_e` be an ordered pair from `r4`. The F_p roots `t0` of `G(t,t,t,s_inf)` are images of the 3-torsion point `x = 0`. The script tries each assignment and sets `w = -1/s_inf`, `u = e·(w·s_e + 1)/(s_e - t0)` and `v = -u·t0`, where `e = (-b)^(1/3)`. It keeps the assignment for which every observation maps to the x-coordinate of a curve point, then computes `K = [m_0^-1 mod n]·P0` and checks `x([m_i]K)` against 40 observations. Finally it derives the key and opens the seal.

6. Run the solver from `work/`:

   ```sh
   python3 -P scripts/solve.py ../files/observations.json
   ```

   Output (about 30 s):

   ```
   u 34559716604220687612953322102
   v 48772199007751653754816185446
   w 22589791273467761145953217267
   x(K) 32469388776030518256910525566
   isfcr{REDACTED}
   ```

### Scripts

#### scripts/solve.py

Runs the whole solve: finds the collisions, the kernel `G`, the torsion images, the map `u, v, w`, the point `K`, and decrypts the seal. Run it from `work/` with `python3 -P scripts/solve.py ../files/observations.json`. It needs `sympy` and `cryptography`.

```python
#!/usr/bin/env python3
"""Usage: solve.py <observations.json>. Prints u, v, w, x(K) and the opened seal."""
import hashlib, itertools, json, sys
from collections import defaultdict

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from sympy import Poly, symbols
from sympy.ntheory import sqrt_mod

d = json.load(open(sys.argv[1]))
p, n, b = int(d['prime']), int(d['order']), int(d['curve_b'])
ms = [int(z) for z in d['multiplier']]
obs = [int(z) for z in d['observation']]
inv = lambda a: pow(a, -1, p)

sums = defaultdict(list)
for i in range(len(ms)):
    for j in range(i + 1, len(ms)):
        sums[(ms[i] + ms[j]) % n].append((i, j))
colls = [v[0] + v[1] for v in sums.values() if len(v) > 1]

# Basis of symmetric polynomials of degree <= 4 in each of 4 variables.
exps = list(itertools.combinations_with_replacement(range(5), 4))
perms = [sorted(set(itertools.permutations(e))) for e in exps]

def row(ys):
    pw = [[pow(y, k, p) for k in range(5)] for y in ys]
    return [sum(pw[0][a] * pw[1][c] * pw[2][e] * pw[3][f] for a, c, e, f in ps) % p for ps in perms]

def kernel(M):
    M = [r[:] for r in M]; cols = len(M[0]); piv = []; r = 0
    for c in range(cols):
        k = next((i for i in range(r, len(M)) if M[i][c]), None)
        if k is None: continue
        M[r], M[k] = M[k], M[r]
        iv = inv(M[r][c]); M[r] = [x * iv % p for x in M[r]]
        for i in range(len(M)):
            if i != r and M[i][c]:
                f = M[i][c]; M[i] = [(x - f * y) % p for x, y in zip(M[i], M[r])]
        piv.append(c); r += 1
    free = [c for c in range(cols) if c not in piv]
    out = []
    for fc in free:
        vec = [0] * cols; vec[fc] = 1
        for i, c in enumerate(piv): vec[c] = -M[i][fc] % p
        out.append(vec)
    return out

ker = kernel([row([obs[i] for i in c]) for c in colls])
assert len(ker) == 1, len(ker)
G = ker[0]

t = symbols('t')
def fp_roots(coeffs):
    f = Poly(coeffs[::-1], t, modulus=p)
    return [int(-g.all_coeffs()[1] * inv(int(g.all_coeffs()[0]))) % p
            for g, _ in f.factor_list()[1] if g.degree() == 1]

# G(t,t,t,s) = c (s-t)^3 (s-T(t)) with T the conjugated tripling map; T(t)=t at the images of
# x=infinity and of the 2-torsion x, so those are roots of d^3/ds^3 G(t,t,t,s) at s=t.
g4 = [0] * 14
for c, ps in zip(G, perms):
    for q in ps:
        if q[3] >= 3:
            k = sum(q) - 3
            g4[k] = (g4[k] + c * q[3] * (q[3] - 1) * (q[3] - 2) // 6) % p
r4 = fp_roots(g4)

def g3(s):
    # G(t,t,t,s): its F_p roots include the images of the 3-torsion x when s is the image of infinity.
    h = [0] * 13
    for c, ps in zip(G, perms):
        for q in ps: h[q[0] + q[1] + q[2]] = (h[q[0] + q[1] + q[2]] + c * pow(s, q[3], p)) % p
    return fp_roots(h)

def add(P, Q):
    if P is None: return Q
    if Q is None: return P
    if P[0] == Q[0]:
        if (P[1] + Q[1]) % p == 0: return None
        l = 3 * P[0] * P[0] * inv(2 * P[1]) % p
    else:
        l = (Q[1] - P[1]) * inv(Q[0] - P[0]) % p
    x = (l * l - P[0] - Q[0]) % p
    return x, (l * (P[0] - x) - P[1]) % p

def mul(k, P):
    R = None
    while k:
        if k & 1: R = add(R, P)
        P = add(P, P); k >>= 1
    return R

e2 = pow(-b % p, pow(3, -1, p - 1), p)
for s_inf, s_e in itertools.permutations(r4, 2):
    for t0 in g3(s_inf):
        if t0 in (s_inf, s_e): continue
        w = -inv(s_inf) % p
        u = e2 * (w * s_e + 1) * inv(s_e - t0) % p
        v = -u * t0 % p
        xs = [(u * y + v) * inv(w * y + 1) % p for y in obs[:40]]
        if any(pow(x ** 3 + b, (p - 1) // 2, p) != 1 for x in xs): continue
        P0 = (xs[0], int(sqrt_mod((xs[0] ** 3 + b) % p, p)))
        K = mul(pow(ms[0], -1, n), P0)
        if any(mul(ms[i], K)[0] != xs[i] for i in range(1, 40)): continue
        width = (p.bit_length() + 7) // 8
        material = b"prismwake-v1\x00" + b"".join(z.to_bytes(width, "big") for z in (K[0], u, v, w))
        key = hashlib.sha256(material).digest()
        pt = ChaCha20Poly1305(key).decrypt(bytes.fromhex(d["nonce"]), bytes.fromhex(d["ciphertext"]), b"prismwake-v1")
        print("u", u); print("v", v); print("w", w); print("x(K)", K[0]); print(pt.decode())
        sys.exit(0)
sys.exit("no consistent map found")
```

### Notes

- `G(t,t,t,t)` is identically zero, because `P + P - P - P = O` for every `P`. The fixed points of the tripling map replace it for finding torsion images.
- Eliminating `u`, `v` and `w` directly from three collisions with resultants also works in principle, but it is far heavier than the linear system.
- The vault also contains `work/scripts/solve3.py`, `work/scripts/solve4.py` and `work/scripts/test_synth.py`. They attack the same collisions with resultants or test synthetic data. Their provenance is not recorded, and they are not needed for the solve.
- The script stops at the first assignment that passes every check and prints the decrypted plaintext.
