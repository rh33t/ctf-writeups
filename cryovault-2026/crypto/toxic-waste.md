### Summary

The trusted setup published a KZG-style SRS `g, g^tau, ..., g^(tau^d)` but kept only its two ends, `A = g^tau` and `B = g^(tau^d)`, with `d = 2^44` dividing `q - 1`. That pair is exactly the auxiliary input for Cheon's discrete-log attack (equivalently Brown-Gallant), which recovers `tau` in `O(sqrt(d) + sqrt((q-1)/d))` group operations instead of the advertised `sqrt(q)`. Here both stages cost about `2^22` steps. The recovered `tau` gives the AES-GCM key `sha256(str(tau))`, which decrypts the flag.

### Steps

1. Read `files/chall.py` and `files/output.json`. `P` is a 1024-bit prime, `q` is an 88-bit prime, `g` generates the order-`q` subgroup, `d = 2^44`, and `q - 1 = d·m` with `m = 11222138928841` a 44-bit prime. Confirm the structure:

   ```sh
   python3 -c "import json;d=json.load(open('files/output.json'));q=d['q'];print((q-1)%d['d']==0,(q-1)//d['d'])"
   ```

   Output: `True 11222138928841`.

2. Run Cheon's two-stage baby-step/giant-step in the exponent group `Z_q^*` with primitive root `zeta = 3`. Write `tau = zeta^k mod q`, and let `M = (q-1)/d = m`.
   - Stage 1: `tau^d = zeta^(d·k)` and `zeta^d` has order `m`, so `B = g^(zeta^(d·k))` determines `k1 = k mod m`. A BSGS over a group of order `m` costs about `sqrt(m) ~ 2^22`.
   - Stage 2: `A^(zeta^(-k1)) = g^(zeta^(k - k1)) = g^(ze^(k2))` with `k = k1 + m·k2` and `ze = zeta^m` of order `d`. A BSGS over a group of order `d` costs about `sqrt(d) = 2^22`.
   - Then `tau = zeta^(k1 + m·k2) mod q`.

   `solve.py` compiles `cheon.c` with GMP and runs both stages.

3. Run the solver from the challenge root:

   ```sh
   python3 work/scripts/solve.py
   ```

   Output:

   ```
   [+] tau = 53372121991905014611291611
   [+] flag = isfcr{REDACTED}
   ```

   The solver also checks `pow(g, tau, P) == A` and `pow(g, pow(tau, d, q), P) == B` before decrypting, so the recovered `tau` reproduces both published elements. The AES-GCM tag then authenticates the plaintext.

### Scripts

#### scripts/solve.py

Compiles `cheon.c` into `work/scratch/cheon` if needed, feeds it the group parameters, verifies the recovered `tau` against both published elements, and decrypts the flag. Run it from the challenge root with `python3 work/scripts/solve.py`. It needs `cc`, the GMP library and `cryptography`.

```python
#!/usr/bin/env python3
"""Recover tau for the toxic-waste SRS with Cheon's attack and decrypt the flag.

Usage: python3 scripts/solve.py [path/to/output.json]

Compiles scripts/cheon.c (GMP) on first run, feeds P,q,g,A,B,d to it, verifies
the recovered tau against both published group elements, then AES-GCM-decrypts
the flag sealed under sha256(str(tau)).
"""
import hashlib
import json
import os
import subprocess
import sys

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.join(HERE, "cheon.c")
# build outside scripts/ so a push carries source only
BIN = os.path.join(HERE, "..", "scratch", "cheon")


def ensure_binary():
    os.makedirs(os.path.dirname(BIN), exist_ok=True)
    if os.path.exists(BIN) and os.path.getmtime(BIN) >= os.path.getmtime(SRC):
        return
    subprocess.run(["cc", "-O2", "-o", BIN, SRC, "-lgmp"], check=True)


def recover_tau(data):
    inp = "\n".join(str(data[k]) for k in ("P", "q", "g", "A", "B", "d")) + "\n"
    out = subprocess.run([BIN], input=inp, capture_output=True, text=True, check=True)
    tau = int(out.stdout.strip())
    P, q, g, A, B, d = (data[k] for k in ("P", "q", "g", "A", "B", "d"))
    assert pow(g, tau, P) == A, "tau does not reproduce A"
    assert pow(g, pow(tau, d, q), P) == B, "tau does not reproduce B"
    return tau


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else os.path.join(HERE, "..", "..", "files", "output.json")
    data = json.load(open(path))
    ensure_binary()
    tau = recover_tau(data)
    print(f"[+] tau = {tau}")

    key = hashlib.sha256(str(tau).encode()).digest()
    nonce = bytes.fromhex(data["flag_nonce"])
    ct = bytes.fromhex(data["flag_ct"]) + bytes.fromhex(data["flag_tag"])
    flag = AESGCM(key).decrypt(nonce, ct, None)
    print(f"[+] flag = {flag.decode()}")


if __name__ == "__main__":
    main()
```

#### scripts/cheon.c

C and GMP implementation of Cheon's two-stage BSGS. It reads `P`, `q`, `g`, `A`, `B` and `d` as decimal lines on stdin and prints `tau`. Build it with `cc -O2 -o cheon cheon.c -lgmp`, or let `solve.py` build it.

```c
/*
 * Cheon's DLP-with-auxiliary-input attack for the toxic-waste SRS.
 *
 * Given g, A = g^tau, B = g^(tau^d), prime q (order of g) and d | q-1,
 * recover tau in O(sqrt(q/d) + sqrt(d)).
 *
 * Reads P, q, g, A, B, d as decimal strings, one per line, on stdin.
 * Prints tau (decimal) on stdout.
 *
 * Build: cc -O2 -o cheon cheon.c -lgmp
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <gmp.h>

#define TABLE_BITS 23
#define TABLE_SIZE (1UL << TABLE_BITS)
#define TABLE_MASK (TABLE_SIZE - 1)

static uint64_t *keys;   /* fingerprint of stored group element */
static uint32_t *vals;   /* index + 1, 0 means empty */

static uint64_t hash_mpz(const mpz_t x) {
    uint64_t h = mpz_get_ui(x);            /* low 64 bits of the group element */
    h ^= h >> 33;
    h *= 0xff51afd7ed558ccdULL;
    h ^= h >> 33;
    if (h == 0) h = 1;
    return h;
}

static void table_clear(void) {
    memset(vals, 0, TABLE_SIZE * sizeof(uint32_t));
}

static void table_insert(const mpz_t x, uint32_t idx) {
    uint64_t h = hash_mpz(x);
    size_t i = h & TABLE_MASK;
    while (vals[i] != 0) {
        i = (i + 1) & TABLE_MASK;
    }
    keys[i] = h;
    vals[i] = idx + 1;
}

static void mpz_read(mpz_t out, const char *line) {
    if (mpz_set_str(out, line, 10) != 0) {
        fprintf(stderr, "bad integer: %s\n", line);
        exit(1);
    }
}

/* read one non-empty line into buf */
static int read_line(char *buf, size_t n) {
    while (fgets(buf, n, stdin)) {
        size_t l = strlen(buf);
        while (l && (buf[l-1] == '\n' || buf[l-1] == '\r')) buf[--l] = 0;
        if (l) return 1;
    }
    return 0;
}

/* find a primitive root mod prime q whose factorization is 2^a * m (m prime) */
static void find_primitive_root(mpz_t zeta, const mpz_t q, const mpz_t m,
                                const mpz_t q_minus_1) {
    mpz_t e2, em, t;
    mpz_inits(e2, em, t, NULL);
    mpz_tdiv_q_ui(e2, q_minus_1, 2);      /* (q-1)/2 */
    mpz_tdiv_q(em, q_minus_1, m);         /* (q-1)/m */
    unsigned long h = 2;
    while (1) {
        mpz_set_ui(zeta, h);
        mpz_powm(t, zeta, e2, q);
        if (mpz_cmp_ui(t, 1) == 0) { h++; continue; }
        mpz_powm(t, zeta, em, q);
        if (mpz_cmp_ui(t, 1) == 0) { h++; continue; }
        break;
    }
    mpz_clears(e2, em, t, NULL);
}

/* ceil(sqrt(n)) */
static void ceil_sqrt(mpz_t out, const mpz_t n) {
    mpz_sqrt(out, n);
    mpz_t sq; mpz_init(sq);
    mpz_mul(sq, out, out);
    if (mpz_cmp(sq, n) < 0) mpz_add_ui(out, out, 1);
    mpz_clear(sq);
}

/*
 * BSGS step for the exponential-exponent relation.
 *   unknown k in [0, range), base_group = g
 *   We are given the target group element Tgt = g^{alpha^k} where the
 *   multiplicative base is `base` (an element of Z/qZ) and alpha = base.
 *   Concretely solves  base^k = X  with X = dlog_g(Tgt) unknown, but
 *   Tgt = g^{base^k}.
 *   baby  S_u = Tgt^{base^{-u}}
 *   giant G_v = g^{(base^{step})^v}
 *   collision S_u = G_v  =>  base^k = base^{u + step*v}, k = u + step*v.
 * Returns k, or -1 if not found.
 */
static int cheon_step(const mpz_t P, const mpz_t q, const mpz_t g,
                      const mpz_t Tgt, const mpz_t base,
                      const mpz_t range, mpz_t k_out) {
    mpz_t step, inv_base, c, S, T, e, tmp;
    mpz_inits(step, inv_base, c, S, T, e, tmp, NULL);

    ceil_sqrt(step, range);

    /* baby table: S_u = Tgt^{inv_base^u} */
    mpz_invert(inv_base, base, q);        /* base^{-1} mod q */
    mpz_set(S, Tgt);
    table_clear();
    unsigned long step_ui = mpz_get_ui(step);
    if (mpz_cmp_ui(step, step_ui) != 0 || step_ui >= TABLE_SIZE) {
        fprintf(stderr, "table too small / step too large: %lu\n", step_ui);
        mpz_clears(step, inv_base, c, S, T, e, tmp, NULL);
        return -1;
    }
    for (unsigned long u = 0; u < step_ui; u++) {
        table_insert(S, (uint32_t)u);
        mpz_powm(S, S, inv_base, P);
    }

    /* giant: T_v = g^{c^v}, c = base^step mod q */
    mpz_powm(c, base, step, q);
    mpz_set(T, g);
    for (unsigned long v = 0; v < step_ui; v++) {
        uint64_t h = hash_mpz(T);
        size_t i = h & TABLE_MASK;
        while (vals[i] != 0) {
            if (keys[i] == h) {
                uint32_t u = vals[i] - 1;
                /* verify: recompute S_u = Tgt^{inv_base^u} and compare */
                mpz_powm_ui(e, inv_base, u, q);
                mpz_powm(tmp, Tgt, e, P);
                if (mpz_cmp(tmp, T) == 0) {
                    mpz_set_ui(k_out, u);
                    mpz_addmul_ui(k_out, step, v);   /* k = u + v*step */
                    mpz_clears(step, inv_base, c, S, T, e, tmp, NULL);
                    return 0;
                }
            }
            i = (i + 1) & TABLE_MASK;
        }
        mpz_powm(T, T, c, P);
    }
    mpz_clears(step, inv_base, c, S, T, e, tmp, NULL);
    return -1;
}

int main(void) {
    char buf[4096];
    mpz_t P, q, g, A, B, d, m, qm1, zd, ze, k1, k2, k, tau, Ge, inv_zeta, tmp;
    mpz_inits(P, q, g, A, B, d, m, qm1, zd, ze, k1, k2, k, tau, Ge, inv_zeta, tmp, NULL);

    if (!read_line(buf, sizeof buf)) return 1; mpz_read(P, buf);
    if (!read_line(buf, sizeof buf)) return 1; mpz_read(q, buf);
    if (!read_line(buf, sizeof buf)) return 1; mpz_read(g, buf);
    if (!read_line(buf, sizeof buf)) return 1; mpz_read(A, buf);
    if (!read_line(buf, sizeof buf)) return 1; mpz_read(B, buf);
    if (!read_line(buf, sizeof buf)) return 1; mpz_read(d, buf);

    keys = malloc(TABLE_SIZE * sizeof(uint64_t));
    vals = calloc(TABLE_SIZE, sizeof(uint32_t));
    if (!keys || !vals) { fprintf(stderr, "alloc failed\n"); return 1; }

    mpz_sub_ui(qm1, q, 1);
    if (mpz_divisible_p(qm1, d) == 0) { fprintf(stderr, "d does not divide q-1\n"); return 1; }
    mpz_divexact(m, qm1, d);

    mpz_t zeta; mpz_init(zeta);
    find_primitive_root(zeta, q, m, qm1);
    gmp_fprintf(stderr, "primitive root zeta = %Zd\n", zeta);

    mpz_powm(zd, zeta, d, q);     /* order m */
    mpz_powm(ze, zeta, m, q);     /* order d */

    /* Step 1: tau^d = zd^{k1}, k1 in [0, m) */
    if (cheon_step(P, q, g, B, zd, m, k1) != 0) {
        fprintf(stderr, "step 1 failed\n"); return 1;
    }
    gmp_fprintf(stderr, "k1 = %Zd\n", k1);

    /* Step 2: zeta^{-k1} * tau = ze^{k2}, k2 in [0, d) */
    mpz_invert(inv_zeta, zeta, q);
    mpz_powm(tmp, inv_zeta, k1, q);
    mpz_powm(Ge, A, tmp, P);      /* Ge = A^{zeta^{-k1}} = g^{zeta^{-k1} tau} */
    if (cheon_step(P, q, g, Ge, ze, d, k2) != 0) {
        fprintf(stderr, "step 2 failed\n"); return 1;
    }
    gmp_fprintf(stderr, "k2 = %Zd\n", k2);

    /* k = k1 + k2*m ; tau = zeta^k mod q */
    mpz_mul(k, k2, m);
    mpz_add(k, k, k1);
    mpz_powm(tau, zeta, k, q);

    gmp_printf("%Zd\n", tau);

    mpz_clears(P, q, g, A, B, d, m, qm1, zd, ze, k1, k2, k, tau, Ge, inv_zeta, tmp, NULL);
    mpz_clear(zeta);
    free(keys); free(vals);
    return 0;
}
```

### Notes

- The advertised security `sqrt(q)` ~ 2^44 ignores that `g^(tau^d)` is published. Cheon's attack reduces the problem to `sqrt(d) + sqrt((q-1)/d)`, which is about 2^22 per stage.
- Giant steps must iterate `T <- T^c`, not `T <- T·c`, because the exponent is `base^(step·v)`, which is exponential in `v`. An earlier toy attempt with the multiplicative form was wrong for this reason.
- The C/GMP run takes about seven minutes on one core in the vault's own timing.
- `work/scripts/cheon_toy.py` is a pure-Python generator of small random instances, with the same solver, used to check the method on toy parameters. It is not needed for the real solve.
- The compiled binary goes to `work/scratch/`, and the build needs the GMP headers and library.
