### Summary

`chall` maps the 28 input bytes, little-endian, to a 224-bit integer `A` and evaluates a Lucas/Chebyshev-style recurrence `V_A` modulo a prime `M`. It accepts the input iff `V_A == T` for a constant `T` stored in `.rodata`. Since `M-1` is smooth (all prime factors are small), inverting the recurrence reduces to a discrete logarithm in `GF(M)*`, which Pohlig-Hellman solves quickly. The discrete log gives `A`, and its 28 little-endian bytes are the flag.

### Steps

1. Inspect the binary. It is a stripped ELF that reads exactly 28 bytes and prints `nope.` otherwise.

   ```sh
   file files/chall
   strings -n 5 files/chall
   ```

2. Disassemble `main` (0x4003c0) and the two modular helper routines. The input is packed little-endian into `A`. The loop over the bits of `A`, from MSB to LSB, maintains the pair `(V_n, V_{n+1})` with

   ```
   V_0 = 2, V_1 = C
   V_{2n}   = V_n^2 - 2
   V_{2n+1} = V_n * V_{n+1} - C     (mod M)
   ```

   At the end the program compares `V_A` with the target `T`. The constants `C`, `M` and `T` are in `.rodata` at virtual addresses 0x401300, 0x401320 and 0x4012e0. Each is 32 bytes, stored as four little-endian qwords.

   ```sh
   objdump -d -M intel files/chall
   objdump -s -j .rodata files/chall
   ```

3. Check the modulus. `M` is prime and `M-1` factors completely into small primes:

   ```
   M-1 = 2 * 997 * 1399 * 1931 * 2297 * 4003 * 5701 * 7103 * 10211 * 12799
           * 14551 * 46229 * 47279 * 48271 * 51263 * 52937 * 53923 * 58771 * 59051
   ```

   The largest factor is 59051, so the group order is smooth and the discrete log is cheap. `sympy.isprime(M)` is True and `sympy.factorint(M - 1)` returns this factorization.

4. Invert the recurrence. Let `alpha = (C + sqrt(C^2 - 4)) / 2` and `y = (T + sqrt(T^2 - 4)) / 2` in `GF(M)*`. Then `V_A = T` is equivalent to `alpha^A = y`. The script computes both square roots with `sqrt_mod`, solves the discrete log with `sympy.discrete_log`, and writes `A` out as 28 little-endian bytes.

   ```sh
   python3 scripts/solve.py
   ```

   ```
   isfcr{REDACTED}
   ```

5. Validate against the binary. The dump has no exec bit, so run a copy.

   ```sh
   mkdir -p scratch && cp files/chall scratch/chall && chmod +x scratch/chall
   printf '%s' "$(python3 scripts/solve.py)" | ./scratch/chall
   ```

   ```
   CORRECT -- the flag is the input you just gave me.
   ```

   A short input prints `need exactly 28 bytes of input` and exits 2.

### Scripts

#### scripts/solve.py

Recovers the 28-byte input by a discrete log over the constants read from `.rodata`. It needs `sympy` installed. Run it from `work/` with `python3 scripts/solve.py`, and it prints the flag.

```python
#!/usr/bin/env python3
"""Solve "The Recurrence" (rev, id 2).

`chall` reads 28 bytes, packs them little-endian into a 224-bit integer A, and
evaluates the Lucas/Chebyshev recurrence

    V_0 = 2, V_1 = C, V_{2n} = V_n^2 - 2, V_{2n+1} = V_n*V_{n+1} - C  (mod M)

over the prime M.  It accepts iff V_A == T.  Since M-1 is fully smooth, the
inverse problem (find A with V_A = T) is a discrete log in GF(M)*:
alpha = (C + sqrt(C^2-4))/2, y = (T + sqrt(T^2-4))/2, alpha^A = y.

Constants below are lifted from files/chall .rodata:
  C at va 0x401300, M at 0x401320, T at 0x4012e0 (4 little-endian qwords).

Run: python3 scripts/solve.py          # prints the flag
"""
from sympy import sqrt_mod, discrete_log

M = int.from_bytes(bytes.fromhex(
    "17de4cc2bfb1ba6e3c95b6f07e808e3f6746b0e2c9fee09251efe2ee13aa7300"), "little")
C = int.from_bytes(bytes.fromhex(
    "a825851ab3e07d5f4bd5152d99669f4c291ce08d1d99f36ded9227f907442e00"), "little")
T = int.from_bytes(bytes.fromhex(
    "003110f1659975bb56cead2f87d3fb938b9903678edef2875b2a2ed0ade84900"), "little")


def sqrt_minus4(v):
    return sqrt_mod((v * v - 4) % M, M)


def main():
    inv2 = pow(2, -1, M)
    alpha = ((C + sqrt_minus4(C)) * inv2) % M
    y = ((T + sqrt_minus4(T)) * inv2) % M
    A = discrete_log(M, y, alpha)
    flag = A.to_bytes(28, "little")
    assert len(flag) == 28
    print(flag.decode())


if __name__ == "__main__":
    main()
```

### Notes

- The script needs `sympy` (`sqrt_mod` and `discrete_log`). Running it with `python3 -I` fails with `ModuleNotFoundError` when `sympy` lives in the user site-packages, so run it without `-I`.
- The dump in `files/` is not executable. Run a copy (`scratch/chall`) instead of `chmod` on the original file.
- The binary's acceptance check is the ground truth. The recovered `A` was also checked in Python by recomputing `V(A) == T` and `alpha^A == y`.
- The inferred flag shape is `isfcr{...}`. All 28-byte solutions with this structure are printable ASCII, so the little-endian bytes decode directly to text.
