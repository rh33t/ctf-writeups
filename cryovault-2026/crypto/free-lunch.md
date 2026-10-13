### Summary

The challenge permutation `P(x, y) = (cbrt(x + y + c_i), x)` over `GF(p)` (with `p = 2 mod 3`, so cubing is a bijection) is a CICO instance: find the smallest `x` with `P(x, 0)[1] == 0`. Reversing the 20 rounds symbolically, with `cubing` cancelling each cube root, gives a polynomial `F(t)` of degree `3^10 = 59049` whose roots in `GF(p)` are exactly the valid starting values. Restricting to those roots with `gcd(F, t^p - t)` and checking each candidate recovers the two solutions. The smallest one is the key seed: `key = SHA256(decimal(x))` opens the AES-GCM ciphertext in `output.json` and reveals the flag.

### Steps

1. Read the challenge data. `files/output.json` contains the prime `p`, the round count `r = 20`, the 20 round constants `c`, and the sealed flag (`flag_ct`, `flag_tag`, `flag_nonce`). The generator in `files/chall.py` shows the permutation and the key rule (`key = SHA256(decimal of the smallest valid x)`), so the goal is to recompute that smallest `x`.

2. Reverse the rounds as polynomials. The forward round maps `(x, y)` to `(cbrt(x + y + c_i), x)`, so the state sequence satisfies `x[i-1] = x[i+1]^3 - x[i] - c[i]`. Start from the output side with `x[R] = t` (an indeterminate) and `x[R-1] = 0` (the required zero second output), then apply the recurrence down to `x[-1]`. The degree grows by a factor 3 every two rounds, so `F = x[-1]` has degree `3^10 = 59049`.
   ```python
   P = {R: nmod_poly([0, 1], p), R - 1: nmod_poly([0], p)}
   for i in range(R - 1, -1, -1):
       P[i - 1] = P[i + 1] ** 3 - P[i] - nmod_poly([c[i] % p], p)
   F = P[-1]
   ```

3. Keep only the roots in `GF(p)`. Since `t^p - t` vanishes exactly on `GF(p)`, `G = gcd(F, t^p - t)` has as roots only the field roots of `F`. For each root `t`, rebuild the chain forward from `x[R] = t` and keep it only if `x[-1] == 0` and the forward permutation `P(x[0], 0)` really has second coordinate zero.
   ```text
   solutions (2): [1093395384440720767, 1530042892650509984]
   ```

4. Pick the smallest valid input and decrypt. The solver takes `min(solutions) = 1093395384440720767`, derives `key = SHA256(b"1093395384440720767")`, and calls `decrypt_and_verify` with the stored nonce and tag. A passing tag confirms the key, and the plaintext is the flag.

5. Run the solver from `work/` with pinned dependencies (`python-flint==0.9.0`, `pycryptodome==3.24.0`). The script reads its data from the path given on the command line, so it can be run with any path to `output.json`.
   ```sh
   python3 -m pip install --target scratch/deps -r scripts/requirements.txt
   PYTHONPATH=scratch/deps python3 scripts/solve.py ../files/output.json
   ```
   ```text
   recurrence degree: 59049
   solutions (2): [1093395384440720767, 1530042892650509984]
   smallest x: 1093395384440720767
   P(x, 0)[1]: 0
   plaintext: isfcr{REDACTED}
   ```

### Scripts

#### scripts/requirements.txt

Pins the two Python packages the solver imports (`python-flint` for `nmod_poly`, `pycryptodome` for AES-GCM); install them as shown in step 5.

```text
python-flint==0.9.0
pycryptodome==3.24.0
```

#### scripts/solve.py

Recovers all valid inputs from `output.json`, selects the smallest, checks it, and decrypts the flag; run it from `work/` as shown in step 5.

```python
#!/usr/bin/env python3

import json
import sys
from hashlib import sha256
from pathlib import Path

from Crypto.Cipher import AES
from flint import nmod_poly


def permutation(x, y, constants, p):
    exponent = pow(3, -1, p - 1)
    for constant in constants:
        x, y = pow((x + y + constant) % p, exponent, p), x
    return x, y


def main():
    if len(sys.argv) != 2:
        raise SystemExit(f"usage: {sys.argv[0]} output.json")

    data = json.loads(Path(sys.argv[1]).read_text())
    p = data["p"]
    rounds = data["r"]
    constants = data["c"]

    polynomials = {
        rounds: nmod_poly([0, 1], p),
        rounds - 1: nmod_poly([0], p),
    }
    for i in range(rounds - 1, -1, -1):
        polynomials[i - 1] = (
            polynomials[i + 1] ** 3
            - polynomials[i]
            - nmod_poly([constants[i] % p], p)
        )

    recurrence = polynomials[-1]
    variable = nmod_poly([0, 1], p)
    base_field_roots = recurrence.gcd(variable.pow_mod(p, recurrence) - variable)

    solutions = set()
    for root, _multiplicity in base_field_roots.roots():
        chain = {rounds: int(root), rounds - 1: 0}
        for i in range(rounds - 1, -1, -1):
            chain[i - 1] = (
                pow(chain[i + 1], 3, p) - chain[i] - constants[i]
            ) % p
        candidate = chain[0]
        if chain[-1] == 0 and permutation(candidate, 0, constants, p)[1] == 0:
            solutions.add(candidate)

    answer = min(solutions)
    assert permutation(answer, 0, constants, p)[1] == 0

    key = sha256(str(answer).encode()).digest()
    cipher = AES.new(key, AES.MODE_GCM, nonce=bytes.fromhex(data["flag_nonce"]))
    plaintext = cipher.decrypt_and_verify(
        bytes.fromhex(data["flag_ct"]), bytes.fromhex(data["flag_tag"])
    )

    print(f"recurrence degree: {recurrence.degree()}")
    print(f"solutions ({len(solutions)}): {sorted(solutions)}")
    print(f"smallest x: {answer}")
    print(f"P(x, 0)[1]: {permutation(answer, 0, constants, p)[1]}")
    print(f"plaintext: {plaintext.decode()}")


if __name__ == "__main__":
    main()
```

### Notes

- The generator plants a solution (`x0`) by choosing the constant `c[R-2]` so that the chain ends at zero. The solver does not use that planted value; it re-checks each candidate with the forward permutation.
- The first solver run failed on missing `flint` and `Crypto` modules. The two pinned packages above fix this; `sympy` is only used by the generator, not by the solver.
- The solver prints the decrypted plaintext. This write-up redacts it. The real flag is never stored in the vault files; `chall.py` only has the placeholder default `isfcr{REDACTED}`.
- The recovered integers are the valid CICO inputs, not the flag. Only the one with the smallest value seeds the key.
