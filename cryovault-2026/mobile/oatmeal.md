### Summary

`silvergate.apk` is a staging build whose `LockActivity` only checks `SHA256(input)` against a hardcoded digest, and its passphrase file is not provided. `base.odex` is a synthetic oat-style container that holds a small AArch64 bytecode VM (`checkFlag_v2`) and a `finalizeFlag` routine. The VM's 24 byte constraints invert directly to a 24-byte secret, `art_image_took_the_cake!`, and `finalizeFlag` hashes that secret with FNV-1a-64 to produce the flag.

### Steps

1. Decompile the APK. `LockActivity.checkFlag` compares `SHA256(input)` with the `EXPECTED` constant, and `LockActivity.deriveFlag` builds `isfcr{hex(char ^ 0x55)}`. `assets/notes.txt` says the `deriveFlag` format is staging-only and that the passphrase lives in a file that is not part of the handout, so the APK path is a dead end for the flag.
   ```sh
   androguard decompile -o dexout files/silvergate.apk
   ```

2. Inspect `base.odex`. It is not a real oat or ELF file: the header is `oat\n243`, the compiler tag is `ART-OPT/13.0.0-r43`, and the file carries decoy strings, the `isfcr{%016llx}` format string, three 24-byte tables at `0x180`, `0x198` and `0x1b0`, a bytecode region at `0x290`, and AArch64 code at `0x4b0`.
   ```sh
   strings -n 4 files/base.odex
   xxd files/base.odex | head -60
   ```

3. Disassemble the AArch64 region with capstone and identify three routines:
   - `checkFlag_v2` at `0x4b0` is a VM with 2-byte opcodes. The opcode is `byte >> 4` and the destination register is `byte & 0xf`. Opcodes: 1 loads `input[operand]`, 2/3/4 load table A/B/C at `operand` XOR a keystream, 5 loads an immediate, 6 adds registers, 7 XORs registers, 8 is `rol8`, 9 asserts equality, 0xa is success and 0xb is failure. The keystream is `ks(i) = ((i*0xa7)^0x5c)&0xff`, with index offsets 0, 0x18 and 0x30 for tables A, B and C.
   - `checkFlag_v1_LEGACY` at `0x7e0` compares 32 raw bytes to `EXPECTED`. It is not on the path used here.
   - `finalizeFlag` at `0x820` runs FNV-1a-64 (offset basis `0xcbf29ce484222325`, prime `0x100000001b3`) over the 24 secret bytes, XORs the result with `0xa55a96693c3cd2ad`, and prints it as `isfcr{%016llx}`.

4. Invert the VM program. The program is 24 groups of 11 two-byte instructions starting at `0x290`, one group per secret byte `i`. Each group asserts:
   ```
   rol8( (input[i] + (A[i] ^ ks(i))) ^ (B[i] ^ ks(i+0x18)), 3 ) == (C[i] ^ ks(i+0x30))
   ```
   Undoing `rol8` with a rotate right and the addition and XOR gives `secret[i] = ((ror8(c, 3) ^ b) - a) & 0xff`, which yields the secret `art_image_took_the_cake!`. The solver also checks that every group has the same opcode layout, and then re-runs the VM over the secret to confirm it reaches the success opcode.

5. Run the solver. It recovers the secret, re-simulates the VM as a self-check, and applies `finalizeFlag`.
   ```sh
   python3 work/scripts/solve.py files/base.odex
   # secret: art_image_took_the_cake!
   # flag: isfcr{REDACTED}
   ```

### Scripts

#### scripts/solve.py

Parses the 24 VM constraint groups from `base.odex`, inverts each to recover the 24-byte secret, re-simulates the embedded VM to confirm it reaches the success opcode, and then applies `finalizeFlag`. Standard library only. Run `python3 work/scripts/solve.py files/base.odex` from the challenge directory; with no argument it defaults to `files/base.odex` next to the challenge.

```python
#!/usr/bin/env python3
"""Recover the Oatmeal flag from base.odex.

The file is a synthetic "oat" container whose embedded AArch64 VM (file offset
0x4b0) verifies a 24-byte secret against three keystream-masked 24-byte tables
(offsets 0x180/0x198/0x1b0). finalizeFlag (offset 0x820) then runs FNV-1a-64 over
that secret, XORs 0xa55a96693c3cd2ad and formats it as isfcr{%016llx}.

Usage: python3 solve.py [path/to/base.odex]
"""
import os
import sys

KS_XOR = 0x5C
KS_MUL = 0xA7
FNV_OFFSET = 0xCBF29CE484222325
FNV_PRIME = 0x100000001B3
FINAL_XOR = 0xA55A96693C3CD2AD


def ks(i):
    return ((i * KS_MUL) ^ KS_XOR) & 0xFF


def ror8(x, n):
    n &= 7
    return x if n == 0 else ((x >> n) | (x << (8 - n))) & 0xFF


def recover_secret(data):
    A = data[0x180:0x198]
    B = data[0x198:0x1B0]
    C = data[0x1B0:0x1C8]
    # 24 groups of 11 two-byte instructions starting at 0x290; instruction 3 holds input index.
    secret = bytearray(24)
    for g in range(24):
        group = [data[0x290 + (g * 11 + k) * 2] for k in range(11)]
        assert group == [0x57, 0x56, 0x77, 0x10, 0x21, 0x60, 0x31, 0x70, 0x80, 0x41, 0x90], hex(g)
        i = data[0x290 + (g * 11 + 3) * 2 + 1]
        a = A[i] ^ ks(i)
        b = B[i] ^ ks(i + 0x18)
        c = C[i] ^ ks(i + 0x30)
        # VM: r = ((input[i] + a) ^ b); assert rol8(r, 3) == c
        secret[i] = ((ror8(c, 3) ^ b) - a) & 0xFF
    return bytes(secret)


def simulate_vm(data, secret):
    """Re-run the embedded VM program over the secret; returns True on the success opcode."""
    A = data[0x180:0x198]
    B = data[0x198:0x1B0]
    C = data[0x1B0:0x1C8]
    regs = [0] * 8
    pc = 0x290
    while pc < 0x4A2:
        op_byte, operand = data[pc], data[pc + 1]
        op, dst = op_byte >> 4, op_byte & 0xF
        if op == 1:
            regs[dst] = secret[operand]
        elif op == 2:
            regs[dst] = A[operand] ^ ks(operand)
        elif op == 3:
            regs[dst] = B[operand] ^ ks(operand + 0x18)
        elif op == 4:
            regs[dst] = C[operand] ^ ks(operand + 0x30)
        elif op == 5:
            regs[dst] = operand
        elif op == 6:
            regs[dst] = (regs[dst] + regs[operand & 0xF]) & 0xFF
        elif op == 7:
            regs[dst] ^= regs[operand & 0xF]
        elif op == 8:
            regs[dst] = ((regs[dst] << (operand & 7)) | (regs[dst] >> (8 - (operand & 7)))) & 0xFF
        elif op == 9:
            if regs[dst] != regs[operand & 0xF]:
                return False
        elif op == 0xA:
            return True
        elif op == 0xB:
            return False
        pc += 2
    return False


def finalize(secret):
    h = FNV_OFFSET
    for byte in secret:
        h ^= byte
        h = (h * FNV_PRIME) & 0xFFFFFFFFFFFFFFFF
    return h ^ FINAL_XOR


def main(path):
    data = open(path, "rb").read()
    secret = recover_secret(data)
    assert simulate_vm(data, secret), "VM rejected recovered secret"
    print("secret:", secret.decode("ascii"))
    print("flag: isfcr{%016x}" % finalize(secret))


if __name__ == "__main__":
    default = os.path.join(os.path.dirname(__file__), "..", "..", "files", "base.odex")
    main(sys.argv[1] if len(sys.argv) > 1 else default)
```

### Notes

- The two `isfcr{...}` strings embedded in `base.odex` are decoys: `isfcr{dev_overlay_do_not_submit_18ca3b}` (its own text says not to submit it) and `isfcr{preprod_token_v3_40df11a0ce9c}`. Neither is the answer.
- The nested `dex.035` blob at `0x890` (4163 bytes, entropy 7.96) has no recoverable structure. XOR and RC4 with the secret did not decode it, so it is treated as filler.
- The APK `EXPECTED` digest was not cracked against the candidate passphrase list. It was not needed, because the `finalizeFlag` output already has the declared `isfcr{%016llx}` shape.
- The APK `deriveFlag` output is the staging format and is not the answer.
- The tools used were androguard 4.1.4 and capstone 6.0.0. The solver itself needs only the Python standard library.
