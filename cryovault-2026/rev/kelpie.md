### Summary

The activation key (16 bytes) goes through a reversible byte-machine (stage 1). Its output `Y` derives, via `HMAC-SHA256`, the AES-256-GCM key of an embedded vault. The CTFd hint gives that AES key directly, so the vault decrypts to a second byte-machine (stage 2) that checks an invertible transform of `Y` against 16 constants. Inverting stage 2 from the constants gives `Y`, and inverting stage 1 from `Y` gives the key, which is the flag.

### Steps

1. Reverse the binary. The flow is: read a line, require the `isfcr{` prefix and 32 hex characters, decode them into 16 bytes `F`, compute `Y = stage1(F)`, compute `k = HMAC-SHA256(key at 0x4028a4, Y)`, decrypt the AES-256-GCM blob at 0x4028d4 (924 bytes, IV at 0x4028b4, tag at 0x4028c0) with `k`, and run the plaintext as a stage-2 program on `Y`. The input is accepted only if the GCM tag verifies and stage 2 returns 0. Stage 1 is a 3-byte-opcode VM whose program sits at 0x4023c0 (length 0x4d1 = 1233 bytes, 411 instructions). The binary has an undocumented `selftest` mode that runs stage 1 over the fixed vector `00 01 .. 0f`, which is useful to check a re-implementation of the VM:
   ```sh
   ./files/kelpie selftest
   # d3e4dd75211d03215a37de7164eb510a
   ```
2. Without the hint, the only constraint on `Y` is the GCM tag, which is 128 bits, and no search over the binary or wordlists finds the key. The CTFd hint `9aebadceb2ae07382a9b56afa8a03c7a7b68f84ddc493d778f0ec0d8a242360f` is 32 bytes and is the AES-256 key `k` itself. It opens the vault with a valid tag.
3. The decrypted plaintext is a 307-instruction stage-2 program followed by `HALT`. It has 3 rounds of `SBOX`, permutation, `XORI`/`MULI`/`ROLI`, `MIX` and `ADDV`, then 16 `CMPI buf[i], constant` checks. Every operation is a bijection (odd multipliers, permutations, AES S-box), so the inverse starts from the 16 constants and replays the program backwards to get `Y`. Check: `HMAC-SHA256(K, Y)` must equal the hint, which the script asserts.
4. Invert stage 1 on `Y` the same way to get `F`. `F` is the activation key, so the script prints it as the flag:
   ```sh
   python3 scripts/solve.py ../files/kelpie
   # isfcr{REDACTED}
   ```
5. Verify on the binary, which prints `Unlocked. Activation accepted.` for the correct key:
   ```sh
   printf 'isfcr{REDACTED}\n' | ../files/kelpie
   # Unlocked. Activation accepted.
   ```

### Scripts

#### scripts/solve.py

Standalone solver. It reads the stage-1 program, the HMAC key, the IV, the tag and the ciphertext from the binary at fixed offsets, decrypts the vault with the hinted key, inverts stage 2 and then stage 1, and prints the key. It needs the `cryptography` package. Run it from `work/` as `python3 scripts/solve.py ../files/kelpie`.

```python
#!/usr/bin/env python3
"""Recover the KELPIE activation key: solve.py <kelpie binary> [aes_key_hex]"""
import hashlib
import hmac
import sys

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

HINT = "9aebadceb2ae07382a9b56afa8a03c7a7b68f84ddc493d778f0ec0d8a242360f"
# .rodata is mapped at 0x402000 from file offset 0x2000
DELTA = 0x400000

elf = open(sys.argv[1], "rb").read()
key = bytes.fromhex(sys.argv[2] if len(sys.argv) > 2 else HINT)


def rd(addr, n):
    return elf[addr - DELTA:addr - DELTA + n]


STAGE1 = rd(0x4023c0, 0x4d1)
HMAC_KEY = rd(0x4028a4, 16)
IV = rd(0x4028b4, 12)
TAG = rd(0x4028c0, 16)
CT = rd(0x4028d4, 0x39c)
PERM = {0x51: [rd(0x402c80 + 16 * i, 16) for i in range(2)],
        0x50: [rd(0x402ca0 + 16 * i, 16) for i in range(2)]}
SBOX = {0x41: rd(0x402cc0, 256), 0x40: rd(0x402dc0, 256)}


def rol(v, n):
    n &= 7
    return ((v << n) | (v >> (8 - n))) & 0xFF


def invert(prog, s):
    ops = [prog[i:i + 3] for i in range(0, len(prog) - 2, 3)]
    for op, a, b in reversed(ops):
        if op == 0x10:
            s[a] ^= s[b]
        elif op == 0x11:
            s[a] = (s[a] - s[b]) & 0xFF
        elif op == 0x12:
            s[a] = (s[a] + s[b]) & 0xFF
        elif op == 0x13:
            s[a], s[b] = s[b], s[a]
        elif op == 0x20:
            s[a] ^= b
        elif op == 0x21:
            s[a] = (s[a] - b) & 0xFF
        elif op == 0x22:
            s[a] = (s[a] + b) & 0xFF
        elif op == 0x23:
            s[a] = (s[a] * pow(b, -1, 256)) & 0xFF
        elif op == 0x30:
            s[a] = rol(s[a], 8 - (b & 7))
        elif op == 0x31:
            s[a] = rol(s[a], b)
        elif op in SBOX:
            s[a] = SBOX[op].index(s[a])
        elif op in PERM:
            s[:] = bytes(s[PERM[op][a].index(j)] for j in range(16))
        elif op == 0x60:
            # the XORed term only depends on s[b], so the op is its own inverse
            s[a] ^= rol(s[b], 3)
    return s


stage2 = AESGCM(key).decrypt(IV, CT + TAG, None)

y = bytearray(16)
for i in range(0, len(stage2), 3):
    if stage2[i] == 0x71:
        y[stage2[i + 1]] = stage2[i + 2]
invert(stage2, y)
assert hmac.new(HMAC_KEY, y, hashlib.sha256).digest() == key

print("isfcr{%s}" % invert(STAGE1, bytearray(y)).hex())
```

### Notes

- The `0x60` opcode (`buf[a] ^= rol(buf[b], 3)`) is its own inverse, because the XORed term depends only on `buf[b]`, which the op does not change. Using `ror` there is wrong.
- The permutation opcodes (`0x50`, `0x51`) use 32-byte tables, two blocks of 16 bytes each. Each block must be inverted separately.
- Anti-debug: if `ptrace(PTRACE_TRACEME)` fails, byte 0 of the input is XORed with `0x5a` before stage 1, so the correct key is rejected under a debugger. Run the binary normally, or use `gdb` only with that in mind.
- The stripped binary links dynamically against `libcrypto.so.3` (OpenSSL 3). The solver needs Python's `cryptography` package for AES-GCM.
- The vault copy of `files/kelpie` has no exec bit. Run `chmod +x` on a copy before the commands in steps 1 and 5.
- Dead end: searching for `Y` or the AES key among constants in the binary, among hashes or among dictionary words. None of these produced a key that passed the GCM tag. Without the hint, the challenge is not solvable with the material in the vault.
- A second attempt in the vault (`work/team/str1x`, status "Blocked") swept about 7.8 million structured stage-1 inputs against both oracles without a hit. Its notes leave open whether the challenge is infeasible or the vault blob was packed inconsistently. Its scripts are superseded by `work/scripts/solve.py` and are not included here.
