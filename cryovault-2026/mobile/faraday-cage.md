### Summary

`Faraday.apk` (`com.lumos.faraday`) sends a 16-byte "UNLOCK challenge response" to `BulbNative.submit`, implemented in `libbulb.so`. The native code first runs a small custom bytecode VM that accepts the input only when four rounds of an AES-like transform map it to a fixed 16-byte target; only then does it derive the flag with BLAKE2s and a custom cipher. Inverting the VM check gives the accepted response `LumosFaradCage01`, and running the real native routine with that response prints the flag.

### Steps

1. Unpack the APK and read the Java side. The point is to find how the 16-byte input reaches native code. `MainActivity` reads a 32-hex-character string, parses it to 16 bytes, calls `BulbNative.submit`, and shows the returned bytes as a GATT notification. Java only checks the length.
   ```sh
   unzip -o files/Faraday.apk -d /tmp/faraday
   dexdump -d /tmp/faraday/classes.dex
   ```

2. Inspect the native library. `submit` is JNI-registered to `libbulb.so` at `0x54c8`, and the worker routine is at `0x43dc`. The worker runs a bytecode VM (program at `0x138a`, 60 instructions, 0xf0 bytes) that sets an accept gate at `state+0x348` (1 = accepted, 2 = rejected). Only when the gate is 1 does the routine run the BLAKE2s and cipher stage that produces the flag.
   ```sh
   llvm-objdump -d -j .text /tmp/faraday/lib/arm64-v8a/libbulb.so
   ```

3. Emulate the native routine with Unicorn to observe the gate and the work memory. Arbitrary inputs (all-zero, and the ASCII string "lumos device key") give gate 2. Emulation also exposed the VM dispatch table and showed that acceptance requires the 16-byte value at `0x132a` to equal `f809792ec246f0098538517c71c64461` after the VM transform.

4. Reimplement the VM transform and invert it. Each round is `x = SubBytes(x)`, a byte permutation, `MixColumns` over GF(2^8) (reduction polynomial `0x11d`, circulant row `[2,3,5,1]`), then XOR with a 16-byte round key. The round keys are consecutive 16-byte substrings of the rodata string at `0x133a`. A first inversion attempt used a 4-byte key stride and did not match the forward mapping, so the round keys must be taken at a 16-byte stride. Inverting four rounds gives the accepted response `4c756d6f734661726164436167653031` (`LumosFaradCage01`). The script checks the result by running the forward transform on it.
   ```sh
   python3 work/scripts/vm_response.py files/Faraday.apk
   # challenge response (hex): 4c756d6f734661726164436167653031
   # challenge response (ascii): LumosFaradCage01
   ```

5. Run the real native `submit` routine (`0x43dc`) with the recovered response. The gate becomes 1 and the routine returns the flag. The script prints the response, the gate value and the flag. Requires `pip install unicorn`.
   ```sh
   python3 work/scripts/emulate_submit.py 4c756d6f734661726164436167653031 files/Faraday.apk
   # response: LumosFaradCage01
   # gate    : 1 (1 = accepted)
   # flag    : isfcr{REDACTED}
   ```
   The output block above shows the format the script prints, not a captured run.

### Scripts

#### scripts/vm_response.py

Extracts `libbulb.so` from the APK, inverts the VM acceptance check, and prints the required 16-byte response. Pure Python with no dependencies. Run `python3 work/scripts/vm_response.py files/Faraday.apk` from the challenge directory.

```python
#!/usr/bin/env python3
"""Derive the 16-byte LW-7 UNLOCK challenge response from Faraday.apk.

The native lib registers com.lumos.faraday.BulbNative.submit([B)[B]. Before it
returns anything it runs a small VM (bytecode at libbulb.so 0x138a) that accepts
the input only when it maps to a fixed target. This script reimplements the VM's
transform and inverts it, yielding the exact 16-byte response.

Usage: vm_response.py [Faraday.apk]
"""
import sys, zipfile, io

APK = sys.argv[1] if len(sys.argv) > 1 else 'files/Faraday.apk'

with zipfile.ZipFile(APK) as z:
    so = z.read('lib/arm64-v8a/libbulb.so')

# VM bytecode and the constant tables it references (VMA == file offset here).
CODE = so[0x138a:0x138a + 0xf0]
SBOX = list(so[0x147a:0x147a + 256])
C16 = list(so[0x132a:0x133a])                 # comparison target
PERM = [so[0x137a + i] for i in range(16)]    # byte shuffle table
KEYS = [list(so[0x133a + 16 * r:0x133a + 16 * r + 16]) for r in range(4)]

INV = [0] * 256
for i, v in enumerate(SBOX):
    INV[v] = i
PINV = [0] * 16
for i, p in enumerate(PERM):
    PINV[p] = i


def gmul(a, b):
    """GF(2^8) multiply, reduction polynomial 0x11d (VM's mul handler)."""
    r = 0
    a &= 0xff
    b &= 0xff
    for _ in range(8):
        if b & 1:
            r ^= a
        b >>= 1
        hi = a & 0x80
        a = (a << 1) & 0xff
        if hi:
            a ^= 0x1d
    return r & 0xff


# The VM's MIX handler is a circulant MixColumns over GF(2^8) with row [2,3,5,1].
MROWS = [[2, 3, 5, 1], [1, 2, 3, 5], [5, 1, 2, 3], [3, 5, 1, 2]]


def ginv(a):
    if a == 0:
        return 0
    for x in range(1, 256):
        if gmul(a, x) == 1:
            return x


def matinv(M):
    A = [row[:] + [1 if i == j else 0 for j in range(4)] for i, row in enumerate(M)]
    for c in range(4):
        p = next(r for r in range(c, 4) if A[r][c])
        A[c], A[p] = A[p], A[c]
        iv = ginv(A[c][c])
        A[c] = [gmul(x, iv) for x in A[c]]
        for r in range(4):
            if r != c and A[r][c]:
                f = A[r][c]
                A[r] = [a ^ gmul(f, b) for a, b in zip(A[r], A[c])]
    return [row[4:] for row in A]


MINV = matinv(MROWS)


def invmix(x):
    o = [0] * 16
    for c in range(4):
        b = x[4 * c:4 * c + 4]
        for r in range(4):
            o[4 * c + r] = (gmul(MINV[r][0], b[0]) ^ gmul(MINV[r][1], b[1]) ^
                            gmul(MINV[r][2], b[2]) ^ gmul(MINV[r][3], b[3]))
    return o


def forward(inp):
    """x -> 4x (SubBytes, permute, MixColumns, xor round key)."""
    def mix(x):
        o = list(x)
        for c in range(4):
            w = int.from_bytes(bytes(x[4 * c:4 * c + 4]), 'little')
            bb = [(w >> (8 * k)) & 0xff for k in range(4)]
            G = gmul
            m = (G(2, bb[0]) ^ G(3, bb[1]) ^ G(5, bb[2]) ^ G(1, bb[3]))
            m |= (G(1, bb[0]) ^ G(2, bb[1]) ^ G(3, bb[2]) ^ G(5, bb[3])) << 8
            m |= (G(5, bb[0]) ^ G(1, bb[1]) ^ G(2, bb[2]) ^ G(3, bb[3])) << 16
            m |= (G(3, bb[0]) ^ G(5, bb[1]) ^ G(1, bb[2]) ^ G(2, bb[3])) << 24
            o[4 * c:4 * c + 4] = list(m.to_bytes(4, 'little'))
        return o

    x = list(inp)
    for r in range(4):
        y = [SBOX[v] for v in x]
        x = [y[PERM[i]] for i in range(16)]
        x = mix(x)
        x = [a ^ b for a, b in zip(x, KEYS[r])]
    return x


def invert(target):
    x = list(target)
    for r in range(3, -1, -1):
        x = [a ^ b for a, b in zip(x, KEYS[r])]
        x = invmix(x)
        y = [x[PINV[k]] for k in range(16)]   # undo x[i] = y[PERM[i]]
        x = [INV[v] for v in y]
    return x


resp = bytes(invert(C16))
assert forward(resp) == C16, 'inversion failed'
print('challenge response (hex):', resp.hex())
print('challenge response (ascii):', resp.decode('latin1'))
```

#### scripts/emulate_submit.py

Loads `libbulb.so` with Unicorn, calls the native routine at `0x43dc` with the 16-byte response, and prints the flag if the VM gate is 1. Requires `pip install unicorn`. Run `python3 work/scripts/emulate_submit.py [response-hex] [Faraday.apk]` from the challenge directory; the response defaults to the recovered value.

```python
#!/usr/bin/env python3
"""Emulate the LW-7 native submit() and print the flag.

com.lumos.faraday.BulbNative.submit([B)[B] is registered to libbulb.so 0x54c8.
The routine at 0x43dc does the work: it runs the input-check VM, and when the
VM sets its accept gate it derives the response with BLAKE2s + a custom cipher.
This harness loads libbulb.so with Unicorn, calls 0x43dc with the supplied
16-byte response, and prints the returned string.

Usage: emulate_submit.py [response-hex] [Faraday.apk]
Requires: unicorn (pip install unicorn)
"""
import sys, struct, zipfile, subprocess, tempfile, os
from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_CODE, UcError
from unicorn.arm64_const import (
    UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2, UC_ARM64_REG_X3,
    UC_ARM64_REG_X4, UC_ARM64_REG_SP, UC_ARM64_REG_LR, UC_ARM64_REG_PC,
)

RESP_HEX = sys.argv[1] if len(sys.argv) > 1 else '4c756d6f734661726164436167653031'
APK = sys.argv[2] if len(sys.argv) > 2 else 'files/Faraday.apk'

with zipfile.ZipFile(APK) as z:
    so = z.read('lib/arm64-v8a/libbulb.so')

# AArch64 PT_LOAD segments: (file offset, vaddr, filesz, memsz)
SEGS = [
    (0x000000, 0x000000, 0x2120, 0x2120),
    (0x002120, 0x003120, 0x2510, 0x2510),
    (0x004630, 0x006630, 0x04e0, 0x04e0),
    (0x004b10, 0x007b10, 0x0000, 0x05e8),
]

mu = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
mu.mem_map(0, 0x10000)
mu.mem_map(0x12000000, 0x1000)
mu.mem_map(0x20000000, 0x20000)   # stack
mu.mem_map(0x30000000, 0x10000)   # scratch buffers
for off, va, fs, _ in SEGS:
    if fs:
        mu.mem_write(va, so[off:off + fs])

# Apply R_AARCH64_RELATIVE relocations (handler pointer table, GOT, etc.).
with tempfile.NamedTemporaryFile(suffix='.so', delete=False) as tf:
    tf.write(so)
    tmp = tf.name
try:
    for line in subprocess.run(['readelf', '-rW', tmp], capture_output=True, text=True).stdout.splitlines():
        p = line.split()
        if len(p) >= 4 and len(p[0]) == 16 and all(c in '0123456789abcdef' for c in p[0]) and 'RELATIVE' in p[2]:
            mu.mem_write(int(p[0], 16), struct.pack('<Q', int(p[-1], 16)))
finally:
    os.unlink(tmp)

RET = 0x12000000
INP, OUT, OUTLEN = 0x30000000, 0x30001000, 0x30002000


def hook_memcpy(uc, addr, size, user):
    x0, x1, x2 = (uc.reg_read(r) for r in (UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2))
    uc.mem_write(x0, bytes(uc.mem_read(x1, x2)))
    uc.reg_write(UC_ARM64_REG_PC, uc.reg_read(UC_ARM64_REG_LR))


def hook_memset(uc, addr, size, user):
    x0, x1, x2 = (uc.reg_read(r) for r in (UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2))
    uc.mem_write(x0, bytes([x1 & 0xff]) * x2)
    uc.reg_write(UC_ARM64_REG_PC, uc.reg_read(UC_ARM64_REG_LR))


mu.hook_add(UC_HOOK_CODE, hook_memcpy, begin=0x5610, end=0x5610)
mu.hook_add(UC_HOOK_CODE, hook_memset, begin=0x5620, end=0x5620)

resp = bytes.fromhex(RESP_HEX)
assert len(resp) == 16, 'response must be 16 bytes'
mu.mem_write(INP, resp)
mu.reg_write(UC_ARM64_REG_X0, INP)
mu.reg_write(UC_ARM64_REG_X1, 16)
mu.reg_write(UC_ARM64_REG_X2, OUT)
mu.reg_write(UC_ARM64_REG_X3, 128)
mu.reg_write(UC_ARM64_REG_X4, OUTLEN)
mu.reg_write(UC_ARM64_REG_SP, 0x20000000 + 0x10000)
mu.reg_write(UC_ARM64_REG_LR, RET)

try:
    mu.emu_start(0x43dc, RET, count=200_000_000)
except UcError as e:
    sys.exit(f'emulation error: {e}')

gate = struct.unpack('<i', bytes(mu.mem_read(0x7e58, 4)))[0]
outlen = struct.unpack('<i', bytes(mu.mem_read(OUTLEN, 4)))[0]
print('response:', resp.decode('latin1'))
print('gate    :', gate, '(1 = accepted)')
if gate != 1:
    sys.exit('VM rejected the response')
print('flag    :', bytes(mu.mem_read(OUT, outlen)).decode('latin1'))
```

### Notes

- `isfcr{nope_this_is_a_decoy_please_move_on}` is a hardcoded string in the `libbulb.so` rodata. It is a decoy and is not accepted as the answer.
- The `armeabi-v7a` build of `libbulb.so` implements the same algorithm; the analysis used the `arm64-v8a` build only.
- Reference hashes from the vault: `Faraday.apk` sha256 `a567ed307cec75881a6ec5dccfb9c3bcabc923272cf345ba6f32054d4f54709f`, `lib/arm64-v8a/libbulb.so` sha256 `9155ebb76b86d48f6b33c1175168ead240308a0498633c26463ae360b5fdd379`.
- `emulate_submit.py` needs the `readelf` binary on PATH for relocations, and `unicorn` installed for Python.
- The solve path is fully offline. No device or network access is needed.
