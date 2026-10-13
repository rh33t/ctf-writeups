### Summary

`FlagChecker.check` in `classes.dex` folds each input byte into a 16-bit rolling value and compares it with a fixed 34-entry table. The recurrence is invertible: once a step matches, the expected state for the next byte is known, so every byte is forced and the single accepted string is recovered directly instead of brute-forced. The APK also carries a decoy checker in an encrypted shadow dex that wins at runtime, so the flag must come from the `classes.dex` checker.

### Steps

1. List the APK contents. The app is a single-activity validator, and its check logic is in `classes.dex`. The archive also contains `assets/theme.pack`, which is the encrypted decoy (see Notes).
   ```sh
   unzip -l files/flaguard.apk
   ```

2. Decompile `FlagChecker`. `apkanalyzer` ships with the Android SDK and reads the APK directly; jadx also works. The check requires the input to start with `isfcr{`, end with `}`, be 34 bytes long, and then fold each byte into a 16-bit state:
   ```
   v = 0x1b7f
   for i in range(len(bytes)):
       v = (v * 0x83 + bytes[i] + P[i % 6]) & 0xffff
       if v != C[i]: return false
   return true
   ```
   with `P = [0x37, 0x8d, 0x19, 0xf2, 0x4b, 0xa6]` and `C` the 34-entry table from the class initialiser.
   ```sh
   apkanalyzer dex code --class dev.srspace.flaguard.FlagChecker files/flaguard.apk
   ```

3. Invert the recurrence. If the check passes, the state after byte `i` equals `C[i]`, so the state before byte `i` is `C[i-1]` (or the initial value for `i = 0`). That fixes each byte:
   ```
   prev = 0x1b7f
   for i in range(34):
       b = (C[i] - prev * 0x83 - P[i % 6]) & 0xffff
       prev = C[i]          # b must land in 0..255, which it does
   ```
   The solver checks that each recovered byte is in range and that the rebuilt string passes the same `check` logic.

4. Run the solver. It reads the `P` and `C` tables from `classes.dex` with a small DEX parser and prints the flag.
   ```sh
   python3 work/scripts/solve.py files/flaguard.apk
   # isfcr{REDACTED}
   ```

### Scripts

#### scripts/solve.py

Reads the `P` and `C` tables from `classes.dex` inside the APK (the `fill-array-data` payloads in `FlagChecker.<clinit>`), inverts the recurrence, verifies the result with the same `check` logic, and prints the flag. Pure Python, standard library only. Run `python3 work/scripts/solve.py files/flaguard.apk` from the challenge directory.

```python
#!/usr/bin/env python3
"""Recover the flag accepted by FlaGuard (id 90).

FlagChecker.check folds each input byte into a 16-bit rolling value and compares
it against a table, so the input can be recovered one byte at a time by running
the recurrence backwards. This script reads the P and C tables straight out of
classes.dex, inverts the recurrence, and verifies the result.

Run: python3 scripts/solve.py files/flaguard.apk
Prints the accepted flag.
"""

import struct
import sys
import zipfile

INIT = 0x1B7F


def uleb128(buf, off):
    result = 0
    shift = 0
    while True:
        b = buf[off]
        off += 1
        result |= (b & 0x7F) << shift
        if not (b & 0x80):
            return result, off
        shift += 7


class Dex:
    def __init__(self, data):
        self.d = data
        self.strings = self._strings()
        self.types = self._types()

    def _strings(self):
        size, off = struct.unpack_from("<II", self.d, 0x38)
        out = []
        for i in range(size):
            (soff,) = struct.unpack_from("<I", self.d, off + 4 * i)
            n, p = uleb128(self.d, soff)
            out.append(self.d[p:p + n].decode("utf-8", "replace"))
        return out

    def _types(self):
        size, off = struct.unpack_from("<II", self.d, 0x40)
        return [self.strings[struct.unpack_from("<I", self.d, off + 4 * i)[0]]
                for i in range(size)]

    def clinit_arrays(self, class_name):
        """Return every array built by fill-array-data in <clinit>, in order."""
        size, off = struct.unpack_from("<II", self.d, 0x60)
        for i in range(size):
            base = off + 32 * i
            class_idx, _, _, _, _, _, data_off, _ = struct.unpack_from("<8I", self.d, base)
            if self.types[class_idx] != class_name or data_off == 0:
                continue
            p = data_off
            counts = []
            for _ in range(4):
                n, p = uleb128(self.d, p)
                counts.append(n)
            for _ in range(sum(counts[:2])):
                _, p = uleb128(self.d, p)
                _, p = uleb128(self.d, p)
            for _ in range(counts[2] + counts[3]):
                _, p = uleb128(self.d, p)
                _, p = uleb128(self.d, p)
                code_off, p = uleb128(self.d, p)
                if code_off:
                    for arr in self._payloads(code_off):
                        yield arr

    def _payloads(self, code_off):
        insns_size, = struct.unpack_from("<I", self.d, code_off + 12)
        insns_off = code_off + 16
        i = 0
        while i < insns_size:
            unit, = struct.unpack_from("<H", self.d, insns_off + 2 * i)
            if (unit & 0xFF) == 0x26:  # fill-array-data
                delta, = struct.unpack_from("<i", self.d, insns_off + 2 * (i + 1))
                yield self._encoded_array(insns_off + 2 * (i + delta))
                i += 3
            else:
                i += 1

    def _encoded_array(self, off):
        ident, width, size = struct.unpack_from("<HHI", self.d, off)
        assert ident == 0x0300
        fmt = {1: "<b", 2: "<h", 4: "<i"}[width]
        return [struct.unpack_from(fmt, self.d, off + 8 + width * i)[0]
                for i in range(size)]


def check(flag, P, C):
    if not (flag.startswith("isfcr{") and flag.endswith("}")):
        return False
    data = flag.encode()
    if len(data) != len(C):
        return False
    v = INIT
    for i, ch in enumerate(data):
        v = (v * 0x83 + ch + P[i % len(P)]) & 0xFFFF
        if v != C[i]:
            return False
    return True


def main():
    if len(sys.argv) != 2:
        sys.exit("usage: solve.py <flaguard.apk>")
    with zipfile.ZipFile(sys.argv[1]) as apk:
        dex = Dex(apk.read("classes.dex"))
    P, C = list(dex.clinit_arrays("Ldev/srspace/flaguard/FlagChecker;"))
    assert len(P) == 6 and len(C) == 34, (len(P), len(C))

    prev = INIT
    flag = bytearray()
    for i, c in enumerate(C):
        b = (c - prev * 0x83 - P[i % len(P)]) & 0xFFFF
        if b > 0xFF:
            sys.exit(f"byte {i} out of range; recurrence does not hold")
        flag.append(b)
        prev = c
    flag = flag.decode()

    assert check(flag, P, C), "reconstructed flag fails FlagChecker.check"
    print(flag)


if __name__ == "__main__":
    main()
```

### Notes

- Decoy shadow checker: `assets/theme.pack` is AES-CBC encrypted. `App.attachBaseContext` (via `App.bind`) decrypts it into a shadow dex and loads it through `InMemoryDexClassLoader` as the parent of the app classloader. Parent-first delegation makes the shadow `FlagChecker` win at runtime, and it accepts `isfcr{p4r3nt_f1rst_d3x_1s_s0_m34n}`. That string is a wrong lead and is not the answer.
- Decryption parameters of the shadow dex, for reference only: the key is `sha256(paletteKeyBytes || "flaguard-boot-v3" || sha256(classes.dex))`, the IV is `sha256(sha256(classes.dex) || paletteKeyBytes[:16])[:16]`, and the 128 `paletteKeyBytes` sit at `(palette.webp[16] & 0x3f) + 0x40`. The decrypted shadow dex is 1296 bytes.
- Emulator check (vault `artifacts/emulator_verify.txt`): on the running app, the shadow flag shows "Accepted." and the `classes.dex` flag shows "Rejected." The CTFd answer is the `classes.dex` one, as confirmed by the user on the challenge page.
- Both `fingerprint()` methods were made to return the same value, so the on-screen `fp=` cannot tell the two checkers apart.
- Solving the shadow dex first is a dead end: it yields the decoy string above, not the flag.
- The solver is pure Python and needs no device or Android tools. It requires only the APK path.
