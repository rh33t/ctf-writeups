### Summary

The check is a knapsack. The binary reads 16 bytes, and each of the 128 input bits selects one 64-byte table entry to add into a 512-bit accumulator. The accumulator must equal a fixed 512-bit target. The input is therefore a 0/1 subset-sum over 128 items of about 400 bits (density about 0.32), which is a low-density instance that lattice reduction solves. Running LLL and then BKZ on the knapsack lattice recovers the subset, which decodes to the 16-byte flag.

### Steps

1. Disassemble `files/chall`. The binary is stripped, but `main` is at `0x4003c0`. It calls `fread(buf, 1, 16, stdin)`, then for each bit `i` that is set in `buf` it adds the `i`-th 64-byte entry of the table at `0x401360` (128 entries) into a 64-byte accumulator. It finishes with `memcmp(acc, target, 64)`, where the target is at `0x401320`.
   ```sh
   objdump -d -M intel files/chall
   ```
2. Extract the 128 items and the target from `.rodata`. Each is 64 bytes read as a little-endian integer. The file offset is the address minus `0x400000`, so the table starts at file offset `0x1360`. Treat the check as a 0/1 subset-sum and build the standard knapsack lattice with rows `(2*I | items)` and a last row `(1, ..., 1 | target)`. Reduce it with LLL, then BKZ with block size 20. The script looks for a reduced row whose last coordinate is 0 and whose other entries are all +1 or -1, then asserts that the selected items add up to the target.
   ```sh
   python3 work/scripts/solve.py
   # bits set: 72
   # flag: b'isfcr{REDACTED}'
   ```
   The script needs the `fpylll` package.
3. Verify the input directly. The vault copy of `files/chall` has no exec bit, so run it through the dynamic loader. It prints `CORRECT` for the right input.
   ```sh
   printf 'isfcr{REDACTED}' | /lib64/ld-linux-x86-64.so.2 ./files/chall
   CORRECT -- the flag is the input you just gave me.
   ```

### Scripts

#### scripts/solve.py

Extracts the 128 table entries and the 512-bit target from the binary, runs the LLL and BKZ subset-sum attack, converts the selected bits back to 16 bytes and prints them. It needs `fpylll`. Run it from the challenge directory as `python3 work/scripts/solve.py`.

```python
#!/usr/bin/env python3
"""The Ledger (id 3) solver.

files/chall sums the 64-byte table entries selected by the 128 bits of a 16-byte
stdin input (512-bit accumulator, no wrap) and compares the total to a 512-bit
target. Recovering the input is a low-density 0/1 subset sum (128 items of ~400
bits, density ~0.32), solved with the standard lattice/BKZ attack.

Run from the challenge directory:
    python3 work/scripts/solve.py
"""
import sys

from fpylll import IntegerMatrix, LLL, BKZ

TABLE_VMA = 0x401360
TARGET_VMA = 0x401320
RODATA_OFF = 0x12a0
RODATA_VMA = 0x4012a0
N = 128


def extract(path='files/chall'):
    data = open(path, 'rb').read()
    off = lambda vma: RODATA_OFF + (vma - RODATA_VMA)
    target = int.from_bytes(data[off(TARGET_VMA):off(TARGET_VMA) + 64], 'little')
    items = [int.from_bytes(data[off(TABLE_VMA) + i * 64:off(TABLE_VMA) + (i + 1) * 64], 'little')
             for i in range(N)]
    return items, target


def attack(items, target, block=20):
    n = len(items)
    B = IntegerMatrix(n + 1, n + 1)
    for i in range(n):
        B[i, i] = 2
        B[i, n] = items[i]
    for j in range(n):
        B[n, j] = 1
    B[n, n] = target
    LLL.reduction(B)
    for b in range(block, max(block, 41), 10):
        BKZ.reduction(B, BKZ.Param(block_size=b))
        for r in range(n + 1):
            row = [int(B[r, c]) for c in range(n + 1)]
            if row[n] == 0 and all(v in (1, -1) for v in row[:n]):
                return [1 if row[i] == 1 else 0 for i in range(n)]
    return None


def to_bytes(bits):
    out = bytearray()
    for k in range(16):
        v = 0
        for j in range(8):
            v |= bits[k * 8 + j] << j
        out.append(v)
    return bytes(out)


if __name__ == '__main__':
    items, target = extract()
    bits = attack(items, target)
    if bits is None:
        print("subset-sum attack failed")
        sys.exit(1)
    flag = to_bytes(bits)
    assert sum(items[i] for i in range(N) if bits[i]) == target
    print("bits set:", sum(bits))
    print("flag:", flag)
```

### Notes

- Plain LLL on the knapsack lattice did not surface the solution vector. The BKZ pass with block size 20 did, which is why the script runs BKZ after LLL.
- `to_bytes` packs bit `k*8+j` into bit `j` of byte `k`, which is the order the binary accepts.
- The recovered input has 72 of its 128 bits set.
- The vault also keeps `work/artifacts/chall.dis` (full disassembly) and `work/artifacts/recovered_input.txt` (the 16 accepted bytes). Neither is needed to run the solve.
