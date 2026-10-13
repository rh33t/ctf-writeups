### Summary

The binary JIT-compiles four small functions into an RWX `mmap` page. Each blob is stored in `.rodata` XORed with a splitmix64 keystream, and is checked against a rolling hash whose seed is the next 8 bytes of input XORed with the previous hash. Once the four blobs are decrypted, they are simple in-place transforms of the 32-byte buffer. Inverting the chain from the final `memcmp` target gives the input, which is the flag.

### Steps

1. Disassemble the binary and locate the main loop. It reads 32 bytes, then runs four rounds with `rbx` from 0 to 3. In each round it computes a seed `r10 = input[8k:8k+8] ^ r9`, builds a keystream from `fin(r10 + (j+1)*G)`, XORs it with the stored blob into the RWX page, checks the rolling hash against the target at `0x4013a0 + 8k`, and runs the blob on the buffer. `r9` starts at `0x1f0d1e5cafeb00b5`, which is non-zero. After the four rounds the buffer is compared with 32 bytes at `0x401380`.
   ```sh
   objdump -d -M intel files/chall
   ```
2. Read the constants from `.rodata`. The binary maps `.rodata` at `0x400000 + file offset`, so file offset = address - `0x400000`. The four blob lengths are at `0x4013c0` (4 x uint32), the four blob pointers at `0x4013e0` (4 x uint64), the four hash targets at `0x4013a0` (4 x uint64, little-endian), and the final target at `0x401380` (32 bytes).
3. Recover the seed of block 0. Assume the flag starts with `isfcr{`, so input bytes 0 to 7 are `isfcr{` plus two unknown printable bytes. For each of the 95 x 95 candidates, compute `seed = (candidate ^ r9_init)` as a little-endian uint64, decrypt the blob with the keystream, and test the rolling hash against the block-0 target. The matching candidate gives input bytes 0 to 7.
4. Recover the seeds of blocks 1 to 3 without guessing. Every compiled blob starts with the same prologue `f30f1efa 55 4889e5` (`endbr64; push rbp; mov rbp,rsp`). XORing the first 8 blob bytes with the prologue gives the keystream word `fin(seed + G)`. Inverting `fin` gives the seed, and the rolling hash of the decrypted blob matches the target.
5. Decrypt the four blobs and read the transforms, which were confirmed by running the decrypted blobs through an RWX `mmap`:
   - `T0`: `buf[i] ^= 7*(i-13)`
   - `T1`: `buf[i] += buf[(i+1)%32]`, in place, so `buf[31]` reads the already updated `buf[0]`
   - `T2`: rotate each byte left by 3 bits
   - `T3`: `buf[i] ^= 31*i + 60`

   Invert them in reverse order (T3, T2, T1, T0) starting from the 32-byte target at `0x401380`. The script prints the input.
   ```sh
   python3 scripts/solve.py files/chall
   # isfcr{REDACTED}
   ```
6. Verify on the binary, which prints `CORRECT` for the right input:
   ```sh
   python3 -c "import sys;sys.stdout.write('isfcr{REDACTED}')" | ./files/chall
   # CORRECT
   ```

### Scripts

#### scripts/solve.py

Recovers the four seeds (checking every block's integrity hash), inverts the four transforms and prints the 32-byte input. It uses only the Python 3 standard library. Run it from `work/` as `python3 scripts/solve.py files/chall`.

```python
#!/usr/bin/env python3
"""ouroboros: recover the 32-byte input that makes files/chall print CORRECT.

The binary JITs four tiny functions into an RWX page (splitmix64-XOR-obfuscated
in .rodata), executes each on the 32-byte input in turn, and memcmp's the result
against a fixed target. Each JIT blob is integrity-checked against a hash, and
the XOR keystream seed for block k is (input[8k:8k+8] ^ r9_{k-1}).

We recover the seeds from the blobs themselves, then invert the composition.
Usage: python3 scripts/solve.py files/chall
"""
import struct
import sys

M = (1 << 64) - 1
G = 0x9e3779b97f4a7c15           # splitmix64 gamma
C1 = 0xbf58476d1ce4e5b9
C2 = 0x94d049bb133111eb
H0 = 0xc0ffeebadc0de5            # hash IV (cmp against target uses this seed)
R0 = 0x1f0d1e5cafeb00b5          # initial r9
PROLOGUE = bytes.fromhex("f30f1efa554889e5")  # endbr64; push rbp; mov rbp,rsp


def fin(z):
    z &= M
    z1 = ((z ^ (z >> 30)) * C1) & M
    z2 = ((z1 ^ (z1 >> 27)) * C2) & M
    return (z2 ^ (z2 >> 31)) & M


def inv_fin(y):
    z = y
    for _ in range(64):          # invert xor-shift by fixed-point iteration
        z = y ^ (z >> 31)
    z = (z * pow(C2, -1, 1 << 64)) & M
    a = z
    for _ in range(64):
        a = z ^ (a >> 27)
    a &= M
    t = (a * pow(C1, -1, 1 << 64)) & M
    b = t
    for _ in range(64):
        b = t ^ (b >> 30)
    return b & M


def rolling(buf, seed=H0):
    rdx = seed
    for b in buf:
        t = ((b ^ rdx) + G) & M
        rdx = ((t ^ (t >> 30)) * C1) & M
        u = ((rdx ^ (rdx >> 27)) * C2) & M
        rdx = (u ^ (u >> 31)) & M
    return rdx


def keystream(r10, n):
    out = bytearray()
    j = 0
    while len(out) < n:
        r8 = fin((r10 + (j + 1) * G) & M)
        for k in range(8):
            out.append((r8 >> (8 * k)) & 0xff)
        j += 1
    return bytes(out[:n])


# Transform inverses (recovered from the JIT blobs). forward order: T0,T1,T2,T3.
def invT0(b): return bytes(b[i] ^ ((7 * (i - 13)) & 0xff) for i in range(32))
def invT2(b): return bytes(((b[i] >> 3) | (b[i] << 5)) & 0xff for i in range(32))
def invT3(b): return bytes(b[i] ^ ((31 * i + 60) & 0xff) for i in range(32))


def invT1(out):
    inn = [0] * 32
    inn[31] = (out[31] - out[0]) & 0xff              # T1 runs in place
    for i in range(30, -1, -1):
        inn[i] = (out[i] - inn[i + 1]) & 0xff
    return bytes(inn)


def main(path):
    raw = open(path, "rb").read()
    blens = struct.unpack_from("<4I", raw, 0x13c0)
    bptrs = struct.unpack_from("<4Q", raw, 0x13e0)
    targets = struct.unpack_from("<4Q", raw, 0x13a0)
    final = raw[0x1380:0x1380 + 32]
    blobs = [raw[p - 0x400000:p - 0x400000 + n] for p, n in zip(bptrs, blens)]

    # Block 0: seed = input[0:8] ^ R0 ; flag starts with the CTF prefix.
    v = None
    for x in range(0x20, 0x7f):
        for y in range(0x20, 0x7f):
            cand = b"isfcr{" + bytes([x, y])
            vv = int.from_bytes(cand, "little") ^ R0
            if rolling(bytes(a ^ b for a, b in zip(blobs[0], keystream(vv, blens[0])))) == targets[0]:
                v = vv
                break
        if v is not None:
            break
    assert v is not None, "block 0 seed not found"

    # Blocks 1..3: the prologue is identical, so its bytes pin the seed.
    r9 = R0
    for k in range(4):
        if k > 0:
            g0 = int.from_bytes(bytes(a ^ b for a, b in zip(blobs[k][:8], PROLOGUE)), "little")
            v = (inv_fin(g0) - G) & M
        code = bytes(a ^ b for a, b in zip(blobs[k], keystream(v, blens[k])))
        assert rolling(code) == targets[k], f"blob {k} integrity failed"
        r9 = rolling(code, r9)

    out = invT3(final)
    out = invT2(out)
    out = invT1(out)
    flag = invT0(out)
    print(flag.decode())


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "files/chall")
```

### Notes

- Endianness trap: the block-0 target in `.rodata` must be read as little-endian (`0xb82e45fb0800fccb`). A first brute force read it big-endian and found nothing.
- `T1` modifies the buffer in place. At `i = 31` it reads the `buf[0]` already updated in the same pass, so the inverse must start from `buf[31] - buf[0]`, as the script does. Modelling `T1` as non-in-place gives a wrong inverse.
- The seed of block `k` depends on `r9`, which is updated from the earlier blobs, so the seeds chain. Each integrity check itself uses the fixed IV `H0`. Block 0 is solved by the flag-prefix guess, blocks 1 to 3 by the prologue.
- `files/chall` has no exec bit. Copy it and run `chmod +x` before the pipe test in step 6.
- The keystream is a splitmix64 finalizer over `seed + (j+1)*G`, with `G = 0x9e3779b97f4a7c15`. `inv_fin` works by fixed-point iteration on the xorshift steps and modular inverses of the two multipliers.
- The vault also holds `work/scripts/solve_chunk.py`, a z3 model of the block-0 constraint. It was an alternative to the brute force and is not needed for the solve.
- Decrypted blobs are kept as `work/artifacts/code0.bin` to `code3.bin` for reference only.
