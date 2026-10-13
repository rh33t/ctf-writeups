### Summary

`chall` does not compare the 32 input bytes directly. It delta-codes them (each byte is XORed with the previous input byte), runs the deltas through an LZMA-style adaptive binary range coder, and `memcmp`s the 36-byte output with an embedded blob. A range coder is bijective, so running the matching decoder over the blob recovers the 32-byte input that the binary accepts, which is the flag.

### Steps

Commands run from the challenge's `work/` directory. The binary dump in `files/` has no exec bit, so it is copied and made executable before running it.

1. Find the target blob and the win condition.

   ```sh
   objdump -s -j .rodata ../files/chall          # target blob at 0x4012e0
   objdump -d -M intel ../files/chall | sed -n '/400573/,/40058c/p'
   ```

   `main` (0x4003c0) reads exactly 32 bytes. Before any comparison it requires the encoder output position (at 0x403080) to equal exactly `0x24`, otherwise it prints `nope.`. Then it calls `memcmp(0x4030a0, 0x4012e0, 0x24)`:

   ```
   400573: cmp QWORD PTR [rip+0x2b05],0x24
   40057b: jne 400597              ; -> "nope." without comparing
   400582: mov esi,0x4012e0        ; target blob
   400587: mov edi,0x4030a0        ; encoder output
   40058c: call memcmp
   ```

   The target blob is 36 bytes: `00691a0d051109094e93af58eb2800763144253827504c83a26d5edea325465dd7b19000`.

2. Understand the encoder (bit loop at 0x4004a0, `ShiftLow` at 0x400700).

   - Delta coding: `d[0] = b[0]` and `d[i] = b[i] ^ b[i-1]`. The XOR base is the previous input byte, while the model context is the previous delta. These are different values, and mixing them up gives wrong output from the first few bytes.
   - Model: 65536 12-bit probabilities, all initialised to 0x800, indexed as `prob[(prev_delta << 8) + node]`. `node` starts at 1 and is updated MSB first, 8 bits per symbol.
   - Per bit: `bound = (range >> 12) * prob`.
     - bit 0: `range = bound`, `prob += (0x1000 - prob) >> 4`
     - bit 1: `range -= bound`, `low += bound`, `prob -= prob >> 5`
   - Normalisation: while `range <= 0xFFFFFF`, shift `range` left by 8 and emit `cache + (low >> 32)`, then `low <<= 8`. Five `ShiftLow` calls at the end flush the buffer.

3. Write the mirror range decoder and run it on the embedded blob.

   ```sh
   python3 scripts/solve.py ../files/chall
   ```

   The decoder reads the blob from `files/chall` at its file offset (`.rodata` at 0x12a0, so the blob is at 0x12e0), decodes 32 bytes, and writes them to stdout. The output is the flag, `isfcr{REDACTED}`. When run on a terminal it also prints the blob, the hex and the ASCII.

4. Confirm with the binary itself.

   ```sh
   cp ../files/chall scratch/chall && chmod +x scratch/chall
   python3 scripts/solve.py ../files/chall > scratch/answer.bin
   ./scratch/chall < scratch/answer.bin
   echo "exit=$?"
   ```

   ```
   CORRECT
   exit=0
   ```

   Checks on the negative side: a 31-byte input prints `need exactly 32 bytes of input` and exits 2, and a wrong 32-byte input prints `nope.` and exits 1.

### Scripts

#### scripts/solve.py

Decodes the embedded blob with the mirror range decoder and writes the 32-byte input to stdout. Run it from `work/` as `python3 scripts/solve.py ../files/chall`, where the argument is the path to the binary.

```python
#!/usr/bin/env python3
"""Recover the 32-byte input of the-press (rev, id 6).

The binary delta-codes the input (d[0]=b[0], d[i]=b[i]^b[i-1]) and feeds it
through an LZMA-style adaptive range coder (loop at 0x4004a0), then compares the
36-byte output with a blob at 0x4012e0.  The coder is bijective, so decoding the
blob with the mirror range decoder yields the input.

Model: 65536 probs (12-bit, init 0x800) at prob[(prev_delta<<8)+node], node
MSB-first from 1.  bound=(range>>12)*prob; bit0: range=bound, prob+=(0x1000-prob)>>4;
bit1: range-=bound, prob-=prob>>5.  Normalise while range<=0xFFFFFF.

Usage: solve.py [path-to-chall]   (default ../files/chall, reads blob from it)
"""
import sys

BLOB_VADDR = 0x4012E0
BLOB_LEN = 0x24
RODATA_VADDR = 0x4012A0
RODATA_OFF = 0x12A0  # file offset of .rodata (objdump: vaddr 0x4012a0 @ off 0x12a0)
MASK32 = 0xFFFFFFFF


class Decoder:
    def __init__(self, blob):
        self.blob = blob
        self.pos = 1              # LZMA: first emitted byte is the 0 cache
        self.code = 0
        for _ in range(4):
            self.code = ((self.code << 8) | self._next()) & MASK32
        self.range = MASK32
        self.prob = [0x800] * 65536

    def _next(self):
        b = self.blob[self.pos] if self.pos < len(self.blob) else 0
        self.pos += 1
        return b

    def _bit(self, idx):
        bound = (self.range >> 12) * self.prob[idx] & MASK32
        if self.code < bound:
            self.range = bound
            self.prob[idx] += (0x1000 - self.prob[idx]) >> 4
            bit = 0
        else:
            self.code = (self.code - bound) & MASK32
            self.range = (self.range - bound) & MASK32
            self.prob[idx] -= self.prob[idx] >> 5
            bit = 1
        while self.range <= 0xFFFFFF:
            self.range = (self.range << 8) & MASK32
            self.code = ((self.code << 8) | self._next()) & MASK32
        return bit

    def decode(self, n):
        out = bytearray()
        prev_delta = 0
        for i in range(n):
            node = 1
            for _ in range(8):
                node = (node << 1) | self._bit((prev_delta << 8) + node)
            delta = node & 0xFF
            out.append(delta if i == 0 else delta ^ out[i - 1])
            prev_delta = delta
        return bytes(out)


def read_blob(path):
    data = open(path, "rb").read()
    off = RODATA_OFF + (BLOB_VADDR - RODATA_VADDR)
    return data[off:off + BLOB_LEN]


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else "../files/chall"
    blob = read_blob(path)
    flag = Decoder(blob).decode(32)
    sys.stdout.buffer.write(flag)
    if not sys.stdout.isatty():
        return
    print()
    print("blob :", blob.hex())
    print("flag :", flag.hex())
    print("ascii:", repr(flag))


if __name__ == "__main__":
    main()
```

### Notes

- The output buffer at 0x4030a0 is only 64 bytes, and the length check requires exactly 0x24 emitted bytes. An input that encodes to a different length is rejected before the `memcmp`.
- Two pitfalls cost earlier drafts time. Using the previous delta as the XOR base (instead of the previous input byte) diverged from the binary at output bytes 2 and 3. Using `prob >> 5` for the bit-1 update instead of `prob - (prob >> 5)` matched short inputs but diverged once a slot had been updated several times.
- The decoder must walk the model tree with the decoded bit. A helper that advances the tree with a passed-in symbol produces a plausible but wrong prefix.
- Reading the disassembly alone was enough to derive the coder. Confirming it was done by running the binary on the recovered input (`CORRECT`), not by trusting the decoder output.
- A teammate's solution (`work/team/str1x/`) reaches the same input with a longer decoder. Its `difftest.py` and `tracecmp.py` compare a re-implemented encoder with the binary under gdb. They are verification scaffolding and are not needed to reproduce the solve.
- `work/artifacts/binary-check.txt` is the saved output of the binary check. It contains the recovered input, so it is not reproduced here.
