### Summary

The pixel data of `mosaic_0417.png` is untouched, and the message is hidden in the encoder's choices that a decoder discards. For each back-reference whose equal-length candidates have distances of both parities, the parity of the distance used is one bit, and these bits form an encrypted blob plus a note that describes the cipher. The padding bits after the stored (sync flush) block headers form the 128-bit key, and decrypting the blob with it gives the flag after the HMAC tag is verified.

### Steps

1. Read the PNG metadata. The `Software` text chunk names the compressor and its modes. The `Comment` chunk is base64 for `isfcr{nope_not_this_one}`, which is a decoy.
   ```sh
   unzip -o ../files/lossless-not-harmless.zip -d scratch/
   exiftool scratch/lossless-not-harmless/mosaic_0417.png
   ```
   ```text
   Software : dfl-stitch 2.3 (equivalent-match mode, flush=sync)
   Comment  : aXNmY3J7bm9wZV9ub3RfdGhpc19vbmV9
   ```

2. Parse the deflate stream token by token. The parser lists the blocks of the IDAT stream. There are 87 blocks: dynamic blocks of exactly 125 tokens each, and the first 31 of them are followed by an empty stored block, which is a sync flush. The parser's output is checked against `zlib.decompress`.
   ```sh
   python3 scripts/tokens.py scratch/lossless-not-harmless/mosaic_0417.png
   ```

3. Find the carrier in the match distances ("equivalent-match" mode). For each back-reference, every distance inside the 32768-byte window that reproduces the same bytes at the same length is an equivalent candidate. Matches are maximal, and when there are two candidates the far one is chosen only when the two distances differ in parity (181 of 181 cases). So each match whose candidates have mixed parity carries one bit: the parity of the distance actually used. The 3528 bits, packed MSB first, give `DFL8`, a u16be length (253), a note, a NUL byte and a 53-byte blob. The note is:
   ```text
   key: 128 pad bits discarded by decoder (stored-block header..byte boundary), stream order, MSB first. ks_i=SHA256(key|nonce|u32be(i)); ct=pt^ks; tag=HMAC-SHA256(key,nonce|ct)[:8]. blob=nonce8|ct|tag8
   ```
   The blob is `nonce8 | ciphertext | tag8`.

4. Read the key from the padding. A real sync flush pads to the byte boundary with zeros. Here the bits between each stored-block header and the next byte boundary are non-zero, and across the 31 flushes they total exactly 128 bits. Packed MSB first, they are the key `2814c69217b303ec00c6280fa2c50286`.

5. Verify the tag, then decrypt. The HMAC-SHA256 tag (first 8 bytes) over `nonce | ciphertext` must match with this key. The plaintext is XORed with a SHA-256 counter keystream, `SHA256(key | nonce | u32be(i))`. The script does steps 2 to 5 from the zip, takes about 40 seconds, and prints the note, the key and the flag.
   ```sh
   python3 scripts/solve.py ../files/lossless-not-harmless.zip
   ```
   Output:
   ```text
   note: key: 128 pad bits discarded by decoder (stored-block header..byte boundary), stream order, MSB first. ks_i=SHA256(key|nonce|u32be(i)); ct=pt^ks; tag=HMAC-SHA256(key,nonce|ct)[:8]. blob=nonce8|ct|tag8
   key: 2814c69217b303ec00c6280fa2c50286
   flag: isfcr{REDACTED}
   ```

### Scripts

`solve.py` imports `tokens.py` from its own directory, so keep both files in the same folder.

#### scripts/tokens.py

Deflate parser for PNG IDAT streams. It reads the stored, fixed and dynamic blocks and yields the literal and length/distance tokens of each block. Run it as `python3 scripts/tokens.py <png>`, and it prints one line per block with the block type, bit positions, token count and match count.

```python
#!/usr/bin/env python3
"""Deflate token parser for PNG IDAT streams: yields blocks with literal and match tokens."""
import struct, sys

LBASE = [3,4,5,6,7,8,9,10,11,13,15,17,19,23,27,31,35,43,51,59,67,83,99,115,131,163,195,227,258]
LEXT = [0]*8 + [1]*4 + [2]*4 + [3]*4 + [4]*4 + [5]*4 + [0]
DBASE = [1,2,3,4,5,7,9,13,17,25,33,49,65,97,129,193,257,385,513,769,1025,1537,2049,3073,4097,6145,8193,12289,16385,24577]
DEXT = [0,0,0,0] + [i // 2 for i in range(2, 28)]
CLORDER = [16,17,18,0,8,7,9,6,10,5,11,4,12,3,13,2,14,1,15]


def idat(d):
    o, out = 8, b''
    while o < len(d):
        l, t = struct.unpack('>I4s', d[o:o+8])
        if t == b'IDAT':
            out += d[o+8:o+8+l]
        o += 12 + l
    return out


class Bits:
    def __init__(self, data):
        self.d, self.p = data, 0

    def get(self, n):
        v = 0
        for i in range(n):
            v |= ((self.d[self.p >> 3] >> (self.p & 7)) & 1) << i
            self.p += 1
        return v


def table(lengths):
    codes, code = {}, 0
    for bl in range(1, 16):
        for sym, l in enumerate(lengths):
            if l == bl:
                codes[(bl, code)] = sym
                code += 1
        code <<= 1
    return codes


def sym(b, t):
    code = 0
    for l in range(1, 16):
        code = (code << 1) | b.get(1)
        if (l, code) in t:
            return t[(l, code)]
    raise ValueError('bad code')


def parse(z):
    """Return (blocks, raw). Each block: dict(type, start, end, tokens); token: ('L', pos, byte) or ('M', pos, len, dist)."""
    b = Bits(z)
    b.p = 16
    out, blocks = bytearray(), []
    final = 0
    while not final:
        start = b.p
        final, typ = b.get(1), b.get(2)
        toks = []
        if typ == 0:
            b.p = (b.p + 7) & ~7
            n = b.get(16)
            b.get(16)
            for _ in range(n):
                toks.append(('L', len(out), b.get(8)))
                out.append(toks[-1][2])
        else:
            if typ == 1:
                lt = table([8]*144 + [9]*112 + [7]*24 + [8]*8)
                dt = table([5]*30)
            else:
                hlit, hdist, hclen = b.get(5) + 257, b.get(5) + 1, b.get(4) + 4
                cl = [0]*19
                for i in range(hclen):
                    cl[CLORDER[i]] = b.get(3)
                ct, ls = table(cl), []
                while len(ls) < hlit + hdist:
                    s = sym(b, ct)
                    if s < 16:
                        ls.append(s)
                    elif s == 16:
                        ls += [ls[-1]] * (3 + b.get(2))
                    elif s == 17:
                        ls += [0] * (3 + b.get(3))
                    else:
                        ls += [0] * (11 + b.get(7))
                lt, dt = table(ls[:hlit]), table(ls[hlit:])
            while True:
                s = sym(b, lt)
                if s == 256:
                    break
                if s < 256:
                    toks.append(('L', len(out), s))
                    out.append(s)
                else:
                    ln = LBASE[s-257] + b.get(LEXT[s-257])
                    ds = sym(b, dt)
                    dist = DBASE[ds] + b.get(DEXT[ds])
                    toks.append(('M', len(out), ln, dist))
                    for _ in range(ln):
                        out.append(out[-dist])
        blocks.append(dict(type=typ, final=final, start=start, end=b.p, tokens=toks))
    return blocks, bytes(out)


if __name__ == '__main__':
    import zlib
    z = idat(open(sys.argv[1], 'rb').read())
    blocks, raw = parse(z)
    assert raw == zlib.decompress(z)
    for i, bl in enumerate(blocks):
        m = [t for t in bl['tokens'] if t[0] == 'M']
        print(i, 'type', bl['type'], 'final', bl['final'], 'bits', bl['start'], bl['end'], 'tokens', len(bl['tokens']), 'matches', len(m))
```

#### scripts/solve.py

Full solve from the challenge zip. It recovers the 3528 distance-parity bits, decodes the `DFL8` container to get the note and the encrypted blob, collects the 128 padding bits as the key, checks the HMAC tag and decrypts the blob. Run it as `python3 scripts/solve.py ../files/lossless-not-harmless.zip`, from the directory that also contains `tokens.py`.

```python
#!/usr/bin/env python3
"""Recover the flag from mosaic_0417.png inside the challenge zip.

Channel 1: each back-reference whose equal-length candidates have mixed distance
parity carries one bit, the parity of the distance actually used (MSB first).
Channel 2: the padding bits of the sync-flush stored blocks form the 128-bit key.
"""
import hashlib, hmac, os, sys, zipfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from tokens import idat, parse


def pack(bits):
    return bytes(int(''.join(map(str, bits[i:i+8])), 2) for i in range(0, len(bits) - 7, 8))


zf = zipfile.ZipFile(sys.argv[1])
z = idat(zf.read('lossless-not-harmless/mosaic_0417.png'))
blocks, raw = parse(z)

bits, pad = [], []
for b in blocks:
    if b['type'] == 0:
        s = b['start'] + 3
        pad += [(z[p >> 3] >> (p & 7)) & 1 for p in range(s, (s + 7) & ~7)]
    for t in b['tokens']:
        if t[0] != 'M':
            continue
        _, pos, ln, dist = t
        target = raw[pos:pos+ln]
        parities = {dist & 1}
        d = 1
        # A candidate needs ln bytes of history, so overlapping ones are compared bytewise.
        while d <= min(pos, 32768) and len(parities) < 2:
            if (d ^ dist) & 1 and all(raw[pos+i-d] == target[i] for i in range(ln)):
                parities.add(d & 1)
            d += 1
        if len(parities) == 2:
            bits.append(dist & 1)

payload = pack(bits)
assert payload[:4] == b'DFL8', payload[:4]
body = payload[6:6 + int.from_bytes(payload[4:6], 'big')]
note, blob = body.split(b'\x00', 1)
print('note:', note.decode())

assert len(pad) == 128, len(pad)
key = pack(pad)
print('key:', key.hex())
nonce, ct, tag = blob[:8], blob[8:-8], blob[-8:]
assert hmac.compare_digest(hmac.new(key, nonce + ct, hashlib.sha256).digest()[:8], tag), 'bad tag'
ks = b''.join(hashlib.sha256(key + nonce + i.to_bytes(4, 'big')).digest() for i in range(len(ct) // 32 + 1))
print('flag:', bytes(a ^ b for a, b in zip(ct, ks)).decode())
```

### Notes

- The carrier is the parity of the distance, not the index of the chosen candidate. Decoding the index (floor(log2 n) bits in a mixed radix) gives noise. The hint is the index histogram: it is uniform for larger candidate sets but about 3:1 toward the nearest candidate when there are only two.
- The `Comment` chunk decodes to the decoy `isfcr{nope_not_this_one}`. Do not submit it.
- `zsteg` and pixel or palette LSB analysis find nothing in this image.
- The solve needs both `scripts/tokens.py` and `scripts/solve.py` in the same directory, because `solve.py` imports the parser by file path.
