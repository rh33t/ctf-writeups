### Summary

The three disk images are a RAID5 array whose power was cut during a write. Half of the sealed report records reached their data chunk, but their stripe parity had already been updated, so the new content of the other half is recovered as parity XOR the sibling chunk. Each record is verified against the SHA-256 list in the intent file. The AES-256-GCM key was supposed to be unlinked after use, but it survives in the ext4 journal because the volume is mounted `data=journal`. Decrypting the six records and concatenating the three token shards gives the flag.

### Steps

Commands are run from the challenge `work/` directory.

1. Extract the three images. Each starts with 1 MiB of random filler, and the member data runs from offset `0x100000` to the end of the file (16 MiB). An ext4 superblock sits at `0x100400` on `bay0.img` and `bay1.img`.
   ```sh
   mkdir -p scratch/extract && unzip -q ../files/write-hole.zip -d scratch/extract
   ```

2. Find the RAID geometry. The member order, chunk size and md layout are not known, so every combination is tried and the one that `e2fsck` accepts is kept. The accepted geometry is member order `bay1, bay2, bay0`, a 32768-byte chunk and the left-symmetric layout. The ext4 superblock announces 8192 blocks of 4096 bytes, which is two data members of 16 MiB. `assemble.py` builds the array image for a given geometry, and `e2fsck` checks it.
   ```sh
   python3 scripts/assemble.py scratch/md0.img 120 32768 ls scratch/extract/write-hole
   e2fsck -fn scratch/md0.img
   ```

3. Read the staging area from the assembled filesystem. `/stage/isfc-stage.py` seals the report in six independent 32 KiB records with AES-256-GCM. The nonce is `struct.pack(">QI", job, idx)`, and the AAD is `payload.bin|<job>|<idx>`. The key is read from `/stage/.keyslot` (magic `KSLT`), which is unlinked after use. The SHA-256 of each sealed record is written to `/stage/job-0007.intent` before `payload.bin` is written. `stat` places the payload on filesystem blocks 1160 to 1207. Those blocks are array chunks 145 to 150, which are stripes 72 to 75, so each record is exactly one chunk.
   ```sh
   debugfs -R 'cat /stage/isfc-stage.py' scratch/md0.img
   debugfs -R 'cat /stage/job-0007.intent' scratch/md0.img
   debugfs -R 'cat /etc/nas.conf' scratch/md0.img
   debugfs -R 'stat /stage/payload.bin' scratch/md0.img
   ```
   The intent file names the job and the `key_id`, and `/etc/nas.conf` confirms `data=journal`.

4. Recover the key from the journal. With `data=journal`, the content of the unlinked keyslot blocks is still in the journal. The keyslot magic `KSLT` appears at array offsets `0xd000` (job 5), `0x13000` (job 6), `0x1a000` and `0x20000` (job 7, the key rotated by the operator). Each blob is 52 bytes: an 8-byte header starting with the magic, the job number as a big-endian u64, the 32-byte key, and a CRC32 over the first 48 bytes. Only the job 7 slot at `0x20000` has a valid CRC and a key whose `sha256(key)[:16]` equals the `key_id` in the intent. The other job 7 slot, at `0x1a000`, is the discarded pre-rotation key and fails GCM authentication.

5. Rebuild the six records. Records 0, 2 and 4 are on disk in their data chunks, and their hashes match the intent. Records 1, 3 and 5 are still job 6 in their data chunks, but the stripe parity already holds job 7 content. For these, `parity XOR sibling chunk` gives the job 7 record, and the hash check passes for records 1 and 5. Record 3 is the only one that fails the hash check, and step 6 handles it.

6. Repair record 3. The parity-derived version of record 3 misses its intent hash by a single bit. Flipping bit 1 of byte 8876 of the record makes the hash match. The sibling chunk matches its own hash, so the flipped bit sits in the parity chunk on `bay1.img`. The solver tries every single-bit flip of a candidate record that already carries the job 7 nonce, and keeps the one that matches the hash.

7. Decrypt the six records and assemble the token. Each record is decrypted with the job 7 key, the nonce and the AAD above, and all six authenticate. The report instructs that the custody token is split into three shards, which are concatenated in numeric order with no separator. The three shards are in records 1, 3 and 5, which exist only through parity. The solver prints the joined token as its last line.
   ```sh
   python3 scripts/solve.py scratch/extract/write-hole scratch/report.bin
   ```
   The output lists each keyslot found, then one line per record naming the source that matched its hash, and the joined token is the last line:
   ```text
   isfcr{REDACTED}
   ```
   The solver takes about 10 seconds and needs the `cryptography` package.

### Scripts

#### scripts/assemble.py

Builds one array image from the three members for a given member order, chunk size and md layout (`la`, `ls`, `ra` or `rs`). It is used to find the geometry, and its output `md0.img` is the input for the `e2fsck` and `debugfs` steps. `solve.py` does not import it, since it maps the members itself. Run it as `python3 scripts/assemble.py scratch/md0.img 120 32768 ls scratch/extract/write-hole`.

```python
#!/usr/bin/env python3
"""Assemble the 3-member RAID5 into one array image.

Usage: assemble.py OUT ORDER CHUNK LAYOUT IMG_DIR
  ORDER   member order as bay indexes, e.g. 012
  CHUNK   chunk size in bytes
  LAYOUT  la | ls | ra | rs (md left/right, asymmetric/symmetric)
"""
import sys

DATA_OFFSET = 0x100000
N = 3


def data_disks(stripe, layout):
    left = layout[0] == "l"
    p = (N - 1 - stripe % N) if left else stripe % N
    if layout[1] == "s":
        return p, [(p + 1 + i) % N for i in range(N - 1)]
    return p, [d for d in range(N) if d != p]


def main():
    out, order, chunk, layout, img_dir = sys.argv[1:6]
    chunk = int(chunk, 0)
    members = [open(f"{img_dir}/bay{c}.img", "rb").read()[DATA_OFFSET:] for c in order]
    with open(out, "wb") as f:
        for stripe in range(len(members[0]) // chunk):
            _, disks = data_disks(stripe, layout)
            for d in disks:
                f.write(members[d][stripe * chunk:(stripe + 1) * chunk])


if __name__ == "__main__":
    main()
```

#### scripts/solve.py

Works directly on the three raw members with the fixed geometry (order `1, 2, 0`, 32768-byte chunks, left-symmetric). It finds the job 7 keyslot in the array by its magic, CRC and `key_id`, then for each of the six intent records it takes either the data chunk or the parity XOR sibling chunk, whichever matches the intent hash (repairing one flipped bit if needed). It decrypts the records, writes the plaintext report and prints the joined custody token. Run it as `python3 scripts/solve.py scratch/extract/write-hole scratch/report.bin`, from `work/`.

```python
#!/usr/bin/env python3
"""Recover the sealed report of job 7 from the three raw members.

Usage: solve.py IMG_DIR OUT_PLAIN
Prints the keyslots found, which source satisfied each intent hash, and the
custody token assembled from the three shards of the decrypted report.
"""
import hashlib, json, re, struct, sys, zlib
from itertools import product
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

DATA_OFFSET = 0x100000
CHUNK = 32768
ORDER = (1, 2, 0)        # bay index of md member 0, 1, 2
N = 3
BLOCK = 4096
PAYLOAD_BLOCK = 1160     # first fs block of /stage/payload.bin (debugfs stat)
INTENT_BLOCK_GLOB = b'"target": "/stage/payload.bin"'


def locate(chunk_no):
    """Left-symmetric: (stripe, data member, sibling data member, parity member)."""
    stripe, k = divmod(chunk_no, N - 1)
    p = N - 1 - stripe % N
    return stripe, (p + 1 + k) % N, (p + 1 + (1 - k)) % N, p


def xor(a, b):
    return bytes(x ^ y for x, y in zip(a, b))


def repair_bit(rec, want):
    """Return (rec with one bit flipped, byte, bit) matching the hash, or None."""
    want = bytes.fromhex(want)
    h = hashlib.sha256()
    for i in range(len(rec)):
        tail = rec[i + 1:]
        for bit in range(8):
            g = h.copy()
            g.update(bytes([rec[i] ^ (1 << bit)]))
            g.update(tail)
            if g.digest() == want:
                return rec[:i] + bytes([rec[i] ^ (1 << bit)]) + tail, i, bit
        h.update(rec[i:i + 1])
    return None


def main():
    img_dir, out = sys.argv[1:3]
    members = [open(f"{img_dir}/bay{b}.img", "rb").read()[DATA_OFFSET:] for b in ORDER]

    def member_chunk(m, stripe):
        return members[m][stripe * CHUNK:(stripe + 1) * CHUNK]

    array = b"".join(member_chunk(locate(c)[1], locate(c)[0])
                     for c in range(len(members[0]) // CHUNK * (N - 1)))

    start = array.index(INTENT_BLOCK_GLOB)
    start = array.rindex(b"{", 0, start)
    intent = json.loads(array[start:array.index(b"}", start) + 1])
    job = intent["job"]

    key = None
    for m in re.finditer(b"KSLT\x01", array):
        blob = array[m.start():m.start() + 52]
        kjob, k, crc = struct.unpack(">8xQ32sI", blob)
        ok = zlib.crc32(blob[:48]) == crc
        kid = hashlib.sha256(k).hexdigest()[:16]
        print(f"keyslot @0x{m.start():x} job={kjob} crc_ok={ok} key_id={kid} key={k.hex()}")
        if ok and kjob == job and kid == intent["key_id"]:
            key = k
    assert key, "no keyslot matches the intent key_id"

    plain = b""
    first = PAYLOAD_BLOCK * BLOCK // CHUNK
    for idx, want in enumerate(intent["records"]):
        stripe, d, sib, p = locate(first + idx)
        cands = {
            f"data(member{d})": member_chunk(d, stripe),
            f"parity(member{p})^sibling(member{sib})":
                xor(member_chunk(p, stripe), member_chunk(sib, stripe)),
        }
        hit = [(n, c) for n, c in cands.items() if hashlib.sha256(c).hexdigest() == want]
        if hit:
            name, rec = hit[0]
        else:
            # only a candidate already carrying this job's nonce is worth repairing
            name, rec = next((n, c) for n, c in cands.items()
                             if c[:12] == struct.pack(">QI", job, idx))
            fixed = repair_bit(rec, want)
            assert fixed, f"record {idx}: no candidate matches the intent hash"
            rec, byte, bit = fixed
            name += f", bit {bit} of byte {byte} flipped back"
        print(f"record {idx}: stripe {stripe} from {name}")
        nonce = struct.pack(">QI", job, idx)
        assert rec[:12] == nonce
        plain += AESGCM(key).decrypt(nonce, rec[12:], b"payload.bin|%d|%d" % (job, idx))

    open(out, "wb").write(plain)
    # the report says: concatenate shard 1, 2, 3 in numeric order, no separators
    shards = dict(re.findall(rb"\[custody-token\] shard (\d)/3 = (.*)", plain))
    print("".join(shards[k].decode() for k in sorted(shards)))


if __name__ == "__main__":
    main()
```

### Notes

- Reading `/stage/payload.bin` from the assembled filesystem gives a mix of job 7 records (0, 2, 4) and job 6 records (1, 3, 5). The report is incomplete there and contains no complete shard, so the token only exists through parity.
- A 1024-byte chunk size is a dead end. Early analysis of the parity pattern suggested it, but no mapping with that chunk size produced a filesystem that `e2fsck` accepts. The 32768-byte chunk is the one that works.
- Six other sectors hold a single flipped bit in otherwise empty space. They break the parity check but do not touch any file.
- The second job 7 keyslot in the journal (`0x1a000`) is the discarded pre-rotation key. It has a valid CRC but fails GCM authentication, so only the `0x20000` slot is used.
- `solve.py` reads the members directly and does not need `md0.img`. The `e2fsck` and `debugfs` steps are only for checking the geometry and reading `/stage`.
- The decrypted report is written to the output path passed as the second argument. The `[custody-token] shard N/3` lines in it are the only lines the solver uses.
