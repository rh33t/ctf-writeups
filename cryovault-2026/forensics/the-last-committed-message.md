### Summary

The handout is a SQLite database in WAL mode, and its write-ahead log keeps the full transaction history across three checkpoint epochs concatenated in one file. Opening the database normally shows only the newest epoch, so the target operation is invisible. Rolling the base database forward frame by frame to the commit that writes operation `op-09e0d79b4b14` (the acknowledged export of `export-07abca69cd99`) gives the note, revision, destination and attachment hash as they were at that commit. These four evidence fields derive the scrypt key that decrypts the flag with AES-GCM.

### Steps

1. Extract the handout and check the database state with a plain open.
   ```sh
   unzip -o ../files/handout.zip -d scratch/
   sqlite3 scratch/the-last-committed-message/case.db \
     "select count(*) from operations;"
   ```
   A plain open reads only the newest WAL epoch, and the target operation id is not present.

2. Locate the commit that writes the target. The WAL has 1538 frames. Replaying them one commit at a time (a frame with a non-zero database size field ends a transaction), the solver rebuilds the database after each commit and checks the `operations` table for `op-09e0d79b4b14`. Two details matter:
   - Each rebuilt image must set the page-1 database size field (bytes 28 to 31) to the commit's database size. Without this, SQLite reports "database disk image is malformed" at epoch boundaries.
   - The rebuild uses the base database as the starting point for all frames up to the candidate commit.

   The first commit where the target appears is WAL frame 455, with a database size of 208 pages. The transaction spanning frames 433 to 455 writes the note row, the attachment record and the operation record together. Applying the segments in file order or in salt-ascending order gives the same rows, so the epoch order does not change the result.

3. Read the four evidence fields from the database image at frame 455. The note is `note-7211098c21a6` at revision `5`. Its destination is the value stored in the `notes` row, and the attachment is `blob-72346f69c681`, whose `sha256` is in the `attachments` table.

4. Build the evidence list, derive the key and decrypt the flag. The evidence list is `[note_id, str(revision), destination, sha256]`, serialized as compact ASCII JSON. The scrypt key comes from `b"isfcr-forensics\x00" + evidence` with the salt from the challenge statement, `n=131072`, `r=8`, `p=1` and a 32-byte output. The AES-GCM ciphertext is then decrypted with the associated data `the-last-committed-message`. The tag only verifies for the exact evidence bytes, so a successful decryption confirms the evidence.
   ```sh
   python3 scripts/solve.py scratch/the-last-committed-message/case.db \
                            scratch/the-last-committed-message/case.db-wal
   ```
   Output:
   ```text
   target op committed at WAL frame 455
   evidence: ["note-7211098c21a6", "5", "sftp://drop-edef61bb364d.example.invalid/inbox/.../5ec4921ffe4835a0.bin?ticket=a638d0e59bf0b87a8d34c22020f0555d", "b89d5c5695803071522614060828e31e9bb4bc25813fdbc5d516db06ac4c2d58"]
   flag: isfcr{REDACTED}
   ```

### Scripts

#### scripts/solve.py

Finds the first WAL commit whose rebuilt database contains `op-09e0d79b4b14`, reads the note, revision, destination and attachment hash from that state, derives the scrypt key from the evidence and decrypts the flag with AES-GCM. Run it from `work/` as `python3 scripts/solve.py <case.db> <case.db-wal>`, after extracting the handout. It needs the `cryptography` package.

```python
#!/usr/bin/env python3
"""Recover the note + attachment state right after op-09e0d79b4b14 committed.

The handout is a SQLite DB in WAL mode.  Its WAL holds the whole transaction
history (several checkpoint epochs concatenated), so rolling the base DB
forward to the commit that writes the operation record yields the historical
row values.  The flag is derived from the four evidence fields.

Usage: solve.py <case.db> <case.db-wal>
"""
import hashlib
import json
import os
import sqlite3
import struct
import sys
import tempfile

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

TARGET_OP = "op-09e0d79b4b14"
PAGE_SIZE = 512

# Flag material from the challenge statement.
SALT = bytes.fromhex("a3845b1a904c5ee73abe7329b5d735d7")
NONCE = bytes.fromhex("ca98cff993b27fd3bb352436")
CIPHERTEXT = bytes.fromhex(
    "3fa8b9049b01fb8d12df130b404352f9c678c272cccb7e6c034554c902f1ca4d"
    "574fc04db8892fead1ad394735e021"
)
AAD = b"the-last-committed-message"


def load_wal(wal_path):
    wal = open(wal_path, "rb").read()
    _, _, page_size, _, _, _, _, _ = struct.unpack(">IIIIIIII", wal[:32])
    assert page_size == PAGE_SIZE
    frame_size = 24 + PAGE_SIZE
    n = (len(wal) - 32) // frame_size
    frames = []
    for i in range(n):
        off = 32 + i * frame_size
        pg, dbsize, _, _, _, _ = struct.unpack(">IIIIII", wal[off:off + 24])
        frames.append((pg, dbsize, wal[off + 24:off + 24 + PAGE_SIZE]))
    return frames


def reconstruct(db_path, frames, stop_frame):
    """Apply frames[0:stop_frame] to the base DB, return (db_bytes, dbsize)."""
    base = open(db_path, "rb").read()
    pages = {i + 1: p for i, p in enumerate(
        [base[j:j + PAGE_SIZE] for j in range(0, len(base), PAGE_SIZE)])}
    dbsize = max(pages)
    for i in range(stop_frame):
        pg, dbsize, data = frames[i]
        pages[pg] = data
        if dbsize:
            hdr = bytearray(pages[1])
            hdr[28:32] = struct.pack(">I", dbsize)
            pages[1] = bytes(hdr)
    out = bytearray()
    for p in range(1, dbsize + 1):
        out += pages.get(p, b"\x00" * PAGE_SIZE)
    return bytes(out)


def find_target_frame(db_path, frames):
    """First frame index whose commit leaves TARGET_OP in the operations table."""
    for i, (pg, dbsize, data) in enumerate(frames):
        if not dbsize:
            continue
        image = reconstruct(db_path, frames, i + 1)
        tmp = os.path.join(tempfile.mkdtemp(prefix="tlcm_"), "r.db")
        with open(tmp, "wb") as f:
            f.write(image)
        try:
            con = sqlite3.connect(tmp)
            hit = con.execute(
                "SELECT 1 FROM operations WHERE operation_id=?", (TARGET_OP,)
            ).fetchone()
            con.close()
        except sqlite3.DatabaseError:
            continue
        if hit:
            return i + 1
    raise SystemExit("target operation was never observed")


def main():
    db_path, wal_path = sys.argv[1], sys.argv[2]
    frames = load_wal(wal_path)
    stop = find_target_frame(db_path, frames)
    print(f"target op committed at WAL frame {stop}")

    image = reconstruct(db_path, frames, stop)
    tmp = os.path.join(tempfile.mkdtemp(prefix="tlcm_"), "r.db")
    with open(tmp, "wb") as f:
        f.write(image)
    con = sqlite3.connect(tmp)
    note_id, revision, destination, attachment_id = con.execute(
        "SELECT note_id, revision, destination, attachment_id FROM notes "
        "WHERE operation_id=?", (TARGET_OP,)).fetchone()
    sha256 = con.execute(
        "SELECT sha256 FROM attachments WHERE attachment_id=?",
        (attachment_id,)).fetchone()[0]
    con.close()

    evidence = [note_id, str(revision), destination, sha256]
    print("evidence:", json.dumps(evidence))

    blob = b"isfcr-forensics\x00" + json.dumps(
        evidence, ensure_ascii=True, separators=(",", ":")).encode("ascii")
    key = hashlib.scrypt(blob, salt=SALT, n=131072, r=8, p=1,
                         maxmem=2 ** 28, dklen=32)
    flag = AESGCM(key).decrypt(NONCE, CIPHERTEXT, AAD).decode()
    print("flag:", flag)


if __name__ == "__main__":
    main()
```

### Notes

- The WAL contains 1538 frames over three salt epochs. The attempt that failed first was a plain `sqlite3` open, which only reads the newest epoch (6 commits of segment A).
- The diagnostic helper `scripts/wal_replay.py` in the vault dumps the operations and notes state at every commit. It is not needed for the solve, and it was used to confirm that the target first appears at frame 455.
- The destination is an `sftp://` URL with a ticket query parameter. It is part of the evidence and is kept as stored, byte for byte.
- The solve depends on the exact destination string and the lowercase hex hash. Any change to either breaks the AES-GCM tag check.
