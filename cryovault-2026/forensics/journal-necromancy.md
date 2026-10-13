### Summary

The vault in the NTFS image is encrypted with AES-256-GCM, and its 32-byte key is the XOR of three shares. Each share was stored in a file that was later deleted, and the MFT records were then reused by a flood of temporary files, so the metadata trail is gone. The deleted data clusters were never zeroed, and each share is still in unallocated space behind a 4-byte marker `de ad 53 47`. Carving the three carriers, XORing the shares and decrypting the vault gives the flag.

### Steps

Commands are run from the challenge `work/` directory.

1. Extract the image and list the live files. The only relevant live files are `/Personal/reminders.txt` and `/Personal/vault/secure_archive.enc`.
   ```sh
   mkdir -p scratch/extract && unzip -q ../files/journal-necromancy.zip -d scratch/extract
   IMG=scratch/extract/journal-necromancy/evidence.img
   ntfsls -f -a -l -R $IMG
   ```

2. Read the scheme from the reminder file and the vault header. The reminder says the cipher is AES-256-GCM, the key is the XOR of three 32-byte shares, and each carrier holds a share, a 1-byte index (1, 2 or 3) and a 1-byte XOR parity. The vault is a 4-byte marker `ENC1`, a 12-byte nonce, the ciphertext and a 16-byte tag.
   ```sh
   ntfscat -f $IMG Personal/reminders.txt
   ntfscat -f $IMG Personal/vault/secure_archive.enc | xxd
   ```

3. Rule out the journals and the MFT. `$LogFile` is entirely `0xff`, and `$Extend` has no `$UsnJrnl`, so neither journal holds the shares. The deleted entries are the directory `/Cache/_c` and 131 random 80-byte `c*_NNNN.tmp` files, which reused the MFT records of the wiped files.
   ```sh
   ntfscat -f $IMG '$LogFile' | xxd | head -3
   ntfsundelete -f $IMG | rg -v '<none>' | head
   ```

4. Find the clusters that are used but not marked allocated. Clusters 10420, 12133 and 13848 are non-zero while `$Bitmap` says they are free. They hold a deleted runtime log, random data and a deleted "Scratch working notes" file. Each carrier is a 38-byte record inside that data: the marker `de ad 53 47`, the index byte, the 32-byte share and the parity byte. Searching for the marker gives exactly three hits, one per index.
   ```sh
   rg -a -b -o '(?-u)\xde\xad\x53\x47' $IMG | cut -d: -f1
   xxd -s $((0x28b4a5d)) -l 38 $IMG
   ```

5. Verify each carrier, rebuild the key and decrypt the vault. The parity check is `parity = XOR(share) XOR index`. The three carriers pass, and the key is `share1 XOR share2 XOR share3`. The GCM tag verifies with no associated data, and the plaintext is the flag.
   ```sh
   python3 scripts/solve.py scratch/extract/journal-necromancy/evidence.img
   ```
   Output (the last line is the flag):
   ```text
   carrier @0x28b4a5d cluster 10420 idx=1 parity_ok=True share=6d71c9d7ead70c055cfa2927a3d3c6a5fb0a7c341b18a986d0196d588b4c9409
   carrier @0x2f65960 cluster 12133 idx=2 parity_ok=True share=e1785bae1e7ae88432441b37d3c3d9e3465f003e540d929367cf1f37cc742540
   carrier @0x36187ce cluster 13848 idx=3 parity_ok=True share=ef39842f2220d28e4a6c38c14e8442048ce9522b0794333c1b54fb3bde564383
   key 63301656d68d360f24d20ad13e945d4231bc2e2148810829ac828954996ef2ca
   isfcr{REDACTED}
   ```

### Scripts

#### scripts/solve.py

Carves the three carriers by searching for the marker, checks each parity byte, XORs the shares into the key, reads the resident `$DATA` of `secure_archive.enc` from its MFT record and decrypts it with AES-256-GCM. Run it with `python3 scripts/solve.py <evidence.img>` after extracting the zip, and it needs the `cryptography` package.

```python
#!/usr/bin/env python3
"""Carve the three key shares from evidence.img and open the vault.

Usage: solve.py IMG
Prints each carrier found, the key, and the decrypted archive.
"""
import re, struct, sys
from functools import reduce
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

CLUSTER = 4096
MFT_OFFSET = 4 * CLUSTER
RECORD = 1024
CARRIER = b"\xde\xadSG"   # marker, then index, 32-byte share, parity


def vault_blob(img):
    """Resident $DATA of the MFT record named secure_archive.enc."""
    name = "secure_archive.enc".encode("utf-16le")
    for off in range(MFT_OFFSET, MFT_OFFSET + 220 * RECORD, RECORD):
        rec = bytearray(img[off:off + RECORD])
        if rec[:4] != b"FILE" or name not in rec:
            continue
        usa_off, usa_count = struct.unpack_from("<HH", rec, 4)
        for i in range(1, usa_count):
            rec[i * 512 - 2:i * 512] = rec[usa_off + 2 * i:usa_off + 2 * i + 2]
        pos = struct.unpack_from("<H", rec, 0x14)[0]
        while True:
            atype, alen = struct.unpack_from("<II", rec, pos)
            if atype == 0x80:
                size, start = struct.unpack_from("<IH", rec, pos + 0x10)
                return bytes(rec[pos + start:pos + start + size])
            pos += alen
    raise SystemExit("vault not found")


def main():
    img = open(sys.argv[1], "rb").read()
    shares = {}
    for m in re.finditer(re.escape(CARRIER), img):
        o = m.start()
        idx, share, parity = img[o + 4], img[o + 5:o + 37], img[o + 37]
        ok = reduce(lambda a, b: a ^ b, share) ^ idx == parity
        print(f"carrier @0x{o:x} cluster {o // CLUSTER} idx={idx} parity_ok={ok} share={share.hex()}")
        if ok:
            shares[idx] = share
    assert sorted(shares) == [1, 2, 3], "need shares 1, 2 and 3"
    key = bytes(a ^ b ^ c for a, b, c in zip(shares[1], shares[2], shares[3]))
    print("key", key.hex())

    blob = vault_blob(img)
    assert blob[:4] == b"ENC1"
    print(AESGCM(key).decrypt(blob[4:16], blob[16:], None).decode())


if __name__ == "__main__":
    main()
```

### Notes

- Despite the title, the solve does not use `$LogFile` or a USN journal. The log is 2 MiB of `0xff` and the USN journal is absent.
- The reminder describes the carrier as share, index, parity. On disk the index byte comes before the share, and a 4-byte marker precedes both. A blind search for share, index and parity only returns chance hits in random data, so search for the marker.
- The directory index slack of `/Cache/_c` still names deleted files such as `setup-2026-03.log` and `wip.tmp`, which is a useful lead but not needed for the solve.
- The key and the three shares are intermediate values of the exploit chain and are shown in full. Only the final flag is redacted.
- The vault record is resident (85 bytes in MFT record 87), so the script reads it from the MFT and does not need a cluster lookup.
