### Summary

The smart lighting mesh uses a fleet-wide Trust Center (TC) Link Key to protect its key transport and the 128-bit network key that encrypts the daily report. The I/Q traces of the coordinator leak the first AES round through power consumption, so a correlation power analysis (CPA) over the nonces recovers the TC Link Key byte by byte. That key validates against the KEY_CONFIRM tags, decrypts the TRANSPORT_KEY frame to the network key, and the network key decrypts the SECURE_REPORT frames, one of which carries the flag.

### Steps

1. Run the recovery script from the challenge `work/` directory. It reads `files/phantom-mesh.zip` directly, so nothing needs to be extracted. It needs NumPy and `cryptography`.
   ```sh
   python3 scripts/solve.py
   ```
   Output:
   ```text
   TC Link Key: 7cf8b0b78be9f36a225c1e70692e1e1c
   KEY_CONFIRM tags verified: 8
   Network key: ffa0be732cd8f56eae8caa21359baf06
   Authenticated reports: 96
   Candidate flag: isfcr{REDACTED}
   ```

2. Recover the TC Link Key with CPA on the aligned I/Q traces. The amplitude `|iq|` of each triggered record is correlated against a Hamming-weight model of the first AES round, `HW(SBOX(nonce_byte XOR guess))`, for each of the 16 key bytes. The nonces come from `traces/nonces.csv` (16-byte values), and the traces from `traces/iq.npz`. For byte `i` the script uses a 120-sample window starting at `1000 + 47*i`. The guess with the largest absolute Pearson correlation in that window is the key byte. The leakage peaks of the 16 bytes occur in sequence between samples 1051 and 1771. Repeating the analysis on independent halves of the traces gives the same guesses.

3. Validate the candidate key with the KEY_CONFIRM frames. Each frame has `payload[2] == 0x12`, a 16-byte nonce at `payload[3:19]` and an 8-byte tag at `payload[19:27]`. The tag equals the first 8 bytes of `AES-128-ECB(tc_key, nonce)`. All eight frames match, which confirms the key.

4. Recover the network key from the TRANSPORT_KEY frame. Frames with `payload[2] == 0x11` carry the transport body. It is decrypted with AES-CCM* under the TC key, with a 4-byte tag. The nonce is the reversed EUI-64, then the frame counter, then the security control byte. The AAD is the security control byte, the counter and the EUI-64. The authenticated plaintext is the NWK key `ffa0be732cd8f56eae8caa21359baf06`. The layouts follow the vendor notes in `docs/`.

5. Decrypt the reports. SECURE_REPORT frames start with `1c 03 21`. Each one is decrypted with the NWK key, using the same CCM* construction. All 96 frames authenticate. The plaintext of one report contains `isfcr{...}` after a 6-byte header, and it is the only one with that prefix, so the script takes it as the flag.

### Scripts

#### scripts/solve.py

Runs the whole chain: AES S-box generation, first-round CPA over the I/Q amplitudes for each key byte, KEY_CONFIRM validation, CCM* decryption of the transport key and of every SECURE_REPORT, and printing of the candidate flag. Run it as `python3 scripts/solve.py` from `work/`, since the archive path is resolved relative to the script's location.

```python
#!/usr/bin/env python3
import csv
import io
import struct
import zipfile
from pathlib import Path

import numpy as np
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESCCM


ROOT = Path(__file__).resolve().parents[2]
ARCHIVE = ROOT / "files" / "phantom-mesh.zip"


def gf_mul(a, b):
    result = 0
    for _ in range(8):
        if b & 1:
            result ^= a
        a = ((a << 1) ^ (0x11B if a & 0x80 else 0)) & 0xFF
        b >>= 1
    return result


def aes_sbox():
    def inverse(value):
        result = 1
        for _ in range(254):
            result = gf_mul(result, value)
        return result if value else 0

    def rotate(value, count):
        return ((value << count) | (value >> (8 - count))) & 0xFF

    return np.array([
        inverse(x) ^ rotate(inverse(x), 1) ^ rotate(inverse(x), 2)
        ^ rotate(inverse(x), 3) ^ rotate(inverse(x), 4) ^ 0x63
        for x in range(256)
    ], dtype=np.uint8)


def packets(pcap):
    offset = 24
    while offset < len(pcap):
        _, _, size, _ = struct.unpack_from("<IIII", pcap, offset)
        offset += 16
        frame = pcap[offset:offset + size]
        offset += size
        yield frame, frame[9:-2]


def decrypt_body(key, body):
    sec_ctl, counter, eui_le = body[0], body[1:5], body[5:13]
    nonce = eui_le[::-1] + counter + bytes([sec_ctl])
    aad = bytes([sec_ctl]) + counter + eui_le
    plaintext = AESCCM(key, tag_length=4).decrypt(nonce, body[13:], aad)
    return plaintext


with zipfile.ZipFile(ARCHIVE) as archive:
    iq = np.load(io.BytesIO(archive.read("phantom-mesh/traces/iq.npz")))["iq"]
    rows = csv.DictReader(io.StringIO(archive.read("phantom-mesh/traces/nonces.csv").decode()))
    nonces = np.stack([
        np.frombuffer(bytes.fromhex(row["nonce_hex"]), dtype=np.uint8)
        for row in rows
    ])
    pcap = archive.read("phantom-mesh/mesh.pcap")

amplitude = np.abs(iq).astype(np.float32)
sbox = aes_sbox()
weights = np.unpackbits(np.arange(256, dtype=np.uint8)[:, None], axis=1).sum(axis=1)
key_bytes = []

for byte_index in range(16):
    start = 1000 + 47 * byte_index
    trace_window = amplitude[:, start:start + 120].copy()
    trace_window -= trace_window.mean(axis=0)
    guesses = np.arange(256, dtype=np.uint8)
    predicted = weights[sbox[np.bitwise_xor(nonces[:, byte_index, None], guesses)]].T.astype(np.float32)
    predicted -= predicted.mean(axis=1, keepdims=True)
    correlation = predicted @ trace_window
    correlation /= np.sqrt(
        (predicted * predicted).sum(axis=1)[:, None]
        * (trace_window * trace_window).sum(axis=0)[None, :]
    )
    key_bytes.append(int(np.max(np.abs(correlation), axis=1).argmax()))

tc_key = bytes(key_bytes)
ecb = Cipher(algorithms.AES(tc_key), modes.ECB()).encryptor()
confirmations = []
transport = None
reports = []
for frame, payload in packets(pcap):
    if payload[:2] != b"\x1c\x03":
        continue
    if payload[2] == 0x12:
        confirmations.append(payload[19:27] == ecb.update(payload[3:19])[:8])
    elif payload[2] == 0x11:
        transport = payload[3:]

if not confirmations or not all(confirmations) or transport is None:
    raise SystemExit("TC Link Key validation failed")

nwk_key = decrypt_body(tc_key, transport)
for frame, payload in packets(pcap):
    if payload[:3] == b"\x1c\x03\x21":
        try:
            report = decrypt_body(nwk_key, payload[3:])
        except Exception:
            continue
        reports.append(report)

matches = [
    report[6:]
    for report in reports
    if len(report) >= 6 and report[6:].startswith(b"isfcr{")
]
if len(matches) != 1:
    raise SystemExit(f"expected one report flag, found {len(matches)}")

flag = matches[0].decode("ascii")
if not flag.endswith("}") or " " in flag or not flag.isprintable():
    raise SystemExit("recovered value does not match the README flag syntax")

print(f"TC Link Key: {tc_key.hex()}")
print(f"KEY_CONFIRM tags verified: {len(confirmations)}")
print(f"Network key: {nwk_key.hex()}")
print(f"Authenticated reports: {len(reports)}")
print(f"Candidate flag: {flag}")
```

### Notes

- The 96 authenticated reports carry the diagnostic data. Only one of them has the `isfcr{` prefix after the 6-byte header, which is why the script requires exactly one match.
- The script's `packets()` helper hard-codes a 9-byte MAC header, a 2-byte FCS and a 16-byte pcap record header. A different capture layout needs different offsets.
- The CPA window offsets (`1000 + 47*i`, 120 samples) are specific to this trace set. Other captures need the peak locations found again.
- The TC Link Key, the network key and the report keys are intermediate values of the chain and are kept in the output. Only the flag is redacted.
- The README names the flag format as `isfcr{...}` with printable ASCII and no spaces inside the braces. The script checks these conditions.
