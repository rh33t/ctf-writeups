### Summary

Trigger-aligned correlation power analysis (CPA) on the lab scope traces recovers the two AES keys used by the IEEE 802.15.4 captures. With those keys, the secured frames authenticate, and they show that a diagnostic message shares its low 16 bits of message ID with an earlier continuity message, so the gateway's dedupe suppressed it. The diagnostic was split into nine Reed-Solomon shards over GF(2^8), eight of which are enough to rebuild the 188-byte `DG15` record. Its authenticated note contains the flag.

### Steps

All paths are relative to the challenge's `work/` directory. The participant bundle is `files/phantom15-participant.zip`. It contains three pcapng captures, `scope_traces.npz`, `scope_session_metadata.bin`, `qualification_vectors.csv` and the text notes. The scripts read the ZIP directly, so there is no need to extract it.

1. Recover the two AES keys with CPA. `scope_session_metadata.bin` (a `P15Q` version 1 file) maps each scope capture to a session and a radio key index: session 31 maps 2,600 captures to key index 43, and session 32 maps 1,800 captures to key index 100. Records whose samples contain the ADC saturation value of magnitude 2.5 are removed (251 records). Each remaining trace is shifted so its trigger peak lines up. The script then correlates the Hamming weight of `SBOX[plaintext_byte XOR key_guess]` with the aligned samples for each of the 16 key bytes. The correct peaks appear at samples `120 + 11*i` for byte `i`.
   ```sh
   python3 scripts/recover_keys.py ../files/phantom15-participant.zip
   ```
   The output lists one line per session, with the key and per-byte correlations (about 0.15 to 0.25). The recovered keys are:
   ```text
   key index 43:  bb5136c65215e473f8973fdaf8d3845c
   key index 100: cea97c91a3504ff1800e51e2aafb3c9b
   ```

2. Authenticate the radio frames. Each pcapng enhanced packet block holds an IEEE 802.15.4 frame. For a secured frame the CCM nonce is the 8 source bytes from the frame (in on-air order), the 4 frame-counter bytes, and the security level `6`. The MAC header up to the auxiliary security header is used as AAD. The payload between that header and the 2-byte FCS is decrypted with AES-CCM and an 8-byte MIC. The script tries the frame with the key for its key index and reports either the plaintext or an invalid MIC.
   ```sh
   python3 scripts/decrypt_frames.py ../files/phantom15-participant.zip
   ```
   The two keys authenticate 40 frames. One frame has an invalid MIC and is discarded. Each monitor's clock is fitted to the HS15 sync ticks, and every authenticated frame is on the channel `[15, 20, 25][(window + 1) mod 3]` expected for its window.

3. Find the dedupe collision and rebuild the record. The earlier continuity message from source `acde480000000f15` has full message ID `0x00004a31`. The later diagnostic has full ID `0xa17c4a31`. A gateway that deduplicates on the low 16 bits sees both as `4a31` and drops the diagnostic. The diagnostic's transport header gives `n`, `k`, the shard index and the original size. Nine distinct authentic shards are present, with indices `0, 1, 3, 4, 6, 8, 9, 10, 11`. The script builds the systematic Reed-Solomon generator over GF(2^8) with polynomial `0x11d`, inverts the rows for any eight available shards, and recovers the 188-byte record.
   ```sh
   python3 scripts/reconstruct_record.py ../files/phantom15-participant.zip
   ```
   The script prints the message statistics and, for the diagnostic message:
   ```text
   authenticated_frames=40 invalid_mics=1
   sensor=0xacde480000000f15 epoch=1783456050650000 sequence=37842 category=7
   samples=(123, 119, 117, 131, 260, 441, 377, 128)
   prior_message_id=0x00004a31
   note=gateway low16 dedupe collision: 4a31 prior, a17c4a31 new; RF valid; isfcr{REDACTED}
   ```

4. Validate the record. The `DG15` record stores a CRC32 over everything before it and a 16-byte BLAKE2s digest after it. `parse_record` asserts both and checks that the record length matches exactly. The authenticated note carries the flag, `isfcr{REDACTED}`.

### Scripts

#### scripts/recover_keys.py

Parses the metadata, the qualification vectors and the scope traces from the ZIP, removes saturated traces, aligns the triggers, and runs byte-wise CPA for both sessions. It prints the recovered key and per-byte correlations. Run it from `work/` with `python3 scripts/recover_keys.py ../files/phantom15-participant.zip`. It needs `numpy`.

```python
#!/usr/bin/env python3
import csv
import io
import struct
import sys
import zipfile

import numpy as np


SBOX = np.frombuffer(bytes.fromhex(
    "637c777bf26b6fc53001672bfed7ab76"
    "ca82c97dfa5947f0add4a2af9ca472c0"
    "b7fd9326363ff7cc34a5e5f171d83115"
    "04c723c31896059a071280e2eb27b275"
    "09832c1a1b6e5aa0523bd6b329e32f84"
    "53d100ed20fcb15b6acbbe394a4c58cf"
    "d0efaafb434d338545f9027f503c9fa8"
    "51a3408f929d38f5bcb6da2110fff3d2"
    "cd0c13ec5f974417c4a77e3d645d1973"
    "60814fdc222a908846eeb814de5e0bdb"
    "e0323a0a4906245cc2d3ac629195e479"
    "e7c8376d8dd54ea96c56f4ea657aae08"
    "ba78252e1ca6b4c6e8dd741f4bbd8b8a"
    "703eb5664803f60e613557b986c11d9e"
    "e1f8981169d98e949b1e87e9ce5528df"
    "8ca1890dbfe6426841992d0fb054bb16"
), dtype=np.uint8)
HAMMING_WEIGHT = np.array([value.bit_count() for value in range(256)], dtype=np.float64)


def load_inputs(path):
    with zipfile.ZipFile(path) as archive:
        metadata = archive.read("participant/scope_session_metadata.bin")
        assert metadata[:4] == b"P15Q"
        version, session_count, samples, period_ps, trigger, reserved = struct.unpack_from(
            "<BBHIHH", metadata, 4
        )
        assert version == 1 and reserved == 0
        sessions = {}
        offset = 16
        for _ in range(session_count):
            session, key_index, reserved, first_capture, count = struct.unpack_from(
                "<BBHII", metadata, offset
            )
            assert reserved == 0
            sessions[session] = (key_index, first_capture, count)
            offset += 12

        rows = csv.DictReader(io.TextIOWrapper(
            archive.open("participant/qualification_vectors.csv"), encoding="ascii"
        ))
        vectors = {
            int(row["capture_id"]): (int(row["session"], 16), bytes.fromhex(row["aes_input_hex"]))
            for row in rows
        }
        scope = np.load(io.BytesIO(archive.read("participant/scope_traces.npz")))
        traces = scope["traces"]
        capture_ids = scope["capture_id"]
        assert traces.shape == (len(vectors), samples)
        assert scope["sample_period_ns"] == period_ps / 1000
        return sessions, vectors, traces, capture_ids, trigger


def recover_key(plaintexts, traces, start_sample):
    guesses = np.arange(256, dtype=np.uint8)
    centered_traces = traces[:, start_sample:].astype(np.float64)
    centered_traces -= centered_traces.mean(axis=0)
    trace_norms = np.sqrt(np.sum(centered_traces * centered_traces, axis=0))
    key = bytearray()
    details = []
    for byte_index in range(16):
        intermediates = SBOX[np.bitwise_xor(plaintexts[:, byte_index, None], guesses)]
        leakage = HAMMING_WEIGHT[intermediates]
        leakage -= leakage.mean(axis=0)
        correlations = leakage.T @ centered_traces
        correlations /= np.sqrt(np.sum(leakage * leakage, axis=0))[:, None] * trace_norms
        scores = np.max(np.abs(correlations), axis=1)
        guess = int(np.argmax(scores))
        sample = start_sample + int(np.argmax(np.abs(correlations[guess])))
        key.append(guess)
        details.append((guess, float(scores[guess]), sample))
    return bytes(key), details


def main():
    sessions, vectors, traces, capture_ids, trigger = load_inputs(sys.argv[1])
    for session, (key_index, first_capture, count) in sessions.items():
        selected = np.array([
            index for index, capture_id in enumerate(capture_ids)
            if vectors[int(capture_id)][0] == session
        ])
        assert len(selected) == count
        assert set(int(capture_ids[index]) for index in selected) == set(range(first_capture, first_capture + count))
        plaintexts = np.array([
            list(vectors[int(capture_ids[index])][1]) for index in selected
        ], dtype=np.uint8)
        session_traces = traces[selected]
        saturated = np.any(np.abs(session_traces) == 2.5, axis=1)
        plaintexts = plaintexts[~saturated]
        session_traces = session_traces[~saturated]
        trigger_positions = np.argmax(session_traces[:, trigger - 12:trigger + 12], axis=1) + trigger - 12
        sample_indexes = np.arange(session_traces.shape[1])[None, :] + trigger_positions[:, None] - trigger
        sample_indexes = np.clip(sample_indexes, 0, session_traces.shape[1] - 1)
        aligned_traces = np.take_along_axis(session_traces, sample_indexes, axis=1)
        key, details = recover_key(plaintexts, aligned_traces, trigger + 10)
        print(f"session={session:02x} key_index={key_index} traces={len(selected) - saturated.sum()} key={key.hex()}")
        for byte_index, (guess, correlation, sample) in enumerate(details):
            print(f"  byte={byte_index:02d} guess={guess:02x} correlation={correlation:.4f} sample={sample}")


if __name__ == "__main__":
    main()
```

#### scripts/decrypt_frames.py

Parses the pcapng enhanced packet blocks and decrypts or authenticates each secured IEEE 802.15.4 frame with the two recovered keys, printing the plaintext or `INVALID MIC`. It is also imported by `reconstruct_record.py`, so it must stay in the same directory. Run it from `work/` with `python3 scripts/decrypt_frames.py ../files/phantom15-participant.zip`. It needs `cryptography`.

```python
#!/usr/bin/env python3
import struct
import sys
import zipfile

from cryptography.hazmat.primitives.ciphers.aead import AESCCM
from cryptography.exceptions import InvalidTag


KEYS = {
    43: bytes.fromhex("bb5136c65215e473f8973fdaf8d3845c"),
    100: bytes.fromhex("cea97c91a3504ff1800e51e2aafb3c9b"),
}


def pcapng_packets(data):
    offset = 0
    endian = "<"
    while offset < len(data):
        block_type = struct.unpack_from(endian + "I", data, offset)[0]
        if block_type == 0x0A0D0D0A:
            magic = data[offset + 8:offset + 12]
            endian = "<" if magic == b"\x4d\x3c\x2b\x1a" else ">"
            block_type = struct.unpack_from(endian + "I", data, offset)[0]
        block_length = struct.unpack_from(endian + "I", data, offset + 4)[0]
        assert block_length >= 12
        assert struct.unpack_from(endian + "I", data, offset + block_length - 4)[0] == block_length
        if block_type == 6:
            timestamp_high, timestamp_low, captured_length = struct.unpack_from(
                endian + "III", data, offset + 12
            )
            timestamp = (timestamp_high << 32) | timestamp_low
            yield timestamp, data[offset + 28:offset + 28 + captured_length]
        offset += block_length


def decrypt_frame(frame):
    assert frame[0] & 8
    security_control = frame[15]
    assert security_control & 7 == 6
    key_index = frame[20]
    nonce = frame[7:15] + frame[16:20] + bytes([security_control & 7])
    plaintext = AESCCM(KEYS[key_index], tag_length=8).decrypt(nonce, frame[21:-2], frame[:21])
    return key_index, int.from_bytes(frame[16:20], "little"), frame[7:15][::-1].hex(), plaintext


def main():
    with zipfile.ZipFile(sys.argv[1]) as archive:
        for name in sorted(item for item in archive.namelist() if item.endswith(".pcapng")):
            print(name)
            for timestamp, frame in pcapng_packets(archive.read(name)):
                if frame[0] & 8:
                    try:
                        key_index, counter, source, plaintext = decrypt_frame(frame)
                        print(timestamp, key_index, counter, source, plaintext.hex(), repr(plaintext))
                    except InvalidTag:
                        print(timestamp, "INVALID MIC", frame.hex())


if __name__ == "__main__":
    main()
```

#### scripts/reconstruct_record.py

Aligns the three monitors' clocks to the HS15 sync frames, checks the channel of every authenticated frame, groups the authentic `P15` transport shards by full message ID, decodes them with Reed-Solomon over GF(2^8), and parses the `DG15` record with its CRC32 and BLAKE2s checks. Run it from `work/` with `python3 scripts/reconstruct_record.py ../files/phantom15-participant.zip`. It imports `decrypt_frames.py` from the same directory and needs `cryptography`.

```python
#!/usr/bin/env python3
import binascii
import hashlib
import struct
import sys
import zipfile
from collections import defaultdict
from functools import reduce
from operator import xor

from cryptography.exceptions import InvalidTag

from decrypt_frames import decrypt_frame, pcapng_packets


def multiply(left, right):
    result = 0
    while right:
        if right & 1:
            result ^= left
        right >>= 1
        left <<= 1
        if left & 0x100:
            left ^= 0x11D
    return result


def power(value, exponent):
    result = 1
    while exponent:
        if exponent & 1:
            result = multiply(result, value)
        value = multiply(value, value)
        exponent >>= 1
    return result


def invert_matrix(matrix):
    size = len(matrix)
    augmented = [row[:] + [int(index == row_index) for index in range(size)] for row_index, row in enumerate(matrix)]
    for column in range(size):
        pivot = next(row for row in range(column, size) if augmented[row][column])
        augmented[column], augmented[pivot] = augmented[pivot], augmented[column]
        inverse = power(augmented[column][column], 254)
        augmented[column] = [multiply(value, inverse) for value in augmented[column]]
        for row in range(size):
            if row == column or not augmented[row][column]:
                continue
            factor = augmented[row][column]
            augmented[row] = [
                value ^ multiply(factor, pivot_value)
                for value, pivot_value in zip(augmented[row], augmented[column])
            ]
    return [row[size:] for row in augmented]


def matrix_multiply(left, right):
    return [[
        reduce(xor, (multiply(left_value, right[row][column]) for row, left_value in enumerate(left_row)), 0)
        for column in range(len(right[0]))
    ] for left_row in left]


def generator_matrix(n, k):
    vandermonde = [[power(row + 1, column) for column in range(k)] for row in range(n)]
    return matrix_multiply(vandermonde, invert_matrix(vandermonde[:k]))


def decode_shards(shards, n, k, width, original_size):
    selected = sorted(shards)[:k]
    decoder = invert_matrix([generator_matrix(n, k)[index] for index in selected])
    source = [[shards[index][column] for index in selected] for column in range(width)]
    blocks = matrix_multiply(decoder, list(map(list, zip(*source))))
    return b"".join(bytes(block) for block in blocks)[:original_size]


def parse_transport(payload):
    assert payload[:3] == b"P15" and payload[3] == 1 and payload[4] == 0xD1
    message_id, stream = struct.unpack_from("<II", payload, 5)
    n, k, index, original_size, width = struct.unpack_from("<BBBHB", payload, 13)
    shard = payload[19:]
    assert len(shard) == width
    return message_id, stream, n, k, index, original_size, width, shard


def parse_sync(frame):
    if frame[0] & 8:
        return None
    payload = frame[9:-2]
    if not payload.startswith(b"VHS15"):
        return None
    window = int.from_bytes(payload[5:7], "little")
    tick = int.from_bytes(payload[7:15], "little")
    return window, tick, payload[15]


def parse_record(record):
    assert record[:4] == b"DG15" and record[4] == 1
    sensor, epoch, sequence, category, sample_count = struct.unpack_from("<QQHBB", record, 5)
    offset = 25
    samples = struct.unpack_from(f"<{sample_count}h", record, offset)
    offset += sample_count * 2
    message_id, prior_message_id, note_length = struct.unpack_from("<IIH", record, offset)
    offset += 10
    note = record[offset:offset + note_length].decode("utf-8")
    offset += note_length
    stored_crc = struct.unpack_from("<I", record, offset)[0]
    assert stored_crc == binascii.crc32(record[:offset]) & 0xFFFFFFFF
    offset += 4
    assert record[offset:offset + 16] == hashlib.blake2s(record[:offset], digest_size=16).digest()
    assert offset + 16 == len(record)
    return sensor, epoch, sequence, category, samples, message_id, prior_message_id, note


def main():
    messages = defaultdict(dict)
    parameters = {}
    timing = defaultdict(list)
    authenticated = 0
    invalid = 0
    with zipfile.ZipFile(sys.argv[1]) as archive:
        names = sorted(name for name in archive.namelist() if name.endswith(".pcapng"))
        for name in names:
            packets = list(pcapng_packets(archive.read(name)))
            sync = [(timestamp, *parsed) for timestamp, frame in packets if (parsed := parse_sync(frame))]
            first_local, _, first_tick, channel = sync[0]
            last_local, _, last_tick, _ = sync[-1]
            scale = (last_tick - first_tick) / (last_local - first_local)
            for timestamp, frame in packets:
                if not frame[0] & 8:
                    continue
                try:
                    _, _, _, payload = decrypt_frame(frame)
                except InvalidTag:
                    invalid += 1
                    continue
                authenticated += 1
                window = max(item[1] for item in sync if item[0] <= timestamp)
                assert channel == [15, 20, 25][(window + 1) % 3]
                if not payload.startswith(b"P15\x01\xd1"):
                    continue
                message_id, stream, n, k, index, original_size, width, shard = parse_transport(payload)
                network_tick = round(first_tick + (timestamp - first_local) * scale)
                current = (stream, n, k, original_size, width)
                assert message_id not in parameters or parameters[message_id] == current
                assert index not in messages[message_id] or messages[message_id][index] == shard
                parameters[message_id] = current
                messages[message_id][index] = shard
                timing[message_id].append(network_tick)

    print(f"authenticated_frames={authenticated} invalid_mics={invalid}")
    for message_id, shards in messages.items():
        stream, n, k, original_size, width = parameters[message_id]
        assert len(shards) >= k
        record = decode_shards(shards, n, k, width, original_size)
        print(
            f"message_id=0x{message_id:08x} stream={stream} shards={sorted(shards)} "
            f"network_ticks={min(timing[message_id])}..{max(timing[message_id])}"
        )
        if not record.startswith(b"DG15"):
            print(repr(record))
            continue
        sensor, epoch, sequence, category, samples, full_id, prior_id, note = parse_record(record)
        assert full_id == message_id
        print(f"sensor=0x{sensor:016x} epoch={epoch} sequence={sequence} category={category}")
        print(f"samples={samples}")
        print(f"prior_message_id=0x{prior_id:08x}")
        print(f"note={note}")


if __name__ == "__main__":
    main()
```

### Notes

- Without per-trace trigger alignment, CPA gives only random-looking maxima around 0.08 to 0.12. The trigger pulse moves by several samples between traces, so each trace must be aligned to its peak before the byte lanes are correlated.
- The 251 saturated scope records are excluded before correlation.
- The keys are the radio keys recovered from the lab data. They are part of the exploit chain, not the flag.
- The gateway's `4a31` dedupe collision is the reason the diagnostic was missed. The full 32-bit IDs differ (`0x00004a31` and `0xa17c4a31`).
- Reed-Solomon recovery uses any eight of the nine authentic shards. The script selects the lowest eight indices.
- `reconstruct_record.py` imports `decrypt_frames.py`, so the three scripts must sit in the same directory. The scripts read the ZIP directly and do not need it extracted.
- `reconstruct_record.py` prints the flag on its `note=` line.
