### Summary

The pcapng holds only QUIC 1-RTT packets, and its embedded TLS keylog lets every packet be decrypted, including the v2 label sets, the key updates and a connection migration. The decrypted streams show a multi-part upload: a JSON manifest lists the part streams, and later `replace` messages swap some parts. The server's per-part status (217 accepted, 26 rejected) decides which of the near-identical parts made up the accepted file. Interleaving the accepted parts gives a raw deflate stream whose inflated SHA-256 is one of the evidence fields for the flag.

### Steps

1. Extract the capture and inspect it. It is UDP only, with no QUIC handshake. The pcapng carries a keylog block (`CLIENT/SERVER_TRAFFIC_SECRET_0` for 5 connections) and a capture comment with the largest packet number per side, which the decryptor needs because the earlier packets are missing.
   ```sh
   mkdir -p scratch/handout && unzip -q -o ../files/handout.zip -d scratch/handout
   capinfos scratch/handout/the-third-key-phase/capture.pcapng
   ```

2. Decrypt every packet. For each traffic secret the script derives the header protection key and the packet keys of 9 successive key updates, for both the v1 labels (`quic key`) and the v2 labels (`quicv2 key`). It tries each connection ID length, and the AEAD tag decides. Connections `87566bdc` and `b662b443` only open with the v2 labels. Connection `87566bdc` migrates from `192.0.2.10:57949` to `203.0.113.37:37187`, changes its connection IDs and goes through three key updates. Generations 1 and 3 share key phase bit 1, so the bit alone does not select the key, and every generation is tried.
   ```sh
   python3 -I scripts/decrypt.py scratch/handout/the-third-key-phase/capture.pcapng scratch/packets.json
   ```
   Output: `decrypted 261 of 265 packets`. The 4 undecrypted packets carry nothing the solve needs.

3. Read the application protocol from the decrypted streams. Client unidirectional stream 2 is a JSON manifest `{"request_id","parts":[stream ids],"unit":N}`. Later client unidirectional streams carry `{"request_id","replace":{"old":new}}`. The server answers each part with `{"stream":id,"status":217|26}`. The file is the parts interleaved round robin in `unit`-byte chunks, and the result is a raw deflate stream. Plain concatenation of the parts fails to inflate. The frame list and the per-connection stream dump help to see this:
   ```sh
   python3 -I scripts/frames.py scratch/packets.json | grep 87566bdc | less
   python3 -I scripts/streams.py scratch/packets.json 87566bdc scratch/s87
   ```

4. Choose the accepted parts. Request `6e26102a48d71fe1d7f68231` appears on two connections. On `bfa62422` the client cancels the transfer, so nothing is accepted there. Connection `87566bdc` completes. Its manifest is `[0,4,8,12]` with `unit` 119. Part 4 is reset and replaced by 20. Part 8 gets status 26 and is replaced by 16, which gets status 217. A last replace of 8 by 24 gets status 26. Statuses 0, 12, 16 and 20 are 217, while 8 and 24 are 26. The accepted parts are therefore `[0,20,16,12]`. The 16456-byte result inflates cleanly, and its SHA-256 is `43669914701c2add27583d67043e96c02f44d622a78116f10fea5fac66e233dd`. The script applies the replace rule, interleaves, inflates, hashes and decrypts the flag.
   ```sh
   python3 -I scripts/solve.py scratch/packets.json artifacts/accepted_file.bin
   ```
   Output:
   ```text
   parts [0, 20, 16, 12] evidence ["6e26102a48d71fe1d7f68231","87566bdc267eee5e8a8a7d0251033ec0ce2aef613ef35623cf1e6dc5fc1310d3","43669914701c2add27583d67043e96c02f44d622a78116f10fea5fac66e233dd"]
   isfcr{REDACTED}
   ```
   The evidence fields are the request id, the `client_random` of connection `87566bdc` (the connection that delivered the file) and the SHA-256 of the accepted file.

### Scripts

The four scripts below are the full chain. `solve.py` imports `streams.py`, which imports `frames.py`, and `decrypt.py` produces the `packets.json` that all of them read. All scripts must be run with `python3 -I` from `work/`, and they need the `cryptography` package.

#### scripts/decrypt.py

Parses the pcapng blocks, reads the keylog and the packet number hints from the capture comment, derives the QUIC 1-RTT keys for both label sets over 9 key generations, and decrypts every short-header packet. The output is a JSON file with the decrypted plaintext of each packet and its metadata. Run it as `python3 -I scripts/decrypt.py <capture.pcapng> scratch/packets.json`.

```python
#!/usr/bin/env python3
"""Decrypt every QUIC 1-RTT packet of the capture, following key updates.

usage: decrypt.py capture.pcapng out.json
"""
import hashlib
import hmac
import json
import struct
import sys

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305

MAX_GENERATION = 8
MAX_DCID_LEN = 20


def blocks(buf):
    off = 0
    while off + 12 <= len(buf):
        btype, blen = struct.unpack_from("<II", buf, off)
        yield btype, buf[off + 8 : off + blen - 4]
        off += blen


def options(body):
    off = 0
    while off + 4 <= len(body):
        code, length = struct.unpack_from("<HH", body, off)
        if code == 0:
            return
        yield code, body[off + 4 : off + 4 + length]
        off += 4 + (length + 3) // 4 * 4


def read_capture(path):
    buf = open(path, "rb").read()
    hints, keylog, packets = {}, "", []
    for btype, body in blocks(buf):
        if btype == 0x0A0D0D0A:
            for code, value in options(body[16:]):
                if code == 1:
                    hints = json.loads(value)
        elif btype == 0x0000000A:
            stype, slen = struct.unpack_from("<II", body)
            if stype == 0x544C534B:
                keylog += body[8 : 8 + slen].decode()
        elif btype == 0x00000006:
            _, ts_hi, ts_lo, caplen, _ = struct.unpack_from("<IIIII", body)
            frame = body[20 : 20 + caplen]
            ihl = (frame[14] & 0x0F) * 4
            ip = frame[14:]
            sport, dport, ulen = struct.unpack_from(">HHH", ip, ihl)
            packets.append(
                {
                    "frame": len(packets) + 1,
                    "ts": (ts_hi << 32 | ts_lo) / 1e6,
                    "src": "%d.%d.%d.%d" % tuple(ip[12:16]) + ":%d" % sport,
                    "dst": "%d.%d.%d.%d" % tuple(ip[16:20]) + ":%d" % dport,
                    "udp": bytes(ip[ihl + 8 : ihl + ulen]),
                }
            )
    return hints, keylog, packets


def expand_label(hash_name, secret, label, length):
    full = b"tls13 " + label
    info = struct.pack(">H", length) + bytes([len(full)]) + full + b"\x00"
    out, block, counter = b"", b"", 1
    while len(out) < length:
        block = hmac.new(secret, block + info + bytes([counter]), hash_name).digest()
        out += block
        counter += 1
    return out[:length]


class Keys:
    def __init__(self, client_random, side, secret, suite, version):
        self.client_random, self.side, self.suite = client_random, side, suite
        self.version = version
        prefix = b"quicv2 " if version == 2 else b"quic "
        self.hash_name = "sha384" if len(secret) == 48 else "sha256"
        self.key_len = 16 if suite == "aes128" else 32
        self.hp = expand_label(self.hash_name, secret, prefix + b"hp", self.key_len)
        self.aeads = []
        for _ in range(MAX_GENERATION + 1):
            key = expand_label(self.hash_name, secret, prefix + b"key", self.key_len)
            iv = expand_label(self.hash_name, secret, prefix + b"iv", 12)
            aead = ChaCha20Poly1305(key) if suite == "chacha20" else AESGCM(key)
            self.aeads.append((aead, iv))
            secret = expand_label(self.hash_name, secret, prefix + b"ku", len(secret))

    def mask(self, sample):
        if self.suite == "chacha20":
            enc = Cipher(algorithms.ChaCha20(self.hp, sample), None).encryptor()
            return enc.update(bytes(5))
        enc = Cipher(algorithms.AES(self.hp), modes.ECB()).encryptor()
        return enc.update(sample)[:5]


def load_keys(keylog):
    keys = []
    for line in keylog.splitlines():
        parts = line.split()
        if len(parts) != 3 or not parts[0].endswith("_TRAFFIC_SECRET_0"):
            continue
        side = "client" if parts[0].startswith("CLIENT") else "server"
        secret = bytes.fromhex(parts[2])
        suites = ["aes256"] if len(secret) == 48 else ["aes128", "chacha20"]
        for suite in suites:
            for version in (1, 2):
                keys.append(Keys(parts[1], side, secret, suite, version))
    return keys


def pn_candidates(truncated, pn_len, hint):
    window = 1 << (8 * pn_len)
    base = (hint & ~(window - 1)) | truncated
    return [base + k * window for k in (0, -1, 1, -2, 2) if base + k * window >= 0]


def try_decrypt(udp, keys, hints, dcid_lens):
    for k in keys:
        hint = hints[k.client_random]["largest_%s_pn" % k.side]
        for dcid_len in dcid_lens:
            pn_off = 1 + dcid_len
            if len(udp) < pn_off + 4 + 16:
                continue
            mask = k.mask(udp[pn_off + 4 : pn_off + 20])
            first = udp[0] ^ (mask[0] & 0x1F)
            if first & 0x18:
                continue
            pn_len = (first & 3) + 1
            pn_bytes = bytes(a ^ b for a, b in zip(udp[pn_off : pn_off + pn_len], mask[1:]))
            header = bytes([first]) + udp[1:pn_off] + pn_bytes
            body = udp[pn_off + pn_len :]
            for pn in pn_candidates(int.from_bytes(pn_bytes, "big"), pn_len, hint):
                for gen, (aead, iv) in enumerate(k.aeads):
                    nonce = (int.from_bytes(iv, "big") ^ pn).to_bytes(12, "big")
                    try:
                        plain = aead.decrypt(nonce, body, header)
                    except Exception:
                        continue
                    return {
                        "client_random": k.client_random,
                        "side": k.side,
                        "suite": k.suite,
                        "version": k.version,
                        "dcid": udp[1:pn_off].hex(),
                        "key_phase_bit": (first >> 2) & 1,
                        "spin": (first >> 5) & 1,
                        "generation": gen,
                        "pn": pn,
                        "plain": plain.hex(),
                    }
    return None


def main():
    hints, keylog, packets = read_capture(sys.argv[1])
    keys = load_keys(keylog)
    out, known_lens = [], []
    for p in packets:
        udp = p.pop("udp")
        res = try_decrypt(udp, keys, hints, known_lens)
        if res is None:
            res = try_decrypt(udp, keys, hints, range(MAX_DCID_LEN + 1))
        if res is None:
            p["raw"] = udp.hex()
        else:
            p.update(res)
            if len(res["dcid"]) // 2 not in known_lens:
                known_lens.append(len(res["dcid"]) // 2)
        out.append(p)
    json.dump(out, open(sys.argv[2], "w"), indent=0)
    done = sum("plain" in p for p in out)
    print("decrypted %d of %d packets" % (done, len(out)))


if __name__ == "__main__":
    main()
```

#### scripts/frames.py

Parses the decrypted QUIC payloads of `packets.json` into frames (STREAM, DATAGRAM, RESET_STREAM, CONNECTION_CLOSE and others) and prints them per packet. It is used for inspection and is also imported by `streams.py`. Run it as `python3 -I scripts/frames.py scratch/packets.json`.

```python
#!/usr/bin/env python3
"""List the QUIC frames of every decrypted packet.

usage: frames.py packets.json   (packets.json comes from decrypt.py)
"""
import json
import sys


def varint(b, o):
    n = 1 << (b[o] >> 6)
    return int.from_bytes(b[o : o + n], "big") & ((1 << (8 * n - 2)) - 1), o + n


def parse(b):
    o = 0
    while o < len(b):
        t, o = varint(b, o)
        if t == 0x00:
            continue
        if t == 0x01:
            yield {"t": "PING"}
        elif t in (0x02, 0x03):
            largest, o = varint(b, o)
            _, o = varint(b, o)
            count, o = varint(b, o)
            first, o = varint(b, o)
            for _ in range(count):
                _, o = varint(b, o)
                _, o = varint(b, o)
            if t == 0x03:
                for _ in range(3):
                    _, o = varint(b, o)
            yield {"t": "ACK", "largest": largest, "first": first, "ranges": count}
        elif t == 0x04:
            sid, o = varint(b, o)
            err, o = varint(b, o)
            size, o = varint(b, o)
            yield {"t": "RESET_STREAM", "sid": sid, "err": err, "final": size}
        elif t == 0x05:
            sid, o = varint(b, o)
            err, o = varint(b, o)
            yield {"t": "STOP_SENDING", "sid": sid, "err": err}
        elif t == 0x06:
            off, o = varint(b, o)
            ln, o = varint(b, o)
            yield {"t": "CRYPTO", "off": off, "data": b[o : o + ln].hex()}
            o += ln
        elif t == 0x07:
            ln, o = varint(b, o)
            yield {"t": "NEW_TOKEN", "data": b[o : o + ln].hex()}
            o += ln
        elif 0x08 <= t <= 0x0F:
            sid, o = varint(b, o)
            off = 0
            if t & 4:
                off, o = varint(b, o)
            ln = len(b) - o
            if t & 2:
                ln, o = varint(b, o)
            yield {"t": "STREAM", "sid": sid, "off": off, "fin": t & 1, "data": b[o : o + ln].hex()}
            o += ln
        elif t in (0x10, 0x12, 0x13, 0x14, 0x16, 0x17, 0x19):
            v, o = varint(b, o)
            yield {"t": "0x%02x" % t, "v": v}
        elif t in (0x11, 0x15):
            sid, o = varint(b, o)
            v, o = varint(b, o)
            yield {"t": "0x%02x" % t, "sid": sid, "v": v}
        elif t == 0x18:
            seq, o = varint(b, o)
            retire, o = varint(b, o)
            ln = b[o]
            cid = b[o + 1 : o + 1 + ln]
            o += 1 + ln
            yield {"t": "NEW_CONNECTION_ID", "seq": seq, "retire": retire, "cid": cid.hex(), "token": b[o : o + 16].hex()}
            o += 16
        elif t in (0x1A, 0x1B):
            yield {"t": "PATH_CHALLENGE" if t == 0x1A else "PATH_RESPONSE", "data": b[o : o + 8].hex()}
            o += 8
        elif t in (0x1C, 0x1D):
            err, o = varint(b, o)
            if t == 0x1C:
                _, o = varint(b, o)
            ln, o = varint(b, o)
            yield {"t": "CONNECTION_CLOSE", "err": err, "reason": b[o : o + ln].decode("latin1")}
            o += ln
        elif t == 0x1E:
            yield {"t": "HANDSHAKE_DONE"}
        elif t in (0x30, 0x31):
            ln = len(b) - o
            if t & 1:
                ln, o = varint(b, o)
            yield {"t": "DATAGRAM", "data": b[o : o + ln].hex()}
            o += ln
        else:
            yield {"t": "UNKNOWN 0x%x" % t, "rest": b[o:].hex()}
            return


def main():
    for p in json.load(open(sys.argv[1])):
        if "plain" not in p:
            print(p["frame"], "UNDECRYPTED", p["src"], p["dst"], p["raw"])
            continue
        head = "%d %s %s gen%d pn%d %s>%s" % (
            p["frame"], p["client_random"][:8], p["side"], p["generation"], p["pn"], p["src"], p["dst"])
        for f in parse(bytes.fromhex(p["plain"])):
            if "data" in f and len(f["data"]) > 96:
                f["len"] = len(f["data"]) // 2
                f["data"] = f["data"][:96] + "..."
            print(head, json.dumps(f, separators=(",", ":")))


if __name__ == "__main__":
    main()
```

#### scripts/streams.py

Rebuilds the byte stream of every STREAM frame of one connection (selected by a `client_random` prefix) and writes each stream to a file. It also lists the DATAGRAM frames. `solve.py` imports its `collect()` function. Run it as `python3 -I scripts/streams.py scratch/packets.json 87566bdc scratch/s87`.

```python
#!/usr/bin/env python3
"""Reassemble streams and datagrams of one connection into files.

usage: streams.py packets.json <client_random prefix> outdir
Writes <side>_s<id>.bin per stream and client_dgram_<idx>.bin per datagram index.
"""
import collections
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import frames


def collect(packets, prefix):
    streams, dgrams, seen = collections.defaultdict(dict), [], set()
    for p in packets:
        if "plain" not in p or not p["client_random"].startswith(prefix):
            continue
        key = (p["side"], p["pn"])
        if key in seen:
            continue
        seen.add(key)
        for f in frames.parse(bytes.fromhex(p["plain"])):
            if f["t"] == "STREAM":
                buf = streams[(p["side"], f["sid"])]
                for i, b in enumerate(bytes.fromhex(f["data"])):
                    buf.setdefault(f["off"] + i, b)
            elif f["t"] == "DATAGRAM":
                dgrams.append((p["frame"], p["pn"], bytes.fromhex(f["data"])))
    return streams, dgrams


def main():
    packets = json.load(open(sys.argv[1]))
    streams, dgrams = collect(packets, sys.argv[2])
    out = sys.argv[3]
    os.makedirs(out, exist_ok=True)
    for (side, sid), buf in sorted(streams.items()):
        data = bytes(buf[i] for i in range(max(buf) + 1))
        open(os.path.join(out, "%s_s%d.bin" % (side, sid)), "wb").write(data)
        print(side, sid, len(data))
    for frame, pn, d in dgrams:
        idx = int.from_bytes(d[:2], "big")
        open(os.path.join(out, "client_dgram_%02d.bin" % idx), "wb").write(d)
        print("dgram frame", frame, "pn", pn, "idx", idx, "hdr", d[:4].hex(), "len", len(d))


if __name__ == "__main__":
    main()
```

#### scripts/solve.py

Applies the manifest and the replace messages to choose the accepted parts (the ones the server answered with status 217), interleaves them in `unit`-byte chunks, inflates the raw deflate stream, hashes the inflated file and decrypts the flag with the statement's scrypt and AES-GCM recipe. It writes the accepted file to the path given as the second argument. Run it as `python3 -I scripts/solve.py scratch/packets.json artifacts/accepted_file.bin`.

```python
#!/usr/bin/env python3
"""Rebuild the accepted upload of a request and decrypt the flag with it.

usage: solve.py packets.json [accepted_file_out]   (packets.json comes from decrypt.py)
"""
import hashlib
import json
import os
import sys
import zlib

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import streams

REQUEST = "6e26102a48d71fe1d7f68231"
ACCEPTED = 217
SALT = bytes.fromhex("55cfbdc7a31326404d59e133d991dc88")
NONCE = bytes.fromhex("f684f2db484cdd8e6f38b16e")
BLOB = bytes.fromhex(
    "c4805539a3db8bc0bba5f5fb6ad76c1125d889aab86af18041007f8f49e30d2b"
    "5822be5cf8d26d21ddb576b25d06bc"
)


def stream_bytes(buf):
    return bytes(buf[i] for i in range(max(buf) + 1))


def accepted_upload(packets, client_random):
    data, _ = streams.collect(packets, client_random)
    status = {}
    for (side, sid), buf in data.items():
        if side == "server":
            msg = json.loads(stream_bytes(buf))
            status[msg["stream"]] = msg["status"]
    manifest, replaces = None, []
    # client-initiated unidirectional streams carry the JSON control messages
    for (side, sid), buf in sorted(data.items()):
        if side != "client" or sid % 4 != 2:
            continue
        msg = json.loads(stream_bytes(buf))
        if msg.get("request_id") != REQUEST:
            return None
        if "parts" in msg:
            manifest = msg
        else:
            replaces.append(msg["replace"])
    if manifest is None:
        return None
    parts = list(manifest["parts"])
    for rep in replaces:
        for old, new in rep.items():
            if status.get(new) == ACCEPTED:
                parts[parts.index(int(old))] = new
    if any(status.get(p) != ACCEPTED for p in parts):
        return None
    chunks = [stream_bytes(data[("client", p)]) for p in parts]
    unit, out, i = manifest["unit"], b"", 0
    while any(i < len(c) for c in chunks):
        for c in chunks:
            out += c[i : i + unit]
        i += unit
    return parts, zlib.decompress(out, -15)


def main():
    packets = json.load(open(sys.argv[1]))
    for cr in sorted({p["client_random"] for p in packets if "plain" in p}):
        res = accepted_upload(packets, cr)
        if res is None:
            continue
        parts, content = res
        digest = hashlib.sha256(content).hexdigest()
        if len(sys.argv) > 2:
            open(sys.argv[2], "wb").write(content)
        evidence = [REQUEST, cr, digest]
        e = json.dumps(evidence, ensure_ascii=True, separators=(",", ":")).encode("ascii")
        key = hashlib.scrypt(b"isfcr-forensics\x00" + e, salt=SALT, n=131072, r=8, p=1, maxmem=2**28, dklen=32)
        print("parts", parts, "evidence", e.decode())
        print(AESGCM(key).decrypt(NONCE, BLOB, b"the-third-key-phase").decode())


if __name__ == "__main__":
    main()
```

### Notes

- Parts 8, 16 and 24 differ by a few bytes and all three inflate without error. Only the server status separates them, and the accepted set is the one the server marked 217.
- The DATAGRAM frames of `87566bdc` (19 units of 119 bytes) inflate to a different, shorter file with the same request id. It is a decoy and is not the accepted upload.
- The hash is taken over the inflated file, not over the interleaved deflate stream.
- Concatenating the parts instead of interleaving them fails to inflate ("invalid distance too far back").
- The v1 labels alone decrypt nothing on `87566bdc` and `b662b443`, even with up to 40 key generations. The v2 labels are required for those connections.
- The `artifacts/accepted_file.bin` written by `solve.py` is the 16456-byte accepted file. Its hash is the evidence field, not the flag.
- The `client_random` of `87566bdc` is part of the evidence and is kept in clear.
