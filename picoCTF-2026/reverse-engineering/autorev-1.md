# autorev-1 — picoCTF 2026

**Category:** Reverse Engineering
**Flag:** `picoCTF{4u7o_r3v_g0_brrr_78c345aa}`
**Remote:** `nc mysterious-sea.picoctf.net 50583`

---

## Description

> You think you can reverse engineer? Let's test out your speed. Connect to the service!

---

## Overview

The server sends 20 ELF x86-64 binaries (one per round), each encoded as a hex string. For each binary we have **1 second** to extract a "secret" value and send it back. Solving manually is impossible — this requires an automated solver.

---

## Reconnaissance

Connecting manually reveals the protocol:

```
Welcome! I think I'm pretty good at reverse enginnering. There's NO WAY
anyone's better than me. Wanna try? I have 20 binaries I'm going to send
you and you have 1 second EACH to get the secret in each one. Good luck >:)
<previous_secret>
Here's the next binary in bytes:
7f454c4602010100...
What's the secret?:
```

Each binary is a small C program that:
1. Stores a hardcoded 32-bit unsigned integer as a local variable
2. Reads a `%u` from stdin via `scanf`
3. Compares the input to the constant and prints `Correct!` or `Nice try :(`

---

## Vulnerability / Key Insight

The secret is a **compile-time constant** stored directly in the binary's `.text` section. No obfuscation, no computation — just a plain immediate value in a `mov` instruction:

```asm
; mov DWORD PTR [rbp-0x4], <secret>
c7 45 fc f1 ba 44 33     ; secret = 0x3344baf1 = 860142321
```

The x86-64 opcode for `mov DWORD PTR [rbp-0x4], imm32` is always:
```
c7 45 fc <4-byte little-endian value>
```

So extracting the secret is a simple pattern search on the raw binary bytes.

---

## Buffered Socket Bug

A critical implementation detail: the server sends round data in a single TCP burst. Using raw `sock.recv()` would consume all of it in the first call, and subsequent reads would block waiting for data that already arrived but was discarded.

The fix is a wrapper class that maintains a local buffer — never discard from it, only consume from the front.

---

## Solution

The solver:
1. Connects to the service with a **buffered socket**
2. For each of 20 rounds:
   - Reads the hex-encoded binary
   - Decodes it to raw bytes
   - Searches for the byte pattern `\xc7\x45\xfc`
   - Interprets the following 4 bytes as a little-endian `uint32`
   - Sends the value back within the 1-second window

```python
#!/usr/bin/env python3
"""
Auto reverse engineering challenge solver.
The server sends ELF binaries as hex strings. Each binary stores a secret 32-bit
unsigned integer and compares it to user input. We extract the constant using
the pattern: c7 45 fc XX XX XX XX = mov DWORD PTR [rbp-0x4], imm32
"""
import socket
import struct
import sys

HOST = 'mysterious-sea.picoctf.net'
PORT = 50583


class BufSock:
    """Socket with a local buffer so no data is lost after delimiter reads."""
    def __init__(self, host, port, timeout=15):
        self._s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._s.connect((host, port))
        self._s.settimeout(timeout)
        self._buf = b''

    def recv_until(self, delim: bytes) -> bytes:
        while delim not in self._buf:
            chunk = self._s.recv(4096)
            if not chunk:
                raise EOFError("Connection closed")
            self._buf += chunk
        idx = self._buf.index(delim) + len(delim)
        result, self._buf = self._buf[:idx], self._buf[idx:]
        return result

    def recv_line(self) -> bytes:
        return self.recv_until(b'\n')

    def send(self, data: bytes):
        self._s.sendall(data)

    def recv_all_available(self) -> bytes:
        """Read whatever is currently available (non-blocking drain)."""
        self._s.settimeout(2)
        try:
            while True:
                chunk = self._s.recv(4096)
                if not chunk:
                    break
                self._buf += chunk
        except (socket.timeout, BlockingIOError):
            pass
        self._s.settimeout(15)
        result, self._buf = self._buf, b''
        return result


def find_secret(binary_data: bytes):
    # Look for: mov DWORD PTR [rbp-0x4], imm32  →  c7 45 fc XX XX XX XX
    for pattern in (b'\xc7\x45\xfc', b'\xc7\x45\xf8', b'\xc7\x45\xf4'):
        idx = binary_data.find(pattern)
        if idx != -1:
            return struct.unpack('<I', binary_data[idx+3:idx+7])[0]
    return None


def main():
    conn = BufSock(HOST, PORT)

    # Receive welcome banner
    banner = conn.recv_until(b'Good luck >:)\n')
    print(banner.decode(), end='')

    for i in range(20):
        header = conn.recv_until(b"Here's the next binary in bytes:\n")
        print(f"[Round {i+1}] {header.decode().strip()}")

        hex_line = conn.recv_line().strip()
        binary_data = bytes.fromhex(hex_line.decode())
        print(f"  Binary size: {len(binary_data)} bytes")

        prompt = conn.recv_until(b'secret?:')

        secret = find_secret(binary_data)
        if secret is None:
            print(f"[!] Could not find secret in binary {i+1}!")
            conn.send(b"0\n")
        else:
            print(f"  Secret: {secret}")
            conn.send(f"{secret}\n".encode())

    import time; time.sleep(1)
    final = conn.recv_all_available()
    print("\n=== Final response ===")
    print(final.decode())


if __name__ == '__main__':
    main()
```

---

## Output

```
[Round 1]  Secret: 2921488971  → Correct!
[Round 2]  Secret: 3703535157  → Correct!
...
[Round 20] Secret: 3265763510  → Correct!

Woah, how'd you do that??
Here's your flag: picoCTF{4u7o_r3v_g0_brrr_78c345aa}
```
