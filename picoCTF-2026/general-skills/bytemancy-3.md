# bytemancy-3 — picoCTF 2026

**Category:** General Skills
**Flag:** `picoCTF{...}` (retrieved at runtime)
**Remote:** `green-hill.picoctf.net 50861`

---

## Challenge Description

> "I will name four procedures hidden inside spellbook. Each round, send me their *raw* 4-byte addresses in little-endian form. 3 correct answers unlock the flag."

The server runs a Python script that:
1. Loads a local ELF binary called `spellbook`
2. Picks 3 random function names from a fixed pool of 4
3. Asks you to send each function's address as a raw 4-byte little-endian integer
4. Prints the flag if all 3 are correct

The four possible functions are:
```
ember_sigil
glyph_conflux
astral_spark
binding_word
```

---

## Analysis

The key insight: **the server uses the same binary we can download locally**. Since there's no ASLR or PIE affecting a plain symbol lookup, the addresses are deterministic — just look them up with `pwntools` and send them in the right format (`p32(elf.symbols[name])`).

### The Bug in the Naive Solver

The first attempt cleared the receive buffer between sends:

```python
sock.sendall(payload)
buf = b""              # ← cleared!
chunk = recv_until(sock, b"\n")
```

The problem: after sending answer #1, the server immediately sends question #2 **including its `==> ` prompt**. The `recv_until(b"\n")` call consumes some of that data, and clearing `buf` throws the rest away. The subsequent `recv_until(b"==> ")` then blocks forever waiting for a prompt that already passed.

The fix: a **single persistent buffer** — never clear it, only consume from the front.

---

## Solution

```python
#!/usr/bin/env python3
import sys
import socket
from pwn import ELF, p32

BINARY_PATH = "./spellbook"

def solve(host: str, port: int) -> None:
    elf = ELF(BINARY_PATH, checksec=False)

    with socket.create_connection((host, port), timeout=15) as sock:
        sock.settimeout(5)
        buf = b""

        while True:
            # Accumulate until a prompt appears
            try:
                while b"==> " not in buf:
                    chunk = sock.recv(4096)
                    if not chunk:
                        return
                    buf += chunk
                    print(chunk.decode(errors="replace"), end="", flush=True)
            except socket.timeout:
                print(buf.decode(errors="replace"))
                return

            # Consume up to and including "==> ", keep the rest
            prompt_end = buf.index(b"==> ") + len(b"==> ")
            head = buf[:prompt_end]
            buf  = buf[prompt_end:]

            if b"for procedure '" not in head:
                continue

            # Parse function name
            marker = b"for procedure '"
            start  = head.rfind(marker) + len(marker)
            end    = head.index(b"'.", start)
            symbol = head[start:end].decode()

            addr    = elf.symbols[symbol]
            payload = p32(addr)
            print(f"\n[*] '{symbol}' → {hex(addr)} → {payload.hex()}")
            sock.sendall(payload)

            # Read the response without dropping it
            try:
                while b"\n" not in buf:
                    chunk = sock.recv(4096)
                    if not chunk:
                        return
                    buf += chunk
                    print(chunk.decode(errors="replace"), end="", flush=True)
            except socket.timeout:
                pass

            # Flag detection
            KNOWN = (
                b"BYTEMANCY", b"Send the", b"==>", b"unlock", b"aether",
                b"runes", b"incantation", b"[", b"\xe2", b"traveler",
                b"Those", b"four bytes", b"rejects", b"hidden",
                b"little-endian", b"procedure", b"spellbook",
            )
            for line in buf.split(b"\n"):
                line = line.strip()
                if line and not any(kw in line for kw in KNOWN):
                    print(f"\n[+] FLAG: {line.decode(errors='replace')}")
                    return

if __name__ == "__main__":
    host = sys.argv[1] if len(sys.argv) > 1 else "localhost"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 1337
    solve(host, port)
```

### Running It

```bash
# Download the spellbook binary from the challenge first
python solve.py green-hill.picoctf.net 50861
```

Expected output:

```
[*] Connected to green-hill.picoctf.net:50861
⊹──────[ BYTEMANCY-3 ]──────⊹
...
[1/3] Send the 4-byte little-endian address for procedure 'glyph_conflux'.
==>
[*] 'glyph_conflux' → 0x804919a → 9a910408
[2/3] Send the 4-byte little-endian address for procedure 'astral_spark'.
==>
[*] 'astral_spark' → 0x8049170 → 70910408
[3/3] Send the 4-byte little-endian address for procedure 'ember_sigil'.
==>
[*] 'ember_sigil' → 0x8049146 → 46910408

[+] FLAG: picoCTF{...}
```

---

## Key Takeaways

- **ELF symbol lookup** with `pwntools` (`elf.symbols[name]`) is the right tool when a server asks you to know addresses inside a binary.
- **`p32()`** is the canonical way to pack a 32-bit value in little-endian format.
- **Don't clear your receive buffer** between sends. In streaming socket I/O, the server may pipeline multiple messages and clearing `buf` silently drops data, causing your reader to block forever.
- Always keep a single accumulator and **slice from the front** once you've processed a complete message.
