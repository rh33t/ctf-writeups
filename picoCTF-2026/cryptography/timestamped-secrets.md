# Timestamped Secrets — picoCTF 2026

**Category:** Cryptography
**Flag:** `picoCTF{sa3S_sEc9t_fbcf37a3}`

---

## Overview

AES-ECB encrypted message where the key is derived from the current Unix timestamp at encryption time. The hint leaks the exact timestamp, making brute-force trivial.

---

## Analysis

The encryption script (`encryption.py`) reveals:

```python
key = sha256(str(timestamp).encode()).digest()[:16]
cipher = AES.new(key, AES.MODE_ECB)
```

Two weaknesses:
1. **Weak key derivation** — the key is just `SHA256(unix_timestamp)[:16]`, a tiny keyspace.
2. **Timestamp leaked** — `message.txt` includes `Hint: The encryption was done around 1770242637 UTC`.

---

## Solution

Try timestamps around the hint value, decrypt, and check for valid plaintext:

```python
from hashlib import sha256
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

ciphertext = bytes.fromhex("030ea2b59ea3cad39da9dfff761acc2598161c602243e2b0e9e571cee8285b87")
hint_ts = 1770242637

for delta in range(-300, 301):
    ts = hint_ts + delta
    key = sha256(str(ts).encode()).digest()[:16]
    cipher = AES.new(key, AES.MODE_ECB)
    try:
        text = unpad(cipher.decrypt(ciphertext), AES.block_size).decode('utf-8')
        if 'pico' in text.lower():
            print(f"ts={ts}: {text}")
    except Exception:
        pass
```

The exact hint timestamp (`delta=0`) decrypts successfully:

```
ts=1770242637: picoCTF{sa3S_sEc9t_fbcf37a3}
```

---

## Key Takeaways

- Never derive cryptographic keys from low-entropy sources like timestamps.
- AES-ECB is deterministic and has no semantic security, but the core issue here is key derivation.
- Leaking even a rough timestamp collapses the keyspace to a few hundred candidates.
