# Secure Password Database — picoCTF 2026

**Category:** Reverse Engineering
**Flag:** `picoCTF{d0nt_trust_us3rs}`
**Vulnerability Class:** Heap memory disclosure (Heartbleed-style) + hash forgery

---

## Overview

The binary simulates a password storage and authentication system. It asks for a password, asks how many bytes long it is, prints that many bytes from the heap, then asks for a hash to authenticate. The vulnerability is that the length parameter is never validated against the actual password size — supplying a large value leaks heap memory beyond the password, including the secret used to generate the authentication hash.

---

## Static Analysis

### `main()` — Heap Layout

#### 1. Heap Allocation and Secret Placement

```c
password_buffer_dst = calloc(0x5a, 1);
for (i = 0; i < 0xd; i = i + 1) {
    password_buffer_dst[i + 0x3c] = obf_bytes[i] ^ 0xaa;
}
```

`calloc(0x5a, 1)` allocates **90 bytes**, zero-initialized. The loop XORs each byte of the global array `obf_bytes` with `0xaa` and writes the result starting at offset **60** of the heap buffer. This places a 13-byte obfuscated secret at `heap[60..72]` before the user inputs anything.

#### 2. Password Input

```c
input_checker = fgets(password_buffer + 1, 0x32, stdin);
strcpy(password_buffer_dst, password_buffer + 1);
```

Heap buffer layout after this step:
```
Offset 0x00 – 0x3b  (bytes  0–59):  user password (null-terminated)
Offset 0x3c – 0x48  (bytes 60–72):  obf_bytes[i] ^ 0xaa  (the secret)
Offset 0x49 – 0x59  (bytes 73–89):  zero-initialized
```

#### 3. The Vulnerable Length Read

```c
input_checker = fgets(password_len, 0x14, stdin);
password_len_int = atoi(password_len);
for (j = 0; (j <= (int)password_len_int && (j < 0x5a)); j++) {
    printf("%d ", (ulong)(uint)(int)password_buffer_dst[j]);
}
```

The only guard is `j < 0x5a` (j < 90). There is **no check** that `password_len_int <= strlen(password)`.

**If you enter `89`, the loop prints the entire heap buffer — including the secret at offsets 60–71.** This is the Heartbleed analogy: the server trusts the client's claimed length.

---

### `hash()` — djb2 Variant

```c
long hash(byte *param_1) {
    local_10 = 0x1505;      // seed = 5381
    while (*local_20 != 0) {
        local_10 = (long)(int)(uint)*local_20 + local_10 * 0x21;  // h = h*33 + c
        local_20++;
    }
    return local_10;
}
```

The standard **djb2** hash. In Python with 64-bit behavior:

```python
def djb2(data: bytes) -> int:
    h = 0x1505
    for b in data:
        if b == 0:
            break
        h = (b + h * 0x21) & 0xFFFFFFFFFFFFFFFF
    return h
```

The `& 0xFFFFFFFFFFFFFFFF` mask is critical — Python integers are arbitrary precision, but C `long` on x86-64 is 64-bit.

---

## Dynamic Analysis — Leaking the Secret

Running the binary and submitting length `89`:

```
Please set a password for your account: A
How many bytes in length is your password? 89
You entered: 89
Your successfully stored password:
65 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0
0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0
0 0 0 0 105 85 98 104 56 49 33 106 42 104 110 33 -86 0 0 0
0 0 0 0 0 0 0 0 0 0 0 0 0
```

Bytes at offsets 60–71: `105 85 98 104 56 49 33 106 42 104 110 33`

```python
leaked = [105, 85, 98, 104, 56, 49, 33, 106, 42, 104, 110, 33]
bytes(leaked).decode()  # → 'iUbh81!j*hn!'
```

The `-86` at offset 72 is `0xaa` in signed representation — the raw `obf_bytes` null terminator XORed with `0xaa`, confirming the XOR key.

---

## Hash Computation

```python
secret = b"iUbh81!j*hn!"
h = djb2(secret)
print(h)  # 15237662580160011234
```

---

## Exploit

```python
#!/usr/bin/env python3
from pwn import *

def djb2(data: bytes) -> int:
    h = 0x1505
    for b in data:
        if b == 0:
            break
        h = (b + h * 0x21) & 0xFFFFFFFFFFFFFFFF
    return h

secret = b"iUbh81!j*hn!"
h = djb2(secret)
print(f"[*] Hash: {h}")

p = remote("candy-mountain.picoctf.net", 62138)

p.recvuntil(b"Please set a password for your account:")
p.sendline(b"A")

p.recvuntil(b"How many bytes in length is your password?")
p.sendline(b"1")  # irrelevant at this point, secret already known

p.recvuntil(b"Enter your hash to access your account!")
p.sendline(str(h).encode())

p.interactive()
```

**Output:**
```
[*] Hash: 15237662580160011234
[+] Opening connection to candy-mountain.picoctf.net on port 62138: Done
picoCTF{d0nt_trust_us3rs}
```

---

## Root Cause Summary

| Design flaw | Impact |
|-------------|--------|
| Secret placed in same heap buffer as user password | Contiguous memory — leakable |
| Length parameter taken from user with no upper bound tied to password length | Attacker controls how far into the buffer the print loop reads |
| `obf_bytes ^ 0xaa` is symmetric and trivial | XOR with known key — secret fully recoverable from leak |
| djb2 is non-cryptographic | Once secret is known, hash is trivially reproducible |

The challenge name references Heartbleed (CVE-2014-0160), which exploited the same class of bug in OpenSSL's TLS heartbeat extension — a user-supplied length field was trusted without validation, causing the server to return more memory than it should have.
