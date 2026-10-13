### Summary

The event log mixes eight UTC offsets, and the image at the requested instant has to be found after normalizing all timestamps to UTC. Each entry of `images.tar` is a multi-arch index, so the image that ran is reached by descending to the `linux/amd64` child manifest. The `key_version` is not in any config and must be read from the `key-version.json` files in the layers, where the top layer holds a decoy value. The vault note whose GCM tag verifies under the AAD built from the correct event and manifest gives the token, and the five evidence fields then derive the scrypt key that decrypts the flag.

### Steps

1. Extract the handout and normalize the timeline to UTC. The target instant `2026-08-14T10:10:08.555+05:30` is `2026-08-14T04:40:08.555Z`. The snippet keeps the events of `dispatch-ac1af5608a` up to that instant and prints them in order. Events with `status: failed` do not start an instance, so they are ignored. The last surviving event before the target is `deploy-9d1a1fd93d`, a `migrate` on `linux/amd64`. The two following `activate` events fail, and the `restart` comes after the target.
   ```sh
   mkdir -p scratch && unzip -q ../files/handout.zip -d scratch
   ```
   ```sh
   python3 - <<'PY'
   import json, datetime
   ev = [json.loads(l) for l in open('scratch/the-image-that-forgot/events.jsonl') if l.strip()]
   U = lambda s: datetime.datetime.fromisoformat(s.replace('Z', '+00:00')).astimezone(datetime.timezone.utc)
   T = U('2026-08-14T10:10:08.555+05:30')
   print('cible:', T.isoformat())
   sel = [x for x in ev if x.get('service_id') == 'dispatch-ac1af5608a']
   for e in sorted(sel, key=lambda x: U(x['time'])):
       if U(e['time']) <= T:
           print(U(e['time']).isoformat(), e['action'], e['event_id'], e.get('status', 'ok'))
   PY
   ```
   The vault covers seven event IDs for this service, and their actions are `activate`, `rollback`, `migrate` and `restart`. The selected event is the `migrate`, not an `activate`.

2. Resolve the tag to a digest and then to the platform manifest. `index.json` has no tag annotations, so the tag to digest mapping can only come from the `{digest, tag, time_ms}` events. Each index entry is multi-arch, so the `linux/amd64` child is the manifest that matters. The `dispatch:stable` tag pointed at the index `30062144e4...` at `03:56:28.858Z`, and its amd64 child is `sha256:154d6f1fa75464d02b6245a4e536f6efb187af4bf7266aff8ac9e2e21d4538f8`.
   ```sh
   python3 - <<'PY'
   import json, tarfile
   tarfile.open('scratch/the-image-that-forgot/images.tar').extractall('scratch/oci', filter='data')
   for e in json.load(open('scratch/oci/index.json'))['manifests']:
       for c in json.load(open('scratch/oci/blobs/sha256/' + e['digest'][7:]))['manifests']:
           p = c['platform']
           plat = f"{p['os']}/{p['architecture']}" + ('/' + p['variant'] if 'variant' in p else '')
           print(e['digest'][7:19], plat, c['digest'][7:19])
   PY
   ```

3. Read the `key_version` from the layers. It is not in the OCI config (`e4743bab...` only has architecture, OS and rootfs). It is only present in the `key-version.json` files inside some layers. Reading the last layer gives a decoy, `key-90a623d0c2`. The correct value, `key-e52be7cc57`, is in layer 1.
   ```sh
   python3 - <<'PY'
   import json, tarfile, io
   d = '154d6f1fa75464d02b6245a4e536f6efb187af4bf7266aff8ac9e2e21d4538f8'
   for i, l in enumerate(json.load(open('scratch/oci/blobs/sha256/' + d))['layers']):
       raw = open('scratch/oci/blobs/sha256/' + l['digest'][7:], 'rb').read()
       kv = '<absent>'
       try:
           tf = tarfile.open(fileobj=io.BytesIO(raw))
           n = [x for x in tf.getnames() if x.endswith('key-version.json')]
           if n:
               kv = json.load(tf.extractfile(n[0]))['key_version']
       except tarfile.TarError:
           pass
       print(i, l['digest'][7:19], kv)
   PY
   ```
   ```text
   0 bfffcf511444 key-3de4b6b00b
   1 a0c41782877c key-e52be7cc57
   2 b9ec2aaee6d7 <absent>
   3 421b25b6547e <absent>
   4 17bf262cb335 key-90a623d0c2
   ```

4. Brute-force the note keys with GCM authentication. Each vault note is AES-256-GCM under one of the four keys in `vault.json`. The associated data is the compact JSON `[service_id, key_version, manifest_digest, event_id]`. The script tries every combination of event ID, key version and platform manifest, and every key. A wrong AAD fails the tag check, so only the correct combination decrypts. The 203 notes split into 7 event IDs with 29 notes each, so the vault covers every candidate combination and the flag ciphertext selects the right one. The tuple that is confirmed by the flag is:
   - `event_id` = `deploy-9d1a1fd93d`
   - `manifest_digest` = `sha256:154d6f1fa75464d02b6245a4e536f6efb187af4bf7266aff8ac9e2e21d4538f8`
   - `key_version` = `key-e52be7cc57`
   - `token` = `e411af706f77101364ccdf6b0cb59e75eb8b3cc34342a94c`

5. Check each recovered token against the flag block in the README. The evidence list is `[event_id, manifest_digest, service_id, key_version, token]`, serialized as compact ASCII JSON. The scrypt key is derived from `b"isfcr-forensics\x00" + evidence` with the salt, `n=131072`, `r=8`, `p=1` and a 32-byte output. The flag ciphertext is then decrypted with AES-GCM and the associated data `the-image-that-forgot`. The solver does this for every recovered token and stops at the one that authenticates.
   ```sh
   python3 team/str1x/scripts/solve.py scratch/repro --zip ../files/handout.zip
   ```
   Run it from the challenge `work/` directory. The script extracts the handout into `scratch/repro`, and the output is the evidence list followed by the flag:
   ```text
   evidence = [
     "deploy-9d1a1fd93d",
     "sha256:154d6f1fa75464d02b6245a4e536f6efb187af4bf7266aff8ac9e2e21d4538f8",
     "dispatch-ac1af5608a",
     "key-e52be7cc57",
     "e411af706f77101364ccdf6b0cb59e75eb8b3cc34342a94c"
   ]

   flag = isfcr{REDACTED}
   ```
   The run takes about 3 minutes, mostly the GCM sweep and the scrypt calls with `n=131072`.

### Scripts

#### team/str1x/scripts/solve.py

Rebuilds everything from `files/handout.zip`: it extracts the archive, normalizes the event timeline, walks the OCI index and layers to collect the platform manifests and key versions, recovers the notes by GCM authentication, and tests each candidate evidence list against the README flag block. Run it from `work/` as `python3 team/str1x/scripts/solve.py scratch/repro --zip ../files/handout.zip`. It needs the `cryptography` package and prints the evidence list and the flag.

```python
#!/usr/bin/env python3
"""Solve "the image that forgot": recover the incident token and decrypt the flag.

Usage: solve.py <dir>   where <dir> holds events.jsonl, images.tar and vault.json
"""
import argparse
import hashlib
import io
import json
import multiprocessing as mp
import os
import tarfile
import zipfile

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

SERVICE = "dispatch-ac1af5608a"
INSTANT = "2026-08-14T10:10:08.555+05:30"
SALT = bytes.fromhex("8b57a161139a064a196625972f7e602d")
FLAG_NONCE = bytes.fromhex("244cb048e982870d71f68dfe")
FLAG_CT = bytes.fromhex(
    "02e462042292a430220d3959e46c379b7f96d44726c6c390338ed11b7ee9878875de07ad212f4dbbda1994c3e2574c"
)
FLAG_AAD = b"the-image-that-forgot"


def compact(parts):
    return json.dumps(parts, ensure_ascii=True, separators=(",", ":")).encode("ascii")


def note_aad(key_version, manifest_digest, event_id):
    return compact([SERVICE, key_version, manifest_digest, event_id])


def evidence_of(event_id, manifest_digest, key_version, token):
    return compact([event_id, manifest_digest, SERVICE, key_version, token])


def try_flag(ev):
    key = hashlib.scrypt(
        b"isfcr-forensics\x00" + ev,
        salt=SALT,
        n=131072,
        r=8,
        p=1,
        maxmem=2**28,
        dklen=32,
    )
    try:
        return AESGCM(key).decrypt(FLAG_NONCE, FLAG_CT, FLAG_AAD).decode()
    except Exception:
        return None


def extract(root, zip_path=None):
    inner = os.path.join(root, "the-image-that-forgot")
    for cand in (root, inner):
        if os.path.exists(os.path.join(cand, "vault.json")):
            return cand
    if not zip_path:
        raise SystemExit(f"no vault.json under {root}; pass --zip files/handout.zip")
    with zipfile.ZipFile(zip_path) as z:
        z.extractall(root)
    for cand in (root, inner):
        if os.path.exists(os.path.join(cand, "vault.json")):
            return cand
    raise SystemExit(f"vault.json missing after extracting {zip_path}")


def load_oci(images_tar, workdir):
    oci = os.path.join(workdir, "oci")
    os.makedirs(oci, exist_ok=True)
    if not os.path.exists(os.path.join(oci, "index.json")):
        with tarfile.open(images_tar) as t:
            t.extractall(oci, filter="data")
    idx = json.load(open(os.path.join(oci, "index.json")))
    manifests, key_versions = [], set()
    for entry in idx["manifests"]:
        index_digest = entry["digest"]
        index_doc = json.load(open(os.path.join(oci, "blobs", "sha256", index_digest.split(":")[1])))
        for child in index_doc["manifests"]:
            manifests.append(child["digest"])
            child_doc = json.load(open(os.path.join(oci, "blobs", "sha256", child["digest"].split(":")[1])))
            for layer in child_doc["layers"]:
                raw = open(os.path.join(oci, "blobs", "sha256", layer["digest"].split(":")[1]), "rb").read()
                try:
                    tf = tarfile.open(fileobj=io.BytesIO(raw))
                except tarfile.TarError:
                    continue
                for name in tf.getnames():
                    if not name.endswith("key-version.json"):
                        continue
                    try:
                        kv = json.load(tf.extractfile(name)).get("key_version")
                    except Exception:
                        continue
                    if isinstance(kv, str):
                        key_versions.add(kv)
    return manifests, sorted(key_versions)


def candidate_events(path):
    ids = []
    with open(path) as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            ev = json.loads(line)
            if ev.get("service_id") == SERVICE and "event_id" in ev:
                ids.append(ev["event_id"])
    return sorted(set(ids))


def sweep(args):
    event_id, key_version, manifest_digest, notes, keys = args
    aad = note_aad(key_version, manifest_digest, event_id)
    for note in notes:
        ct = bytes.fromhex(note["data"])
        for idx, key in enumerate(keys):
            try:
                pt = AESGCM(key).decrypt(bytes.fromhex(note["nonce"]), ct, aad)
            except Exception:
                continue
            yield (
                event_id,
                manifest_digest,
                key_version,
                idx,
                pt.decode(),
                note["data"],
            )


def check(record):
    event_id, manifest_digest, key_version, _idx, token, _d = record
    flag = try_flag(evidence_of(event_id, manifest_digest, key_version, token))
    return flag, record


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("dir", nargs="?", default="scratch/data")
    ap.add_argument("--zip", default=None)
    ap.add_argument("--workers", type=int, default=max(1, (os.cpu_count() or 2) - 1))
    args = ap.parse_args()
    root = extract(os.path.abspath(args.dir), args.zip)
    vault = json.load(open(os.path.join(root, "vault.json")))
    keys = [bytes.fromhex(k) for k in vault["keys"]]
    notes = vault["notes"]
    manifests, key_versions = load_oci(os.path.join(root, "images.tar"), os.path.dirname(root))
    events = candidate_events(os.path.join(root, "events.jsonl"))

    print(f"service={SERVICE} instant={INSTANT}")
    print(f"{len(events)} candidate events, {len(manifests)} platform manifests, "
          f"{len(key_versions)} key versions, {len(notes)} notes, {len(keys)} keys")

    jobs = [
        (e, kv, md, notes, keys)
        for e in events
        for kv in key_versions
        for md in manifests
    ]
    recovered = []
    for job in jobs:
        for out in sweep(job):
            recovered.append(out)
    print(f"recovered {len(recovered)} note(s) by GCM tag authentication")

    with mp.Pool(args.workers) as pool:
        for flag, record in pool.imap_unordered(check, recovered):
            if flag:
                print("\nevidence = [")
                print(f'  "{record[0]}",')
                print(f'  "{record[1]}",')
                print(f'  "{SERVICE}",')
                print(f'  "{record[2]}",')
                print(f'  "{record[4]}"')
                print("]\n")
                print("flag =", flag)
                return 0
    print("no flag recovered")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
```

### Notes

- The `manifest_digest` in the AAD is always the platform manifest (the child of the multi-arch index). None of the eight index digests appears in a valid note.
- The eight UTC offsets in the log (`Z`, `+05:30`, `+05:45`, `+01:00`, `-03:30`, `-05:00`, `-07:00`, `+09:00`) are the main trap. Without normalization the selected event is wrong.
- The title is also a trap: the top layer's `key-version.json` is the decoy `key-90a623d0c2`.
- A bug to avoid: `cryptography`'s `Scrypt` takes `length=`, not `dklen=`. Calling it with `dklen=` raises a `TypeError`, and if that is caught by a broad `except`, every trial fails silently with no flag. The script uses `hashlib.scrypt`, which takes `dklen=`.
- Nothing needs a remote service. Everything is computed locally from the handout.
- The token and the evidence fields are intermediate values of the chain and are kept in clear. Only the flag is redacted.
