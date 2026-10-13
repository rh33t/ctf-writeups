### Summary

Draftpad marks the private part of a document with a redaction window stored as fixed pin positions (`private_start` and `private_end`). Those positions do not move when blocks are inserted before them, so the real private blocks drift out of the window as the document grows. The admin's flag block then sits outside the window with `is_private:false`, and it is returned in cleartext by `GET /api/document` and `GET /api/export/public`. No write access is needed: one read of the document shows the flag.

### Steps

1. Read the document. The flag block is returned without redaction. It has id `blk_flag`, parent `blk_pstart`, author `admin`, and `is_private:false`.

   ```sh
   curl -sS https://isfcrpesu-draftpad.chals.io/api/document
   ```

   The relevant block in the response:

   ```json
   {"id":"blk_flag","parent_id":"blk_pstart","author":"admin","content":"release flag: isfcr{REDACTED}","is_private":false}
   ```

   The flag is at index 10 of the block list. It is not inside the private section as far as the redaction logic is concerned.

2. Compare the stored pins with the real block positions to confirm the desync.

   ```sh
   curl -sS https://isfcrpesu-draftpad.chals.io/api/pins
   ```

   The pins report `private_start` at position 19 and `private_end` at position 22. The real `blk_pstart` and `blk_pend` markers sit at indices 8 and 11. The only blocks flagged `is_private:true` are two later guest-inserted blocks at indices 20 and 21, so the admin's private content lies outside the window. The redaction is positional, and insertions before the markers move the content but not the window.

3. The public export leaks the same content. The page describes this endpoint as the reviewed public export, but the flag line appears in cleartext in the output.

   ```sh
   curl -sS https://isfcrpesu-draftpad.chals.io/api/export/public
   ```

   The export includes a "confidential (do not export)" section, and the flag line sits inside it. The redaction failure therefore reaches both endpoints.

No script is needed. The solve is three GET requests. The state helper in the vault (`work/scripts/fetch-state.sh`) only re-downloads the same endpoints for later inspection.

### Scripts

No script is needed to reproduce the solve. The three `curl` commands in the steps are enough. The vault's `work/scripts/fetch-state.sh` re-pulls `/api/document`, `/api/log`, `/api/pins` and `/api/export/public` into a directory for offline inspection. It is not part of the exploit.

### Notes

- The indices (8 and 11, window 19 to 22) are a snapshot of a shared, globally mutable instance. Other participants' probe blocks show up in the document and in the log, and the numbers change as they add blocks. The bug is that the stored pin window does not follow insertions, so the redaction and the content fall out of step. Expect different numbers on a new run.
- The flag block is already outside the window in the live state, so no mutating operation (`POST /api/ops` with `insert` or `delete`) is needed.
- Endpoints that look like private or backup views return 404: `/api/export/private`, `/api/blocks`, `/api/private`, `/api/dump` and `/api/document/raw`. No login was found.
- The host is volatile and shared. The vault captures in `work/artifacts/` for `api-document.json`, `api-log.json` and `api-pins.json` are empty files, so the values shown above come from the live responses recorded in the vault's STATE notes. The file `api-export-public.txt` holds the public export text, which includes the confidential section.
