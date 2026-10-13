### Summary

The print-job shadow file (`FP02CF4.SHD`) names the owner `j.holbrook`, the workstation `FIN-WKS-014` and the print time in FILETIME format. The scanned page carries a grid of yellow tracking dots that repeats across the whole page; one copy encodes the print time and the seven-digit printer serial, so the scan can be tied to the spool job. The flag is the first 16 hex characters of SHA-256 over `username|serial|timestamp`, wrapped in `isfcr{}`.

### Steps

1. Run the solver against the challenge archive. It needs Python 3, Pillow and NumPy. It reads the three files (`FP02CF4.SHD`, `FP02CF4.SPL`, `scan.png`) straight from the ZIP, so nothing has to be extracted first.
   ```sh
   python3 scripts/solve.py ../files/ghost-spooler.zip
   ```
   The SHD owner pointer at offset `0x10` resolves to the UTF-16LE string `j.holbrook`. The machine pointer at `0x58` resolves to `FIN-WKS-014`. The FILETIME at `0x40` is `0x01db090f0de78e00`, which converts to `2024-09-17T14:37:00Z`. The seconds are zero, as the task requires.

2. Decode the yellow-dot matrix on `scan.png`. The grid has 15 columns and 8 rows, with a 9 pixel pitch. The first dot center is `(90,60)`. The same block is repeated every 300 pixels, giving 88 copies on the page (11 rows by 8 columns). All copies are identical, so the script asserts equality across all of them. The data rows and columns each have odd parity, which is also checked. The top row and the left column are parity bits and are dropped. Each remaining column is read as a 7-bit value with weights `64,32,16,8,4,2,1`:
   ```text
   80,37,14,17,9,24,8,8,4,2,0,1,3,0,0
   ```
   Columns 2 to 6 give minute, hour, day, month and two-digit year. They match the SHD timestamp exactly, which confirms the field order. Columns 7 to 13 give the seven serial digits, `8842013`.

3. Check that the scan and the spool job are the same document. The solver prints the text records of the EMF stream in `FP02CF4.SPL`. The title, addressee, sender, date, subject and first paragraph of the scan match these records. The scan also has a second paragraph, a signature and a footer that are not in the SPL records. Matching text plus the timestamp that is encoded in the dots ties the scan to the job submitted from `FIN-WKS-014`.

4. Build the flag from the recovered values. The hash input is `j.holbrook|8842013|2024-09-17T14:37:00Z`. The solver computes this, and the same result can be reproduced directly:
   ```sh
   python3 -c 'import hashlib; s="j.holbrook|8842013|2024-09-17T14:37:00Z"; print("isfcr{" + hashlib.sha256(s.encode()).hexdigest()[:16] + "}")'
   ```
   Output: `isfcr{REDACTED}`

### Scripts

#### scripts/solve.py

Parses the ZIP, decodes the SHD fields, verifies the tracking grid across all 88 copies, checks the encoded date against the SHD, prints the SPL text for comparison with the scan and prints the candidate flag. Run it as `python3 scripts/solve.py ../files/ghost-spooler.zip` from the challenge `work/` directory. It needs Pillow and NumPy.

```python
#!/usr/bin/env python3
import argparse
import hashlib
import io
import struct
import zipfile
from datetime import datetime, timedelta, timezone

import numpy as np
from PIL import Image


parser = argparse.ArgumentParser()
parser.add_argument('archive')
args = parser.parse_args()
with zipfile.ZipFile(args.archive) as archive:
    shd = archive.read('ghost-spooler/FP02CF4.SHD')
    spl = archive.read('ghost-spooler/FP02CF4.SPL')
    image = np.array(Image.open(io.BytesIO(archive.read('ghost-spooler/scan.png'))).convert('RGB'))


def wide_string(offset):
    end = offset
    while shd[end:end + 2] != b'\0\0':
        end += 2
    return shd[offset:end].decode('utf-16le')


username = wide_string(struct.unpack_from('<I', shd, 0x10)[0]).lower()
machine = wide_string(struct.unpack_from('<I', shd, 0x58)[0])
filetime = struct.unpack_from('<Q', shd, 0x40)[0]
printed = datetime(1601, 1, 1, tzinfo=timezone.utc) + timedelta(microseconds=filetime // 10)
timestamp = printed.strftime('%Y-%m-%dT%H:%M:%SZ')
yellow = (image[:, :, 0] > 230) & (image[:, :, 2] < 200)
grid = yellow[np.ix_(60 + np.arange(8) * 9, 90 + np.arange(15) * 9)]
for row in range(11):
    for column in range(8):
        repeated = yellow[np.ix_(60 + row * 300 + np.arange(8) * 9,
                                90 + column * 300 + np.arange(15) * 9)]
        assert np.array_equal(grid, repeated)
assert np.all(grid[:, 1:].sum(axis=0) % 2 == 1)
assert np.all(grid[1:].sum(axis=1) % 2 == 1)
values = grid[1:].T @ np.array([64, 32, 16, 8, 4, 2, 1])
assert list(values[1:6]) == [printed.minute, printed.hour, printed.day, printed.month, printed.year % 100]
assert all(0 <= digit <= 9 for digit in values[6:13])
serial = ''.join(map(str, values[6:13]))
print('Tracking matrix (top row and left column are parity):')
for row in grid:
    print(''.join(str(int(bit)) for bit in row))
print('Column values:', values.tolist())
print('All 88 copies agree; data-row and data-column odd parity verified.')
print('Machine:', machine)
print('Username:', username)
print('Serial:', serial)
print('UTC timestamp:', timestamp)
print('SPL text for comparison with scan:')
offset = 24
while offset < len(spl):
    kind, size = struct.unpack_from('<II', spl, offset)
    if kind == 84:
        count, position = struct.unpack_from('<II', spl, offset + 44)
        print(spl[offset + position:offset + position + count * 2].decode('utf-16le'))
    offset += size
payload = f'{username}|{serial}|{timestamp}'
print('Hash input:', payload)
print('SHA-256:', hashlib.sha256(payload.encode()).hexdigest())
print('Candidate: isfcr{' + hashlib.sha256(payload.encode()).hexdigest()[:16] + '}')
```

### Notes

- The field order in the dots is a simplified one (consecutive minute, hour, day, month, year, then serial), not the standard EFF Xerox BCD layout. Decoding with the standard layout does not reproduce the SHD date.
- Repetition is not evidence of an empty grid. The 88 identical copies are the encoding itself, and the team note that the dots "encode nothing" is wrong. An earlier attempt concluded the serial was missing and was blocked for that reason; reading the dots as above resolves it.
- The footer on the scan (`Page 1 of 1 - Printed on internal color device - Do not distribute`) carries no model or serial, so the serial must come from the dot matrix.
- The vault STATE records that the flag was accepted by the user. No checker service exists for this challenge.
