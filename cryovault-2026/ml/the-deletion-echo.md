### Summary

The service leaks each snapshot's Hessian `H` through the predictive variance and `theta` through the predicted mean, so both can be recovered by least squares from the query responses. Comparing `H` between the pre-deletion and post-deletion snapshots, after adding the ingested batch, isolates the deleted records as a 0/1 combination of their feature outer products. The difference of `4*H*theta` is an exact integer combination of the labels, which a short lattice (BKZ) search resolves into the private labels.

### Steps

All paths are relative to the challenge's `work/` directory. The archive contains `data.json` (the service contract, snapshots, queries, candidates and ingest batches) and `unlock.py`.

1. Build a Python environment with NumPy, fpylll and cryptography. fpylll provides the BKZ reduction used in step 4.
   ```sh
   uv venv scratch/venv --python 3.12
   uv pip install --python scratch/venv/bin/python numpy fpylll cysignals cryptography
   ```

2. Recover `H` and `theta` for every snapshot. For each snapshot the predictive variance is `s2 + q^T (s2 H^-1) q`, which is linear in `s2` and in the entries of `s2 H^-1`. The solver fits this by least squares over the 240 queries (79 unknowns) and inverts the result to get `H`. The means are fitted the same way to get `theta`. Features are multiples of 1/4 and labels are integers, so `4*H*theta = 4*X^T*y` is an integer vector. The fitted values land within 0.013 of an integer and are rounded.

3. Find the deleted set. The ridge term and noise variance cancel when comparing two versions of the same service, so for each ordered snapshot pair and each ingest batch `B` the solver solves `H_old + B^T B - H_new = sum_j z_j x_j x_j^T` with `z` in `[0, 1]` over the 140 candidate records. Only `snapshot-80794d4ee21c` to `snapshot-e385b6f3720a` with `ingest-e0449f2a` fits. The solution has 26 coefficients within 0.023 of 1 and the rest near 0. `snapshot-d1f54facd170` is a stale redeploy of the pre-deletion snapshot and gives the same deleted set.

4. Recover the labels. With the deleted set fixed, `4*(u_new - u_old) = (4B)^T b - (4X_del)^T y` is a system of 12 exact integer equations in 36 unknowns (10 ingested labels and 26 deleted labels), each in `{0, 1, 2, 3}`. The solver embeds this system in a lattice whose target vector encodes the bounds, runs LLL and BKZ, and keeps the single solution that satisfies all equations. The final output line is the sorted answer list.
   ```sh
   scratch/venv/bin/python -I scripts/solve.py ../files/the_deletion_echo.zip
   ```
   The answer is a JSON list of `record-id:label` strings. The solver also writes it to `artifacts/answer.json`:
   ```json
   ["record-0730706150:0", "record-28c0bbf813:2", "record-2e6662ecc6:3", "record-3de105d25d:3", "record-3ee76f33c8:2", "record-46126dd779:0", "record-473e486afd:0", "record-49aa7c51a4:2", "record-507645d5d9:2", "record-58fad90382:2", "record-5bc7d8554c:1", "record-66f65f5026:0", "record-71fb3e266c:2", "record-7796490f27:1", "record-77a4509144:1", "record-8f4b4073f9:1", "record-90769aad7a:1", "record-978b124800:1", "record-9cddf7a4fb:0", "record-9cfdc74744:3", "record-b9e67b6811:2", "record-cf44aec78a:2", "record-cf4fee237a:0", "record-d32fd7d5d5:1", "record-ebfb2ad09e:0", "record-ee9e7ec4d8:1"]
   ```

5. Submit the answer to the supplied validator. `unlock.py` decrypts with AES-GCM keyed on the list, so a wrong list does not produce a flag, and a correct one prints it.
   ```sh
   unzip -o ../files/the_deletion_echo.zip unlock.py -d scratch/
   scratch/venv/bin/python -I scratch/unlock.py "$(cat artifacts/answer.json)"
   ```
   The output is `isfcr{REDACTED}`.

### Scripts

#### scripts/solve.py

Performs the whole recovery: per-snapshot `H` and `theta`, the deleted-record search, and the BKZ label recovery. Run it from `work/` as `scratch/venv/bin/python -I scripts/solve.py ../files/the_deletion_echo.zip`. The last line of stdout is the JSON answer list.

```python
#!/usr/bin/env python3
"""Recover the deleted records and labels. Usage: solve.py files/the_deletion_echo.zip"""
import json
import sys
import zipfile
from itertools import permutations

import numpy as np
from fpylll import BKZ, LLL, IntegerMatrix

d = json.loads(zipfile.ZipFile(sys.argv[1]).read('data.json'))
c = d['contract']
n = c['dimension']
ij = np.triu_indices(n)


def feats(recs):
    raw = np.array([r['raw'] for r in recs])
    return (raw[:, c['permutation']] - np.array(c['center'])) / np.array(c['scale'])


def sym(x):
    return np.array([np.outer(v, v)[ij] for v in x])


# variance = s2 + q^T (s2 H^-1) q is linear in s2 and the entries of s2 H^-1
H, u4 = {}, {}
for s in d['snapshots']:
    qs = [q for q in d['queries'] if q['snapshot_id'] == s['id']]
    x = feats(qs)
    a = sym(x)
    a[:, ij[0] != ij[1]] *= 2
    var = [float(q['predictive_variance']) for q in qs]
    fit = np.linalg.lstsq(np.column_stack([np.ones(len(x)), a]), var, rcond=None)[0]
    inv = np.zeros((n, n))
    inv[ij] = fit[1:] / fit[0]
    inv[(ij[1], ij[0])] = inv[ij]
    H[s['id']] = np.linalg.inv(inv)
    theta = np.linalg.lstsq(x, [float(q['mean']) for q in qs], rcond=None)[0]
    # features are multiples of 1/4 and labels integers, so 4 H theta = 4 X^T y is integral
    v = 4 * H[s['id']] @ theta
    u4[s['id']] = np.round(v).astype(int)
    print(s['id'], 'noise', round(fit[0], 6), 'max |4u - round|', round(abs(v - u4[s['id']]).max(), 4))


def bounded_labels(M, w):
    """All integer c in [0,3]^k with M c = w found as short vectors (2c-3 | 3) of an embedding lattice."""
    k = M.shape[1]
    big = 10 ** 6
    rows = [[big * int(v) for v in M[:, i]] + [2 * (i == j) for j in range(k)] + [0] for i in range(k)]
    rows.append([-big * int(v) for v in w] + [-3] * k + [3])
    B = IntegerMatrix.from_matrix(rows)
    LLL.reduction(B)
    BKZ.reduction(B, BKZ.Param(block_size=min(30, k + 1)))
    found = []
    for r in range(B.nrows):
        row = [B[r, j] for j in range(B.ncols)]
        if any(row[:len(w)]) or abs(row[-1]) != 3:
            continue
        sol = [(v * row[-1] // 3 + 3) // 2 for v in row[len(w):-1]]
        if all(0 <= v <= 3 for v in sol) and (M @ np.array(sol) == w).all():
            found.append(sol)
    return found


# H_new - H_old = B^T B - sum over deleted x x^T: bounded least squares over the candidates
X = feats(d['candidates'])
A = sym(X).T
norm = np.linalg.norm(A, axis=1)
A = A / norm[:, None]
step = 1 / np.linalg.svd(A, compute_uv=False)[0] ** 2
hits = []
for old, new in permutations(H, 2):
    for batch in d['ingest']:
        Bx = feats(batch['records'])
        target = (Bx.T @ Bx - H[new] + H[old])[ij] / norm
        z = np.zeros(len(X))
        for _ in range(3000):
            zz = np.clip(z + step * A.T @ (target - A @ z), 0, 1)
            if np.max(abs(zz - z)) < 1e-10:
                break
            z = zz
        sel = np.where(z > .5)[0]
        if len(sel) and np.linalg.norm(A @ np.round(z) - target) < 0.01:
            hits.append((old, new, batch, sel))
            print('deletion', old, '->', new, 'with', batch['batch_id'], 'deleted', len(sel), 'max fractional part', round(max(abs(z - np.round(z))), 4))
# 4 u_new - 4 u_old = (4 B)^T b - (4 X_deleted)^T y
answers = set()
for old, new, batch, sel in hits:
    Bx = feats(batch['records'])
    M = np.round(4 * np.column_stack([Bx.T, -X[sel].T])).astype(int)
    sols = bounded_labels(M, u4[new] - u4[old])
    print(old, '->', new, 'label solutions', len(sols))
    assert len(sols) == 1
    labels = sols[0][len(Bx):]
    answers.add(json.dumps(sorted(f"{d['candidates'][i]['id']}:{y}" for i, y in zip(sel, labels))))
# a stale redeploy duplicates the pre-deletion snapshot, so every hit must agree
assert len(answers) == 1
print(answers.pop())
```

### Notes

- `H` itself cannot be rounded to its exact value. Its entries reach about 5e6 and the oracle noise is about 1e-9 relative, so `H` is only good enough for differences. Only `4*H*theta` is precise enough to round to integers.
- The ridge and the noise variance never need to be known, because the ridge cancels in the `H` difference between two versions of the same service.
- `snapshot-d1f54facd170` is a stale redeploy of the pre-deletion snapshot. It is not a separate version, and the solver asserts that all hits agree.
- Hand-written float LLL and Babai helpers were tried first and dropped. fpylll is required for the label step.
- The solver uses `assert len(sols) == 1`, so a different environment that yields several label solutions will fail loudly instead of printing a wrong list.
- The `uv` environment is created under `work/scratch/` and is not part of the challenge files.
