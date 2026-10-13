### Summary

The server aggregates client updates with a `mix` weight per round, and every round is a linear combination of the per-client gradients. Because each checkpoint is reused with different mix weights, the target client's gradient can be separated exactly. That gradient is a rank-2 function of its two 16-byte records, and the constant bias feature and constant label fix the factorization, so the two records can be recovered and passed to `unlock.py`.

### Steps

All paths are relative to the challenge's `work/` directory. The challenge archive contains `data.json` (the model, 6 checkpoints, 61 updates) and `unlock.py`.

1. Extract the archive so `data.json` and `unlock.py` are available locally.
   ```sh
   unzip ../files/the_aggregate_remembers.zip -d scratch/extract
   ```
   Of the 61 updates, 60 belong to cohort `acquisition-A` (6 to 13 per checkpoint, each with a 3-client `mix`). The single `acquisition-B` round is ignored.

2. De-mix the per-client gradients. For a round at checkpoint `w` with delta `delta` and learning rate `lr`, the mixed gradient is `-delta/lr - weight_decay*w`, which equals `sum_c (mix_c / sum(mix)) * g_c(w)`. For each checkpoint the normalized mix matrix has rank 3, so a least-squares solve over that checkpoint's rounds gives `g_c(w)` for every client, including the target. The residual is about 1e-2 because the deltas carry small noise.

3. Factor the target gradient. Every label and the bias feature are 1, so the gradient of the half-squared-error loss over the two records is `g(w) = A (w - e_bias)`, where `A = (x1 x1^T + x2 x2^T) / 2` and `x1`, `x2` are the two feature vectors. The six target gradients have rank 2 (singular values about 559, 52.8, then below 0.06), so `A` is fitted as a symmetric 2x2 matrix `S` on the span `P` of those gradients. Writing `x_i = P L r_i` with `L L^T = 2S` and orthonormal `r1`, `r2`, the bias feature of each record must equal 1. That forces `r1` and `r2` to lie at +45 and -45 degrees from `h = L^T P[bias]`, which leaves only the order of the two records undetermined.

4. Undo the preprocessing. Features are `x[j] = (raw[permutation[j]] - center[j]) / scale[j]`, so `raw[permutation[j]] = x[j] * scale[j] + center[j]`. The recovered values lie within 0.2 of integers and are rounded to bytes. The script performs steps 2 to 4 and prints the sorted answer list.
   ```sh
   python3 scripts/solve.py scratch/extract/data.json
   ```
   Output:
   ```json
   ["07841f68cb73fe5aac5cbf66f113f992", "ff1247cd40f11a77f9495f7ba9648a20"]
   ```

5. Submit the answer to the supplied validator. `unlock.py` decrypts an AES-GCM blob with a key derived from the answer, so a wrong list is rejected and a correct one prints the flag.
   ```sh
   python3 scratch/extract/unlock.py '["07841f68cb73fe5aac5cbf66f113f992", "ff1247cd40f11a77f9495f7ba9648a20"]'
   ```
   The output is `isfcr{REDACTED}`.

### Scripts

#### scripts/solve.py

Recovers the target client's two raw records from `data.json`, prints diagnostics on stderr and the sorted JSON answer on stdout. Run it as `python3 scripts/solve.py scratch/extract/data.json` after extracting the archive. It needs `numpy`.

```python
#!/usr/bin/env python3
"""Recover the target client's two raw records from data.json and print the unlock answer."""
import json
import sys

import numpy as np

d = json.load(open(sys.argv[1]))
m = d["model"]
n = m["dimension"]
lr = eval(m["lr"])
wd = eval(m["weight_decay"])
t = m["clients"].index(m["target_client"])
W = {c["id"]: np.array(c["weights"], float) for c in m["checkpoints"]}

# Per checkpoint, the mixed gradient is linear in the per-client gradients.
V, G = [], []
for k, w in W.items():
    rounds = [u for u in d["updates"] if u["cohort"] == "acquisition-A" and u["checkpoint"] == k]
    M = np.array([u["mix"] for u in rounds], float)
    M /= M.sum(1, keepdims=True)
    R = np.array([-np.array(u["delta"], float) / lr - wd * w for u in rounds])
    g, res, rank, _ = np.linalg.lstsq(M, R, rcond=None)
    print(f"{k}: rounds={len(rounds)} rank={rank} max_resid={np.abs(M @ g - R).max():.2e}", file=sys.stderr)
    e = np.zeros(n + 1)
    e[n] = 1
    V.append(w - e)
    G.append(g[t])
V, G = np.array(V), np.array(G)

# g(w) = A (w - e_bias), A = (x1 x1^T + x2 x2^T) / 2 since labels and bias feature are 1.
U, s, Pt = np.linalg.svd(G)
print("singular values of target gradients:", np.round(s, 6), file=sys.stderr)
P = Pt[:2].T
S = np.linalg.lstsq(V @ P, G @ P, rcond=None)[0].T
S = (S + S.T) / 2
ev, Q = np.linalg.eigh(S)
L = Q * np.sqrt(2 * ev)

# x_i = P L r_i with r1, r2 orthonormal; the bias feature of each x_i equals 1.
h = L.T @ P[n]
print("|h|^2 (expect 2):", h @ h, file=sys.stderr)
a = np.arctan2(h[1], h[0])
out = []
for th in (a + np.pi / 4, a - np.pi / 4):
    x = P @ L @ np.array([np.cos(th), np.sin(th)])
    v = x[:n] * np.array(m["scale"]) + np.array(m["center"])
    print("raw (permuted order):", np.round(v, 4), file=sys.stderr)
    raw = [0] * n
    for j, p in enumerate(m["permutation"]):
        raw[p] = int(round(v[j]))
    out.append(bytes(raw).hex())
print(json.dumps(sorted(out)))
```

### Notes

- Only cohort `acquisition-A` is used. The single `acquisition-B` round is a distractor and is excluded by the filter in the script.
- The gradient residual is about 1e-2 because the deltas are noisy. The rounding to bytes still works because the recovered values land within 0.2 of integers.
- The target is looked up from `model.target_client` in the client list, not hardcoded.
- `solve.py` calls `eval` on the `lr` and `weight_decay` strings from `data.json`. Run it only on the supplied data.
- `unlock.py` needs `cryptography`. `solve.py` needs `numpy`.
- `scratch/` is a local working directory and is not part of the challenge files.
