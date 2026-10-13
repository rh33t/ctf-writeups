### Summary

The black-box model is a piecewise-affine function built from one base affine rule plus a set of ReLU-style hinge terms. Each local seven-point cloud determines the active affine rule exactly, and the paired clouds in each capture straddle one hinge's zero hyperplane, which exposes the hinge and the side on which it is active. Subtracting the active hinges from every local rule gives one shared base rule, the full model is then reconstructed and checked against the 16 anchors, and the 24 target outputs are evaluated exactly.

### Steps

All paths are relative to the challenge's `work/` directory. The archive contains `data.json` (model version, captures, anchors, targets) and `unlock.py`.

1. Keep only the captures whose `model_version` matches `data["model_version"]`. Here that is `v-8fb4ff`, which covers 18 of the 22 captures. The other 4 captures are tagged `v-41e59d` and are decoys. Each capture holds two clouds of seven samples in six dimensions. Each cloud gives a 7x7 exact linear system over the rationals (six coefficients plus an intercept), so solving it yields the local affine model.

2. Compare the two clouds inside each capture. Subtracting the two local affine models gives a difference form. The 18 captures yield 18 differences, which reduce to nine unique integer affine forms, each seen twice. For each form, the two clouds of its capture lie on opposite sides of its zero hyperplane, so each form is a hinge. The active side is the sign of the difference form at the first sample of the second cloud. Keeping this sign matters: two of the hinges are active on their negative side.

3. Remove the active hinges from each local model. For every cloud, subtract every hinge that is active at that cloud's first sample. All 36 clouds then give the same base affine form `(-3, -2, -5, 0, 1, -5, 0)`, where the last entry is the intercept. The solver asserts that the bases agree and that the rebuilt model reproduces all 16 independent anchors exactly before printing the targets.
   ```sh
   mkdir -p scratch
   python3 scripts/solve.py ../files/the_shape_of_silence.zip | tee scratch/answer.json
   ```
   The output is a JSON list of 24 reduced rationals, in the order of `data["targets"]`:
   ```json
   ["5441/64","909/32","8939/64","1055/32","6041/64","1305/64","4173/32","4559/64","1597/16","1309/64","3015/32","423/4","2145/64","9475/64","26","2777/64","-1437/64","2969/64","983/16","5471/64","4163/64","5835/64","2971/64","2007/64"]
   ```

4. Pass the list to the supplied validator. `unlock.py` hashes the compact JSON answer into an AES-256-GCM key and decrypts, so a wrong list prints `Rejected.` and the correct list prints the flag.
   ```sh
   unzip -p ../files/the_shape_of_silence.zip unlock.py > scratch/unlock.py
   python3 scratch/unlock.py "$(cat scratch/answer.json)"
   ```
   The output is `isfcr{REDACTED}`.

### Scripts

#### scripts/solve.py

Reconstructs the signed hinge model from the current-version capture pairs, checks it against every anchor, and prints the 24 target outputs as a compact JSON list. Run it from `work/` as `python3 scripts/solve.py ../files/the_shape_of_silence.zip`. It needs `sympy`.

```python
#!/usr/bin/env python3
import json
import sys
import zipfile

from sympy import Matrix, Rational


def load_data(path):
    with zipfile.ZipFile(path) as archive:
        return json.loads(archive.read("data.json"))


def affine_model(cloud):
    matrix = Matrix([[Rational(value) for value in point["x"]] + [1] for point in cloud])
    outputs = Matrix([Rational(point["y"]) for point in cloud])
    return tuple(matrix.inv() * outputs)


def evaluate(form, point):
    return sum(form[index] * Rational(value) for index, value in enumerate(point)) + form[-1]


def main():
    data = load_data(sys.argv[1])
    captures = [
        capture for capture in data["captures"]
        if capture["model_version"] == data["model_version"]
    ]

    terms = []
    active_signs = []
    for capture in captures:
        first, second = capture["clouds"]
        delta = tuple(
            right - left
            for left, right in zip(affine_model(first), affine_model(second))
        )
        if delta in terms:
            continue
        first_values = [evaluate(delta, point["x"]) for point in first]
        second_values = [evaluate(delta, point["x"]) for point in second]
        assert all(value < 0 for value in first_values) and all(value > 0 for value in second_values) \
            or all(value > 0 for value in first_values) and all(value < 0 for value in second_values)
        terms.append(delta)
        active_signs.append(1 if second_values[0] > 0 else -1)

    bases = set()
    for capture in captures:
        for cloud in capture["clouds"]:
            model = affine_model(cloud)
            point = cloud[0]["x"]
            active = [
                term for term, sign in zip(terms, active_signs)
                if sign * evaluate(term, point) > 0
            ]
            bases.add(tuple(
                coefficient - sum(term[index] for term in active)
                for index, coefficient in enumerate(model)
            ))
    assert len(bases) == 1
    base = bases.pop()

    def predict(point):
        result = evaluate(base, point)
        for term, sign in zip(terms, active_signs):
            value = evaluate(term, point)
            if sign * value > 0:
                result += value
        return result

    assert all(predict(anchor["x"]) == Rational(anchor["y"]) for anchor in data["anchors"])
    print(json.dumps([str(predict(point)) for point in data["targets"]], separators=(",", ":")))


if __name__ == "__main__":
    main()
```

### Notes

- The four captures tagged `v-41e59d` are decoys. Including them would produce extra base forms and wrong targets, so the filter on `model_version` is required.
- Treating every hinge as a positive ReLU gives four apparent base forms and matches only 5 of the 16 anchors. Two hinges have negative output weights, so their sign must be kept, which gives a single base form and 16 of 16 anchors.
- Before the hinge structure was found, polynomial fits (degree up to 5), rational P/Q fits, separable sums, and symmetric-polynomial bases were tried and did not reproduce the anchors. These dead ends are not needed for the solve.
- The clouds are very tight (coordinates differ by about 1/1024), so the exact rational arithmetic in `sympy` matters. Floating point is not used by the solver.
- The solver checks the anchors with `assert`, so a wrong model fails before any answer is printed.
- The oracle is cheap: a wrong list only returns `Rejected.`, so the answer should be checked against the anchors locally first, as the script does.
