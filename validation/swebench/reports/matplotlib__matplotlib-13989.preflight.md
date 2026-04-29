# Pre-flight Rehearsal — matplotlib/matplotlib#0

> Issue: https://github.com/matplotlib/matplotlib/issues/matplotlib__matplotlib-13989 · title: matplotlib__matplotlib-13989 · model: gpt-5.4-mini

_Generated 2026-04-29T20:42:28Z_

## Issue Description

# matplotlib__matplotlib-13989

**Repository**: `matplotlib/matplotlib` at `a3e2897b`

## Problem statement

hist() no longer respects range=... when density=True
<!--To help us understand and resolve your issue, please fill out the form to the best of your ability.-->
<!--You can feel free to delete the sections that do not apply.-->

### Bug report

**Bug summary**

<!--A short 1-2 sentences that succinctly describes the bug-->

**Code for reproduction**

<!--A minimum code snippet required to reproduce the bug.
Please make sure to minimize the number of dependencies required, and provide
any necessary plotted data.
Avoid using threads, as Matplotlib is (explicitly) not thread-safe.-->

```python
_, bins, _ = plt.hist(np.random.rand(10), "auto", range=(0, 1), density=True)
print(bins)
```

**Actual outcome**

<!--The output produced by the above code, which may be a screenshot, console output, etc.-->

```
[0.00331535 0.18930174 0.37528813 0.56127453 0.74726092 0.93324731]
```

**Expected outcome**

Some array where the first value is 0 and the last one is 1.

Note that this bug doesn't happen if density=False.

Bisects to https://github.com/matplotlib/matplotlib/pull/8638/commits/239be7b18e311c57a1393b6eeefc62b7cc629339 (#8638).

**Matplotlib version**
<!--Please specify your platform and versions of the relevant libraries you are using:-->
  * Operating system: linux
  * Matplotlib version: master
  * Matplotlib backend (`print(matplotlib.get_backend())`): any
  * Python version: 37
  * Jupyter version (if applicable): no
  * Other libraries: numpy 1.16.2

<!--Please tell us how you installed matplotlib and python e.g., from source, pip, conda-->
<!--If you installed from conda, please specify which channel you used if not the default-->




## What we're asking

Produce a plan and a diff sketch that would resolve this issue. Identify the file(s) you'd touch and the key edits.

## Plan: Minimalist

### Plan
- Inspect `Axes.hist` bin-edge computation for the `density=True` path and find where `range=` is being dropped when bins are auto-computed.
- Ensure the `range` argument is passed through to the bin estimator even when `density=True`, so the computed bins span the requested interval.
- Keep behavior unchanged for `density=False` and for explicit bin edges.
- Add or update a regression test covering `bins="auto"`, `range=(0, 1)`, `density=True`, asserting the returned bin edges start/end at the requested range.
- Make the smallest possible code change in the histogram implementation only.

### Diff sketch

#### `lib/matplotlib/axes/_axes.py`
```diff
@@ def hist(self, x, bins=None, range=None, density=None, ...):
-    # current bin selection / histogram call path
-    bins = np.histogram_bin_edges(x, bins, ...)
+    # When bins are inferred, ensure range is forwarded even if density=True.
+    # This keeps auto-selected bins constrained to the user-requested range.
+    bins = np.histogram_bin_edges(x, bins=bins, range=range)
```

If the code already has separate branches for `density=True`, the minimal fix is likely in that branch:
```diff
@@
-    bins = np.histogram_bin_edges(x, bins)
+    bins = np.histogram_bin_edges(x, bins=bins, range=range)
```

#### `lib/matplotlib/tests/test_axes.py` (or existing histogram test file)
```diff
+def test_hist_density_respects_range():
+    _, bins, _ = plt.hist(np.random.rand(10), bins="auto", range=(0, 1), density=True)
+    assert bins[0] == 0
+    assert bins[-1] == 1
```

If the test suite prefers deterministic data:
```diff
+    x = np.linspace(0.1, 0.9, 10)
+    _, bins, _ = plt.hist(x, bins="auto", range=(0, 1), density=True)
+    np.testing.assert_allclose(bins[[0, -1]], [0, 1])
```

### Risks
- `np.histogram_bin_edges(..., range=...)` may slightly change bin selection for some edge cases, but only in the intended direction: respecting the user-supplied range.
- If `Axes.hist` already handles `range` elsewhere, changing the bin-edge call could duplicate behavior; need to confirm the smallest targeted branch.
- A regression test using random input could be flaky if the bin estimator behaves unexpectedly; deterministic input is safer.

## Plan: Defensive

### Plan
- Inspect `Axes.hist` / `numpy.histogram` call flow to find where `range` gets dropped when `density=True` and bins are auto-selected.
- Ensure the `range=` argument is always forwarded to the bin edge computation path, not only to the counting/density normalization path.
- Add/adjust regression test(s) covering `hist(..., range=(0, 1), density=True)` with `"auto"` bins to assert the returned bin edges start/end at the requested range.
- Verify behavior remains unchanged for `density=False` and for explicit bin edges.
- Guard against edge cases: empty input, degenerate ranges, and non-finite inputs, preserving existing validation/errors.

---

### Diff sketch

#### `lib/matplotlib/axes/_axes.py`
Key edit: make sure the `range` is passed into the code path that determines bins before calling `numpy.histogram`.

```diff
@@ def hist(self, x, bins=None, range=None, density=None, weights=None, ...):
-    # existing logic computes bins / histogram
+    # Ensure the requested range is honored when bins are inferred
+    # (e.g. bins="auto") and density normalization is requested.
+    # range must be forwarded to the bin-edge selection step, not only
+    # to the histogram counting step.

     if ...:
-        bin_edges = np.histogram_bin_edges(x, bins=bins, weights=weights)
+        bin_edges = np.histogram_bin_edges(x, bins=bins, range=range, weights=weights)
     else:
         ...
```

If the code path already uses `np.histogram`, the likely fix is to preserve `range` in the inferred-bins branch rather than overwriting it with computed edges from `x` alone.

Potentially also:
```diff
@@
-    n, bins = np.histogram(x, bins, range=None, weights=weights)
+    n, bins = np.histogram(x, bins=bins, range=range, weights=weights)
```

depending on where the regression was introduced.

#### `lib/matplotlib/tests/test_axes.py`
Add a regression test.

```diff
+def test_hist_density_respects_range():
+    x = np.random.RandomState(0).rand(10)
+    _, bins, _ = plt.hist(x, "auto", range=(0, 1), density=True)
+    assert bins[0] == 0
+    assert bins[-1] == 1
```

Prefer deterministic input and maybe a stricter assertion:
```diff
+    np.testing.assert_allclose(bins[[0, -1]], [0, 1])
```

If there is already a histogram test module, place it there instead of `test_axes.py`.

---

### Risks foreseen
- **Behavioral compatibility:** fixing `range` propagation may slightly change bin selection for `"auto"` / other adaptive bin rules in edge cases, but that is the intended behavior per API.
- **Density normalization coupling:** `density=True` normalizes counts by bin widths; changing edges may alter numeric outputs for users relying on the buggy behavior, so the regression test should assert only the contract (`range` respected) rather than exact histogram heights.
- **Empty or masked inputs:** if `range` is forwarded earlier, ensure existing error messages and fallback behavior remain unchanged for empty arrays or all-nonfinite data.
- **Different internal paths:** `hist` has several branches (`stacked`, multiple datasets, weights, log, cumulative). The fix should be applied to the shared bin-edge determination path to avoid inconsistent behavior across branches.

## Plan: TestFirst

## 1) Test cases to prove the fix

I’d start by adding/adjusting tests around `Axes.hist` to cover both the regression and nearby edge cases:

1. **Regression case: `density=True` respects explicit `range`**
   - Input: random data in `[0, 1]`
   - Call: `plt.hist(data, bins="auto", range=(0, 1), density=True)`
   - Assert:
     - returned `bins[0] == 0`
     - returned `bins[-1] == 1`
   - This is the core failure described in the issue.

2. **Control case: `density=False` still respects `range`**
   - Same data/call but `density=False`
   - Assert bin edges still span the explicit range.
   - Confirms the bug is specific to the density path.

3. **Range is respected even when the automatic binning heuristic chooses fewer bins**
   - Use a small/degenerate dataset and `bins="auto"` with `range=(a, b)`.
   - Assert the output bins always include `a` and `b`.
   - Ensures no hidden interaction with the “auto” bin calculation.

4. **Explicit numeric bin count with `density=True` and `range`**
   - Call `plt.hist(data, bins=5, range=(0, 1), density=True)`
   - Assert first/last bin edges are exactly `0` and `1`.
   - Guards against the bug being tied to only the string/bin estimator path.

5. **Data outside the range**
   - Use data containing values outside `(0, 1)` and call `hist(..., range=(0, 1), density=True)`
   - Assert bins still span `(0, 1)` and out-of-range samples are excluded from the histogram counts.
   - Protects the intended semantics of `range`.

---

## 2) Short implementation plan

- Inspect `Axes.hist` bin computation for the `density=True` path and compare it to the non-density path.
- Find where `range` is lost after automatic bin estimation.
- Ensure the computed bin edges are clipped/constructed to exactly match the user-supplied `range` before density normalization.
- Add regression tests for both `"auto"` and numeric bin counts.
- Run hist-related tests to confirm no change in output shape or normalization behavior.

---

## 3) Diff sketch

### `lib/matplotlib/axes/_axes.py`
Key edit likely in `Axes.hist`:

- In the branch that computes bin edges for `bins='auto'` / string/bin-estimator cases:
  - preserve the user-provided `range`
  - when `range` is explicitly set, make sure the final `bins` array starts/ends with that range
- If density normalization currently triggers a re-computation or replaces the bins with estimator-generated edges, change it so density only affects counts scaling, not bin edge generation.

Sketch:

```diff
diff --git a/lib/matplotlib/axes/_axes.py b/lib/matplotlib/axes/_axes.py
@@ def hist(self, x, bins=None, range=None, density=False, ...):
-    # existing bin selection / normalization logic
+    # preserve explicit range when bins are auto-computed
+    # ensure density normalization does not alter bin edges
+    if range is not None:
+        # bins computed from estimator should be constrained to range
+        # final edges must begin/end at range[0], range[1]
+        ...
```

### `lib/matplotlib/tests/test_axes.py` or `lib/matplotlib/tests/test_hist.py`
Add regression tests:

```diff
+def test_hist_density_respects_range_auto_bins():
+    data = np.random.RandomState(0).rand(10)
+    _, bins, _ = plt.hist(data, bins="auto", range=(0, 1), density=True)
+    assert bins[0] == 0
+    assert bins[-1] == 1
+
+def test_hist_density_respects_range_numeric_bins():
+    data = np.random.RandomState(0).rand(10)
+    _, bins, _ = plt.hist(data, bins=5, range=(0, 1), density=True)
+    assert bins[0] == 0
+    assert bins[-1] == 1
```

If existing histogram tests already use `bins` return values, I’d extend them rather than add a new file.

---

## 4) Risks foreseen

- **Changing the bin-edge construction could alter legacy behavior** for callers that implicitly relied on the buggy density path.
- **Float equality in tests**: direct comparisons to `0` and `1` are safe if the code explicitly sets those edges, but if the implementation uses numerical operations, `assert_allclose` may be safer.
- **Interaction with `bins='auto'` heuristics**: the fix should preserve the estimator’s bin count while only anchoring the endpoints to `range`; otherwise histogram shape may change unexpectedly.
- **Multi-series / shared bins behavior**: `hist` supports sequences of datasets; the fix should be careful not to break the shared-bin logic across multiple inputs.

## Plan: RefactorHappy

### Plan
- Inspect `Axes.hist` binning logic for the `density=True` path, especially where `bins='auto'` and `range=...` are handled.
- Restore the contract that an explicit `range` constrains bin edges even when density normalization is requested.
- Prefer a small local refactor in `axes/_axes.py` so bin computation and normalization remain separate concerns.
- Add or adjust a regression test covering `bins="auto", range=(0, 1), density=True` to assert the returned bin edges start/end at the requested range.
- Keep behavior unchanged for `density=False` and for cases without an explicit `range`.

### Diff sketch

#### `lib/matplotlib/axes/_axes.py`
Key edit: ensure `range` is applied before/while selecting bins for `density=True`, instead of being lost during auto-binning.

```diff
diff --git a/lib/matplotlib/axes/_axes.py b/lib/matplotlib/axes/_axes.py
@@ def hist(self, x, bins=None, range=None, density=False, ...):
-    # current logic may compute bins on the raw data even when range is set
-    # and density=True, causing auto binning to ignore the requested range.
+    # Ensure explicit range constrains the data used to determine bin edges,
+    # including the density=True / bins="auto" path.
+    if range is not None:
+        # use the same clipped/filtered data for bin estimation
+        # (or pass range through to the bin estimator if already supported)
+        ...
 
-    bin_edges = np.histogram_bin_edges(x, bins, range=range)
+    bin_edges = np.histogram_bin_edges(x, bins, range=range)
     counts, bin_edges = np.histogram(x, bin_edges, density=False)
 
     if density:
         # normalize counts by bin width after bins are finalized
         counts = counts / (counts.sum() * np.diff(bin_edges))
```

More concretely, if the current implementation computes `bin_edges` via a helper that ignores `range` for `density=True`, patch that helper call so `range` is forwarded unconditionally, and avoid any branch that recomputes edges from unclipped data.

#### `lib/matplotlib/tests/test_axes.py` (or existing histogram tests file)
Add a regression test:

```diff
diff --git a/lib/matplotlib/tests/test_axes.py b/lib/matplotlib/tests/test_axes.py
@@ def test_hist_auto_range_density():
+    np.random.seed(0)
+    _, bins, _ = plt.hist(np.random.rand(10), "auto", range=(0, 1), density=True)
+    assert bins[0] == 0
+    assert bins[-1] == 1
```

If the project prefers numeric tolerance:

```python
assert bins[0] == pytest.approx(0)
assert bins[-1] == pytest.approx(1)
```

### Risks
- `hist()` has several intertwined code paths (`bins` as int/str/array, stacked histograms, weights, cumulative, density), so a fix in one branch could accidentally affect others if not carefully scoped.
- Some internal behavior may rely on the current bin-edge computation order; forwarding `range` too early could alter edge rounding or the exact number of bins for `"auto"`.
- If the bug originates in a shared helper or NumPy interaction, the fix may need to be applied at the helper boundary rather than only inside `Axes.hist`.
- A regression test using random data could be flaky unless it only asserts the endpoint behavior, not the exact intermediate bin edges.

## Judge Verdict

## Ranked list

1. **Minimalist**  
   **Rationale:** Best balance of precision and scope: it targets the likely regression point directly, saying to “**ensure the `range` argument is passed through to the bin estimator even when `density=True`**,” and proposes the smallest code change plus a focused regression test.

2. **Defensive**  
   **Rationale:** Solid and careful, but a bit too broad; it correctly emphasizes forwarding `range` “**to the bin-edge selection step, not only to the histogram counting step**,” yet it adds extra edge-case caution that isn’t necessary for this specific fix.

3. **RefactorHappy**  
   **Rationale:** Directionally right about separating bin computation and normalization, but it drifts toward refactoring and speculative internals (“**use the same clipped/filtered data for bin estimation**”) rather than the smallest targeted fix.

4. **TestFirst**  
   **Rationale:** Strong on validation, but it overreaches with five test cases; for this issue, a single regression test around `"auto"`, `range=(0, 1)`, and `density=True` is enough to drive the fix.

## Winner

**Minimalist**

## Brief rationale

The issue description is very specific: `hist()` “**no longer respects range=... when density=True**,” and the bug bisects to a particular commit. Minimalist matches that with the most plausible implementation strategy: **forward `range` into the bin-edge computation path** and add a regression test asserting the returned bins start and end at the requested range.

## Recommended synthesis

- **Take Minimalist’s diff strategy**: small change in `lib/matplotlib/axes/_axes.py`, likely in `Axes.hist` / bin-edge selection.
- **Borrow Defensive’s caution**: confirm the fix applies to the shared bin-inference path so it doesn’t break multi-dataset / weights / stacked cases.
- **Borrow TestFirst’s validation idea, but only one test**: a deterministic regression test for `bins="auto", range=(0, 1), density=True` checking `bins[0] == 0` and `bins[-1] == 1`.

## Open questions for the human engineer

1. **Where exactly is the bug introduced?**  
   Is the broken logic in `Axes.hist` itself, or in a helper / NumPy call chain that `hist` relies on?

2. **Should the fix be in `Axes.hist` or a shared histogram helper?**  
   The issue says it bisects to a specific commit; we should confirm the narrowest correct layer to patch.

3. **What exact test file is preferred in this repo state?**  
   `lib/matplotlib/tests/test_axes.py` versus a histogram-specific test module.

4. **Do we need to preserve any subtle bin-estimation behavior for `"auto"` beyond endpoints?**  
   The expected contract here is just that `range` is respected, but we should verify no unintended side effects on bin count or density normalization.
