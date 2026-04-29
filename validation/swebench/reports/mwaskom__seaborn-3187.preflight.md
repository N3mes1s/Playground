# Pre-flight Rehearsal — mwaskom/seaborn#0

> Issue: https://github.com/mwaskom/seaborn/issues/mwaskom__seaborn-3187 · title: mwaskom__seaborn-3187 · model: gpt-5.4-mini

_Generated 2026-04-29T20:42:45Z_

## Issue Description

# mwaskom__seaborn-3187

**Repository**: `mwaskom/seaborn` at `22cdfb0c`

## Problem statement

Wrong legend values of large ranges
As of 0.12.1, legends describing large numbers that were created using `ScalarFormatter` with an offset are formatted without their multiplicative offset value. An example:
```python
import seaborn as sns
import seaborn.objects as so

penguins = sns.load_dataset("Penguins")
penguins["body_mass_mg"] = penguins["body_mass_g"]*1000
(
    so.Plot(
        penguins, x="bill_length_mm", y="bill_depth_mm",
        color="species", pointsize="body_mass_mg",
    )
    .add(so.Dot())
)
```
The code creates the following plot:
![image](https://user-images.githubusercontent.com/13831112/205512305-778966db-f8d8-43f3-a2c0-5e5ce95bae39.png)
which is wrong because `body_mass_mg` is in the order of 1E6. The issue also reproduces if you create the mentioned plot using `scatterplot`.
 
I believe the issue stems from not using the offset value of the `ScalarFormatter` used to generate the tick labels:
https://github.com/mwaskom/seaborn/blob/ba786bc14eb255f6b4fb7619c8210c5a8016a26f/seaborn/_core/scales.py#L377-L382
Examining the code of `ScalarFormatter` suggests the issue also depends on the following rcParam settings:
`mpl.rcParams['axes.formatter.useoffset']`
`mpl.rcParams['axes.formatter.offset_threshold']`
However, I did not test it. 

The offset value can be safely retrieved from all formatters and based on that it can be used to create the legend title and/or labels.


## What we're asking

Produce a plan and a diff sketch that would resolve this issue. Identify the file(s) you'd touch and the key edits.

## Plan: Minimalist

Plan:
- Inspect the numeric legend/scale formatting path in `seaborn/_core/scales.py`, especially where `ScalarFormatter` is used to generate tick labels for legends.
- Preserve the formatter’s offset text and incorporate it into the legend title or labels when the formatter reports a non-zero offset.
- Keep the change localized to the scale formatting helper so both `objects` and `scatterplot` legend generation benefit.
- Add or update a regression test covering a large-range numeric variable that triggers `ScalarFormatter` offset formatting.
- Verify the output still matches existing behavior for small ranges and non-offset formatters.

Diff sketch:
```diff
diff --git a/seaborn/_core/scales.py b/seaborn/_core/scales.py
@@
-        formatter = mticker.ScalarFormatter(...)
-        labels = [formatter.format_data_short(val) for val in levels]
+        formatter = mticker.ScalarFormatter(...)
+        labels = [formatter.format_data_short(val) for val in levels]
+        offset = formatter.get_offset()
+        if offset:
+            # Include the multiplicative offset/scaling text in the legend
+            # presentation so large values are not shown without context.
+            title = f"{title} {offset}" if title else offset
```

```diff
diff --git a/tests/test_scales.py b/tests/test_scales.py
@@
+def test_numeric_legend_includes_scalarformatter_offset():
+    # Use a variable spanning a range large enough to trigger ScalarFormatter
+    # offset behavior and assert the legend title/labels reflect it.
+    ...
+    assert "1e" in legend_text or "×" in legend_text
```

Risks:
- `ScalarFormatter.get_offset()` returns display text that may be backend/locale/version dependent, so the exact string assertion in tests must be flexible.
- Some existing legends may intentionally rely on compact titles; appending offset text could slightly change layout.
- If the formatter offset is only needed for certain scales, applying it broadly could affect unrelated numeric legends, so the condition should be narrowly targeted to offset-bearing formatters.

## Plan: Defensive

## Plan

- Inspect the legend/scale-label generation path for numeric `pointsize`/`size` and other continuous semantic scales in `seaborn/_core/scales.py`.
- Confirm how seaborn currently formats legend tick values when matplotlib’s `ScalarFormatter` is using an offset, and identify where the offset is being discarded.
- Update the formatter/label construction to incorporate both:
  - the tick label text, and
  - the formatter’s multiplicative offset / scientific scaling factor.
- Add guardrails for edge cases:
  - no offset present,
  - non-ScalarFormatter formatters,
  - invalid/empty formatter state.
- Add or adjust tests covering large-valued numeric legends with `useoffset=True` and/or thresholds that trigger offsets.
- Verify behavior remains unchanged for normal small ranges and for other formatters.

## Diff sketch

### `seaborn/_core/scales.py`
Key edit area: the continuous scale legend labeling logic around the current `ScalarFormatter` tick formatting path.

Possible changes:
- When constructing legend labels for numeric scales, retrieve the formatter’s offset/scientific multiplier:
  - prefer the public-ish formatter methods/attributes if available,
  - fall back defensively if not.
- Combine offset information into the legend title or tick labels so values are displayed in the true magnitude.
- Ensure the logic works whether the formatter returns labels like `0.5, 1.0` with an offset annotation, or formatted values with scientific notation.

Sketch:
```diff
@@ class Continuous(...):
-    labels = [formatter(val) for val in ticks]
+    labels = [formatter(val) for val in ticks]
+    offset = getattr(formatter, "get_offset", lambda: "")()
+    # If formatter has an offset/scaling component, incorporate it into the legend
+    # so labels represent actual data magnitudes.
+    if offset:
+        title = f"{title} {offset}"  # or equivalent structured title formatting
+    # Alternatively, adjust labels by the formatter's offset/scalar value directly.
```

More robust version:
```diff
+    if isinstance(formatter, matplotlib.ticker.ScalarFormatter):
+        formatter.set_locs(ticks)
+        offset = formatter.get_offset()
+        # Use formatter.format_data_short / format_data depending on desired output,
+        # or prepend/append offset in the legend title.
```

### `tests/...`
Likely a test module covering scales/legend formatting, possibly:
- `tests/_core/test_scales.py`
- or an existing objects/scatterplot legend test file if that is where continuous legends are validated.

Key edits:
- Add a regression test that creates a plot with a large numeric `pointsize` variable and asserts the legend includes the multiplier/offset indication.
- Cover both `seaborn.objects` and `scatterplot` if the code path is shared and easy to assert.
- Parameterize on `mpl.rcParams["axes.formatter.useoffset"]` if needed to ensure the bug reproduces and the fix is stable.

Example sketch:
```diff
+def test_continuous_legend_includes_scalarformatter_offset():
+    df = ...
+    df["body_mass_mg"] = df["body_mass_g"] * 1000
+    p = so.Plot(df, x="bill_length_mm", y="bill_depth_mm", pointsize="body_mass_mg").add(so.Dot())
+    # Assert legend text includes scientific/offset component, not just raw tick labels.
+    assert "10" in legend_text or "×" in legend_text
```

## Risks

- **Matplotlib formatter coupling:** `ScalarFormatter` behavior depends on rcParams and internal state; relying on private-ish attributes may be brittle across matplotlib versions.
- **Legend readability:** Incorporating offsets directly into labels could make legends noisier; placement in title vs. labels needs care.
- **Behavior changes for existing plots:** Some plots may currently “look okay” due to implicit formatting; changing the legend text format could alter baseline expectations.
- **Multiple continuous scale types:** If the formatting helper is shared, a fix for `pointsize` may affect other semantics (hue, size, alpha, linewidth), so regression coverage should include them or at least ensure shared logic remains correct.
- **Testing under different rcParams:** The bug may only reproduce with certain `axes.formatter.*` settings, so tests must be explicit and restore rcParams afterward to avoid cross-test contamination.

## Plan: TestFirst

## Test cases to prove the fix

1. **Large numeric `pointsize` with `ScalarFormatter` offset**
   - Reproduce the reported example with `body_mass_mg` around `1e6`.
   - Assert the legend title or label shows the multiplicative scale / offset context, not just the mantissa-like tick labels.
   - Expected: legend entries are no longer misleadingly small when values are large.

2. **Same case through both APIs**
   - `seaborn.objects.Plot(..., pointsize=...)`
   - `seaborn.scatterplot(..., size=...)`
   - Expected: both code paths produce consistent, correct legend formatting.

3. **No offset needed**
   - Use a numeric range that `ScalarFormatter` renders without an offset.
   - Expected: behavior remains unchanged; legend labels still look normal.

4. **Offset suppressed by rcParams**
   - Set `mpl.rcParams["axes.formatter.useoffset"] = False`.
   - Expected: legend formatting respects that setting and does not invent an offset.

5. **Threshold-dependent offset behavior**
   - Exercise a range near `axes.formatter.offset_threshold`.
   - Expected: legend uses the formatter’s actual offset state, not a hardcoded assumption.

6. **Non-numeric or categorical size/color values**
   - Ensure these code paths are unaffected.
   - Expected: categorical legends remain unchanged.

---

## Short plan

- Inspect the numeric scale legend formatting path in `seaborn/_core/scales.py`.
- Reuse the `ScalarFormatter`’s offset information when building legend labels/titles instead of only using the raw tick label formatter.
- Preserve existing behavior for cases where no offset is active or when non-numeric scales are used.
- Add regression tests covering large numeric ranges and rcParam combinations.
- Verify both `objects` API and `scatterplot`/high-level legend generation remain consistent.

---

## Diff sketch

### `seaborn/_core/scales.py`
Key edits:
- In the numeric scale/legend formatter code around the existing `ScalarFormatter` usage, extract:
  - formatted tick labels
  - formatter offset / order-of-magnitude metadata
- Incorporate the offset into the legend title or label construction.
- Ensure the logic uses the formatter’s actual state rather than inferring from visible labels alone.
- Keep fallback behavior unchanged when offset is zero or unavailable.

Pseudo-edit:
```diff
- labels = [formatter.format_data_short(v) for v in values]
+ labels = [formatter.format_data_short(v) for v in values]
+ offset = formatter.get_offset()
+ if offset:
+     # include offset / scientific multiplier in legend context
+     legend_title = f"{base_label} {offset}"  # or equivalent structured rendering
```

More likely:
- build legend text from `formatter.get_offset()` / `formatter.orderOfMagnitude`
- avoid showing plain “1, 2, 3” when the actual scale is `1e6`

### `seaborn/_core/tests/test_scales.py` or nearby scale/legend tests
Key edits:
- Add regression tests for:
  - large `pointsize` values
  - `useoffset=True/False`
  - threshold-sensitive cases
- Assert legend text includes the offset/scientific scale context.

Pseudo-test cases:
```python
def test_numeric_size_legend_includes_offset():
    ...
    legend_texts = extract_legend_texts(ax)
    assert "1e6" in legend_texts or "×10^6" in legend_texts
```

### Possibly `seaborn/tests/test_relational.py`
If the bug is reproduced via `scatterplot`, add a regression there too:
- Create scatterplot with large size values
- Assert legend formatting is correct and stable under rcParams

---

## Risks

- **Formatting consistency across matplotlib versions**: `ScalarFormatter.get_offset()` / related behavior can vary slightly, so tests should assert the semantic presence of the scale factor rather than exact punctuation.
- **Legend readability**: incorporating offset text may make legends longer; need to ensure titles/labels don’t become duplicated or awkward.
- **Backwards compatibility**: existing plots that rely on the current compact style could change visually.
- **Multiple scale types**: the fix should only affect numeric scales using `ScalarFormatter`, not categorical or datetime formatting paths.
- **rcParam sensitivity**: hidden interactions with `axes.formatter.useoffset` and `axes.formatter.offset_threshold` could create flaky tests if ranges are borderline.

## Plan: RefactorHappy

1. **Plan**
- Inspect the legend-tick formatting path in `seaborn/_core/scales.py`, especially where `ScalarFormatter` is used to build labels for variable-specific legends.
- Preserve the formatter’s offset/scaling information when generating legend text, rather than only using `format_data_short` / raw tick labels.
- Make the label construction robust for both `ScalarFormatter` cases with and without an offset, so existing legends remain unchanged when no offset is needed.
- Add or adjust a regression test covering a large-range numeric semantic (e.g. `pointsize` or `size`) that currently produces incorrect legend values.
- If needed, factor the formatter-to-label logic into a small helper to keep the change local and reusable.

2. **Diff sketch**

```diff
diff --git a/seaborn/_core/scales.py b/seaborn/_core/scales.py
index <old>..<new> 100644
--- a/seaborn/_core/scales.py
+++ b/seaborn/_core/scales.py
@@
 class Continuous:
     ...
     def _legend_artist(self, ...):
         ...
-        formatter = mpl.ticker.ScalarFormatter()
-        formatter.set_locs(levels)
-        labels = [formatter.format_data_short(l) for l in levels]
+        formatter = mpl.ticker.ScalarFormatter()
+        formatter.set_locs(levels)
+        offset = formatter.get_offset()
+        labels = [formatter.format_data_short(l) for l in levels]
+        # If ScalarFormatter has an offset/scaling, include it in the legend
+        # title or labels so values are interpreted correctly.
+        if offset:
+            title = f"{title} {offset}" if title else offset
+        ...
         return legend_data, labels, title
```

```diff
diff --git a/tests/test_scales.py b/tests/test_scales.py
index <old>..<new> 100644
--- a/tests/test_scales.py
+++ b/tests/test_scales.py
@@
 def test_continuous_legend_includes_scalarformatter_offset():
     penguins = load_dataset("penguins")
     penguins["body_mass_mg"] = penguins["body_mass_g"] * 1000
     p = (
         so.Plot(
             penguins, x="bill_length_mm", y="bill_depth_mm",
             pointsize="body_mass_mg",
         )
         .add(so.Dot())
     )
     # Assert legend title/labels include offset/scaling information
     # and/or that displayed values match expected magnitudes.
     ...
```

3. **Risks**
- `ScalarFormatter.get_offset()` can return an empty string or a math-text formatted string; inserting it directly into legend text may require careful formatting to avoid awkward labels.
- The change could affect multiple legend-producing paths if they share the same formatter logic, so we should verify size/color/marker legends still render identically when no offset is present.
- Depending on how seaborn combines legend title and entries, the offset may belong in the title, the labels, or a separate annotation; choosing the wrong placement could be visually confusing even if numerically correct.
- Matplotlib version differences around `ScalarFormatter` internals could make this brittle unless the code uses only public APIs and a regression test anchors the behavior.

## Judge Verdict

## Ranked list

1. **Defensive**  
   **Rationale:** Best balance of correctness and robustness: it explicitly calls out the need to inspect the numeric legend path, handle offset/no-offset/non-`ScalarFormatter` cases, and add tests for `useoffset`/threshold behavior, which matches the issue’s rcParam sensitivity.

2. **RefactorHappy**  
   **Rationale:** Strong on keeping the fix localized and reusable, with a concrete sketch that preserves formatter state via `get_offset()`, but it is a bit too assumption-heavy about where the legend text should be altered.

3. **Minimalist**  
   **Rationale:** Good instinct to keep the change local and add a regression test, but the diff sketch is overly simplistic and risks misunderstanding the actual legend construction—especially the fact that `get_offset()` alone may not be sufficient unless formatter state is initialized correctly.

4. **TestFirst**  
   **Rationale:** Excellent test coverage ideas, but it is mostly a test matrix and does not give a sufficiently concrete implementation path; it also spreads attention across more scenarios than are necessary for the reported bug.

## Winner

**Defensive**

## Brief rationale for the winner

The issue description explicitly hints at rcParam dependence:

> “I believe the issue stems from not using the offset value of the `ScalarFormatter` used to generate the tick labels… this issue also depends on the following rcParam settings…”

The **Defensive** plan is the only one that directly addresses those edge cases up front:

> “Add guardrails for edge cases: no offset present, non-ScalarFormatter formatters, invalid/empty formatter state.”

and

> “Add or adjust tests covering large-valued numeric legends with `useoffset=True` and/or thresholds that trigger offsets.”

That makes it the safest plan for a formatter-driven bug where display behavior can vary by matplotlib config.

## Synthesis recommendation

Take **Defensive’s** guardrails and test scope, combine with **RefactorHappy’s** localized implementation style, and use **TestFirst’s** explicit rcParam cases as the regression matrix. In other words:

- **Implementation shape:** local helper in `seaborn/_core/scales.py`
- **Behavior:** preserve/consult `ScalarFormatter` offset info
- **Tests:** include `useoffset=True/False` and threshold-triggered cases

## Open questions for the human engineer

1. **Where exactly should the offset appear?**  
   Should it be appended to the legend title, embedded in the labels, or shown as a separate annotation? The plans assume title augmentation, but that may not match seaborn’s existing legend style.

2. **Which code path is authoritative?**  
   The issue mentions both `seaborn.objects` and `scatterplot`; do they truly share the same formatter helper, or do we need two test locations and possibly two call sites?

3. **Should the fix use `ScalarFormatter.get_offset()` directly, or reconstruct the scale from formatter state?**  
   `get_offset()` is convenient, but it may depend on `set_locs()` and formatter internals; we need to confirm that’s stable for the relevant legend-generation path.

4. **What is the expected visual form of the offset text?**  
   Is seaborn expected to preserve matplotlib’s mathtext/exponent style exactly, or normalize it into a simpler string?

5. **Do we need to honor all `axes.formatter.*` rcParams, or only the specific ones that trigger this bug?**  
   The issue mentions `useoffset` and `offset_threshold`, but there may be additional formatter settings that affect the output.

6. **What is the smallest regression test that reproduces this reliably?**  
   We should confirm whether the penguins `body_mass_mg` example is stable enough across matplotlib versions, or whether a smaller synthetic dataset would be more deterministic.
