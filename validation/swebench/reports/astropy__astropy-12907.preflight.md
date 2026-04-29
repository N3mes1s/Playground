# Pre-flight Rehearsal — astropy/astropy#0

> Issue: https://github.com/astropy/astropy/issues/astropy__astropy-12907 · title: astropy__astropy-12907 · model: gpt-5.4-mini

_Generated 2026-04-29T20:41:50Z_

## Issue Description

# astropy__astropy-12907

**Repository**: `astropy/astropy` at `d16bfe05`

## Problem statement

Modeling's `separability_matrix` does not compute separability correctly for nested CompoundModels
Consider the following model:

```python
from astropy.modeling import models as m
from astropy.modeling.separable import separability_matrix

cm = m.Linear1D(10) & m.Linear1D(5)
```

It's separability matrix as you might expect is a diagonal:

```python
>>> separability_matrix(cm)
array([[ True, False],
       [False,  True]])
```

If I make the model more complex:
```python
>>> separability_matrix(m.Pix2Sky_TAN() & m.Linear1D(10) & m.Linear1D(5))
array([[ True,  True, False, False],
       [ True,  True, False, False],
       [False, False,  True, False],
       [False, False, False,  True]])
```

The output matrix is again, as expected, the outputs and inputs to the linear models are separable and independent of each other.

If however, I nest these compound models:
```python
>>> separability_matrix(m.Pix2Sky_TAN() & cm)
array([[ True,  True, False, False],
       [ True,  True, False, False],
       [False, False,  True,  True],
       [False, False,  True,  True]])
```
Suddenly the inputs and outputs are no longer separable?

This feels like a bug to me, but I might be missing something?


## What we're asking

Produce a plan and a diff sketch that would resolve this issue. Identify the file(s) you'd touch and the key edits.

## Plan: Minimalist

Plan:
- Inspect `astropy/modeling/separable.py` to see how `CompoundModel` cases are reduced and where nested `&` compositions lose block-diagonal structure.
- Fix the `&`/`CompoundModel` handling so it uses the child models’ actual separability matrices recursively, rather than flattening in a way that treats nested compound outputs as coupled.
- Keep the change minimal and localized to separability logic; do not alter model composition behavior.
- Add/adjust a targeted test covering `Pix2Sky_TAN() & (Linear1D & Linear1D)` and the expected block-diagonal matrix.
- Run/consider existing separability tests to ensure no regressions for `|`, `&`, and nested compound models.

Diff sketch:
- `astropy/modeling/separable.py`
  - In the `CompoundModel` separability computation for `&`, ensure each operand is evaluated via `separability_matrix`/recursive helper, preserving full matrix shape for nested compound models.
  - If current logic uses a simple `n_inputs`/`n_outputs` shortcut, replace it with block-diagonal assembly from the left/right separability matrices.
  - Ensure the result for nested compound operands is concatenated as blocks, not merged by treating all outputs of the nested right-hand compound as one side.
- `astropy/modeling/tests/test_separable.py`
  - Add a regression test asserting:
    - `separability_matrix(m.Linear1D(10) & m.Linear1D(5))` is diagonal.
    - `separability_matrix(m.Pix2Sky_TAN() & (m.Linear1D(10) & m.Linear1D(5)))` yields the expected 4x4 matrix with the lower-right 2x2 diagonal block.
  - Optionally add a test for deeper nesting to lock in recursive behavior.

Risks:
- Separability logic is subtle; changing block assembly for `&` could affect other compound-model shapes if input/output dimensions are inferred incorrectly.
- Some existing tests may rely on the current, buggy flattening behavior for particular nested compositions.
- If the bug actually stems from a utility that computes matrices from shapes rather than from recursion, fixing only the top-level `&` path may miss other nested operators.
Plan:
- Inspect `astropy/modeling/separable.py` and find the `CompoundModel` handling for `&`.
- Make the `&` path recurse on both operands so nested compound models preserve their own separability matrices.
- Keep the change localized to separability computation only.
- Add a regression test for `Pix2Sky_TAN() & (Linear1D & Linear1D)`.

Diff sketch:
- `astropy/modeling/separable.py`
  - Update the logic for the `&` operator in the compound-model separability helper.
  - Ensure the left and right operands are each evaluated recursively into separability matrices, then combined as a block diagonal.
  - Avoid any flattening shortcut that treats a nested compound operand as if its outputs were all mutually dependent.
- `astropy/modeling/tests/test_separable.py`
  - Add a regression test for nested `&` composition:
    - `cm = Linear1D(10) & Linear1D(5)`
    - `separability_matrix(Pix2Sky_TAN() & cm)` should be:
      ```python
      [[True,  True,  False, False],
       [True,  True,  False, False],
       [False, False, True,  False],
       [False, False, False, True]]
      ```
  - Optionally assert the non-nested cases still work unchanged.

Risks:
- The separability code is shared across several compound patterns; a small change to `&` could impact other nested model shapes.
- If there is an underlying shape/inference bug elsewhere, this fix may only address the reported case.
- Test expectations must match the model’s actual input/output ordering, so care is needed to avoid accidental off-by-one block placement.

## Plan: Defensive

### Plan
- Inspect `astropy/modeling/separable.py` to find how `CompoundModel` trees are converted into the separability matrix.
- Reproduce the nested-`CompoundModel` case and trace where a right-hand `&` branch is being treated as a single block instead of recursively flattened.
- Update the separability logic for `CompoundModel` so `&` composition is handled recursively for both operands, preserving block-diagonal structure even when operands are themselves compound models.
- Add or adjust tests in `astropy/modeling/tests/test_separable.py` for nested `&` cases, including the specific regression from the issue.
- Add input validation / defensive guards for malformed model trees or unexpected operand shapes, and ensure failures are explicit rather than silently producing incorrect matrices.

### Diff sketch

#### `astropy/modeling/separable.py`
Key edits:
- In the function(s) that compute separability for `CompoundModel` (likely `_separable` and/or helpers for `&` and `|`), ensure recursive evaluation of **both** left and right operands when building a separability matrix.
- For `&`:
  - If either child is itself a `CompoundModel`, recurse into it first to obtain its full separability matrix.
  - Combine the two child matrices using block-diagonal assembly based on their actual output/input dimensionality, not on a shallow leaf-only assumption.
- Add guardrails:
  - Validate expected matrix shapes before concatenation/stacking.
  - Raise a clear error if a child model reports inconsistent `n_inputs`/`n_outputs` versus matrix dimensions.
- If there is a fast-path for leaf models, keep it, but ensure nested compound models do not bypass the recursive path.

Sketch:
```diff
diff --git a/astropy/modeling/separable.py b/astropy/modeling/separable.py
@@
 def _separable(model):
-    # existing logic for CompoundModel and leaf models
+    # existing logic for CompoundModel and leaf models
+    # ensure recursive evaluation for nested CompoundModel operands
@@
 def _separable_compound(model):
     if model.op == '&':
-        # current shallow logic
+        left = _separable(model.left)
+        right = _separable(model.right)
+        _validate_separable_shape(left, model.left)
+        _validate_separable_shape(right, model.right)
+        return _cstack_block_diag(left, right)
@@
+def _validate_separable_shape(matrix, model):
+    # guard against inconsistent outputs/inputs
+    ...
```

#### `astropy/modeling/tests/test_separable.py`
Key edits:
- Add regression test for the exact nested case:
  - `separability_matrix(m.Pix2Sky_TAN() & (m.Linear1D(10) & m.Linear1D(5)))`
  - Assert the result is the expected block-diagonal matrix with the last two outputs independent.
- Add a smaller nested `&` test with only linear models to isolate the bug from the coordinate transform complexity.
- Optionally add a test for `separability_matrix` on deeper nesting to ensure recursion remains correct.

Sketch:
```diff
diff --git a/astropy/modeling/tests/test_separable.py b/astropy/modeling/tests/test_separable.py
@@
 def test_separability_matrix_compound_and():
     cm = m.Linear1D(10) & m.Linear1D(5)
     assert_array_equal(separability_matrix(cm), expected)
+
+def test_separability_matrix_nested_compound_and():
+    cm = m.Linear1D(10) & m.Linear1D(5)
+    model = m.Pix2Sky_TAN() & cm
+    expected = np.array([
+        [True, True, False, False],
+        [True, True, False, False],
+        [False, False, True, False],
+        [False, False, False, True],
+    ])
+    assert_array_equal(separability_matrix(model), expected)
```

### Risks
- `separable.py` may have special-case logic for `&`, `|`, and `fix_inputs`; changing recursion could affect existing compound-model behavior beyond the reported case.
- Some models may have ambiguous or unconventional `n_inputs`/`n_outputs`; stricter validation could surface new errors in edge cases that previously passed silently.
- If there are helper functions relying on shallow structures, a recursive fix might require adjusting multiple code paths to keep matrix dimensions consistent.
- Performance may change slightly for deeply nested compound models due to additional recursion, though correctness is the main concern here.

## Plan: TestFirst

## Test plan

I’d start by enumerating the cases that prove the bug and guard against regressions:

1. **Baseline separable compound**
   - `Linear1D(10) & Linear1D(5)`
   - Expect a 2x2 identity-like separability matrix.

2. **Non-nested mixed compound**
   - `Pix2Sky_TAN() & Linear1D(10) & Linear1D(5)`
   - Expect the first 2 outputs to depend on the first 2 inputs, and each linear output to depend only on its own input.

3. **Nested compound reproducer**
   - `Pix2Sky_TAN() & (Linear1D(10) & Linear1D(5))`
   - Expect the same matrix as case 2.
   - This is the bug: nested `CompoundModel` currently loses separability information.

4. **Deeper nesting**
   - e.g. `Pix2Sky_TAN() & ((Linear1D(10) & Linear1D(5)) & Linear1D(7))`
   - Ensures recursive handling works more than one level deep.

5. **Unary + nested compound edge case**
   - A model with one input/output combined with nested compound submodels, to ensure 1D cases still propagate correctly.

6. **Non-separable branch inside nested structure**
   - Compose a model like `Pix2Sky_TAN() & (Linear1D(10) | Linear1D(5))` only if valid in the modeling framework, to ensure the fix doesn’t incorrectly mark dependent outputs as independent.

7. **Shape/consistency checks**
   - Assert matrix shape matches `n_outputs x n_inputs` for all above cases.

## Implementation plan

- Fix the separability computation to **recursively inspect nested `CompoundModel`s** rather than treating them as opaque operands.
- Ensure the logic used for `&` composition merges the left/right separability matrices using the correct column offsets even when either side is itself compound.
- Add regression tests for:
  - the exact reproducer from the issue,
  - an equivalent flat/non-nested form,
  - at least one deeper nesting case.

## Diff sketch

### `astropy/modeling/separable.py`
Key edits:
- In the separability helper(s) for compound models, detect when an operand is itself a `CompoundModel` and recursively compute its separability matrix before combining.
- Preserve the existing behavior for leaf models and for models whose separability is known from `separable` / `is_separable`.
- Make the `&` combination logic use the full output/input dimensions of the recursively computed submatrices, so nested compounds are aligned properly.

Pseudo-edit sketch:

```diff
 def separability_matrix(model):
-    return _separability_matrix(model)
+    return _separability_matrix(model)

 def _separability_matrix(model):
     if not isinstance(model, CompoundModel):
         return _leaf_separability(model)
+
+    # Recursively resolve nested compound operands
+    left = _separability_matrix(model.left)
+    right = _separability_matrix(model.right)
+
+    if model.op is operator.and_:
+        return _cstack(left, right)
+    elif model.op is operator.or_:
+        return _cdot(left, right)
+    elif model.op is operator.rshift or model.op is operator.lshift:
+        ...
```

Potentially, if the current code already has combination helpers like `_cstack` / `_cdot` / `_coord_matrix`, the main fix is to make them accept already-expanded matrices for compound children.

### `astropy/modeling/tests/test_separable.py`
Add regression tests:

```diff
+def test_separability_matrix_nested_compound_and():
+    cm = models.Linear1D(10) & models.Linear1D(5)
+    model = models.Pix2Sky_TAN() & cm
+    expected = np.array([...], dtype=bool)
+    assert_array_equal(separability_matrix(model), expected)
+
+def test_separability_matrix_flat_vs_nested_equivalent():
+    flat = models.Pix2Sky_TAN() & models.Linear1D(10) & models.Linear1D(5)
+    nested = models.Pix2Sky_TAN() & (models.Linear1D(10) & models.Linear1D(5))
+    assert_array_equal(separability_matrix(flat), separability_matrix(nested))
+
+def test_separability_matrix_deep_nested():
+    model = models.Pix2Sky_TAN() & ((models.Linear1D(10) & models.Linear1D(5)) & models.Linear1D(7))
+    # validate shape and expected block structure
```

## Risks

- **Behavioral regressions in other composition operators**: if the fix changes combination logic too broadly, it may affect `|`, `&`, or model chaining semantics outside this bug.
- **Assumptions about matrix orientation**: separability matrices have shape and block semantics that must remain consistent; a mistake in offsets can silently produce wrong matrices.
- **Indirect effects on custom models**: any custom model relying on previous (incorrect) behavior may see changed results, though this is desirable for correctness.
- **Incomplete recursion handling**: if nested compounds can appear on both sides of multiple operators, the recursion must be careful not to double-count inputs/outputs or mishandle model trees.

If you want, I can turn this into a more concrete patch outline against the current `separable.py` structure in Astropy.

## Plan: RefactorHappy

### 1) Plan

- Inspect `astropy/modeling/separable.py`, especially the logic for handling `CompoundModel` trees and the `&` operator.
- Reproduce the nested-compound case mentally: the current code likely treats nested `CompoundModel`s as opaque leaves instead of flattening or recursively combining their separability matrices.
- Refactor the separability combination helper so `&` composition always uses the child models’ actual separability matrices, regardless of nesting depth.
- Add/adjust a unit test covering `separability_matrix(m.Pix2Sky_TAN() & (m.Linear1D(10) & m.Linear1D(5)))` and the equivalent nested form to ensure identical results.
- Keep the fix local to separability computation; avoid changing model semantics elsewhere.
- If needed, add a small helper to normalize/flatten nested `CompoundModel` handling for separability only.

---

### 2) Diff sketch

#### `astropy/modeling/separable.py`
```diff
@@
 def separability_matrix(transform):
-    # existing logic...
+    # Ensure compound models are evaluated recursively so nested
+    # CompoundModels don't get treated as atomic blocks.
     return _separability_matrix(transform)

@@
 def _separability_matrix(transform):
     if isinstance(transform, CompoundModel):
-        return _cmp_separable(transform)
+        return _cmp_separable(transform)
     ...
 
@@
 def _coord_matrix(model, pos):
-    # current leaf handling may assume non-compound models only
+    # If a nested CompoundModel appears here, recurse instead of
+    # building an incorrect all-True block.
+    if isinstance(model, CompoundModel):
+        return _separability_matrix(model)
     ...
 
@@
 def _cstack(left, right):
-    # combine matrices for '&'
+    # combine matrices for '&'
+    # Ensure left/right can themselves be compound and already have
+    # correct block structure.
     ...
```

Possible refactor: introduce a helper like:
```diff
+def _model_separability(model):
+    if isinstance(model, CompoundModel):
+        return _separability_matrix(model)
+    return _coord_matrix(model, ...)
```
and use it in the `&` branch so nested compounds are handled recursively rather than flattened incorrectly.

#### `astropy/modeling/tests/test_separable.py`
```diff
@@
 def test_separability_matrix_simple_and():
     cm = models.Linear1D(10) & models.Linear1D(5)
     expected = np.array([[True, False],
                          [False, True]])
     assert_allclose(separability_matrix(cm), expected)
 
+def test_separability_matrix_nested_and():
+    cm = models.Linear1D(10) & models.Linear1D(5)
+    nested = models.Pix2Sky_TAN() & cm
+    direct = models.Pix2Sky_TAN() & models.Linear1D(10) & models.Linear1D(5)
+
+    expected = np.array([
+        [True,  True,  False, False],
+        [True,  True,  False, False],
+        [False, False, True,  False],
+        [False, False, False, True ],
+    ])
+
+    assert_allclose(separability_matrix(nested), expected)
+    assert_allclose(separability_matrix(direct), expected)
```

If the implementation uses a recursive helper already, the change may be as small as ensuring `CompoundModel` children are always passed back through the separability dispatcher instead of being “collapsed” too early.

---

### 3) Risks

- **Regression risk in other compound operators**: changing recursive handling could affect `|` (composition) or `&` if the helper is shared too broadly.
- **Shape/arity mismatches**: recursive matrices must still preserve the correct input/output dimensions for nested models.
- **Existing assumptions about leaf models**: some code may assume `_coord_matrix` only sees atomic models; adding recursion needs care to avoid double-processing.
- **Test expectation subtlety**: the correct separability pattern depends on how `Pix2Sky_TAN` is represented; the test should match current model arity/output shape exactly.

If you want, I can also draft a more concrete patch outline against the current `separable.py` helper structure (e.g., which branch in `_separable` / `_cstack` / `_cdot` is most likely the culprit).

## Judge Verdict

## Ranked list

1. **Minimalist**  
   **Rationale:** Best fit for the bug: it stays tightly scoped to `astropy/modeling/separable.py`, correctly targets recursive handling of nested `CompoundModel`s, and includes a concrete regression test for the exact failure mode.

2. **TestFirst**  
   **Rationale:** Strongest on verification and regression coverage, but it is more expansive than needed and mixes in some speculative cases; still, its “flat vs nested equivalent” test is especially valuable.

3. **Defensive**  
   **Rationale:** Sensible but overreaches by proposing guardrails/validation that aren’t clearly needed for this bug and could broaden the patch surface unnecessarily.

4. **RefactorHappy**  
   **Rationale:** Directionally correct, but the sketch is the least concrete and drifts toward vague refactoring rather than a targeted fix.

## Winner

**Minimalist**

## Brief rationale

The issue is specifically that nested `&` compositions are being handled incorrectly, and Minimalist most directly addresses that with the least risk. It focuses on the likely fault line in `separable.py` and proposes the exact regression case from the issue.

Concrete supporting passages:
- Minimalist says: **“Fix the `&`/`CompoundModel` handling so it uses the child models’ actual separability matrices recursively, rather than flattening in a way that treats nested compound outputs as coupled.”**
- It also pins the test to the reported case: **“`separability_matrix(m.Pix2Sky_TAN() & (m.Linear1D(10) & m.Linear1D(5)))` yields the expected 4x4 matrix with the lower-right 2x2 diagonal block.”**

That is more actionable than RefactorHappy’s vague **“If needed, add a small helper”** and less speculative than Defensive’s added validation.

## Recommended synthesis

Use **Minimalist as the implementation plan** and borrow the best tests from **TestFirst**:
- keep the fix localized to `astropy/modeling/separable.py`,
- add the exact nested regression,
- also add the **flat vs nested equivalence** assertion from TestFirst.

This gives you a minimal patch with strong regression coverage.

## Open questions for the human engineer

1. **What is the current internal structure of `separable.py`?**  
   We should confirm whether the bug lives in `_separable`, `_cstack`, `_cdot`, or another helper before editing.

2. **Should the fix normalize nested `&` trees or just recurse through them?**  
   Recursion is likely enough, but if the code already assumes a flattened tree in some helper, we may need a small normalization step.

3. **Are there existing tests for nested compound separability that need updating?**  
   We should check whether any current expectations are incorrect or incomplete.

4. **Does `Pix2Sky_TAN()` have any special separability behavior already encoded?**  
   The exact matrix shape and block semantics should be verified against current Astropy conventions.

5. **Should we add a symmetry test for nested `|` or only for `&`?**  
   The issue is about `&`, but we should confirm whether the same machinery affects other operators.
