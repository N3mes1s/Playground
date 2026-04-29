# Pre-flight Rehearsal — pallets/flask#0

> Issue: https://github.com/pallets/flask/issues/pallets__flask-5014 · title: pallets__flask-5014 · model: gpt-5.4-mini

_Generated 2026-04-29T20:42:56Z_

## Issue Description

# pallets__flask-5014

**Repository**: `pallets/flask` at `7ee9ceb7`

## Problem statement

Require a non-empty name for Blueprints
Things do not work correctly if a Blueprint is given an empty name (e.g. #4944).
It would be helpful if a `ValueError` was raised when trying to do that.


## What we're asking

Produce a plan and a diff sketch that would resolve this issue. Identify the file(s) you'd touch and the key edits.

## Plan: Minimalist

### Plan
- Add validation in `flask/sansio/blueprints.py` where `Blueprint` is initialized.
- Reject empty blueprint names (`""`) by raising `ValueError`.
- Keep the change narrowly scoped so existing behavior for valid names is unchanged.
- Add or adjust tests in the blueprint test module to assert the new error.
- Ensure the error message is clear and consistent with Flask-style validation.

### Diff sketch

#### `src/flask/sansio/blueprints.py`
```diff
 class Blueprint:
     def __init__(self, name, import_name, ...):
+        if not name:
+            raise ValueError("Blueprint name must not be empty.")
         self.name = name
         self.import_name = import_name
         ...
```

#### `tests/test_blueprints.py` (or existing blueprint test file)
```diff
 def test_blueprint_requires_non_empty_name():
-    # existing behavior / missing test
+    with pytest.raises(ValueError, match="must not be empty"):
+        Blueprint("", __name__)
```

### Risks
- Some code may currently rely on empty blueprint names, though that behavior is already broken per the issue.
- If there are multiple blueprint constructors or wrappers, the validation must be placed where all creation paths pass through; otherwise the check could be bypassed.
- The exact test file name may differ in the repo, so the test should be added to the existing blueprint test module rather than creating a new one unnecessarily.

## Plan: Defensive

## Plan

- Locate `Blueprint` construction and add an early validation for `name`.
- Reject empty blueprint names with a clear `ValueError` before any registration or derived-name logic runs.
- Add or update tests to cover:
  - `Blueprint("")` raises `ValueError`
  - valid non-empty names still work
- Check for any other code paths that create blueprints indirectly and ensure the same invariant is enforced centrally in `flask/sansio/blueprints.py`.
- Keep the change minimal to avoid affecting import/registration behavior for existing valid blueprints.

## Diff sketch

### `src/flask/sansio/blueprints.py`
Key edit in `Blueprint.__init__`:

```diff
 class Blueprint(Scaffold):
     def __init__(self, name: str, import_name: str, ...):
-        self.name = name
+        if not isinstance(name, str):
+            raise TypeError("name must be a string")
+        if name == "":
+            raise ValueError("Blueprint name must not be empty.")
+
+        self.name = name
         ...
```

Notes:
- If the codebase already relies on type checking elsewhere, keep the new guard aligned with existing style.
- Prefer validating before any use of `name` in endpoint prefixes, dotted name splitting, or registration bookkeeping.

### `tests/test_blueprints.py` (or existing blueprint test module)
Add coverage:

```diff
+def test_blueprint_name_must_not_be_empty():
+    with pytest.raises(ValueError, match="must not be empty"):
+        Blueprint("", __name__)
+
+def test_blueprint_name_non_empty_ok(app):
+    bp = Blueprint("bp", __name__)
+    assert bp.name == "bp"
```

If there is already a blueprint validation test file, extend it there rather than creating a new one.

## Risks foreseen

- **Backward compatibility:** Any code accidentally constructing `Blueprint("")` will now fail earlier with a `ValueError`; this is intended but may surface latent bugs.
- **Validation consistency:** If there are alternate creation paths or subclasses that bypass `__init__`, they may still allow invalid names unless the check is centralized in the base constructor.
- **Test fragility:** Existing tests that implicitly rely on empty-string behavior (unlikely, but possible) may need adjustment.
- **Message matching:** Keep the error message stable and specific so tests don’t become brittle.

## Plan: TestFirst

### Test cases to prove the change works

1. **Reject empty blueprint name**
   - Creating `Blueprint("", __name__)` should raise `ValueError`.
   - This is the primary regression test for the bug.

2. **Reject whitespace-only?**
   - Clarify desired behavior:
     - If only `""` is disallowed, `" "` may still be accepted.
     - If the intent is “non-empty” literally, then whitespace-only names should still pass unless explicitly normalized.
   - I would keep the change strict to `""` only unless the project wants stronger validation.

3. **Accept normal blueprint names**
   - `Blueprint("admin", __name__)` should still work.
   - Ensures no regression in standard usage.

4. **Accept non-string-like names?**
   - Current Flask likely expects `name` to be a string; if not validated elsewhere, test that existing accepted types continue to behave as before.
   - This is mostly a compatibility check, not necessarily a new test.

5. **Registration behavior unchanged for valid names**
   - A valid blueprint can still be registered and routes still resolve.
   - This guards against accidentally over-tightening validation.

---

### Plan

1. Add validation in `Blueprint.__init__` to reject an empty `name`.
2. Raise `ValueError` with a clear message as soon as the blueprint is constructed.
3. Add tests covering empty-name rejection and normal-name acceptance.
4. Keep the validation minimal to avoid changing any other blueprint semantics.
5. Ensure the error is raised before any blueprint internals depend on the name.

---

### Diff sketch

#### `src/flask/blueprints.py`
```diff
 class Blueprint(Scaffold):
     def __init__(self, name, import_name, ...):
+        if not name:
+            raise ValueError("Blueprint name must not be empty.")
         super().__init__(...)
         self.name = name
```

#### `tests/test_blueprints.py`
```diff
+import pytest
+
+def test_blueprint_empty_name_raises():
+    with pytest.raises(ValueError, match="Blueprint name must not be empty"):
+        Blueprint("", __name__)
+
+def test_blueprint_valid_name_still_works():
+    bp = Blueprint("admin", __name__)
+    assert bp.name == "admin"
```

---

### Risks

- **Backward compatibility:** Any existing code that accidentally creates `Blueprint("")` will now fail earlier with `ValueError`. This is intended, but it is a behavior change.
- **Scope of validation:** If there are code paths that rely on deferred validation or on empty names being transformed later, this could expose hidden assumptions.
- **Message stability:** If tests assert on the exact error message, wording should be chosen carefully and kept consistent with Flask’s style.

## Plan: RefactorHappy

### Plan
- Add validation in `flask/sansio/blueprints.py` so `Blueprint` rejects empty names as early as possible.
- Raise a `ValueError` with a clear message when `name == ""` (and keep existing non-string behavior unchanged unless it naturally fails elsewhere).
- Add/adjust a test in the blueprint test module to assert the exception and message.
- Keep the change localized to blueprint construction; no routing behavior changes needed.
- Optionally add a small refactor to reuse a tiny helper/guard for name validation if there’s already nearby constructor validation.

### Diff sketch

#### `src/flask/sansio/blueprints.py`
```diff
 class Blueprint(Scaffold):
     def __init__(self, name, import_name, ...):
+        if not name:
+            raise ValueError("Blueprint name must not be empty.")
         self.name = name
         self.import_name = import_name
         ...
```

If there is already constructor validation nearby, this can be folded into that block, e.g. alongside checks for `url_prefix`, `subdomain`, etc.

#### `tests/test_blueprints.py` (or nearest existing blueprint test file)
```diff
+def test_blueprint_rejects_empty_name():
+    with pytest.raises(ValueError, match="must not be empty"):
+        Blueprint("", __name__)
```

If there is an existing constructor-validation test group, add it there instead of creating a new standalone test.

### Risks
- `if not name` also rejects other falsey values like `None` and `0`; this is usually desirable for blueprint names, but if the project wants to distinguish empty string from other invalid values, the check should be narrowed to `name == ""`.
- Some downstream code may currently rely on creating an invalid blueprint and failing later; this change moves the failure earlier, which is the intended fix but could surface in tests.
- Test file location/name may differ in this repo layout, so the patch should follow the existing blueprint test structure.

## Judge Verdict

## Ranked list

### 1) **Minimalist** — **Winner**
**Rationale:** It targets the right constructor path and stays narrowly scoped; the key edit is concrete and appropriate: **“Add validation in `flask/sansio/blueprints.py` where `Blueprint` is initialized”** with **“Reject empty blueprint names (`""`) by raising `ValueError`.”** The diff sketch is also aligned with the issue and avoids unnecessary extra validation.

### 2) **Defensive**
**Rationale:** Good on enforcing the invariant centrally and testing the behavior, but it overreaches by proposing type validation that is not requested and may change behavior unnecessarily; e.g. **“if not isinstance(name, str): raise TypeError”** is not supported by the issue statement.

### 3) **RefactorHappy**
**Rationale:** Similar to Minimalist, but it introduces optional refactoring that is not needed for this fix and could distract from the minimal patch; its own note admits the check may be better narrowed to `name == ""`.

### 4) **TestFirst**
**Rationale:** It has useful test ideas, but it is less precise on implementation and includes speculative cases like **“Reject whitespace-only?”** and **“Accept non-string-like names?”**, which are open-ended and not necessary for the requested fix.

## Winner

**Minimalist**

## Brief rationale

It best matches the issue: validate blueprint name at construction, raise `ValueError` for the empty string, and add a focused regression test. It is the cleanest fit for the user’s request without extra behavior changes.

## Recommended synthesis

Use **Minimalist’s implementation sketch** plus **TestFirst’s clarity on the regression test**, but keep the test list minimal:
- one test that `Blueprint("", __name__)` raises `ValueError`
- optionally one sanity test that a normal name still works

Avoid Defensive’s extra `TypeError` guard unless the existing codebase already enforces that pattern.

## Open questions for the human engineer

1. **Exact file path:** Is the constructor in `src/flask/sansio/blueprints.py` or another blueprint module in this repo version?
2. **Validation scope:** Should the guard be strictly `name == ""`, or should all falsey values be rejected via `if not name`?
3. **Error message wording:** Do we want a Flask-style canonical message, and if so, what exact text should tests match?
4. **Test location:** Which blueprint test file is the existing canonical home for constructor validation tests?
5. **Backward compatibility:** Is there any supported use of empty blueprint names in extensions or downstream code that needs consideration before enforcing the new invariant?
