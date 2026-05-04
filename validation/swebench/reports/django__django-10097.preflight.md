# Pre-flight Rehearsal — django/django#0

> Issue: https://github.com/django/django/issues/django__django-10097 · title: django__django-10097 · model: gpt-5.4-mini

_Generated 2026-04-29T20:42:11Z_

## Issue Description

# django__django-10097

**Repository**: `django/django` at `b9cf764b`

## Problem statement

Make URLValidator reject invalid characters in the username and password
Description
	 
		(last modified by Tim Bell)
	 
Since #20003, core.validators.URLValidator accepts URLs with usernames and passwords. RFC 1738 section 3.1 requires "Within the user and password field, any ":", "@", or "/" must be encoded"; however, those characters are currently accepted without being %-encoded. That allows certain invalid URLs to pass validation incorrectly. (The issue originates in Diego Perini's ​gist, from which the implementation in #20003 was derived.)
An example URL that should be invalid is http://foo/bar@example.com; furthermore, many of the test cases in tests/validators/invalid_urls.txt would be rendered valid under the current implementation by appending a query string of the form ?m=foo@example.com to them.
I note Tim Graham's concern about adding complexity to the validation regex. However, I take the opposite position to Danilo Bargen about invalid URL edge cases: it's not fine if invalid URLs (even so-called "edge cases") are accepted when the regex could be fixed simply to reject them correctly. I also note that a URL of the form above was encountered in a production setting, so that this is a genuine use case, not merely an academic exercise.
Pull request: ​https://github.com/django/django/pull/10097
Make URLValidator reject invalid characters in the username and password
Description
	 
		(last modified by Tim Bell)
	 
Since #20003, core.validators.URLValidator accepts URLs with usernames and passwords. RFC 1738 section 3.1 requires "Within the user and password field, any ":", "@", or "/" must be encoded"; however, those characters are currently accepted without being %-encoded. That allows certain invalid URLs to pass validation incorrectly. (The issue originates in Diego Perini's ​gist, from which the implementation in #20003 was derived.)
An example URL that should be invalid is http://foo/bar@example.com; furthermore, many of the test cases in tests/validators/invalid_urls.txt would be rendered valid under the current implementation by appending a query string of the form ?m=foo@example.com to them.
I note Tim Graham's concern about adding complexity to the validation regex. However, I take the opposite position to Danilo Bargen about invalid URL edge cases: it's not fine if invalid URLs (even so-called "edge cases") are accepted when the regex could be fixed simply to reject them correctly. I also note that a URL of the form above was encountered in a production setting, so that this is a genuine use case, not merely an academic exercise.
Pull request: ​https://github.com/django/django/pull/10097


## What we're asking

Produce a plan and a diff sketch that would resolve this issue. Identify the file(s) you'd touch and the key edits.

## Plan: Minimalist

### Plan
- Update `django/core/validators.py` so `URLValidator` explicitly rejects unencoded `:`, `@`, and `/` characters in the userinfo portion of the URL.
- Keep the existing overall regex structure intact; add a small, targeted check rather than rewriting the validator.
- Add/adjust tests in `tests/validators/tests.py` (and/or `tests/validators/invalid_urls.txt` if that suite is used here) to cover invalid user/password cases like `http://foo/bar@example.com`.
- Ensure valid URLs with percent-encoded reserved characters in userinfo still pass.
- Run the existing URL validator tests to confirm no regressions in accepted host/path/query cases.

### Diff sketch

#### `django/core/validators.py`
Key edit: tighten the `URLValidator.regex` so userinfo cannot contain raw `:`, `@`, or `/`.

```diff
 class URLValidator(RegexValidator):
-    regex = re.compile(
-        r'^(?:[a-z0-9.+-]*:(?://)?)?...'
-    )
+    regex = re.compile(
+        r'^(?:[a-z0-9.+-]*:(?://)?)?'
+        r'(?:'
+            r'(?:'
+                r'[^/?#@:\s]+'
+                r'(?:%[0-9A-Fa-f]{2}|[^/?#@:\s])*'
+            r'@'
+        r')?'
+        r'...'
+    )
```

Or, if the current regex already has a userinfo subgroup, modify just that subgroup to exclude raw `:`, `@`, and `/` and allow only percent-encoded forms there.

#### `tests/validators/tests.py`
Add explicit validator cases:

```diff
 class URLValidatorTests(SimpleTestCase):
+    def test_userinfo_invalid_characters(self):
+        validator = URLValidator()
+        invalid_urls = [
+            'http://foo/bar@example.com',
+            'http://foo:bar@example.com',   # raw colon in userinfo
+            'http://foo@bar@example.com',   # raw @ in userinfo
+        ]
+        for url in invalid_urls:
+            with self.assertRaises(ValidationError):
+                validator(url)
+
+    def test_userinfo_percent_encoded(self):
+        validator = URLValidator()
+        valid_urls = [
+            'http://foo%2Fbar@example.com',
+            'http://foo%3Abar@example.com',
+            'http://foo%40bar@example.com',
+        ]
+        for url in valid_urls:
+            validator(url)
```

#### `tests/validators/invalid_urls.txt` (if this suite is used for URL cases)
Add/ensure entries such as:

```diff
+http://foo/bar@example.com
+http://foo:bar@example.com
+http://foo@bar@example.com
```

### Risks
- The regex change could accidentally reject some currently valid URLs if the userinfo pattern is tightened too aggressively.
- URL parsing/validation behavior may differ across Python versions or platforms; the smallest regex tweak is safer than larger refactoring.
- Existing tests may rely on permissive behavior for edge-case URLs, so we should verify only the intended userinfo characters are blocked.

## Plan: Defensive

## Plan

1. **Tighten `URLValidator`’s URL regex** so the userinfo portion before `@` only accepts percent-encoded reserved characters, not raw `:`, `@`, or `/`.
2. **Add regression tests** covering invalid user/password URLs like `http://foo/bar@example.com` and related cases that could previously slip through.
3. **Preserve existing valid behavior** for properly encoded userinfo such as `http://user%3Apass@example.com`.
4. **Run validation against the existing invalid URL corpus** to ensure the change doesn’t accidentally reject unrelated URLs or widen acceptance.
5. **Keep the change localized** to `django/core/validators.py` and `tests/validators/` to minimize risk.

---

## Diff sketch

### `django/core/validators.py`
Key edit: update the URL regex in `URLValidator.regex` to restrict userinfo.

```diff
diff --git a/django/core/validators.py b/django/core/validators.py
index <old>.. <new> 100644
--- a/django/core/validators.py
+++ b/django/core/validators.py
@@ class URLValidator(RegexValidator):
-    # existing regex allows username/password too broadly
+    # Restrict userinfo so raw ":", "@", and "/" are not accepted there.
+    # These must be percent-encoded per RFC 1738 section 3.1.
     regex = _lazy_re_compile(
-        r'^(?:[a-z0-9\.\-\+]*)://...'
+        r'^(?:[a-z0-9\.\-\+]*)://'
+        r'(?:'
+        r'(?:[^\s:@/]+(?::[^\s:@/]*)?)@'   # userinfo without raw reserved chars
+        r')?'
+        r'...'
     )
```

Notes:
- The exact pattern should be adjusted to match the current implementation style.
- The important part is to ensure the user/password segment does **not** allow raw `:`, `@`, `/`.
- If the current regex already has a userinfo subpattern, refine that subpattern rather than restructuring the whole expression.

### `tests/validators/tests.py` or `tests/validators/test_validators.py`
Key edit: add regression tests for invalid userinfo characters and valid encoded equivalents.

```diff
diff --git a/tests/validators/tests.py b/tests/validators/tests.py
index <old>.. <new> 100644
--- a/tests/validators/tests.py
+++ b/tests/validators/tests.py
@@ class URLValidatorTests(SimpleTestCase):
+    def test_rejects_invalid_userinfo_characters(self):
+        invalid_urls = [
+            "http://foo/bar@example.com",
+            "http://foo:bar@example.com/baz",   # depending on current parser semantics
+            "http://foo@bar@example.com",
+        ]
+        for url in invalid_urls:
+            with self.subTest(url=url):
+                with self.assertRaises(ValidationError):
+                    URLValidator()(url)
+
+    def test_accepts_encoded_userinfo_characters(self):
+        valid_urls = [
+            "http://foo%2Fbar@example.com",
+            "http://foo%3Abar@example.com",
+            "http://foo%40bar@example.com",
+        ]
+        for url in valid_urls:
+            with self.subTest(url=url):
+                URLValidator()(url)
```

### `tests/validators/invalid_urls.txt`
Key edit: add/ensure cases like `http://foo/bar@example.com` remain invalid even if query strings are appended.

```diff
diff --git a/tests/validators/invalid_urls.txt b/tests/validators/invalid_urls.txt
index <old>.. <new> 100644
--- a/tests/validators/invalid_urls.txt
+++ b/tests/validators/invalid_urls.txt
@@
 http://foo/bar@example.com
+http://foo/bar@example.com?m=foo@example.com
```

---

## Risks

- **False negatives on legitimate URLs**: if the regex is tightened too aggressively, some valid userinfo forms may start failing. This is the main risk, especially around percent-encoded sequences and optional password syntax.
- **Regex complexity**: modifying a large validation regex can be error-prone and hard to review. A small, targeted change is preferable.
- **Behavior differences across schemes**: if the regex is scheme-agnostic, ensure the userinfo restriction applies consistently to all supported schemes without breaking scheme-specific patterns.
- **Test coverage gaps**: the bug involves subtle parsing behavior; without a few carefully chosen cases, regressions could reappear via other invalid combinations.

If you want, I can also draft the likely exact regex adjustment based on Django’s current `URLValidator` implementation at `b9cf764b`.

## Plan: TestFirst

## 1) Test plan

Add/extend tests to prove URL validation now rejects illegal reserved characters in the userinfo portion, while still allowing valid percent-encoded forms.

### Core invalid cases
1. `http://foo/bar@example.com`
   - Should be rejected because `/` appears in the username/password area before `@`.

2. `http://foo:bar@example.com`
   - Should be rejected because `:` is unescaped in userinfo.

3. `http://foo@bar@example.com`
   - Should be rejected because `@` is unescaped in userinfo.

4. Variants with password too:
   - `http://user:pa:ss@example.com`
   - `http://user:pa@ss@example.com`
   - `http://user/pa@example.com`
   - All should be rejected.

### Valid control cases
5. Percent-encoded equivalents should still pass:
   - `http://foo%2Fbar@example.com`
   - `http://foo:bar%40example.com@example.com` if otherwise structurally valid
   - `http://user%3Aname:pass@example.com`
   - `http://user:pass%2Fword@example.com`

6. Existing valid URLs without userinfo should still pass:
   - `http://example.com`
   - `https://example.com/path?x=1`

### Regression cases from existing invalid URLs
7. Ensure URLs in `tests/validators/invalid_urls.txt` that become “accidentally valid” when adding a query string like `?m=foo@example.com` remain invalid.
   - This is a good regression sweep around any invalid URLs that contain `@`-like patterns in the path.

### Edge cases
8. IPv6 hosts with userinfo:
   - `http://user:pass@[2001:db8::1]/`
   - valid
   - `http://user/pass@[2001:db8::1]/`
   - invalid

9. Authentication-like strings in path/query should not be over-rejected:
   - `http://example.com/path/foo:bar@baz`
   - should remain governed by the path rules, not userinfo rules.

---

## 2) Implementation plan

The cleanest fix is to tighten the URLValidator regex so that the optional `userinfo@` part only accepts percent-encoded reserved characters in the username/password fields, rather than raw `:`, `@`, or `/`.

High-level approach:
- Keep the overall validator structure intact.
- Modify the host/userinfo portion of the regex to restrict the userinfo grammar.
- Add focused tests covering both invalid raw characters and valid encoded equivalents.
- Ensure no broad regression for normal URLs, IPv6, or existing validated schemes.

---

## 3) Diff sketch

### `django/core/validators.py`
Key edit: update `URLValidator.regex` / `_lazy_re_compile(...)` pattern.

```diff
diff --git a/django/core/validators.py b/django/core/validators.py
index ....... .. .......
--- a/django/core/validators.py
+++ b/django/core/validators.py
@@ class URLValidator:
-    # existing regex (includes optional userinfo)
+    # Tighten userinfo so raw ':', '@', '/' are not accepted.
+    # Allow percent-encoded bytes in userinfo instead.
     regex = _lazy_re_compile(
-        r'...(?:(?:[^\s/?#@]+)(?::[^\s/?#@]*)?@)?...'
+        r'...(?:(?:[^\s/?#@:%]+(?:%[0-9A-Fa-f]{2}|[^\s/?#@:%])*)'
+        r'(?::(?:%[0-9A-Fa-f]{2}|[^\s/?#@:%])*)?@)?...'
     )
```

Notes:
- The exact regex shape will depend on the current implementation, but the important change is:
  - user part and password part must not allow raw `:`, `@`, or `/`
  - percent-encoded octets remain allowed
- Keep the rest of the URL pattern unchanged.

### `tests/validators/tests.py` (or the relevant URLValidator test module)
Add explicit tests.

```diff
diff --git a/tests/validators/tests.py b/tests/validators/tests.py
index ....... .. .......
--- a/tests/validators/tests.py
+++ b/tests/validators/tests.py
@@ class URLValidatorTests(SimpleTestCase):
+    def test_url_validator_rejects_invalid_userinfo_chars(self):
+        validator = URLValidator()
+        invalid_urls = [
+            "http://foo/bar@example.com",
+            "http://foo:bar@example.com",
+            "http://foo@bar@example.com",
+            "http://user:pa:ss@example.com",
+            "http://user:pa@ss@example.com",
+            "http://user/pa@example.com",
+        ]
+        for url in invalid_urls:
+            with self.subTest(url=url):
+                with self.assertRaises(ValidationError):
+                    validator(url)
+
+    def test_url_validator_allows_percent_encoded_userinfo_chars(self):
+        validator = URLValidator()
+        valid_urls = [
+            "http://foo%2Fbar@example.com",
+            "http://user%3Aname:pass@example.com",
+            "http://user:pass%2Fword@example.com",
+        ]
+        for url in valid_urls:
+            with self.subTest(url=url):
+                validator(url)
```

If the repo already has data-driven tests for URLs:
- Add the invalid examples to `tests/validators/invalid_urls.txt`
- Add the valid encoded examples to the valid URL test data file if present

---

## 4) Risks

1. **Regex complexity / maintainability**
   - Tightening userinfo inside the main URL regex can make it harder to read and slightly harder to maintain.

2. **False negatives for unusual but accepted real-world URLs**
   - Some applications may have been relying on Django accepting malformed userinfo. This change intentionally breaks that behavior.

3. **Over-rejection if the pattern is too strict**
   - If the regex mistakenly disallows valid percent-encoded sequences or legitimate punctuation, it could reject URLs that should pass.

4. **Interaction with IPv6 and other host forms**
   - Must ensure the userinfo change does not interfere with bracketed IPv6 hosts, ports, or authentication-less URLs.

If you want, I can also provide a more concrete regex-level patch against Django’s current `URLValidator` implementation style.

## Plan: RefactorHappy

### Plan
- Update `django/core/validators.py` so `URLValidator` explicitly rejects unescaped `:`, `@`, and `/` in the userinfo portion of the netloc.
- Keep the change localized: add a small helper regex/check near the existing URL validation logic rather than expanding the main URL regex too much.
- Add/adjust tests in `tests/validators/tests.py` and/or `tests/validators/invalid_urls.txt` to cover:
  - `http://foo/bar@example.com`
  - usernames/passwords containing raw `:`, `@`, `/`
  - accepted, %-encoded equivalents like `foo%3Abar@example.com`
- Ensure the new check does not break valid URLs with:
  - no userinfo
  - IPv6 hosts
  - ports
  - query strings and fragments
- Run the validator test suite to verify existing invalid URL cases remain invalid.

### Diff sketch

#### `django/core/validators.py`
Key edit: extend `URLValidator.__call__()` (or the internal netloc validation path) to inspect the parsed `netloc` before accepting the URL.

```diff
 class URLValidator(RegexValidator):
     ...
     def __call__(self, value):
         super().__call__(value)
         value = force_str(value)
         scheme, netloc, path, query, fragment = urlsplit(value)
+
+        # Reject raw reserved characters in userinfo.
+        # RFC 1738 requires ":", "@", and "/" to be percent-encoded
+        # within username/password.
+        if '@' in netloc:
+            userinfo, _, hostport = netloc.rpartition('@')
+            if any(ch in userinfo for ch in ('/', ':', '@')):
+                raise ValidationError(self.message, code=self.code)
+
         # existing host/scheme/path checks continue here...
```

Possible refinement if the repo already has netloc parsing helpers:

```diff
+        if '@' in netloc:
+            userinfo, _, _ = netloc.rpartition('@')
+            if re.search(r'[:/@]', userinfo):
+                raise ValidationError(self.message, code=self.code)
```

This keeps the change small and avoids rewriting the broader URL regex.

#### `tests/validators/tests.py`
Key edit: add explicit regression tests for invalid and valid userinfo cases.

```diff
 class URLValidatorTests(SimpleTestCase):
+    def test_invalid_userinfo_characters(self):
+        validator = URLValidator()
+        invalid_urls = [
+            'http://foo/bar@example.com',
+            'http://foo:ba:r@example.com',
+            'http://foo@bar@example.com',
+            'http://foo/bar:pw@example.com',
+        ]
+        for url in invalid_urls:
+            with self.subTest(url=url):
+                with self.assertRaises(ValidationError):
+                    validator(url)
+
+    def test_valid_percent_encoded_userinfo(self):
+        validator = URLValidator()
+        valid_urls = [
+            'http://foo%2Fbar@example.com',
+            'http://foo%3Abar@example.com',
+            'http://foo%40bar@example.com',
+        ]
+        for url in valid_urls:
+            with self.subTest(url=url):
+                validator(url)
```

#### `tests/validators/invalid_urls.txt`
Key edit: add the reported regression case if this repo uses the text fixture for URLValidator invalid cases.

```diff
+http://foo/bar@example.com
```

### Risks
- **False positives on unusual but technically parsed URLs:** inspecting `netloc`/`userinfo` too aggressively could reject edge cases that the current validator accepts, especially around percent-encoding and unusual authority formats.
- **IPv6/port parsing interactions:** if the check doesn’t carefully separate `userinfo` from host/port, URLs like `user@[2001:db8::1]:8000` could be mishandled.
- **Behavioral drift from existing accepted inputs:** adding a new userinfo rule may cause some legacy tests or downstream apps to fail if they relied on permissive validation.
- **Regex/logic complexity creep:** if the fix is implemented inside the main regex, it may be harder to maintain; keeping it as a post-parse check reduces that risk.

## Judge Verdict

## Ranked list

### 1) **Defensive** — **Winner**
**Rationale:** It stays localized to `django/core/validators.py` and `tests/validators/`, explicitly preserves encoded forms, and its diff sketch is the safest wording-wise because it acknowledges the current implementation style: *“modify that subpattern rather than restructuring the whole expression”* and *“Restrict userinfo so raw ":", "@", and "/" are not accepted.”*

### 2) **Minimalist**
**Rationale:** This is close to the right scope and rightly prefers a small change, but its regex sketch is too hand-wavy (`r'...`), and the proposed test list is thinner than the issue warrants.

### 3) **TestFirst**
**Rationale:** Best test coverage by far, but the implementation plan is weaker because it leans on a broad regex rewrite and includes several speculative edge cases that could overcomplicate the fix.

### 4) **RefactorHappy**
**Rationale:** This is the riskiest because it proposes a post-parse `netloc`/userinfo check in `__call__()` instead of fixing the validator’s actual acceptance pattern; it also quotes the bug correctly but may create parsing inconsistencies.

---

## Winner
**Defensive**

### Brief rationale
The issue specifically asks to reject raw `:`, `@`, and `/` in username/password while keeping the rest of `URLValidator` stable. Defensive most directly matches that goal without overreaching: it says, *“Tighten `URLValidator`’s URL regex so the userinfo portion before `@` only accepts percent-encoded reserved characters”* and pairs that with targeted regression tests for `http://foo/bar@example.com` and encoded equivalents.

---

## Synthesis I’d recommend
Take **Defensive’s** implementation shape and **TestFirst’s** stronger test list, but trim TestFirst’s speculative cases.

Concretely:
- **Implementation:** use Defensive/Minimalist’s “tighten the userinfo part of the regex” approach.
- **Tests:** include the core cases from TestFirst:
  - invalid: `http://foo/bar@example.com`, `http://foo:bar@example.com`, `http://foo@bar@example.com`
  - valid: `http://foo%2Fbar@example.com`, `http://foo%3Abar@example.com`, `http://foo%40bar@example.com`
- **Avoid** the broader IPv6/path/query permutations unless current test failures suggest they’re necessary.

---

## Brief rationale per rank

1. **Defensive** — Best balance of specificity and safety; it directly targets the userinfo grammar and explicitly preserves percent-encoding.
2. **Minimalist** — Correct instinct on scope, but the diff sketch is under-specified and too dependent on “current regex already has a userinfo subgroup.”
3. **TestFirst** — Excellent coverage, but it mixes in a lot of extra cases and suggests more sweeping pattern changes than needed.
4. **RefactorHappy** — The post-parse check is conceptually clean, but it’s not the least risky path for Django’s `URLValidator` and may diverge from the actual validation semantics.

---

## Open questions for the human engineer

1. **Where exactly is the current userinfo handling in Django `b9cf764b`?**
   - Before coding, confirm whether `URLValidator` already has a separable userinfo regex subgroup or whether the validator is mostly host-based.

2. **Should the fix be regex-only or a post-parse check?**
   - The issue asks to “reject invalid characters”; it does not mandate a regex-only solution, but the safest change likely depends on the current implementation structure.

3. **Which test fixture is authoritative here?**
   - Is `tests/validators/tests.py` the main home, or should `tests/validators/invalid_urls.txt` be updated as the canonical regression corpus?

4. **Do we need to preserve any currently-accepted malformed URLs for backward compatibility?**
   - The issue implies “no,” but it’s worth confirming before tightening acceptance.

5. **Should the regression tests include only the reported case or also encoded-control cases?**
   - I’d recommend yes, but the maintainer may want the smallest possible test set.

6. **Are there existing validators or helper regexes shared with other URL-like checks?**
   - If so, changing one pattern may have side effects elsewhere.
