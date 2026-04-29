# SWE-Bench Verified validation: pre-flight-rehearsal

5 sampled SWE-Bench Verified issues fed into `pre-flight-rehearsal/cli.py`. Per case we compare the Judge-picked implementer plan to the canonical patch.

## Verdicts

| Instance | Repo | Verdict | Files hit | Tokens hit | Judge winner |
|---|---|---|---|---|---|
| `astropy__astropy-12907` | `astropy/astropy` | **caught** | 1/1 | 2/3 | — |
| `django__django-10097` | `django/django` | **caught** | 1/1 | 2/3 | Rationale |
| `matplotlib__matplotlib-13989` | `matplotlib/matplotlib` | **caught** | 1/1 | 1/3 | — |
| `mwaskom__seaborn-3187` | `mwaskom/seaborn` | **caught** | 1/2 | 10/30 | — |
| `pallets__flask-5014` | `pallets/flask` | **caught** | 1/1 | 4/4 | Rationale |

**Aggregate**: caught=5, partial=0, missed=0 (out of 5)

## astropy__astropy-12907 — verdict: **caught**

- repo: `astropy/astropy`
- canonical patch: 470 chars across 1 files: ['astropy/modeling/separable.py']
- judge winner: **none-detected**
- file overlap: ['astropy/modeling/separable.py']
- distinctive-token overlap: 2/3 (67%)
- picked plan first 400 chars: _## Plan: Minimalist  Plan: - Inspect `astropy/modeling/separable.py` to see how `CompoundModel` cases are reduced and where nested `&` compositions lose block-diagonal structure. - Fix the `&`/`CompoundModel` handling so it uses the child models’ actual separability matrices recursively, rather than flattening in a way that treats nested compound outputs as coupled. - Keep the change minimal and l_

## django__django-10097 — verdict: **caught**

- repo: `django/django`
- canonical patch: 562 chars across 1 files: ['django/core/validators.py']
- judge winner: **Rationale**
- file overlap: ['django/core/validators.py']
- distinctive-token overlap: 2/3 (67%)
- picked plan first 400 chars: _## Plan: Minimalist  ### Plan - Update `django/core/validators.py` so `URLValidator` explicitly rejects unencoded `:`, `@`, and `/` characters in the userinfo portion of the URL. - Keep the existing overall regex structure intact; add a small, targeted check rather than rewriting the validator. - Add/adjust tests in `tests/validators/tests.py` (and/or `tests/validators/invalid_urls.txt` if that su_

## matplotlib__matplotlib-13989 — verdict: **caught**

- repo: `matplotlib/matplotlib`
- canonical patch: 505 chars across 1 files: ['lib/matplotlib/axes/_axes.py']
- judge winner: **none-detected**
- file overlap: ['lib/matplotlib/axes/_axes.py']
- distinctive-token overlap: 1/3 (33%)
- picked plan first 400 chars: _## Plan: Minimalist  ### Plan - Inspect `Axes.hist` bin-edge computation for the `density=True` path and find where `range=` is being dropped when bins are auto-computed. - Ensure the `range` argument is passed through to the bin estimator even when `density=True`, so the computed bins span the requested interval. - Keep behavior unchanged for `density=False` and for explicit bin edges. - Add or u_

## mwaskom__seaborn-3187 — verdict: **caught**

- repo: `mwaskom/seaborn`
- canonical patch: 1531 chars across 2 files: ['seaborn/_core/scales.py', 'seaborn/utils.py']
- judge winner: **none-detected**
- file overlap: ['seaborn/_core/scales.py']
- distinctive-token overlap: 10/30 (33%)
- picked plan first 400 chars: _## Plan: Minimalist  Plan: - Inspect the numeric legend/scale formatting path in `seaborn/_core/scales.py`, especially where `ScalarFormatter` is used to generate tick labels for legends. - Preserve the formatter’s offset text and incorporate it into the legend title or labels when the formatter reports a non-zero offset. - Keep the change localized to the scale formatting helper so both `objects`_

## pallets__flask-5014 — verdict: **caught**

- repo: `pallets/flask`
- canonical patch: 390 chars across 1 files: ['src/flask/blueprints.py']
- judge winner: **Rationale**
- file overlap: ['src/flask/blueprints.py']
- distinctive-token overlap: 4/4 (100%)
- picked plan first 400 chars: _## Plan: Minimalist  ### Plan - Add validation in `flask/sansio/blueprints.py` where `Blueprint` is initialized. - Reject empty blueprint names (`""`) by raising `ValueError`. - Keep the change narrowly scoped so existing behavior for valid names is unchanged. - Add or adjust tests in the blueprint test module to assert the new error. - Ensure the error message is clear and consistent with Flask-s_
