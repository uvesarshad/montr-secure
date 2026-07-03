# corpus/python-vuln — intentionally vulnerable Django app (Phase 3)

> ⛔ **Intentionally vulnerable code. DO NOT DEPLOY.** Like
> `packages/fixtures/sample-repos/**`, this tree is excluded from
> lint/format/typecheck and is only ever read by the golden-corpus scorer.

A minimal Django project exercising the Python App-Map analyzer
(`@montr/appmap` `languages/python`) + the Python discovery ruleset + the Python
confirmation heuristics (build-plan §7 Wave 4, PRD §16 Phase 3). Its secured
counterpart is [`../python-clean`](../python-clean).

## Planted findings (see `ground-truth.manifest.json`)

| Category           | CWE     | OWASP    | Location              | Exploitable | Fix class      |
| ------------------ | ------- | -------- | --------------------- | ----------- | -------------- |
| `sql_injection`    | CWE-89  | A03:2021 | `myapp/views.py:18`   | yes         | auto-eligible  |
| `xss`              | CWE-79  | A03:2021 | `myapp/views.py:21`   | yes         | auto-eligible  |
| `ssrf`             | CWE-918 | A10:2021 | `myapp/views.py:28`   | yes         | auto-eligible  |
| `idor`             | CWE-639 | A01:2021 | `myapp/views.py:34`   | yes         | human-required |
| `hardcoded_secret` | CWE-798 | A07:2021 | `myapp/settings.py:5` | yes         | human-required |

The manifest conforms to `GroundTruthManifestSchema` from `@montr/fixtures` and
is cross-checked against the analyzer's real output (each planted finding's
`file:line` corroborated by an emitted taint sink / secret surface / route) in
`packages/appmap/src/languages/python/index.test.ts`. It is a **standalone** manifest —
the shared `corpus/ground-truth.manifest.json` and its `corpus/repos/*` loader
are intentionally left untouched (parallel-safety), so wiring these repos into
the CI regression gate is a follow-up for WS-P.

## What the analyzer extracts

- **routes** — Django `urlpatterns` (`path()` / `re_path()`), normalised
  (`<int:order_id>` / `(?P<order_id>…)` → `{order_id}`).
- **orm_models** — `User`, `Order` (Django `models.Model`, fields + implicit `id` PK).
- **data_stores** — postgres (from the settings `ENGINE`).
- **env_surface** — hard-coded `SECRET_KEY` (config_file) + `os.environ.get` reads.
- **taint** — `request.GET` sources → raw-SQL / `mark_safe` / `requests.get` sinks.
