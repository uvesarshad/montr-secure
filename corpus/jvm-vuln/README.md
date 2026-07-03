# corpus/jvm-vuln — intentionally vulnerable Spring Boot app (Phase 3, JVM)

> ⛔ **Intentionally vulnerable code. DO NOT DEPLOY.** Like
> `packages/fixtures/sample-repos/**`, this tree is excluded from
> lint/format/typecheck and is only ever read by the golden-corpus scorer and the
> offline JVM stack-breadth tests.

A minimal Spring Boot / JPA project exercising the JVM App-Map analyzer
(`@montr/appmap` `languages/java`) + the JVM discovery ruleset
(`@montr/discovery` `rulesets/java`) + the JVM confirmation heuristics
(`@montr/confirm` `heuristics/java`) (build-plan §7 Wave 4, PRD §16 Phase 3). Its
secured counterpart is [`../jvm-clean`](../jvm-clean).

## Planted findings (see `ground-truth.manifest.json`)

| Category                   | CWE     | OWASP    | Location                        | Exploitable | Fix class      |
| -------------------------- | ------- | -------- | ------------------------------- | ----------- | -------------- |
| `sql_injection`            | CWE-89  | A03:2021 | `web/UserController.java:36`    | yes         | auto-eligible  |
| `command_injection`        | CWE-78  | A03:2021 | `web/NetworkController.java:22` | yes         | auto-eligible  |
| `insecure_deserialization` | CWE-502 | A08:2021 | `web/ImportController.java:23`  | yes         | auto-eligible  |
| `broken_access_control`    | CWE-284 | A01:2021 | `web/AdminController.java:29`   | yes         | human-required |
| `hardcoded_secret`         | CWE-798 | A07:2021 | `resources/application.yml:7`   | yes         | human-required |

Access-control (`broken_access_control`) and secret-rotation (`hardcoded_secret`)
fixes are labelled `human-required` per golden rule #3. The three injection classes
are mechanical/low-blast-radius `auto-eligible` fixes (parameterize the query,
drop `Runtime.exec` for an allow-listed resolver, bind a typed DTO instead of a
native `ObjectInputStream`).

The manifest matches `GroundTruthManifestSchema` from `@montr/fixtures`. It is a
**standalone** manifest — the shared `corpus/ground-truth.manifest.json` and its
`corpus/repos/*` loader are intentionally left untouched (parallel-safety), so
wiring these repos into the CI regression gate is a follow-up for WS-P (mirrors
the `corpus/python-vuln` note exactly).

## Extra offline-detector coverage (not headline findings)

Beyond the five data-flow / access-control / secret findings above, the app also
plants config/crypto issues the JVM discovery ruleset's offline detectors catch:
a wildcard actuator exposure and hard-coded `app.api-key` in `application.yml`,
weak `MessageDigest.getInstance("MD5")` in `util/HashUtil.java`, and a globally
disabled CSRF filter in `config/SecurityConfig.java`.

## What the analyzer extracts

- **routes** — Spring `@RestController` + `@GetMapping`/`@PostMapping`/
  `@DeleteMapping` under a class `@RequestMapping` base, with `@PreAuthorize` auth
  state (`isAuthenticated()` → `authenticated`, no annotation → `unknown`).
- **orm_models** — JPA `@Entity Order` (fields + `@Id` PK), linked to the
  postgres datastore parsed from `application.yml`.
- **data_stores** — postgres (from `spring.datasource.url`).
- **env_surface** — hard-coded `spring.datasource.password` + `app.api-key`
  (metadata only, never the value — golden rule #1).
- **taint** — `@RequestParam` / `@PathVariable` / `HttpServletRequest` sources →
  string-concatenated JDBC / `Runtime.exec` / `ObjectInputStream.readObject` sinks.
