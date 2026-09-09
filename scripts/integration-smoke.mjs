#!/usr/bin/env node
/**
 * ⛔ THE real docker-compose integration smoke test (build-plan suggested
 * enhancement #12 — "compose up, hit /health, run one scan end to end. That
 * single test would have caught A1, A3 and A5 before they were checked off.").
 *
 * Unlike `scripts/e2e-scan.mjs` / `scripts/corpus-scan.mjs` / `scripts/selfscan.mjs`
 * (which drive apps/worker IN-PROCESS with a fake in-memory store + fake LLM
 * gateway — fast, but never boot a single real container), THIS script brings
 * up the REAL compose stack from the REAL images built off
 * deploy/docker/Dockerfile.{api,worker,web} — postgres, redis, the one-shot
 * one-shot `migrate` job (auto-run via depends_on), api, worker, web — over the REAL docker
 * network, and drives it purely through the REAL, versioned HTTP surface
 * (A3's `/api/v1/...` routes): register → login → POST /api/v1/scans with a
 * real target repo → poll until the real worker container has picked the job
 * off real Redis, built a real App Map against real files, and persisted it to
 * real Postgres, readable back through the real api container.
 *
 * This is the class of bug an in-process/unit-test harness structurally cannot
 * see: wrong CMD/entrypoint (A1), a stale/unversioned HTTP contract between
 * apps/web and apps/api (A3), or a bad container arg in a deploy manifest (A5,
 * covered on the Helm side by the `helm` CI job's template rendering — this
 * script is the docker-compose analogue: if the containers can't actually
 * talk to each other, this fails; a `docker compose build`-only job cannot
 * catch that).
 *
 * ⛔ NO real LLM key is available in CI (golden rule #2 — BYO-key, never a
 * shared/vendored credential). A fake key is used, so Layer 2/3
 * (correlation / exploit confirmation) are expected to degrade rather than
 * crash — EVERY LLM call site in this codebase independently catches its own
 * gateway errors and falls back to the deterministic/un-enriched result
 * (packages/appmap/src/llm.ts `labelAuthBoundaries`, packages/discovery/src/triage.ts
 * `triageCandidates`, packages/correlation/src/{correlate,llm}.ts) — so this
 * script does NOT wait for the scan to reach "completed". It asserts the part
 * that proves the containers are really wired together: the real worker
 * picked up the real BullMQ job, ran the real deterministic Layer-0 App-Map
 * builder against the real fixture repo's real files, and persisted
 * `appMapId` + `costEstimate` onto the scan row in real Postgres — readable
 * back through the real api container. That is a meaningful, un-fakeable,
 * cross-container smoke assertion.
 *
 * Usage:
 *   node scripts/integration-smoke.mjs            # full run (build + up + assert + teardown)
 *   node scripts/integration-smoke.mjs --skip-build # reuse already-built images (fast local iteration)
 *   node scripts/integration-smoke.mjs --keep       # skip `down -v` teardown (debugging)
 *   pnpm run smoke                                  # same as the plain invocation
 *
 * Env overrides (rarely needed):
 *   SMOKE_API_PORT          default 3001 (must match docker-compose.yml's api port mapping)
 *   SMOKE_WEB_PORT          default 3000 (must match docker-compose.yml's web port mapping)
 *   SMOKE_HEALTH_TIMEOUT_MS default 180000 — how long to poll api /health before giving up
 *   SMOKE_SCAN_TIMEOUT_MS   default 180000 — how long to poll scan progress before giving up
 *   SMOKE_KEEP_UP=1         same as --keep
 *
 * Exit code: 0 on every assertion passing, non-zero otherwise. `docker compose
 * down -v` always runs on the way out (success, assertion failure, or crash),
 * matching the CI job's `if: always()` cleanup step.
 */
import { spawnSync } from "node:child_process";
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { randomBytes, randomUUID } from "node:crypto";

const ROOT = fileURLToPath(new URL("..", import.meta.url));
const COMPOSE_DIR = join(ROOT, "deploy", "docker");
const COMPOSE_FILE = join(COMPOSE_DIR, "docker-compose.yml");
const ENV_FILE = join(COMPOSE_DIR, ".env");
const ENV_EXAMPLE = join(COMPOSE_DIR, ".env.example");
const FIXTURE_REPO = join(ROOT, "packages", "fixtures", "sample-repos", "vulnerable-nextjs");
const WORKER_REPO_PATH = "/workspace/vulnerable-nextjs";

const args = process.argv.slice(2);
const SKIP_BUILD = args.includes("--skip-build");
const KEEP_UP = args.includes("--keep") || process.env["SMOKE_KEEP_UP"] === "1";

const API_PORT = Number(process.env["SMOKE_API_PORT"] ?? 3001);
const WEB_PORT = Number(process.env["SMOKE_WEB_PORT"] ?? 3000);
const API_BASE = `http://127.0.0.1:${API_PORT}`;
const WEB_BASE = `http://127.0.0.1:${WEB_PORT}`;
const HEALTH_TIMEOUT_MS = Number(process.env["SMOKE_HEALTH_TIMEOUT_MS"] ?? 180_000);
const SCAN_TIMEOUT_MS = Number(process.env["SMOKE_SCAN_TIMEOUT_MS"] ?? 180_000);

let step = 0;
function log(msg) {
  step += 1;
  console.log(`\n[smoke ${String(step).padStart(2, "0")}] ${msg}`);
}
function fail(msg) {
  console.error(`\n[smoke] FAILED: ${msg}`);
  process.exitCode = 1;
  throw new Error(msg);
}
function sleep(ms) {
  return new Promise((res) => setTimeout(res, ms));
}

/** Run a command to completion, streaming output; throws on non-zero exit. */
function run(cmd, cmdArgs, opts = {}) {
  console.log(`+ ${cmd} ${cmdArgs.join(" ")}`);
  const result = spawnSync(cmd, cmdArgs, {
    cwd: ROOT,
    stdio: "inherit",
    ...opts,
  });
  if (result.error) throw result.error;
  if (result.status !== 0) {
    throw new Error(`command failed (exit ${result.status}): ${cmd} ${cmdArgs.join(" ")}`);
  }
  return result;
}

/** Same as `run`, but never throws — used only for best-effort cleanup. */
function runBestEffort(cmd, cmdArgs) {
  console.log(`+ ${cmd} ${cmdArgs.join(" ")} (best-effort)`);
  spawnSync(cmd, cmdArgs, { cwd: ROOT, stdio: "inherit" });
}

function compose(...composeArgs) {
  return ["compose", "-f", COMPOSE_FILE, ...composeArgs];
}

/** Write a throwaway `.env` for this run: real .env.example values plus the
 * secrets `apps/api`'s `production-deps.ts` requires (JWT_SECRET/CSRF_SECRET)
 * that — deliberately or not — are NOT enumerated in .env.example, so a plain
 * `cp .env.example .env && docker compose up` would crash-loop the api
 * container on a missing-env-var throw. This script supplies its own
 * throwaway values so the real boot path is exercised end to end; it does not
 * edit .env.example (out of scope here — see the smoke-test report). */
function writeEnvFile() {
  if (!existsSync(ENV_EXAMPLE)) fail(`missing ${ENV_EXAMPLE}`);
  const base = readFileSync(ENV_EXAMPLE, "utf8");
  const jwtSecret = randomBytes(32).toString("hex");
  const csrfSecret = randomBytes(32).toString("hex");
  const extra = [
    "",
    "# --- appended by scripts/integration-smoke.mjs (throwaway CI secrets) ---",
    `JWT_SECRET=${jwtSecret}`,
    `CSRF_SECRET=${csrfSecret}`,
    // MONTR_LLM_API_KEY is deliberately blank in .env.example ("leave BLANK
    // here"); a fake, obviously-non-real key lets the worker boot + attempt
    // (and gracefully fail) real LLM calls without needing a live credential.
    "MONTR_LLM_API_KEY=sk-ant-smoketest-000000000000000000000000",
    "",
  ].join("\n");
  writeFileSync(ENV_FILE, base + extra, "utf8");
  log(`wrote throwaway ${ENV_FILE} (.env.example + JWT_SECRET/CSRF_SECRET/fake LLM key)`);
}

/** Poll `check()` until it returns true or `timeoutMs` elapses. */
async function pollUntil(label, timeoutMs, intervalMs, check) {
  const deadline = Date.now() + timeoutMs;
  let lastErr;
  while (Date.now() < deadline) {
    try {
      const result = await check();
      if (result) return result;
    } catch (err) {
      lastErr = err;
    }
    await sleep(intervalMs);
  }
  fail(
    `timed out after ${timeoutMs}ms waiting for: ${label}` +
      (lastErr ? ` (last error: ${lastErr instanceof Error ? lastErr.message : lastErr})` : ""),
  );
}

async function fetchJson(url, opts = {}) {
  const res = await fetch(url, opts);
  let body;
  const text = await res.text();
  try {
    body = text ? JSON.parse(text) : undefined;
  } catch {
    body = text;
  }
  return { res, body };
}

async function main() {
  log("writing throwaway deploy/docker/.env");
  writeEnvFile();

  // Always start from a clean slate (stray containers/volumes from a prior
  // interrupted run must not leak state into this one).
  log("tearing down any stray stack from a previous run (best-effort)");
  runBestEffort("docker", compose("down", "-v", "--remove-orphans"));

  if (!SKIP_BUILD) {
    log("building api/worker/web + migrate images (docker compose build)");
    run("docker", compose("build"));
  } else {
    log("--skip-build: reusing already-built images");
  }

  // Bring the stack up exactly the way deploy/docker/README.md documents it —
  // one `up`, no manual migration step. This is deliberate: the previous version
  // of this script ran `--profile migrate run --rm migrate` by hand BEFORE
  // starting api/worker, which meant it kept passing while the documented
  // one-command bring-up was broken (the migrate service was profile-gated and
  // nothing depended on it, so a real operator got api/worker against a
  // schema-less database). Working around the bug is what let it survive. Now
  // migrations must run because api/worker declare
  // `depends_on: migrate: service_completed_successfully` — if that wiring
  // regresses, this job fails instead of silently compensating.
  log("bringing up the whole stack the documented way (docker compose up -d)");
  run("docker", compose("up", "-d"));

  log(`polling ${API_BASE}/health (timeout ${HEALTH_TIMEOUT_MS}ms)`);
  await pollUntil("api /health to report healthy", HEALTH_TIMEOUT_MS, 2000, async () => {
    let res;
    try {
      res = await fetch(`${API_BASE}/health`);
    } catch {
      return false;
    }
    if (!res.ok) return false;
    const body = await res.json().catch(() => undefined);
    const ok = body && body.status === "ok";
    if (ok) console.log(`  api /health -> ${JSON.stringify(body)}`);
    return ok;
  });

  log(`polling ${WEB_BASE}/ (web console boots and can reach the api — A3 contract)`);
  await pollUntil("web root to respond < 500", HEALTH_TIMEOUT_MS, 2000, async () => {
    try {
      const res = await fetch(WEB_BASE + "/", { redirect: "manual" });
      // The healthcheck in docker-compose.yml itself only requires status<500
      // (see the web service's HEALTHCHECK) — mirror that bar here.
      return res.status < 500;
    } catch {
      return false;
    }
  });

  log(`copying the vulnerable-nextjs fixture repo into the worker container's /workspace`);
  if (!existsSync(FIXTURE_REPO)) {
    fail(`fixture repo not found: ${FIXTURE_REPO}`);
  }
  run("docker", compose("cp", FIXTURE_REPO + "/.", `worker:${WORKER_REPO_PATH}`));

  log("registering a bootstrap user via POST /api/v1/auth/register (real, versioned A3 route)");
  const email = `smoke-${randomUUID()}@example.test`;
  const password = "Sm0ke-Test-Password-2026!";
  {
    const { res, body } = await fetchJson(`${API_BASE}/api/v1/auth/register`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ email, password }),
    });
    if (res.status !== 201) {
      fail(`register expected 201, got ${res.status}: ${JSON.stringify(body)}`);
    }
    // First user of a fresh client is auto-promoted to `approver` (bootstrap
    // rule) — sufficient role to create scans (requireRole("operator","approver")).
    console.log(`  registered ${email} as role='${body.user.role}'`);
  }

  log("logging in via POST /api/v1/auth/login to get a bearer token");
  let token;
  {
    const { res, body } = await fetchJson(`${API_BASE}/api/v1/auth/login`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ email, password }),
    });
    if (res.status !== 200 || !body?.token) {
      fail(`login expected 200 + token, got ${res.status}: ${JSON.stringify(body)}`);
    }
    token = body.token;
  }

  log("creating a real scan via POST /api/v1/scans (A3's versioned scans route)");
  let scanId;
  {
    const { res, body } = await fetchJson(`${API_BASE}/api/v1/scans`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: `Bearer ${token}`,
      },
      body: JSON.stringify({ repo: WORKER_REPO_PATH, branch: "main", mode: "full" }),
    });
    if (res.status !== 201 || !body?.scan?.id) {
      fail(`scan create expected 201, got ${res.status}: ${JSON.stringify(body)}`);
    }
    scanId = body.scan.id;
    console.log(`  scan created: id=${scanId} status=${body.scan.status}`);
  }

  log(
    `polling GET /api/v1/scans/${scanId}(/status) until the real worker (real Redis job, real ` +
      `Postgres persistence) reports Layer-0 done — appMapId + costEstimate populated ` +
      `(timeout ${SCAN_TIMEOUT_MS}ms)`,
  );
  let sawRunning = false;
  const layer0Result = await pollUntil(
    "scan to progress past Layer 0 (appMapId + costEstimate populated) without failing first",
    SCAN_TIMEOUT_MS,
    3000,
    async () => {
      const { res: scanRes, body: scanBody } = await fetchJson(
        `${API_BASE}/api/v1/scans/${scanId}`,
        { headers: { authorization: `Bearer ${token}` } },
      );
      if (scanRes.status !== 200) return false;
      const scan = scanBody.scan;

      const { res: statusRes, body: statusBody } = await fetchJson(
        `${API_BASE}/api/v1/scans/${scanId}/status`,
        { headers: { authorization: `Bearer ${token}` } },
      );
      const status = statusRes.status === 200 ? statusBody : undefined;

      console.log(
        `  scan.status=${scan.status} gateState=${status?.gateState ?? "?"} ` +
          `appMapId=${scan.appMapId ?? "-"} costEstimate=${status?.costEstimate ? "set" : "-"}`,
      );

      if (scan.status === "running") sawRunning = true;

      // A real infra failure (not the expected fake-LLM degradation) should
      // fail fast rather than silently time out.
      if (scan.status === "failed" && !scan.appMapId) {
        fail(
          `scan failed before Layer 0 (App Map) ever completed — this is the class of bug ` +
            `(A1/A3/A5-style) this smoke test exists to catch: ${JSON.stringify(scan)}`,
        );
      }

      if (scan.appMapId && status?.costEstimate) {
        return { scan, status };
      }
      return false;
    },
  );

  if (!sawRunning) {
    console.warn(
      "  note: never observed status === 'running' between polls (Layer 0 may have finished " +
        "between two polls) — appMapId/costEstimate proof below is what matters.",
    );
  }

  console.log(
    `\n[smoke] Layer 0 proof: appMapId=${layer0Result.scan.appMapId} ` +
      `costEstimate=${JSON.stringify(layer0Result.status.costEstimate)}`,
  );

  log("confirming GET /api/v1/scans/:id/findings is reachable (api <-> store read path)");
  {
    const { res, body } = await fetchJson(`${API_BASE}/api/v1/scans/${scanId}/findings`, {
      headers: { authorization: `Bearer ${token}` },
    });
    if (res.status !== 200) {
      fail(`findings endpoint expected 200, got ${res.status}: ${JSON.stringify(body)}`);
    }
    console.log(
      `  confirmed=${body.confirmed?.length ?? 0} unconfirmed=${body.unconfirmed?.length ?? 0} ` +
        `(low/zero counts are EXPECTED here — no real LLM key means Layer 2/3 degrade; this ` +
        `only proves the read path works)`,
    );
  }

  console.log(
    "\n[smoke] PASS — postgres, redis, the one-shot migrate job, api, worker, and web all came " +
      "up as real containers, talked to each other over the real docker network, and a real " +
      "scan created through the real A3 /api/v1/scans route reached real, persisted Layer-0 " +
      "output (App Map + cost estimate) built from a real fixture repo by the real worker " +
      "container. Layers 2/3 were not waited on (no live LLM key in CI — expected).",
  );
}

async function teardown() {
  if (KEEP_UP) {
    console.log(
      "\n[smoke] --keep / SMOKE_KEEP_UP=1 set — leaving the stack up for inspection.\n" +
        `  Tear down manually with: docker compose -f ${COMPOSE_FILE} down -v`,
    );
    return;
  }
  log("tearing down (docker compose down -v)");
  runBestEffort("docker", compose("down", "-v", "--remove-orphans"));
}

main()
  .then(async () => {
    await teardown();
    process.exit(process.exitCode ?? 0);
  })
  .catch(async (err) => {
    console.error(`\n[smoke] error: ${err instanceof Error ? err.stack : err}`);
    await teardown();
    process.exit(1);
  });
