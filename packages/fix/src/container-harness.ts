/**
 * E13 — Ephemeral-container harness for real proof-of-fix (build-plan follow-on
 * to A22). Given a filesystem checkout of a TARGET application (not this
 * monorepo — the app under scan), stand up a genuinely throwaway Docker
 * container running that app, hand back a base URL reachable only from this
 * host, and guarantee teardown.
 *
 * Genericity (documented honestly, per the task's own request):
 *  - A target with its OWN `Dockerfile` is built as-is — the strongest signal,
 *    since it is how the target actually deploys in reality.
 *  - A target with a `package.json` "start" or "dev" script but no Dockerfile
 *    gets a minimal SYNTHESIZED Node Dockerfile (`node:20-alpine`, `npm ci`/
 *    `npm install`, `npm run <script>`).
 *  - Anything else — no Dockerfile, no recognizable Node entry point (a
 *    source-only checkout in another language, a monorepo needing a build step
 *    this harness doesn't know about, etc.) — is OUT OF SCOPE for this pass.
 *    `startEphemeralContainer` throws a clearly-worded error in that case, and
 *    the caller (see container-validate.ts) treats it exactly like any other
 *    container-infra failure: fail closed, degrade to the existing
 *    vitest-subprocess proof, never hang or crash the pipeline.
 *
 * Safety:
 *  - The container is attached ONLY to a freshly-created, dedicated bridge
 *    network with IP masquerade explicitly disabled
 *    (`--opt com.docker.network.bridge.enable_ip_masquerade=false`). Verified
 *    empirically against this host's real Docker engine (not assumed): with
 *    masquerade off, the container's own OUTBOUND connections (to the real
 *    internet, or to any other container/network on this host — the network
 *    is freshly created and nothing else is ever attached to it) fail closed,
 *    while INBOUND connections via a published port still work — the same
 *    "no unscoped egress" discipline `packages/confirm/src/live.ts`'s
 *    guard.ts enforces for live DAST, mirrored here at the network layer.
 *    (A plain `--internal` network was tried first and rejected: on this
 *    engine it disables the SAME NAT chain that published-port forwarding
 *    depends on, so `-p` stops working entirely — masquerade-disabled is the
 *    real mechanism that keeps inbound reachable while blocking outbound.)
 *  - The app is published to `127.0.0.1:<random port>` only (loopback, not
 *    `0.0.0.0`) — reachable from THIS process, not from the wider network.
 *  - Every docker invocation (network create, build, run, port, rm) is bounded
 *    by a shared timeout budget; a container that fails to build, start, or
 *    become ready within that budget throws and triggers teardown — fail
 *    closed, never a hung pipeline.
 *  - Teardown (`stop()`) always removes the container and the network. It is
 *    also invoked automatically if any setup step throws.
 */
import { existsSync } from "node:fs";
import { readFile, rm, writeFile } from "node:fs/promises";
import { randomUUID } from "node:crypto";
import { join } from "node:path";

export interface ContainerHarnessOptions {
  /** Directory containing the FULL target application checkout (build context). */
  repoDir: string;
  /** Port the app listens on inside the container. Default 3000. */
  port?: number;
  /** Shared timeout budget (ms) across network create + build + run + readiness. */
  timeoutMs: number;
  /** Override the docker binary (tests may point this at a stub). Default "docker". */
  dockerBin?: string;
}

export type ContainerHarnessKind = "dockerfile" | "synthesized-node";

export interface RunningContainer {
  /** `http://127.0.0.1:<port>` — reachable from this host only. */
  baseUrl: string;
  containerId: string;
  networkName: string;
  imageTag: string;
  harness: ContainerHarnessKind;
  /** Idempotent-ish teardown: removes the container and the network. */
  stop(): Promise<void>;
}

const DEFAULT_PORT = 3000;
const SYNTHESIZED_DOCKERFILE_NAME = ".montr-fix-proof.Dockerfile";

interface PackageJsonShape {
  scripts?: Record<string, string>;
}

async function readPackageJson(repoDir: string): Promise<PackageJsonShape | null> {
  try {
    const raw = await readFile(join(repoDir, "package.json"), "utf8");
    const parsed: unknown = JSON.parse(raw);
    return parsed !== null && typeof parsed === "object" ? (parsed as PackageJsonShape) : null;
  } catch {
    return null;
  }
}

interface DockerfileResolution {
  dockerfilePath: string;
  harness: ContainerHarnessKind;
}

/** See the module doc comment above for exactly how far this genericity goes. */
async function resolveDockerfile(
  repoDir: string,
  port: number,
): Promise<DockerfileResolution | null> {
  const ownDockerfile = join(repoDir, "Dockerfile");
  if (existsSync(ownDockerfile)) {
    return { dockerfilePath: ownDockerfile, harness: "dockerfile" };
  }
  const pkg = await readPackageJson(repoDir);
  const scriptName = pkg?.scripts?.start ? "start" : pkg?.scripts?.dev ? "dev" : null;
  if (!scriptName) return null;
  const synthesizedPath = join(repoDir, SYNTHESIZED_DOCKERFILE_NAME);
  const dockerfile = [
    "FROM node:20-alpine",
    "WORKDIR /app",
    "COPY . .",
    "RUN if [ -f package-lock.json ]; then npm ci; else npm install; fi",
    `ENV PORT=${port}`,
    `EXPOSE ${port}`,
    `CMD ["npm", "run", "${scriptName}"]`,
    "",
  ].join("\n");
  await writeFile(synthesizedPath, dockerfile, "utf8");
  return { dockerfilePath: synthesizedPath, harness: "synthesized-node" };
}

async function execDocker(
  dockerBin: string,
  args: string[],
  timeoutMs: number,
): Promise<{ stdout: string; stderr: string }> {
  const { execa } = await import("execa");
  const res = await execa(dockerBin, args, {
    reject: false,
    timeout: Math.max(1000, timeoutMs),
    maxBuffer: 16 * 1024 * 1024,
  });
  if (res.failed || (res.exitCode !== undefined && res.exitCode !== 0)) {
    const detail = (String(res.stderr ?? "") || String(res.stdout ?? "")).slice(0, 2000);
    throw new Error(
      `${dockerBin} ${args.join(" ")} failed (exit ${res.exitCode ?? "unknown"}${res.timedOut ? ", timed out" : ""}): ${detail}`,
    );
  }
  return { stdout: String(res.stdout ?? ""), stderr: String(res.stderr ?? "") };
}

async function waitForReady(baseUrl: string, timeoutMs: number): Promise<void> {
  const { request } = await import("undici");
  const deadline = Date.now() + timeoutMs;
  let lastErr: unknown;
  while (Date.now() < deadline) {
    try {
      const res = await request(baseUrl, {
        method: "GET",
        signal: AbortSignal.timeout(Math.min(2000, Math.max(250, timeoutMs))),
      });
      await res.body.text().catch(() => undefined);
      return;
    } catch (err) {
      lastErr = err;
      await new Promise((resolve) => setTimeout(resolve, 400));
    }
  }
  throw new Error(
    `container did not become ready within the harness timeout budget: ${
      lastErr instanceof Error ? lastErr.message : String(lastErr)
    }`,
  );
}

/**
 * Build + start a genuinely ephemeral, network-isolated container for
 * `opts.repoDir`. Throws (never hangs, never leaks resources — the network and
 * any created container are removed on any failure path) when the timeout
 * budget is exceeded or the target cannot be containerized by this pass's
 * supported recipes (see module doc comment).
 */
export async function startEphemeralContainer(
  opts: ContainerHarnessOptions,
): Promise<RunningContainer> {
  const dockerBin = opts.dockerBin ?? "docker";
  const port = opts.port ?? DEFAULT_PORT;
  const deadline = Date.now() + opts.timeoutMs;
  const remaining = (): number => Math.max(1000, deadline - Date.now());

  const resolved = await resolveDockerfile(opts.repoDir, port);
  if (!resolved) {
    throw new Error(
      "no containerization recipe found for this target checkout: no Dockerfile and no " +
        'package.json "start"/"dev" script (a non-Node checkout with no Dockerfile of its own ' +
        "is out of scope for this harness pass)",
    );
  }

  const id = randomUUID().slice(0, 8);
  const imageTag = `montr-fixproof-${id}`;
  const networkName = `montr-fixproof-net-${id}`;
  const containerName = `montr-fixproof-run-${id}`;

  const cleanupSynthesizedDockerfile = async (): Promise<void> => {
    if (resolved.harness === "synthesized-node") {
      await rm(resolved.dockerfilePath, { force: true }).catch(() => undefined);
    }
  };

  let containerId: string | undefined;
  const stop = async (): Promise<void> => {
    if (containerId) {
      await execDocker(dockerBin, ["rm", "-f", containerId], 15_000).catch(() => undefined);
    }
    await execDocker(dockerBin, ["network", "rm", networkName], 15_000).catch(() => undefined);
    // The built image is a lingering resource too (a uniquely-tagged, one-off
    // image per harness run) — remove it so nothing accumulates across repeated
    // proof-of-fix validations. Best-effort: a build that failed before an
    // image was produced has nothing to remove here.
    await execDocker(dockerBin, ["rmi", "-f", imageTag], 15_000).catch(() => undefined);
    await cleanupSynthesizedDockerfile();
  };

  try {
    // Masquerade-disabled bridge network: published ports still work (host ->
    // container), but the container's own outbound traffic (internet, or any
    // other container/network on this host) fails closed — see module doc
    // comment for why this, and not `--internal`, is the real mechanism here.
    await execDocker(
      dockerBin,
      [
        "network",
        "create",
        "--opt",
        "com.docker.network.bridge.enable_ip_masquerade=false",
        networkName,
      ],
      remaining(),
    );

    await execDocker(
      dockerBin,
      ["build", "-t", imageTag, "-f", resolved.dockerfilePath, opts.repoDir],
      remaining(),
    );

    const { stdout: runOut } = await execDocker(
      dockerBin,
      [
        "run",
        "-d",
        "--name",
        containerName,
        "--network",
        networkName,
        // Loopback-only publish: reachable from this host, not from the network.
        "-p",
        `127.0.0.1:0:${port}`,
        "-e",
        `PORT=${port}`,
        imageTag,
      ],
      remaining(),
    );
    containerId = runOut.trim().split("\n").pop() ?? runOut.trim();
    if (!containerId) throw new Error("docker run produced no container id");

    const { stdout: portOut } = await execDocker(
      dockerBin,
      ["port", containerId, `${port}/tcp`],
      remaining(),
    );
    const hostAddr = portOut.trim().split("\n")[0] ?? "";
    const hostPort = hostAddr.split(":").pop();
    if (!hostPort || Number.isNaN(Number(hostPort))) {
      throw new Error(`could not determine the published host port from: ${portOut}`);
    }
    const baseUrl = `http://127.0.0.1:${hostPort}`;

    await waitForReady(baseUrl, remaining());

    return { baseUrl, containerId, networkName, imageTag, harness: resolved.harness, stop };
  } catch (err) {
    await stop();
    throw err;
  }
}
