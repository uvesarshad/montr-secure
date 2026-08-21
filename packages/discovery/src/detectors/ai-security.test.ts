/**
 * E11 — unit tests for the AI-application security agent, one pair per
 * sub-category (vulnerable fixture detected, clean fixture not flagged),
 * using in-memory files for fast/precise assertions, plus an integration
 * test replaying the checked-in `packages/fixtures/sample-repos/ai-app-*`
 * corpus end to end (mirroring `tests/discovery.detectors.test.ts`'s
 * `VULN_REPO`/`CLEAN_REPO` fsFileProvider pattern).
 */
import { fileURLToPath } from "node:url";
import { describe, it, expect } from "vitest";
import { getHardenedDefaults } from "@montr/config";
import { createNullLogger } from "@montr/telemetry";
import { AppMapSchema, type Category, type ScanScope } from "@montr/contracts";
import { detectAiSecurity } from "./ai-security.js";
import type { DetectorContext } from "../types.js";
import { fsFileProvider, memoryFileProvider, type RepoFile } from "../util/files.js";

const FULL_SCOPE: ScanScope = {
  mode: "full",
  includePaths: [],
  excludePaths: [],
  changedFiles: [],
  reachableFromChanges: false,
};

const minimalAppMap = AppMapSchema.parse({
  id: "appmap_test_0001",
  clientId: "client_test_0001",
  repo: "https://example.test/repo.git",
  branch: "main",
  commitSha: "0000000000000000000000000000000000000a",
  createdAt: "2026-01-15T10:00:00.000Z",
});

function makeCtx(files: readonly RepoFile[]): DetectorContext {
  const warnings: string[] = [];
  return {
    clientId: "client_test_0001",
    scanId: "scan_test_0001",
    appMap: minimalAppMap,
    scope: FULL_SCOPE,
    config: getHardenedDefaults(),
    repoRoot: undefined,
    files: memoryFileProvider(files),
    now: () => "2026-01-15T10:00:00.000Z",
    logger: createNullLogger(),
    signal: undefined,
    warnings,
    warn(detector: string, message: string): void {
      warnings.push(`[${detector}] ${message}`);
    },
  };
}

function byCategory(candidates: Awaited<ReturnType<typeof detectAiSecurity>>, category: Category) {
  return candidates.filter((c) => c.category === category);
}

describe("discovery/ai-security — prompt injection surface", () => {
  const CLIENT_IMPORT = `import Anthropic from "@anthropic-ai/sdk";\nconst anthropic = new Anthropic({ apiKey: process.env.KEY });\n`;

  it("flags unsanitized user input concatenated into the system prompt", async () => {
    const vulnerable = `${CLIENT_IMPORT}
export async function chat(userMessage: string) {
  return anthropic.messages.create({
    model: "claude-opus-5",
    system: \`You are helpful. The user said: \${userMessage}\`,
    messages: [{ role: "user", content: userMessage }],
  });
}
`;
    const ctx = makeCtx([{ path: "src/chat.ts", content: vulnerable }]);
    const candidates = await detectAiSecurity(ctx);
    const hits = byCategory(candidates, "prompt_injection");
    expect(hits.length).toBeGreaterThan(0);
    expect(hits[0]?.ruleId).toBe("ai.prompt-injection-surface");
  });

  it("does not flag a static system prompt with a sanitized user message", async () => {
    const clean = `${CLIENT_IMPORT}
function sanitizeForPrompt(input: string): string {
  return input.replace(/[^\\w\\s]/g, "");
}
export async function chat(userMessage: string) {
  return anthropic.messages.create({
    model: "claude-opus-5",
    system: "You are a helpful assistant.",
    messages: [{ role: "user", content: \`Q: \${sanitizeForPrompt(userMessage)}\` }],
  });
}
`;
    const ctx = makeCtx([{ path: "src/chat.ts", content: clean }]);
    const candidates = await detectAiSecurity(ctx);
    expect(byCategory(candidates, "prompt_injection")).toHaveLength(0);
  });
});

describe("discovery/ai-security — unsafe tool/function exposure", () => {
  const CLIENT_IMPORT = `import Anthropic from "@anthropic-ai/sdk";\nconst anthropic = new Anthropic({ apiKey: process.env.KEY });\n`;

  it("flags a dangerous tool (shell exec) with no authorization gate", async () => {
    const vulnerable = `${CLIENT_IMPORT}
async function runShellCommand(cmd: string) {
  const { execSync } = await import("node:child_process");
  return execSync(cmd).toString();
}
export async function agentTurn(userInput: string) {
  return anthropic.messages.create({
    model: "claude-opus-5",
    system: "You are an ops assistant.",
    messages: [{ role: "user", content: userInput }],
    tools: [{ name: "run_shell_command", description: "Execute an arbitrary shell command.", handler: runShellCommand }],
  });
}
`;
    const ctx = makeCtx([{ path: "src/agent.ts", content: vulnerable }]);
    const candidates = await detectAiSecurity(ctx);
    const hits = candidates.filter((c) => c.ruleId === "ai.unsafe-tool-exposure");
    expect(hits.length).toBeGreaterThan(0);
    expect(hits[0]?.category).toBe("broken_access_control");
  });

  it("does not flag a read-only tool with no dangerous capability", async () => {
    const clean = `${CLIENT_IMPORT}
async function readOnlyLookup(query: string) {
  return { result: query };
}
export async function agentTurn(userInput: string) {
  return anthropic.messages.create({
    model: "claude-opus-5",
    system: "You are a lookup assistant.",
    messages: [{ role: "user", content: userInput }],
    tools: [{ name: "lookup_record", description: "Look up a record (read-only).", handler: readOnlyLookup }],
  });
}
`;
    const ctx = makeCtx([{ path: "src/agent.ts", content: clean }]);
    const candidates = await detectAiSecurity(ctx);
    expect(candidates.filter((c) => c.ruleId === "ai.unsafe-tool-exposure")).toHaveLength(0);
  });
});

describe("discovery/ai-security — unescaped LLM output rendered to users", () => {
  const CLIENT_IMPORT = `import Anthropic from "@anthropic-ai/sdk";\nconst anthropic = new Anthropic({ apiKey: process.env.KEY });\n`;

  it("flags an LLM response rendered via dangerouslySetInnerHTML with no escaping", async () => {
    const vulnerable = `${CLIENT_IMPORT}
export async function AnswerPanel({ question }: { question: string }) {
  const response = await anthropic.messages.create({
    model: "claude-opus-5",
    system: "Answer in HTML.",
    messages: [{ role: "user", content: question }],
  });
  const html = response.content[0].text;
  return <div dangerouslySetInnerHTML={{ __html: html }} />;
}
`;
    const ctx = makeCtx([{ path: "src/panel.tsx", content: vulnerable }]);
    const candidates = await detectAiSecurity(ctx);
    const hits = byCategory(candidates, "xss");
    expect(hits.length).toBeGreaterThan(0);
    expect(hits[0]?.ruleId).toBe("ai.unescaped-llm-output-xss");
  });

  it("does not flag a sanitized LLM response rendered via dangerouslySetInnerHTML", async () => {
    const clean = `${CLIENT_IMPORT}
import DOMPurify from "dompurify";
export async function AnswerPanel({ question }: { question: string }) {
  const response = await anthropic.messages.create({
    model: "claude-opus-5",
    system: "Answer in HTML.",
    messages: [{ role: "user", content: question }],
  });
  const rawHtml = response.content[0].text;
  const safeHtml = DOMPurify.sanitize(rawHtml);
  return <div dangerouslySetInnerHTML={{ __html: safeHtml }} />;
}
`;
    const ctx = makeCtx([{ path: "src/panel.tsx", content: clean }]);
    const candidates = await detectAiSecurity(ctx);
    expect(byCategory(candidates, "xss")).toHaveLength(0);
  });
});

describe("discovery/ai-security — secrets leaking into prompts", () => {
  const CLIENT_IMPORT = `import Anthropic from "@anthropic-ai/sdk";\nconst anthropic = new Anthropic({ apiKey: process.env.KEY });\n`;

  it("flags a hardcoded credential interpolated into an LLM call", async () => {
    const vulnerable = `${CLIENT_IMPORT}
export async function ticket(body: string) {
  return anthropic.messages.create({
    model: "claude-opus-5",
    system: "You triage tickets. Escalation key: sk_live_51H8x9K2mN3pQ7rS4tUvWxYz for routing.",
    messages: [{ role: "user", content: body }],
  });
}
`;
    const ctx = makeCtx([{ path: "src/ticket.ts", content: vulnerable }]);
    const candidates = await detectAiSecurity(ctx);
    const hits = byCategory(candidates, "sensitive_data_exposure").filter(
      (c) => c.ruleId === "ai.secret-into-prompt",
    );
    expect(hits.length).toBeGreaterThan(0);
  });

  it("flags an env-sourced credential interpolated into an LLM call", async () => {
    const vulnerable = `${CLIENT_IMPORT}
export async function chat(userMessage: string) {
  const dbPassword = process.env.DB_PASSWORD;
  return anthropic.messages.create({
    model: "claude-opus-5",
    system: \`Debug password: \${dbPassword}. User said: \${userMessage}\`,
    messages: [{ role: "user", content: userMessage }],
  });
}
`;
    const ctx = makeCtx([{ path: "src/chat.ts", content: vulnerable }]);
    const candidates = await detectAiSecurity(ctx);
    const hits = byCategory(candidates, "sensitive_data_exposure").filter(
      (c) => c.ruleId === "ai.secret-into-prompt",
    );
    expect(hits.length).toBeGreaterThan(0);
  });

  it("does not flag an LLM call with no credential in its arguments", async () => {
    const clean = `${CLIENT_IMPORT}
export async function chat(userMessage: string) {
  return anthropic.messages.create({
    model: "claude-opus-5",
    system: "You are a helpful assistant.",
    messages: [{ role: "user", content: userMessage }],
  });
}
`;
    const ctx = makeCtx([{ path: "src/chat.ts", content: clean }]);
    const candidates = await detectAiSecurity(ctx);
    expect(candidates.filter((c) => c.ruleId === "ai.secret-into-prompt")).toHaveLength(0);
  });
});

describe("discovery/ai-security — missing output validation", () => {
  const CLIENT_IMPORT = `import Anthropic from "@anthropic-ai/sdk";\nimport { execSync } from "node:child_process";\nconst anthropic = new Anthropic({ apiKey: process.env.KEY });\n`;

  it("flags an LLM response driving a shell command with no validation", async () => {
    const vulnerable = `${CLIENT_IMPORT}
export async function runSuggestedCommand(task: string) {
  const response = await anthropic.messages.create({
    model: "claude-opus-5",
    system: "Suggest a shell command.",
    messages: [{ role: "user", content: task }],
  });
  const suggestedCommand = response.content[0].text;
  return execSync(suggestedCommand).toString();
}
`;
    const ctx = makeCtx([{ path: "src/run.ts", content: vulnerable }]);
    const candidates = await detectAiSecurity(ctx);
    const hits = byCategory(candidates, "command_injection").filter((c) =>
      c.ruleId.startsWith("ai.missing-output-validation"),
    );
    expect(hits.length).toBeGreaterThan(0);
  });

  it("does not flag an LLM response checked against an allowlist before use", async () => {
    const clean = `${CLIENT_IMPORT}
const ALLOWED_COMMANDS = ["status", "diskspace", "uptime"];
export async function runSuggestedCommand(task: string) {
  const response = await anthropic.messages.create({
    model: "claude-opus-5",
    system: "Suggest one of: status, diskspace, uptime.",
    messages: [{ role: "user", content: task }],
  });
  const suggestedCommand = response.content[0].text.trim();
  if (!ALLOWED_COMMANDS.includes(suggestedCommand)) {
    throw new Error("command not allowed");
  }
  return execSync(suggestedCommand).toString();
}
`;
    const ctx = makeCtx([{ path: "src/run.ts", content: clean }]);
    const candidates = await detectAiSecurity(ctx);
    expect(
      candidates.filter((c) => c.ruleId.startsWith("ai.missing-output-validation")),
    ).toHaveLength(0);
  });
});

describe("discovery/ai-security — repo with no LLM SDK call sites", () => {
  it("degrades to an empty result, no scanner binary required", async () => {
    const ctx = makeCtx([{ path: "src/index.ts", content: "export const x = 1;\n" }]);
    const candidates = await detectAiSecurity(ctx);
    expect(candidates).toHaveLength(0);
  });
});

describe("discovery/ai-security — sample-repo corpus (integration)", () => {
  const VULN_REPO = fileURLToPath(
    new URL("../../../fixtures/sample-repos/ai-app-vulnerable", import.meta.url),
  );
  const CLEAN_REPO = fileURLToPath(
    new URL("../../../fixtures/sample-repos/ai-app-clean", import.meta.url),
  );

  it("flags at least one finding per sub-category against ai-app-vulnerable", async () => {
    const ctx: DetectorContext = {
      ...makeCtx([]),
      repoRoot: VULN_REPO,
      files: fsFileProvider(VULN_REPO),
    };
    const candidates = await detectAiSecurity(ctx);
    const ruleIds = new Set(candidates.map((c) => c.ruleId.split(".").slice(0, 2).join(".")));
    expect(ruleIds).toContain("ai.prompt-injection-surface");
    expect(ruleIds).toContain("ai.unsafe-tool-exposure");
    expect(ruleIds).toContain("ai.unescaped-llm-output-xss");
    expect(ruleIds).toContain("ai.secret-into-prompt");
    expect(ruleIds).toContain("ai.missing-output-validation");
  });

  it("produces no findings against ai-app-clean", async () => {
    const ctx: DetectorContext = {
      ...makeCtx([]),
      repoRoot: CLEAN_REPO,
      files: fsFileProvider(CLEAN_REPO),
    };
    const candidates = await detectAiSecurity(ctx);
    expect(candidates).toHaveLength(0);
  });
});
