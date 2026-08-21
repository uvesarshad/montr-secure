/**
 * AI-application security agent (E11, §7 L1 breadth). Scans the TARGET app
 * (the customer's codebase, never this product's own code) for five
 * vulnerability shapes specific to LLM-integrated applications:
 *
 *   1. Prompt injection surface   — unsanitized data reaching an LLM call's
 *      `system`/early `messages` content, where it can override instructions.
 *   2. Unsafe tool/function exposure — an LLM call configured with dangerous
 *      tools (shell/file-write/unrestricted-HTTP) and no visible
 *      authorization/confirmation gate.
 *   3. Unescaped LLM output rendered to users — an LLM response reaching an
 *      HTML-injection sink (XSS, but the untrusted source is the model).
 *   4. Secrets leaking into prompts — a credential-shaped literal or env-var
 *      reference flowing into an LLM call's arguments (the secret then leaves
 *      the target's infrastructure to a third-party provider — a DIFFERENT
 *      risk from this repo's own `hardcoded_secret`/gitleaks layer, which
 *      finds secrets in code generally, not specifically ones sent off-box).
 *   5. Missing output validation — an LLM response used directly to drive a
 *      sensitive sink (DB query, file path, shell command, an authorization
 *      decision) with no parse/validate/allowlist call in between anywhere in
 *      the same file.
 *
 * DESIGN CHOICE (Semgrep vs. AST — see docs/modules/discovery.md for the full
 * writeup): every curated Semgrep ruleset in this codebase today is a hosted
 * Registry pack id (`p/owasp-top-ten`, ...) selected in `rulesets/<lang>/`;
 * there is no existing convention for a repo-committed, product-curated
 * Semgrep rule FILE (the only Semgrep YAML this codebase authors is
 * client-supplied, via `custom-rules.ts`, validated and materialized to a temp
 * `--config` file at scan time). Shipping these five checks as bundled
 * Semgrep YAML would be a new, untested distribution mechanism AND would make
 * this module's own tests depend on the `semgrep` binary being installed —
 * this codebase's detector unit tests are deliberately offline (see
 * `secrets.ts`'s regex `FileDetector`s and `sca.ts`'s `collectCalledPackages`,
 * neither of which shells out). All five checks below are therefore a single
 * lightweight, deterministic, offline detector, following `sca.ts`'s
 * established ts-morph AST pattern (in-memory `Project`, single-file/same-file
 * analysis, NOT full interprocedural taint — the same documented limitation
 * `collectCalledPackages` carries). Three of the five (unsafe tool exposure,
 * secrets-into-prompt, unescaped-output) are closer in spirit to `secrets.ts`'s
 * regex-window `FileDetector`s (a match, then a bounded look-around for a
 * guard/validation marker) than to real dataflow, and are implemented that
 * way; prompt-injection-surface and missing-output-validation need enough
 * structure (which call argument is the `system`/`messages` field; which
 * sink an identifier reaches) that a real AST walk is a better fit than a
 * regex window, so those two use ts-morph node inspection directly.
 *
 * ⛔ Like every Layer 1 detector, this is deliberately over-inclusive —
 * candidates are noisy, unconfirmed input for Layer 2 correlation, never a
 * verdict (golden rule #6/#7). Static confirmation of `prompt_injection`
 * (a real `TaintSinkKind` + Layer 3 data-flow proof) is a documented follow-up
 * outside this change's scope for `packages/confirm` — see
 * `packages/confirm/src/taxonomy.ts`'s `DATAFLOW_SINK_KINDS.prompt_injection`.
 */
import { Node, Project, SyntaxKind, ts, type CallExpression, type SourceFile } from "ts-morph";
import type { Category, CandidateFinding } from "@montr/contracts";
import type { DetectorContext } from "../types.js";
import { buildCandidate } from "../util/candidate.js";
import { isSourceFile, readAll } from "../util/files.js";

/* ---------------------------------------------------------------------- */
/* LLM SDK call-site recognition                                          */
/* ---------------------------------------------------------------------- */

/** npm packages recognized as LLM provider SDKs. */
const LLM_SDK_PACKAGES = new Set([
  "openai",
  "@anthropic-ai/sdk",
  "@aws-sdk/client-bedrock-runtime",
  "@google-cloud/vertexai",
  "@azure/openai",
]);

/** Method-chain suffixes (joined with `.`) that invoke a chat/completion call. */
const LLM_CALL_SUFFIXES = [
  "messages.create",
  "messages.stream",
  "chat.completions.create",
  "completions.create",
];

/** Local identifiers bound to an LLM provider client instance in one file. */
function collectLlmClientVars(sf: SourceFile): Set<string> {
  const sdkImportBindings = new Set<string>();
  for (const imp of sf.getImportDeclarations()) {
    const spec = imp.getModuleSpecifierValue();
    if (!LLM_SDK_PACKAGES.has(spec)) continue;
    const def = imp.getDefaultImport();
    if (def) sdkImportBindings.add(def.getText());
    const ns = imp.getNamespaceImport();
    if (ns) sdkImportBindings.add(ns.getText());
    for (const named of imp.getNamedImports()) {
      sdkImportBindings.add(named.getAliasNode()?.getText() ?? named.getNameNode().getText());
    }
  }

  const clientVars = new Set<string>(sdkImportBindings);
  if (sdkImportBindings.size === 0) return clientVars;

  for (const ctor of sf.getDescendantsOfKind(SyntaxKind.NewExpression)) {
    const callee = ctor.getExpression();
    if (!Node.isIdentifier(callee) || !sdkImportBindings.has(callee.getText())) continue;
    const decl = ctor.getFirstAncestorByKind(SyntaxKind.VariableDeclaration);
    const name = decl?.getNameNode();
    if (name && Node.isIdentifier(name)) clientVars.add(name.getText());
  }
  return clientVars;
}

/** The leftmost identifier of a (possibly chained) member-access expression. */
function leftmostIdentifier(expr: Node): string | undefined {
  let cur: Node = expr;
  while (Node.isPropertyAccessExpression(cur) || Node.isElementAccessExpression(cur)) {
    cur = cur.getExpression();
  }
  return Node.isIdentifier(cur) ? cur.getText() : undefined;
}

/** The dotted property-name suffix of a chained member-access (`a.b.c` -> `"b.c"`). */
function propertySuffix(expr: Node): string {
  const parts: string[] = [];
  let cur: Node = expr;
  while (Node.isPropertyAccessExpression(cur)) {
    parts.unshift(cur.getName());
    cur = cur.getExpression();
  }
  return parts.join(".");
}

/**
 * All local `const`/`let`/`var` declarations in a file, INCLUDING ones nested
 * inside function bodies. `SourceFile.getVariableDeclarations()` only returns
 * top-level ones (ts-morph's documented behavior), which would silently miss
 * every `const response = await llm.messages.create(...)` sitting inside a
 * route handler — i.e. the overwhelming majority of real call sites. Use this
 * everywhere a whole-file declaration lookup is needed.
 */
function allVariableDeclarations(sf: SourceFile) {
  return sf.getDescendantsOfKind(SyntaxKind.VariableDeclaration);
}

/**
 * Strip `//` and `/* *\/` comments before a whole-file/whole-function text
 * scan for guard/validation keyword markers. Without this, a descriptive
 * comment ("no authorization check here") or a stale TODO ("// TODO:
 * sanitize this") flips the heuristic in either direction — a real false
 * negative (or, less dangerously, a false positive) that has nothing to do
 * with actual code. Deliberately simple/regex-based, matching this
 * codebase's existing heuristic-detector bar (see `secrets.ts`'s
 * `FileDetector`s) rather than a full trivia-aware AST pass.
 */
function stripComments(text: string): string {
  return text.replace(/\/\*[\s\S]*?\*\//g, " ").replace(/\/\/.*$/gm, " ");
}

/** All recognized LLM SDK call sites in a source file. */
function findLlmCallSites(sf: SourceFile): CallExpression[] {
  const clientVars = collectLlmClientVars(sf);
  if (clientVars.size === 0) return [];
  const out: CallExpression[] = [];
  for (const call of sf.getDescendantsOfKind(SyntaxKind.CallExpression)) {
    const expr = call.getExpression();
    if (!Node.isPropertyAccessExpression(expr)) continue;
    const root = leftmostIdentifier(expr);
    if (!root || !clientVars.has(root)) continue;
    const suffix = propertySuffix(expr);
    if (LLM_CALL_SUFFIXES.some((s) => suffix === s || suffix.endsWith(`.${s}`))) {
      out.push(call);
    }
  }
  return out;
}

/* ---------------------------------------------------------------------- */
/* 1. Prompt injection surface                                            */
/* ---------------------------------------------------------------------- */

const ESCAPE_MARKERS = /sanitiz|sanitis|escap|encode|validate|allowlist|whitelist/i;

/** True when `node` is dynamic content (template interpolation / concatenation)
 *  with no escape/sanitize marker wrapping the dynamic part, one hop through a
 *  local `const`/`let` declaration when the value is a bare identifier. */
function isUnsanitizedDynamicPrompt(node: Node, depth = 0): boolean {
  if (Node.isStringLiteral(node) || Node.isNoSubstitutionTemplateLiteral(node)) return false;
  if (Node.isTemplateExpression(node)) {
    const spans = node.getTemplateSpans();
    return spans.some((s) => !ESCAPE_MARKERS.test(s.getExpression().getText()));
  }
  if (Node.isBinaryExpression(node) && node.getOperatorToken().getText() === "+") {
    const left = node.getLeft();
    const right = node.getRight();
    return (
      (!Node.isStringLiteral(left) && !ESCAPE_MARKERS.test(left.getText())) ||
      (!Node.isStringLiteral(right) && !ESCAPE_MARKERS.test(right.getText()))
    );
  }
  if (Node.isIdentifier(node) && depth === 0) {
    const decls = allVariableDeclarations(node.getSourceFile()).filter(
      (d) => d.getNameNode().getText() === node.getText(),
    );
    for (const d of decls) {
      const init = d.getInitializer();
      if (init && isUnsanitizedDynamicPrompt(init, depth + 1)) return true;
    }
    return false;
  }
  // A bare non-literal expression (function call, property access with no
  // visible escape marker) reaching the prompt directly.
  if (!Node.isIdentifier(node)) return !ESCAPE_MARKERS.test(node.getText());
  return false;
}

/** Object-literal properties from an LLM call's first (options) argument. */
function firstArgProperties(call: CallExpression): Map<string, Node> {
  const arg = call.getArguments()[0];
  const out = new Map<string, Node>();
  if (!arg || !Node.isObjectLiteralExpression(arg)) return out;
  for (const prop of arg.getProperties()) {
    if (!Node.isPropertyAssignment(prop)) continue;
    const name = prop.getName();
    if (name) out.set(name, prop.getInitializer() ?? prop);
  }
  return out;
}

function detectPromptInjectionSurface(ctx: DetectorContext, sf: SourceFile): CandidateFinding[] {
  const out: CandidateFinding[] = [];
  for (const call of findLlmCallSites(sf)) {
    const props = firstArgProperties(call);
    const checks: Array<{ label: string; node: Node }> = [];

    const systemProp = props.get("system");
    if (systemProp) checks.push({ label: "system", node: systemProp });

    const messagesProp = props.get("messages");
    if (messagesProp && Node.isArrayLiteralExpression(messagesProp)) {
      const first = messagesProp.getElements()[0];
      if (first && Node.isObjectLiteralExpression(first)) {
        const content = first
          .getProperties()
          .find(
            (p): p is import("ts-morph").PropertyAssignment =>
              Node.isPropertyAssignment(p) && p.getName() === "content",
          );
        if (content?.getInitializer()) {
          checks.push({ label: "messages[0].content", node: content.getInitializer()! });
        }
      }
    }

    for (const { label, node } of checks) {
      if (!isUnsanitizedDynamicPrompt(node)) continue;
      const line = node.getStartLineNumber();
      out.push(
        buildCandidate(ctx, {
          source: "custom",
          ruleId: "ai.prompt-injection-surface",
          category: "prompt_injection",
          file: sf.getFilePath().replace(/^\//, ""),
          line,
          rawSeverity: "high",
          snippet: node.getText().slice(0, 200),
          title: `Unsanitized dynamic content reaches the LLM call's ${label} context`,
          metadata: { detector: "ai-security", check: "prompt-injection-surface", field: label },
        }),
      );
    }
  }
  return out;
}

/* ---------------------------------------------------------------------- */
/* 2. Unsafe tool / function exposure                                     */
/* ---------------------------------------------------------------------- */

const DANGEROUS_TOOL_MARKERS =
  /exec(?:ute)?|shell|bash|spawn|child_process|command|write_?file|delete_?file|unlink|rm\s|http_?request|fetch_?url|unrestricted|run_?sql|execute_?sql|eval\(/i;

const AUTHZ_GUARD_MARKERS =
  /confirm|authoriz|approval|approve|require[_A-Za-z]*role|permission|allowlist|human[_-]?in[_-]?the[_-]?loop|askUser|guard\(|rbac|sandbox/i;

function detectUnsafeToolExposure(ctx: DetectorContext, sf: SourceFile): CandidateFinding[] {
  const out: CandidateFinding[] = [];
  const fileText = stripComments(sf.getFullText());
  for (const call of findLlmCallSites(sf)) {
    const props = firstArgProperties(call);
    const toolsProp = props.get("tools") ?? props.get("functions");
    if (!toolsProp || !Node.isArrayLiteralExpression(toolsProp)) continue;
    for (const el of toolsProp.getElements()) {
      if (!Node.isObjectLiteralExpression(el)) continue;
      const text = el.getText();
      if (!DANGEROUS_TOOL_MARKERS.test(text)) continue;

      // Look for a referenced handler function in the same file and check its
      // OWN body for a guard marker first (stronger signal); fall back to a
      // whole-file guard scan (weaker — documented) when no handler is found.
      let guarded = false;
      const handlerProp = el
        .getProperties()
        .find(
          (p): p is import("ts-morph").PropertyAssignment =>
            Node.isPropertyAssignment(p) &&
            ["handler", "execute", "run", "fn"].includes(p.getName()),
        );
      const handlerInit = handlerProp?.getInitializer();
      if (handlerInit && Node.isIdentifier(handlerInit)) {
        const fn = sf.getFunctions().find((f) => f.getName() === handlerInit.getText());
        if (fn) guarded = AUTHZ_GUARD_MARKERS.test(stripComments(fn.getBodyText() ?? ""));
        else guarded = AUTHZ_GUARD_MARKERS.test(fileText);
      } else {
        guarded = AUTHZ_GUARD_MARKERS.test(fileText);
      }
      if (guarded) continue;

      out.push(
        buildCandidate(ctx, {
          source: "custom",
          ruleId: "ai.unsafe-tool-exposure",
          category: "broken_access_control",
          file: sf.getFilePath().replace(/^\//, ""),
          line: el.getStartLineNumber(),
          rawSeverity: "high",
          snippet: text.slice(0, 200),
          title:
            "LLM-exposed tool grants a dangerous capability with no visible authorization gate",
          metadata: { detector: "ai-security", check: "unsafe-tool-exposure" },
        }),
      );
    }
  }
  return out;
}

/* ---------------------------------------------------------------------- */
/* 3. Unescaped LLM output rendered to users                              */
/* ---------------------------------------------------------------------- */

/** Local identifiers whose value derives from an LLM call result (one hop
 *  through a `const`/`let` initializer referencing an already-tracked var). */
function collectLlmResponseVars(sf: SourceFile, callSites: readonly CallExpression[]): Set<string> {
  const vars = new Set<string>();
  const isLlmCallText = (node: Node): boolean =>
    callSites.some((c) => node.getPos() <= c.getPos() && node.getEnd() >= c.getEnd());

  for (const decl of allVariableDeclarations(sf)) {
    const init = decl.getInitializer();
    if (!init) continue;
    const name = decl.getNameNode();
    if (!Node.isIdentifier(name)) continue;
    const unwrapped = Node.isAwaitExpression(init) ? init.getExpression() : init;
    if (Node.isCallExpression(unwrapped) && isLlmCallText(unwrapped)) {
      vars.add(name.getText());
    }
  }
  // One more hop: `const html = response.content[0].text` where `response` is
  // already tracked.
  let grew = true;
  while (grew) {
    grew = false;
    for (const decl of allVariableDeclarations(sf)) {
      const init = decl.getInitializer();
      const name = decl.getNameNode();
      if (!init || !Node.isIdentifier(name) || vars.has(name.getText())) continue;
      const root =
        leftmostIdentifier(init) ?? (Node.isIdentifier(init) ? init.getText() : undefined);
      if (root && vars.has(root)) {
        vars.add(name.getText());
        grew = true;
      }
    }
  }
  return vars;
}

function referencesTrackedVar(node: Node, tracked: ReadonlySet<string>): boolean {
  if (Node.isIdentifier(node)) return tracked.has(node.getText());
  for (const id of node.getDescendantsOfKind(SyntaxKind.Identifier)) {
    if (tracked.has(id.getText())) return true;
  }
  return false;
}

function detectUnescapedLlmOutput(
  ctx: DetectorContext,
  sf: SourceFile,
  responseVars: ReadonlySet<string>,
): CandidateFinding[] {
  if (responseVars.size === 0) return [];
  const out: CandidateFinding[] = [];

  // JSX `dangerouslySetInnerHTML={{ __html: <expr> }}`.
  for (const attr of sf.getDescendantsOfKind(SyntaxKind.JsxAttribute)) {
    if (attr.getNameNode().getText() !== "dangerouslySetInnerHTML") continue;
    const init = attr.getInitializer();
    if (!init || !Node.isJsxExpression(init)) continue;
    const expr = init.getExpression();
    if (!expr || !Node.isObjectLiteralExpression(expr)) continue;
    const htmlProp = expr
      .getProperties()
      .find(
        (p): p is import("ts-morph").PropertyAssignment =>
          Node.isPropertyAssignment(p) && p.getName() === "__html",
      );
    const htmlInit = htmlProp?.getInitializer();
    if (htmlInit && referencesTrackedVar(htmlInit, responseVars)) {
      out.push(
        buildCandidate(ctx, {
          source: "custom",
          ruleId: "ai.unescaped-llm-output-xss",
          category: "xss",
          file: sf.getFilePath().replace(/^\//, ""),
          line: attr.getStartLineNumber(),
          rawSeverity: "high",
          snippet: attr.getText().slice(0, 200),
          title: "LLM response rendered via dangerouslySetInnerHTML with no escaping",
          metadata: {
            detector: "ai-security",
            check: "unescaped-llm-output",
            sink: "dangerouslySetInnerHTML",
          },
        }),
      );
    }
  }

  // `el.innerHTML = <expr>` assignment.
  for (const bin of sf.getDescendantsOfKind(SyntaxKind.BinaryExpression)) {
    if (bin.getOperatorToken().getText() !== "=") continue;
    const left = bin.getLeft();
    if (!Node.isPropertyAccessExpression(left) || left.getName() !== "innerHTML") continue;
    const right = bin.getRight();
    if (referencesTrackedVar(right, responseVars)) {
      out.push(
        buildCandidate(ctx, {
          source: "custom",
          ruleId: "ai.unescaped-llm-output-xss",
          category: "xss",
          file: sf.getFilePath().replace(/^\//, ""),
          line: bin.getStartLineNumber(),
          rawSeverity: "high",
          snippet: bin.getText().slice(0, 200),
          title: "LLM response assigned directly to innerHTML with no escaping",
          metadata: { detector: "ai-security", check: "unescaped-llm-output", sink: "innerHTML" },
        }),
      );
    }
  }
  return out;
}

/* ---------------------------------------------------------------------- */
/* 4. Secrets leaking into prompts                                        */
/* ---------------------------------------------------------------------- */

/** Same well-known credential shapes as `secrets.ts`'s `SECRET_RULES`, scoped
 *  here to an LLM call's OWN argument list rather than the whole file — a
 *  distinct risk (the secret leaves the target's infra to a third-party LLM
 *  provider), not a duplicate of the general hardcoded-secret detector. */
const SECRET_VALUE_PATTERNS: ReadonlyArray<{ rule: string; re: RegExp }> = [
  { rule: "stripe-live-secret-key", re: /sk_live_[0-9a-zA-Z]{10,}/ },
  { rule: "stripe-test-secret-key", re: /sk_test_[0-9a-zA-Z]{10,}/ },
  { rule: "aws-access-key-id", re: /AKIA[0-9A-Z]{16}/ },
  { rule: "google-api-key", re: /AIza[0-9A-Za-z\-_]{35}/ },
  { rule: "slack-token", re: /xox[baprs]-[0-9A-Za-z-]{10,}/ },
  { rule: "github-token", re: /gh[pousr]_[0-9A-Za-z]{20,}/ },
];

const SECRET_NAME_RE = /(api[_-]?key|secret|password|passwd|token|credential)/i;

function detectSecretsIntoPrompt(ctx: DetectorContext, sf: SourceFile): CandidateFinding[] {
  const out: CandidateFinding[] = [];
  for (const call of findLlmCallSites(sf)) {
    for (const arg of call.getArguments()) {
      for (const strLit of [
        ...arg.getDescendantsOfKind(SyntaxKind.StringLiteral),
        ...arg.getDescendantsOfKind(SyntaxKind.NoSubstitutionTemplateLiteral),
      ]) {
        const text = strLit.getLiteralText();
        const hit = SECRET_VALUE_PATTERNS.find((p) => p.re.test(text));
        if (!hit) continue;
        out.push(
          buildCandidate(ctx, {
            source: "custom",
            ruleId: "ai.secret-into-prompt",
            category: "sensitive_data_exposure",
            file: sf.getFilePath().replace(/^\//, ""),
            line: strLit.getStartLineNumber(),
            rawSeverity: "critical",
            snippet: `hardcoded ${hit.rule} interpolated into an LLM call (value redacted)`,
            title: "Hardcoded credential flows into an LLM prompt (leaves the trust boundary)",
            metadata: { detector: "ai-security", check: "secret-into-prompt", rule: hit.rule },
          }),
        );
      }

      // process.env.<NAME> or an identifier whose own name looks secret-shaped,
      // referenced inside a template-literal interpolation within the call args.
      for (const span of arg.getDescendantsOfKind(SyntaxKind.TemplateSpan)) {
        const exprText = span.getExpression().getText();
        const envMatch = /process\.env\.([A-Za-z0-9_]+)/.exec(exprText);
        const name = envMatch?.[1] ?? exprText;
        if (!SECRET_NAME_RE.test(name)) continue;
        out.push(
          buildCandidate(ctx, {
            source: "custom",
            ruleId: "ai.secret-into-prompt",
            category: "sensitive_data_exposure",
            file: sf.getFilePath().replace(/^\//, ""),
            line: span.getStartLineNumber(),
            rawSeverity: "high",
            snippet: `credential-shaped value ('${name}') interpolated into an LLM call`,
            title: "Secret-shaped value flows into an LLM prompt (leaves the trust boundary)",
            metadata: { detector: "ai-security", check: "secret-into-prompt", variable: name },
          }),
        );
      }
    }
  }
  return out;
}

/* ---------------------------------------------------------------------- */
/* 5. Missing output validation                                           */
/* ---------------------------------------------------------------------- */

/** Sensitive sink recognized downstream of an LLM response, and the CATEGORY
 *  the finding takes — the underlying exploitation mechanics and remediation
 *  are the SAME as tainted user input reaching that sink kind; what's new is
 *  the taint SOURCE (an LLM response), captured via `metadata.aiSource`. */
const OUTPUT_SINKS: ReadonlyArray<{ suffix: string; category: Category; label: string }> = [
  { suffix: "queryRawUnsafe", category: "sql_injection", label: "raw SQL query" },
  { suffix: "executeRawUnsafe", category: "sql_injection", label: "raw SQL query" },
  { suffix: "exec", category: "command_injection", label: "shell command" },
  { suffix: "execSync", category: "command_injection", label: "shell command" },
  { suffix: "spawn", category: "command_injection", label: "shell command" },
  { suffix: "readFile", category: "path_traversal", label: "file path" },
  { suffix: "readFileSync", category: "path_traversal", label: "file path" },
  { suffix: "writeFile", category: "path_traversal", label: "file path" },
  { suffix: "writeFileSync", category: "path_traversal", label: "file path" },
];

const VALIDATION_MARKER_RE =
  /\.parse\(|\.safeParse\(|JSON\.parse\(|validate\(|sanitiz|sanitis|allowlist|whitelist|\.includes\(|switch\s*\(/;

function detectMissingOutputValidation(
  ctx: DetectorContext,
  sf: SourceFile,
  responseVars: ReadonlySet<string>,
): CandidateFinding[] {
  if (responseVars.size === 0) return [];
  const out: CandidateFinding[] = [];
  const fileText = stripComments(sf.getFullText());

  for (const call of sf.getDescendantsOfKind(SyntaxKind.CallExpression)) {
    const expr = call.getExpression();
    const name = Node.isPropertyAccessExpression(expr) ? expr.getName() : expr.getText();
    const sink = OUTPUT_SINKS.find((s) => s.suffix === name);
    if (!sink) continue;
    const args = call.getArguments();
    const taintedArg = args.find((a) => referencesTrackedVar(a, responseVars));
    if (!taintedArg) continue;

    // Same-file heuristic: does ANY tracked response identifier ever pass
    // through a recognized validation/allowlist marker anywhere in the file?
    // (Same fail-safe-leaning shape as the rest of this codebase's window
    // checks — deliberately whole-file rather than strictly "before the sink
    // line", since a validation helper is commonly defined and called ahead
    // of its use but source order across hoisted functions is not reliable.)
    const validated = VALIDATION_MARKER_RE.test(fileText);
    if (validated) continue;

    out.push(
      buildCandidate(ctx, {
        source: "custom",
        ruleId: `ai.missing-output-validation.${sink.category}`,
        category: sink.category,
        file: sf.getFilePath().replace(/^\//, ""),
        line: call.getStartLineNumber(),
        rawSeverity: "high",
        snippet: call.getText().slice(0, 200),
        title: `LLM response used to drive a ${sink.label} with no parse/validate/allowlist check`,
        metadata: {
          detector: "ai-security",
          check: "missing-output-validation",
          aiSource: true,
          sinkFn: name,
        },
      }),
    );
  }
  return out;
}

/* ---------------------------------------------------------------------- */
/* Entry point                                                            */
/* ---------------------------------------------------------------------- */

/**
 * Run the AI-application security agent over every parseable TS/JS source
 * file. Single-file analysis only (no cross-file taint) — see the module doc
 * comment for why, mirroring `sca.ts`'s `collectCalledPackages` scope.
 */
export async function detectAiSecurity(ctx: DetectorContext): Promise<CandidateFinding[]> {
  if (ctx.signal?.aborted) return [];
  const sources = await readAll(ctx.files, isSourceFile);
  if (sources.length === 0) return [];

  const project = new Project({
    useInMemoryFileSystem: true,
    skipFileDependencyResolution: true,
    skipLoadingLibFiles: true,
    compilerOptions: {
      allowJs: true,
      jsx: ts.JsxEmit.Preserve,
      noLib: true,
      target: ts.ScriptTarget.Latest,
    },
  });
  for (const file of sources) {
    try {
      project.createSourceFile(file.path, file.content, { overwrite: true });
    } catch {
      /* unparsable/oversized file -> skip; other files still contribute */
    }
  }

  const out: CandidateFinding[] = [];
  for (const sf of project.getSourceFiles()) {
    if (ctx.signal?.aborted) break;
    const callSites = findLlmCallSites(sf);
    out.push(...detectPromptInjectionSurface(ctx, sf));
    out.push(...detectUnsafeToolExposure(ctx, sf));
    out.push(...detectSecretsIntoPrompt(ctx, sf));
    const responseVars = collectLlmResponseVars(sf, callSites);
    out.push(...detectUnescapedLlmOutput(ctx, sf, responseVars));
    out.push(...detectMissingOutputValidation(ctx, sf, responseVars));
  }
  return out;
}
