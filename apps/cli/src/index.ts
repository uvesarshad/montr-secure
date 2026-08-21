/**
 * @montr/cli — the `montr` CLI (A15). This module surface exists for tests
 * and any programmatic embedding; the actual executable is `./main.ts`
 * (`bin: montr`, see package.json).
 */
export { run, parseArgs, USAGE, CLI_EXIT, exitLabel } from "./cli.js";
export { createApiClient, CliApiError } from "./http.js";
export type { MontrApiClient, CreateScanInput, FindingsResult, HttpClientOptions } from "./http.js";
export { detectBranch, detectRepoName, detectChangedFiles } from "./git.js";
