/**
 * @montr/fixtures — shared, DETERMINISTIC test fixtures + mocks. Unblocks all
 * parallel work: every downstream package builds and tests against these instead
 * of another agent's live code (golden rule #9). All fixtures are validated
 * against @montr/contracts schemas on load.
 */
export * from "./ids.js";
export * from "./appmap.js";
export * from "./findings.js";
export * from "./cost.js";
export * from "./scan.js";
export * from "./fixes.js";
export * from "./report.js";
export * from "./llm.js";
export * from "./manifest.js";
