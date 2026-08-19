# Module: Layer 2 Finding Correlation

Scope: Candidate deduplication, structural grounding against the App Map, reachability scoring, and root-cause aggregation.
Rendering context: Server
Project tier: 4
Last updated: auto

Overview
The Correlation module implements Layer 2 of the analysis pipeline within packages/correlation. Known as the core differentiation layer of Montr Secure, it ingests noisy, multi-tool CandidateFinding records from Layer 1 and cross-references them against the structural AppMap produced in Layer 0. Layer 2 eliminates duplicate alerts, verifies route reachability, evaluates authentication exposure, calculates multidimensional risk scores, and generates ranked ProbableFinding records. Candidates that lack plausible exploit paths are demoted to an unconfirmed appendix rather than deleted.

Entry Points and Core Runners
Layer 2 Runner: packages/correlation/src/correlate.ts exports runLayer2Correlation, which orchestrates deduplication, grounding, hypothesis generation, and scoring.
Queue Execution: apps/worker/src/runners.ts pulls Layer 2 jobs from BullMQ and passes candidate records and AppMap graphs to the correlation engine.

Key Components and Scoring Algorithms
Root-Cause Deduplicator: packages/correlation/src/dedup.ts groups candidate findings originating from different tools (such as Semgrep and OSV) that point to the exact same source code location or underlying vulnerability.
Structural Grounder: packages/correlation/src/grounding.ts traces paths from discovered HTTP routes and input sources through the application to the finding location, verifying if user input can genuinely reach the vulnerable code.
Scoring Engine: packages/correlation/src/scoring.ts computes three distinct scoring dimensions: reachability score (0.0 to 1.0 based on route paths and middleware), exposure score (public versus authenticated), and impact score (data leakage or command execution severity). It combines these into an overall numerical rank.
Hypothesis Generator: packages/correlation/src/hypotheses.ts constructs plain-language reachability and exploit hypotheses describing the exact attack path an adversary would take.
Taxonomy Mapper: packages/correlation/src/taxonomy.ts normalizes multi-engine categories into standardized Category enums.

Demote-Never-Delete Architecture
Probable Finding Entity: Validated correlated issues are persisted as ProbableFinding rows in Postgres with scores, rank, exposure, and exploit hypotheses.
Unconfirmed Appendix: Candidate findings that fail reachability verification or represent library dead code are marked with unconfirmed status and given an unconfirmedReason string. They are retained in database records and displayed in report appendixes to maintain complete audit transparency.

Constraints and Edge Cases
AGENT NOTE: Correlation algorithms operate purely on normalized AppMap models and CandidateFinding contracts, remaining strictly independent of programming language syntaxes.
AGENT AVOID: Never delete candidate findings during correlation. Always set status to unconfirmed with an explicit rationale to preserve evidentiary trails.

Update Triggers
Update this file when scoring formulas change in packages/correlation/src/scoring.ts, when grounding heuristics evolve in packages/correlation/src/grounding.ts, or when the ProbableFinding schema changes in packages/contracts/src/findings.ts.

Related Docs
docs/modules/appmap.md — Structural App Map consumed during grounding.
docs/modules/confirmation.md — Confirmation engine validating probable findings.
