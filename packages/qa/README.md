# @montr/qa — QA harness + golden-corpus gate (WS-P)

Precision/recall scoring and the CI regression gate for Montr Secure
(build-plan §4.7, PRD §15/§19). Deterministic, offline (no Postgres/Redis/network),
metadata-only output (golden rule #1), and provider-agnostic — model access is
only ever through the `@montr/contracts` `LLMGateway` interface (golden rule #2).

## What it provides

- **Scorer** (`scorer.ts`) — compares a scan's `ConfirmedFinding[]` against the
  golden-corpus ground truth and reports precision, recall, and the headline
  **false-positive rate** (target < 5%), overall and **per category**. A confirmed
  finding matches a label on category + file + line (within a tolerance).
  `exploitable: false` labels must be demoted, not confirmed (over-confirmation
  counts as a false positive).
- **Corpus loader** (`corpus.ts`) — merges the `@montr/fixtures` seed repos with
  the expanded `corpus/` repos into one validated manifest, resolving each repo
  to an on-disk path and cross-checking with `fast-glob`.
- **Baseline gate** (`baseline.ts`) — reads a committed threshold file
  (`corpus/baseline.json`) and reports every breach. Drives the CLI exit code.
- **Model-variance harness** (`model-variance.ts`) — runs the corpus across the
  gateway's models and emits a model matrix, flagging accuracy cliffs that
  justify the model floor (DECIDE-3). Uses the fixtures fake adapter today.
- **Per-layer metrics** (`layer-metrics.ts`) — findings in/out, dedup rate,
  confirmation rate, demotion rate across Layers 1–3.
- **CLI** (`cli.ts`) — the `qa:corpus` entrypoint with clear exit codes for CI.

## CLI

```bash
pnpm --filter @montr/qa qa:corpus                       # self-check (perfect scanner)
pnpm --filter @montr/qa qa:corpus -- --findings scan.json --json
pnpm --filter @montr/qa qa:variance                     # model matrix
```

`--findings <path>` scores real scan output. Shape:

```json
{ "results": [{ "repo": "vulnerable-nextjs", "confirmed": [/* ConfirmedFinding[] */] }] }
```

Exit codes: `0` OK · `1` REGRESSION · `2` USAGE · `3` CORPUS_ERROR · `4` RUNTIME_ERROR.

## Integration point

Today the CLI self-check uses a synthetic "perfect scanner" so the gate is
runnable and green before the pipeline exists. At integration, feed the real
Layer-3 output per repo via `--findings` (or plug a `CorpusScanner` /
`ModelScanner` into `runCorpus` / `runModelVariance`). Nothing else changes —
the scorer, baseline, exit codes, and reports are the stable contract.
