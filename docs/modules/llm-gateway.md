# Module: LLM Gateway and Cost Metering

Scope: Multi-provider BYO-key LLM client, model matrix routing, key-tier safety guards, prompt management, and real-time cost metering.
Rendering context: Server
Project tier: 4
Last updated: auto

Overview
The LLM Gateway and Cost Meter modules (implemented across packages/llm-gateway and packages/cost-meter) provide a unified, provider-agnostic interface for executing language model operations across the pipeline. Montr Secure enforces a strict bring-your-own-key (BYO-key) architecture, where customer credentials communicate directly with upstream providers (Anthropic, AWS Bedrock, GCP Vertex AI, Azure OpenAI) without intermediary proxies. Cost is treated as a first-class operational metric, tracking token expenditures in real time and enforcing hard-halt budget limits before budget overruns occur.

Entry Points and Gateway Architecture
Gateway Client: packages/llm-gateway/src/gateway.ts exports the LlmGateway service used by all pipeline layers to execute completions.
Cost Meter Service: packages/cost-meter/src/meter.ts exports the CostMeter class, which measures prompt, completion, and cached token usage per request.
Provider Adapters: Located in packages/llm-gateway/src/adapters, containing dedicated API drivers for Anthropic, Bedrock, Vertex AI, and Azure OpenAI.

Model Matrix and Tier Routing
Triage Tier: Managed by packages/llm-gateway/src/models.ts. Routes high-volume filtering in Layer 1 and candidate grouping in Layer 2 to fast, cost-effective models (such as Claude Haiku 4.5).
Default Tier: Routes Layer 0 AST extraction and Layer 4 patch synthesis to balanced models (such as Claude Sonnet 5).
Confirmation Tier: Routes Layer 3 interprocedural static taint proofs to high-capacity reasoning models (such as Claude Opus 4.8). The gateway enforces an accuracy floor, warning operators if sub-floor models are selected.

Key-Tier Safety Guard and Prompt Registry
Key-Tier Guard: packages/llm-gateway/src/keytier.ts inspects API key patterns and metadata to identify consumer or non-enterprise keys that may retain customer data, logging warnings or blocking execution based on configuration.
Prompt Registry: packages/llm-gateway/src/prompts.ts manages versioned prompt templates stored in the PromptVersion database table, allowing regression tracking and template optimization.

Cost Metering and Hard-Halt Enforcement
Pricing Engine: packages/cost-meter/src/pricing.ts maintains up-to-date per-million token pricing tables across input, output, and cached prompt tokens for each supported model.
Pre-Scan Estimation: packages/cost-meter/src/estimate.ts models projected token consumption based on repository size, route counts, and AST complexity during Layer 0.
Real-Time Metering: After every LLM invocation, packages/cost-meter updates the Scan record costActual metrics in Postgres.
Hard-Halt Ceiling: If cumulative dollar or token expenditure breaches configured limits (such as MONTR_BUDGET_MAX_USD), the meter throws a BudgetExceededError, signaling the orchestrator to halt analysis immediately and emit a partial report.

Constraints and Edge Cases
AGENT NOTE: Source SDKs for LLM providers are strictly confined to packages/llm-gateway. No other package or application may import provider SDKs directly.
AGENT AVOID: Never disable budget hard-halt enforcement in production environments.

Update Triggers
Update this file when new provider adapters are added to packages/llm-gateway/src/adapters, when pricing models change in packages/cost-meter/src/pricing.ts, or when the model matrix is updated in packages/contracts/src/llm.ts.

Related Docs
docs/infra/environment.md — Environment variables configuring LLM keys and model choices.
docs/architecture/data-flow.md — Cross-layer LLM interactions and token metering.
