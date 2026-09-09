# External Services and Integrations

Scope: Third-party APIs, LLM providers, VCS integrations, vulnerability data feeds, and secret managers.
Rendering context: Server
Project tier: 4
Last updated: auto

Overview
Montr Secure integrates with external services under a strict default-deny network egress policy. Source code only exits the customer perimeter when communicating with the customer BYO-key LLM endpoint. Additional integrations include Git version control platforms for automated pull request creation, vulnerability databases for dependency reachability analysis, and HashiCorp Vault for dynamic secret resolution.

Upstream LLM Providers in packages/llm-gateway
Anthropic: Native adapter in packages/llm-gateway/src/adapters/anthropic.ts. Uses Claude Opus 4.8 for confirmation proofs, Claude Sonnet 5 for default analysis and fix generation, and Claude Haiku 4.5 for rapid triage.
AWS Bedrock: Bedrock adapter in packages/llm-gateway/src/adapters/bedrock.ts supporting Claude model deployments in customer AWS accounts.
GCP Vertex AI: Google Cloud Vertex AI adapter in packages/llm-gateway/src/adapters/vertex.ts.
Azure OpenAI: Azure OpenAI adapter in packages/llm-gateway/src/adapters/azure.ts.
Direct OpenAI, Google Gemini, xAI Grok, Moonshot Kimi, Zhipu GLM, DeepSeek (A3): one generic OpenAiCompatibleAdapter in packages/llm-gateway/src/adapters/openai-compatible.ts covers all six — the openai SDK pointed at each provider's own base URL with a Bearer key, sharing azure.ts's request-body builder and tool-call parser rather than a second copy. Moonshot, Zhipu, and DeepSeek default to the data_retaining key tier (packages/llm-gateway/src/keytier.ts) absent an operator-declared enterprise tier.
Rate Limits and Fallbacks: packages/llm-gateway/src/retry.ts implements exponential backoff with jitter on HTTP 429 rate limit responses. Key-tier safety guards flag data-retaining consumer keys.

Version Control Systems in packages/report
GitHub: VCS adapter in packages/report/src/vcs.ts communicating with the GitHub REST API. Creates isolated remediation branches, commits synthesized diff patches, and opens automated pull requests for auto-eligible fixes.
GitLab: VCS adapter in packages/report/src/vcs.ts creating branches and merge requests via GitLab API v4.
GitHub PR comment (A15): packages/report/src/vcs.ts also exports postGitHubComment, a small additive function using the same lazily-imported @octokit/rest client as the auto-fix PR opener but calling issues.createComment against an arbitrary existing PR/issue rather than opening one. Used by apps/api's webhook scan trigger (docs/api/route-handlers.md) to post a single acknowledgement summary comment, not per-line review annotations; posting the confirmed-findings summary itself once a webhook-triggered scan completes is not yet wired (would require apps/worker's Layer 5 to persist and read back the originating PR reference) and is deferred.
Authentication: VCS personal access tokens or OAuth tokens are provided per scan or loaded from environment variables and encrypted at rest in Postgres.

Vulnerability Feeds and Security Databases
Open Source Vulnerabilities (OSV): Queried by packages/discovery/src/advisories.ts to match manifest package versions against known advisory identifiers (CVE and GHSA).
Air-Gapped Mirror: For disconnected installations, advisory databases are packaged into signed offline archives using deploy/airgap/build-bundle.sh and imported locally without outbound network access.

Secret Management and Key Resolvers
HashiCorp Vault: Dynamic key resolution in packages/config/src/key-source.ts connecting to Vault KV v2 secrets engines over HTTPS. Authenticates using static tokens or AppRole credentials (role ID and secret ID) to fetch AES-256-GCM field encryption keys at startup.

Update Triggers
Update this file when a new LLM provider adapter is added to packages/llm-gateway, when VCS platform integrations are modified in packages/report, or when external vulnerability data sources evolve.

Related Docs
docs/modules/llm-gateway.md — LLM gateway architecture and model matrix.
docs/infra/environment.md — Environment variables configuring external service credentials.
