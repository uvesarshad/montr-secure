# Deployment Architecture

Scope: Deployment modes, container orchestration, Kubernetes Helm charts, and air-gapped installation procedures.
Rendering context: Server
Project tier: 4
Last updated: auto

Overview
Montr Secure deploys entirely within customer-managed on-premises or cloud perimeters across three supported operational modes. Deployments can run via Docker Compose on single virtual machines, Kubernetes clusters managed with Helm 3, or fully isolated air-gapped environments using offline signed security rule bundles. All deployment manifests enforce strict security postures including non-root execution, read-only root filesystems, dropped Linux capabilities, and default-deny egress policies allowing traffic exclusively to the designated LLM endpoint.

Deployment Targets
Docker Compose Mode: Defined in deploy/docker/docker-compose.yml, this mode launches five co-located services: apps/api on port 3001, apps/web on port 3000, apps/worker for pipeline execution, PostgreSQL 16 for durable state, and Redis 7 for BullMQ queues. Named Docker volumes persist database records, Redis snapshots, and local scanner caches.
Kubernetes Helm Chart: Located in deploy/helm/montr-secure, the chart manages Deployment objects, ClusterIP Services, Ingress routes, HorizontalPodAutoscalers, and PodDisruptionBudgets. It includes hardened Kubernetes security contexts with automountServiceAccountToken disabled, readOnlyRootFilesystem enabled with emptyDir temporary volumes for worker workspaces, and dedicated ServiceAccounts per workload.
Air-Gapped Installation: Managed via scripts in deploy/airgap, this mode enables execution in disconnected networks. The build-bundle script creates Cosign-signed tar archives containing deterministic Semgrep rulesets and vulnerability advisory mirrors. The import-bundle script cryptographically verifies bundle signatures or SHA-256 checksums before deploying rule packages.

Build-Time and Runtime Differences
Build-Time Config: Dockerfiles located in deploy/docker build multi-stage images. Dockerfile.web consumes NEXT_PUBLIC_API_BASE_URL as a build argument to inline the API endpoint into the client JavaScript bundle. Dockerfile.worker installs runtime scanner binaries including Semgrep, Gitleaks, and OSV Scanner into the container image.
Runtime Config: Services dynamically resolve database connections, Redis URLs, JWT and CSRF secrets, and BYO-key LLM provider credentials via environment variables or mounted HashiCorp Vault secrets loaded at process initialization.

Infrastructure Dependencies and Network Security
PostgreSQL: Primary relational datastore storing scans, app maps, findings, fixes, audit logs, and encrypted credentials.
Redis: Message broker for BullMQ job queues, distributed scan locking, and cross-process kill switch event propagation.
Egress Firewall: NetworkPolicy manifests and packages/security/src/egress-guard.ts enforce default-deny egress policies. The only permitted outbound connection is direct communication with the client LLM provider or an internal model proxy.
Health Probes: Both apps/api and apps/web expose unauthenticated GET /health endpoints targeted by Kubernetes liveness and readiness probes and Docker healthchecks.

Environment Promotion Path
Development: Local execution using pnpm dev commands with in-process or local Redis and Postgres instances.
Staging: Automated deployment via Helm to staging Kubernetes namespaces where live DAST target testing and Golden Corpus regression validation occur.
Production: Promotion to production Kubernetes namespaces with locked DAST policies blocking live production testing, enforceModelFloor enabled, and budget hard-halt enforcement active.

Update Triggers
Update this file when Dockerfile definitions change in deploy/docker, when Kubernetes manifests or values.yaml change in deploy/helm/montr-secure, when air-gapped bundling workflows evolve in deploy/airgap, or when runtime infrastructure dependencies change.

Related Docs
docs/infra/environment.md — Environment variables configured across deployment environments.
docs/modules/orchestration.md — Worker process execution and queue management across deployments.
