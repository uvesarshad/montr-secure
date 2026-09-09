-- E16: broadened target coverage (IaC/Dockerfile/Kubernetes/Terraform).
-- Adds `insecure_configuration` as a new member of the `Category` enum for
-- IaC misconfigurations that are not themselves a secret, an access-control
-- gap, or a crypto weakness (those reuse hardcoded_secret /
-- broken_access_control / weak_crypto instead) — a container running as
-- root, an unpinned base image tag, ADD-vs-COPY misuse, a Kubernetes pod
-- missing resource limits, or a privileged/hostNetwork/hostPID pod.
-- STRICTLY ADDITIVE — no existing enum value is removed or renamed, so every
-- existing row and every existing `Record<Category, ...>` consumer keeps
-- working; consumers just gained one more key to handle (mirrors migration
-- 7_prompt_injection_category's precedent).

-- AlterEnum
ALTER TYPE "Category" ADD VALUE 'insecure_configuration';
