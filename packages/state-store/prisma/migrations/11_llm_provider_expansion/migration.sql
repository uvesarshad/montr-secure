-- A3: LLM gateway supports only the Anthropic model family (contracts'
-- ProviderSchema, packages/contracts/src/llm.ts) admitted only anthropic,
-- bedrock, vertex, azure — four transport routes to one model family. This
-- adds the six BYO-key providers now reached through the generic
-- OpenAiCompatibleAdapter (packages/llm-gateway/src/adapters/openai-compatible.ts):
-- openai, google, xai, moonshot, zhipu, deepseek.
-- STRICTLY ADDITIVE — no existing enum value is removed or renamed, so every
-- existing LlmCredential row keeps working; consumers just gained six more
-- values to handle (mirrors migration 7_prompt_injection_category's and
-- 8_insecure_configuration_category's additive-enum precedent).

-- AlterEnum
ALTER TYPE "Provider" ADD VALUE 'openai';
ALTER TYPE "Provider" ADD VALUE 'google';
ALTER TYPE "Provider" ADD VALUE 'xai';
ALTER TYPE "Provider" ADD VALUE 'moonshot';
ALTER TYPE "Provider" ADD VALUE 'zhipu';
ALTER TYPE "Provider" ADD VALUE 'deepseek';
