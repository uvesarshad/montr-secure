-- Multi-provider support: extend the Provider enum with the direct BYO-key
-- providers (OpenAI-compatible + Google direct). Idempotent so re-applies are safe.
ALTER TYPE "Provider" ADD VALUE IF NOT EXISTS 'openai';
ALTER TYPE "Provider" ADD VALUE IF NOT EXISTS 'google';
ALTER TYPE "Provider" ADD VALUE IF NOT EXISTS 'xai';
ALTER TYPE "Provider" ADD VALUE IF NOT EXISTS 'moonshot';
ALTER TYPE "Provider" ADD VALUE IF NOT EXISTS 'zhipu';
ALTER TYPE "Provider" ADD VALUE IF NOT EXISTS 'deepseek';
