-- E11: AI-application security ruleset. Adds `prompt_injection` as a new
-- member of the `Category` enum so Layer 1 detectors can classify LLM-prompt
-- construction, unsafe tool exposure, unescaped LLM output, secret-into-prompt,
-- and missing-output-validation findings distinctly from the generic "other"
-- bucket. STRICTLY ADDITIVE — no existing enum value is removed or renamed,
-- so every existing row and every existing `Record<Category, ...>` consumer
-- keeps working; consumers just gained one more key to handle.

-- AlterEnum
ALTER TYPE "Category" ADD VALUE 'prompt_injection';
