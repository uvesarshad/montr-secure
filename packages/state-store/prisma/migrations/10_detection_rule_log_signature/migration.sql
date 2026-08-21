-- B4: adds `DetectionRule.logSignature`, the "what this looks like in your
-- logs" narrative (packages/report/src/detection-rules builds these
-- alongside B3's rule `content`) — concrete fields to alert on, the log
-- pattern, and expected false-alarm sources, as a nullable Json column
-- (DetectionLogSignatureSchema, @montr/contracts). STRICTLY ADDITIVE and
-- nullable — pre-B4 DetectionRule rows (B1/B3-only, no B4 narrative yet)
-- read back as `logSignature: null`, no backfill required.

-- AlterTable
ALTER TABLE "DetectionRule" ADD COLUMN "logSignature" JSONB;
