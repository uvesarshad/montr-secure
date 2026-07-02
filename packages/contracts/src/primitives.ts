import { z } from "zod";

/**
 * Shared primitive schemas used across the whole data model.
 * Kept unbranded (plain validated strings/numbers) so fixtures and downstream
 * agents can construct values ergonomically while still validating at runtime.
 */

/** Opaque entity identifier (ULID/UUID/nanoid — validated as a non-empty string). */
export const IdSchema = z.string().min(1);
export type Id = z.infer<typeof IdSchema>;

/** ISO-8601 timestamp, e.g. "2026-07-02T12:00:00.000Z". */
export const IsoDateTimeSchema = z.string().datetime({ offset: true });
export type IsoDateTime = z.infer<typeof IsoDateTimeSchema>;

/** Git commit SHA (short or full). */
export const CommitShaSchema = z.string().regex(/^[0-9a-f]{7,64}$/i, "invalid commit sha");
export type CommitSha = z.infer<typeof CommitShaSchema>;

/** Repository-relative POSIX file path. */
export const FilePathSchema = z.string().min(1);
export type FilePath = z.infer<typeof FilePathSchema>;

/** 1-indexed source line. 0 is permitted for "whole file / not applicable". */
export const LineNumberSchema = z.number().int().nonnegative();
export type LineNumber = z.infer<typeof LineNumberSchema>;

/** Absolute or relative URL. */
export const UrlSchema = z.string().url();
export type Url = z.infer<typeof UrlSchema>;

/** Normalized score in [0, 1]. Used for reachability/exposure/impact ranking. */
export const Score01Schema = z.number().min(0).max(1);
export type Score01 = z.infer<typeof Score01Schema>;

/** Semver-ish version string (loose). */
export const VersionSchema = z.string().min(1);
export type Version = z.infer<typeof VersionSchema>;

/** A precise location in source code. */
export const SourceLocationSchema = z.object({
  file: FilePathSchema,
  line: LineNumberSchema,
  endLine: LineNumberSchema.optional(),
  column: LineNumberSchema.optional(),
  endColumn: LineNumberSchema.optional(),
  symbol: z.string().optional(),
});
export type SourceLocation = z.infer<typeof SourceLocationSchema>;
