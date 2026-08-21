/**
 * Embedding generation (E5) — turns AST chunks into vectors via an injected
 * `EmbeddingProviderAdapter` (@montr/llm-gateway/embeddings.ts). Batched to
 * keep individual provider requests bounded; a chunk whose embedding call
 * fails is dropped with a warning rather than failing the whole build (an
 * index build should degrade — fewer chunks indexed — not crash a Layer 0
 * run over one bad embedding call).
 */
import type { EmbeddingCallMetadata, EmbeddingProviderAdapter } from "@montr/llm-gateway";
import type { CodeChunkDraft, EmbeddedCodeChunk } from "./types.js";

/** Conservative default: well under every major provider's per-request input-count limit. */
export const DEFAULT_EMBED_BATCH_SIZE = 64;

export interface EmbedChunksOptions {
  batchSize?: number;
  metadata: EmbeddingCallMetadata;
  /** Called once per chunk that failed to embed (e.g. for a structured log at the call site). */
  onError?: (chunk: CodeChunkDraft, error: unknown) => void;
}

function batches<T>(items: T[], size: number): T[][] {
  const out: T[][] = [];
  for (let i = 0; i < items.length; i += size) out.push(items.slice(i, i + size));
  return out;
}

/**
 * Embed every chunk in `chunks`, batching requests to the adapter. Returns
 * only the chunks that successfully got an embedding, in no particular
 * order relative to input (batches may complete/fail independently).
 */
export async function embedChunks(
  adapter: EmbeddingProviderAdapter,
  model: string,
  chunks: CodeChunkDraft[],
  opts: EmbedChunksOptions,
): Promise<EmbeddedCodeChunk[]> {
  if (chunks.length === 0) return [];
  const batchSize = opts.batchSize ?? DEFAULT_EMBED_BATCH_SIZE;
  const result: EmbeddedCodeChunk[] = [];

  for (const batch of batches(chunks, batchSize)) {
    try {
      const response = await adapter.embed({
        input: batch.map((c) => c.content),
        model,
        metadata: opts.metadata,
      });
      for (let i = 0; i < batch.length; i++) {
        const chunk = batch[i];
        const embedding = response.embeddings[i];
        if (!chunk || !embedding) continue;
        result.push({ ...chunk, embedding, embeddingModel: response.model });
      }
    } catch (err) {
      // One bad batch shouldn't sink the whole build — surface it per-chunk
      // and keep going with the next batch.
      for (const chunk of batch) opts.onError?.(chunk, err);
    }
  }

  return result;
}
