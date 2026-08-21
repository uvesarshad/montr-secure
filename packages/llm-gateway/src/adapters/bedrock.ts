import { ProviderNotConfiguredError, type LLMRequest, type LLMStreamEvent } from "@montr/contracts";
import type { MontrConfig } from "@montr/config";
import { buildAnthropicStyleFields } from "../mapping.js";
import {
  mapAnthropicMessage,
  mapAnthropicStream,
  type AnthropicMessageLike,
  type AnthropicStreamEventLike,
} from "./anthropic.js";
import { type AdapterCompletion, type ProviderAdapter } from "./types.js";
import { type AdapterEgress } from "./egress.js";

/** Resolve the Bedrock Runtime host that will be contacted (env-configured region). */
function bedrockDefaultEndpoint(): string {
  const region = process.env.AWS_REGION ?? process.env.AWS_DEFAULT_REGION;
  return region
    ? `https://bedrock-runtime.${region}.amazonaws.com`
    : "https://bedrock-runtime.amazonaws.com";
}

/**
 * AWS Bedrock adapter (`@aws-sdk/client-bedrock-runtime`). Uses the Bedrock
 * InvokeModel path with the Anthropic Messages body (`bedrock-2023-05-31`), so
 * it reuses the Anthropic response/stream mapping. Credentials come from the
 * standard AWS chain; region from `AWS_REGION`. Model ids get the `anthropic.`
 * provider prefix.
 */

/** Low-level transport: decodes Bedrock response bytes into Anthropic-shaped JSON. */
export interface BedrockTransport {
  invoke(modelId: string, body: string, signal?: AbortSignal): Promise<AnthropicMessageLike>;
  invokeStream(
    modelId: string,
    body: string,
    signal?: AbortSignal,
  ): AsyncIterable<AnthropicStreamEventLike>;
}

export const BEDROCK_ANTHROPIC_VERSION = "bedrock-2023-05-31";

function buildBedrockBody(request: LLMRequest, modelId: string): string {
  // Bedrock's InvokeModel path takes the same Anthropic Messages body as the
  // native API (tools, output_config.effort/format, thinking, cache_control
  // on system all carry over — Bedrock's Claude models accept the identical
  // fields) plus the Bedrock-specific `anthropic_version` envelope field.
  const body: Record<string, unknown> = {
    anthropic_version: BEDROCK_ANTHROPIC_VERSION,
    ...buildAnthropicStyleFields(request, modelId),
  };
  return JSON.stringify(body);
}

export interface BedrockAdapterOptions {
  config: MontrConfig;
  /** Injectable transport (tests). Defaults to a real Bedrock Runtime client. */
  transport?: BedrockTransport;
  /** ⛔ Egress guard asserted before every outbound request (golden rule #1). */
  egress?: AdapterEgress;
}

export class BedrockAdapter implements ProviderAdapter {
  readonly provider = "bedrock" as const;
  private transport?: BedrockTransport;

  constructor(private readonly options: BedrockAdapterOptions) {
    this.transport = options.transport;
  }

  private async getTransport(): Promise<BedrockTransport> {
    if (!this.transport) this.transport = await createDefaultBedrockTransport(this.options.config);
    return this.transport;
  }

  /** ⛔ Assert the outbound Bedrock host is the configured endpoint before dispatch. */
  private assertEgress(): void {
    this.options.egress?.assert(this.options.config.llm.endpoint ?? bedrockDefaultEndpoint());
  }

  /** First-party Claude ids get the `anthropic.` Bedrock prefix; others pass through. */
  resolveModelId(modelId: string): string {
    return modelId.includes(".") ? modelId : `anthropic.${modelId}`;
  }

  async complete(
    request: LLMRequest,
    modelId: string,
    signal?: AbortSignal,
  ): Promise<AdapterCompletion> {
    this.assertEgress();
    const transport = await this.getTransport();
    const msg = await transport.invoke(
      this.resolveModelId(modelId),
      buildBedrockBody(request, modelId),
      signal,
    );
    return mapAnthropicMessage(msg, modelId);
  }

  async *stream(
    request: LLMRequest,
    modelId: string,
    signal?: AbortSignal,
  ): AsyncGenerator<LLMStreamEvent> {
    this.assertEgress();
    const transport = await this.getTransport();
    const events = transport.invokeStream(
      this.resolveModelId(modelId),
      buildBedrockBody(request, modelId),
      signal,
    );
    yield* mapAnthropicStream(events);
  }
}

async function createDefaultBedrockTransport(config: MontrConfig): Promise<BedrockTransport> {
  const region = process.env.AWS_REGION ?? process.env.AWS_DEFAULT_REGION;
  if (!region) {
    throw new ProviderNotConfiguredError("AWS region not configured (AWS_REGION) for Bedrock", {
      provider: "bedrock",
    });
  }
  const mod = (await import("@aws-sdk/client-bedrock-runtime")) as unknown as {
    BedrockRuntimeClient: new (cfg: Record<string, unknown>) => {
      send: (
        command: unknown,
        options?: { abortSignal?: AbortSignal },
      ) => Promise<{ body?: unknown }>;
    };
    InvokeModelCommand: new (input: Record<string, unknown>) => unknown;
    InvokeModelWithResponseStreamCommand: new (input: Record<string, unknown>) => unknown;
  };
  const client = new mod.BedrockRuntimeClient({
    region,
    ...(config.llm.endpoint ? { endpoint: config.llm.endpoint } : {}),
  });
  const decode = (bytes: Uint8Array): unknown => JSON.parse(new TextDecoder().decode(bytes));

  return {
    async invoke(modelId, body, signal) {
      const cmd = new mod.InvokeModelCommand({
        modelId,
        body,
        contentType: "application/json",
        accept: "application/json",
      });
      const res = await client.send(cmd, signal ? { abortSignal: signal } : undefined);
      return decode(res.body as Uint8Array) as AnthropicMessageLike;
    },
    async *invokeStream(modelId, body, signal) {
      const cmd = new mod.InvokeModelWithResponseStreamCommand({
        modelId,
        body,
        contentType: "application/json",
        accept: "application/json",
      });
      const res = await client.send(cmd, signal ? { abortSignal: signal } : undefined);
      const stream = res.body as AsyncIterable<{ chunk?: { bytes?: Uint8Array } }> | undefined;
      if (!stream) return;
      for await (const event of stream) {
        const bytes = event.chunk?.bytes;
        if (bytes) yield decode(bytes) as AnthropicStreamEventLike;
      }
    },
  };
}
