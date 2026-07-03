import { ProviderNotConfiguredError, type LLMRequest, type LLMStreamEvent } from "@montr/contracts";
import type { MontrConfig } from "@montr/config";
import {
  collectSystem,
  extractVertexToolCalls,
  mapVertexFinishReason,
  toVertexContents,
  toVertexTools,
  type VertexContent,
  type VertexToolDef,
} from "../mapping.js";
import { makeUsage, type AdapterCompletion, type ProviderAdapter } from "./types.js";
import { type AdapterEgress } from "./egress.js";

/** Resolve the Vertex AI host that will be contacted (env-configured location). */
function vertexDefaultEndpoint(): string {
  const location =
    process.env.GOOGLE_CLOUD_LOCATION ?? process.env.VERTEX_LOCATION ?? "us-central1";
  return `https://${location}-aiplatform.googleapis.com`;
}

/**
 * GCP Vertex AI adapter (`@google-cloud/vertexai`). Maps the unified request to
 * the Vertex generative-model API (system → systemInstruction, messages →
 * contents). Project/location come from GCP env (ADC auth); no Anthropic key.
 */

export interface VertexResponseLike {
  candidates?: Array<{
    content?: {
      parts?: Array<{ text?: string; functionCall?: { name?: string; args?: unknown } }>;
    };
    finishReason?: string;
  }>;
  usageMetadata?: {
    promptTokenCount?: number;
    candidatesTokenCount?: number;
    totalTokenCount?: number;
  };
}

export interface VertexGenerateRequest {
  contents: VertexContent[];
  systemInstruction?: string;
  generationConfig: { maxOutputTokens: number; temperature?: number };
  tools?: VertexToolDef[];
}

export interface VertexTransport {
  generate(
    model: string,
    req: VertexGenerateRequest,
    signal?: AbortSignal,
  ): Promise<VertexResponseLike>;
  generateStream(
    model: string,
    req: VertexGenerateRequest,
    signal?: AbortSignal,
  ): AsyncIterable<VertexResponseLike>;
}

function vertexText(resp: VertexResponseLike): string {
  const parts = resp.candidates?.[0]?.content?.parts ?? [];
  return parts.map((p) => p.text ?? "").join("");
}

function buildRequest(request: LLMRequest): VertexGenerateRequest {
  const req: VertexGenerateRequest = {
    contents: toVertexContents(request),
    generationConfig: { maxOutputTokens: request.maxTokens },
  };
  const system = collectSystem(request);
  if (system) req.systemInstruction = system;
  if (request.temperature !== undefined) req.generationConfig.temperature = request.temperature;
  const tools = toVertexTools(request);
  if (tools) req.tools = tools;
  return req;
}

export interface VertexAdapterOptions {
  config: MontrConfig;
  /** Injectable transport (tests). Defaults to a real Vertex AI client. */
  transport?: VertexTransport;
  /** ⛔ Egress guard asserted before every outbound request (golden rule #1). */
  egress?: AdapterEgress;
}

export class VertexAdapter implements ProviderAdapter {
  readonly provider = "vertex" as const;
  private transport?: VertexTransport;

  constructor(private readonly options: VertexAdapterOptions) {
    this.transport = options.transport;
  }

  private async getTransport(): Promise<VertexTransport> {
    if (!this.transport) this.transport = await createDefaultVertexTransport(this.options.config);
    return this.transport;
  }

  /** ⛔ Assert the outbound Vertex host is the configured endpoint before dispatch. */
  private assertEgress(): void {
    this.options.egress?.assert(this.options.config.llm.endpoint ?? vertexDefaultEndpoint());
  }

  resolveModelId(modelId: string): string {
    return modelId;
  }

  async complete(
    request: LLMRequest,
    modelId: string,
    signal?: AbortSignal,
  ): Promise<AdapterCompletion> {
    this.assertEgress();
    const transport = await this.getTransport();
    const resp = await transport.generate(modelId, buildRequest(request), signal);
    const u = resp.usageMetadata;
    const toolCalls = extractVertexToolCalls(resp.candidates?.[0]?.content?.parts);
    return {
      id: `${modelId}:response`,
      model: modelId,
      content: vertexText(resp),
      // Gemini reports finishReason STOP even when it emits a functionCall, so a
      // present tool call is the authoritative "tool_use" signal.
      stopReason: toolCalls
        ? "tool_use"
        : mapVertexFinishReason(resp.candidates?.[0]?.finishReason),
      ...(toolCalls ? { toolCalls } : {}),
      usage: makeUsage(u?.promptTokenCount ?? 0, u?.candidatesTokenCount ?? 0, {
        totalTokens: u?.totalTokenCount,
      }),
    };
  }

  async *stream(
    request: LLMRequest,
    modelId: string,
    signal?: AbortSignal,
  ): AsyncGenerator<LLMStreamEvent> {
    this.assertEgress();
    const transport = await this.getTransport();
    const events = transport.generateStream(modelId, buildRequest(request), signal);
    let promptTokens = 0;
    let outputTokens = 0;
    let totalTokens: number | undefined;
    let finishReason: string | undefined;

    for await (const resp of events) {
      const text = vertexText(resp);
      if (text) yield { type: "text_delta", text };
      const u = resp.usageMetadata;
      if (u) {
        promptTokens = u.promptTokenCount ?? promptTokens;
        outputTokens = u.candidatesTokenCount ?? outputTokens;
        totalTokens = u.totalTokenCount ?? totalTokens;
      }
      const fr = resp.candidates?.[0]?.finishReason;
      if (fr) finishReason = fr;
    }

    yield {
      type: "message_done",
      usage: makeUsage(promptTokens, outputTokens, { totalTokens }),
      stopReason: mapVertexFinishReason(finishReason),
    };
  }
}

async function createDefaultVertexTransport(config: MontrConfig): Promise<VertexTransport> {
  const project =
    process.env.GOOGLE_CLOUD_PROJECT ?? process.env.GCLOUD_PROJECT ?? process.env.VERTEX_PROJECT;
  const location =
    process.env.GOOGLE_CLOUD_LOCATION ?? process.env.VERTEX_LOCATION ?? "us-central1";
  if (!project) {
    throw new ProviderNotConfiguredError(
      "GCP project not configured (GOOGLE_CLOUD_PROJECT) for Vertex",
      { provider: "vertex" },
    );
  }
  const mod = (await import("@google-cloud/vertexai")) as unknown as {
    VertexAI: new (opts: Record<string, unknown>) => {
      getGenerativeModel: (params: Record<string, unknown>) => {
        generateContent: (req: unknown) => Promise<{ response: VertexResponseLike }>;
        generateContentStream: (
          req: unknown,
        ) => Promise<{ stream: AsyncIterable<VertexResponseLike> }>;
      };
    };
  };
  const vertex = new mod.VertexAI({
    project,
    location,
    ...(config.llm.endpoint ? { apiEndpoint: config.llm.endpoint } : {}),
  });
  const model = (name: string, systemInstruction?: string) =>
    vertex.getGenerativeModel({
      model: name,
      ...(systemInstruction ? { systemInstruction } : {}),
    });

  return {
    async generate(name, req) {
      const gm = model(name, req.systemInstruction);
      const result = await gm.generateContent({
        contents: req.contents,
        generationConfig: req.generationConfig,
        ...(req.tools ? { tools: req.tools } : {}),
      });
      return result.response;
    },
    async *generateStream(name, req) {
      const gm = model(name, req.systemInstruction);
      const result = await gm.generateContentStream({
        contents: req.contents,
        generationConfig: req.generationConfig,
        ...(req.tools ? { tools: req.tools } : {}),
      });
      for await (const item of result.stream) yield item;
    },
  };
}
