import { describe, it, expect, vi } from "vitest";
import { parseConfig, type MontrConfig } from "@montr/config";
import type { LLMStreamEvent, Provider } from "@montr/contracts";
import { MontrLlmGateway } from "./gateway.js";
import { resolvePromptTemplate, type PromptVersionSource } from "./prompts.js";
import type { AdapterCompletion, ProviderAdapter } from "./adapters/index.js";

/** A no-op adapter — these tests never call complete()/stream(). */
function fakeAdapter(): ProviderAdapter {
  return {
    provider: "anthropic" as Provider,
    resolveModelId: (id: string) => id,
    complete: (): Promise<AdapterCompletion> => {
      throw new Error("not used in these tests");
    },
    stream: (): AsyncIterable<LLMStreamEvent> => {
      throw new Error("not used in these tests");
    },
  };
}

function cfg(clientId = "client_a"): MontrConfig {
  return parseConfig({ clientId, llm: { apiKey: "sk-test", provider: "anthropic" } });
}

/** An in-memory PromptVersionSource — mirrors state-store's getActive() contract. */
function fakeSource(active: Record<string, string | undefined>): PromptVersionSource {
  return {
    getActive: async (name, clientId) => {
      const key = clientId ? `${name}::${clientId}` : name;
      const template = active[key];
      return template !== undefined ? { template } : null;
    },
  };
}

describe("resolvePromptTemplate", () => {
  it("returns the fallback unchanged when no source is configured (today's behavior)", async () => {
    const out = await resolvePromptTemplate(undefined, "fix.system", "HARDCODED");
    expect(out).toBe("HARDCODED");
  });

  it("returns the fallback when the source has no active version for that key", async () => {
    const source = fakeSource({});
    const out = await resolvePromptTemplate(source, "fix.system", "HARDCODED");
    expect(out).toBe("HARDCODED");
  });

  it("returns the DB-active template when the source has one", async () => {
    const source = fakeSource({ "fix.system": "DB VERSION 2" });
    const out = await resolvePromptTemplate(source, "fix.system", "HARDCODED");
    expect(out).toBe("DB VERSION 2");
  });

  it("threads clientId through to the source and prefers the client-scoped result", async () => {
    const source = fakeSource({ "fix.system::client_a": "CLIENT A OVERRIDE" });
    const out = await resolvePromptTemplate(source, "fix.system", "HARDCODED", {
      clientId: "client_a",
    });
    expect(out).toBe("CLIENT A OVERRIDE");
  });

  it("fails safe to the fallback (and reports via onError) when the lookup throws", async () => {
    const source: PromptVersionSource = {
      getActive: async () => {
        throw new Error("db unreachable");
      },
    };
    const onError = vi.fn();
    const out = await resolvePromptTemplate(source, "fix.system", "HARDCODED", {}, onError);
    expect(out).toBe("HARDCODED");
    expect(onError).toHaveBeenCalledOnce();
  });
});

describe("MontrLlmGateway.resolvePrompt", () => {
  it("falls back to the hardcoded default when constructed without a promptSource", async () => {
    const gateway = new MontrLlmGateway({ config: cfg(), adapter: fakeAdapter() });
    await expect(gateway.resolvePrompt("triage.system", "HARDCODED")).resolves.toBe("HARDCODED");
  });

  it("resolves the active DB version, defaulting clientId to config.clientId", async () => {
    const source = fakeSource({ "triage.system::client_a": "DB TRIAGE PROMPT" });
    const gateway = new MontrLlmGateway({
      config: cfg("client_a"),
      adapter: fakeAdapter(),
      promptSource: source,
    });
    await expect(gateway.resolvePrompt("triage.system", "HARDCODED")).resolves.toBe(
      "DB TRIAGE PROMPT",
    );
  });

  it("falls back to hardcoded when the configured source has nothing active yet — no regression on an empty DB", async () => {
    const source = fakeSource({});
    const gateway = new MontrLlmGateway({
      config: cfg("client_a"),
      adapter: fakeAdapter(),
      promptSource: source,
    });
    await expect(gateway.resolvePrompt("triage.system", "HARDCODED")).resolves.toBe("HARDCODED");
  });

  it("an explicit clientId override wins over config.clientId", async () => {
    const source = fakeSource({ "fix.system::client_b": "CLIENT B OVERRIDE" });
    const gateway = new MontrLlmGateway({
      config: cfg("client_a"),
      adapter: fakeAdapter(),
      promptSource: source,
    });
    await expect(
      gateway.resolvePrompt("fix.system", "HARDCODED", { clientId: "client_b" }),
    ).resolves.toBe("CLIENT B OVERRIDE");
  });
});
