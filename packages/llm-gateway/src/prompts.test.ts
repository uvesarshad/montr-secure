import { describe, it, expect, vi } from "vitest";
import { parseConfig, type MontrConfig } from "@montr/config";
import type { LLMStreamEvent, Provider } from "@montr/contracts";
import { MontrLlmGateway } from "./gateway.js";
import {
  resolvePromptTemplate,
  resolvePromptVersionTemplate,
  type PromptVersionSource,
} from "./prompts.js";
import { InMemoryPromptVersionRegistry } from "./prompt-version-registry.js";
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

/* --------------------------------------------------------------------------- *
 * E15 — versioned prompt resolution (resolvePromptVersionTemplate,
 * MontrLlmGateway.resolvePromptVersion, InMemoryPromptVersionRegistry).
 * --------------------------------------------------------------------------- */

describe("resolvePromptVersionTemplate", () => {
  it("returns the fallback unchanged when no source is configured", async () => {
    const out = await resolvePromptVersionTemplate(undefined, "fix.system", 2, "HARDCODED");
    expect(out).toBe("HARDCODED");
  });

  it("returns the fallback when the source has no listVersions support (getActive-only source)", async () => {
    const source: PromptVersionSource = { getActive: async () => null };
    const out = await resolvePromptVersionTemplate(source, "fix.system", 1, "HARDCODED");
    expect(out).toBe("HARDCODED");
  });

  it("resolves an exact version by number, independent of which one is active", async () => {
    const registry = new InMemoryPromptVersionRegistry();
    const v1 = registry.createVersion({ name: "fix.system", template: "V1 TEXT" });
    const v2 = registry.createVersion({ name: "fix.system", template: "V2 TEXT" });
    registry.markActive(v1.id); // v1 is active; we still want v2's template.
    expect(v2.version).toBe(2);

    const out = await resolvePromptVersionTemplate(registry, "fix.system", 2, "HARDCODED");
    expect(out).toBe("V2 TEXT");
  });

  it("falls back when the requested version number doesn't exist", async () => {
    const registry = new InMemoryPromptVersionRegistry();
    registry.createVersion({ name: "fix.system", template: "V1 TEXT" });
    const out = await resolvePromptVersionTemplate(registry, "fix.system", 99, "HARDCODED");
    expect(out).toBe("HARDCODED");
  });

  it("fails safe to the fallback (and reports via onError) when listVersions throws", async () => {
    const source: PromptVersionSource = {
      getActive: async () => null,
      listVersions: async () => {
        throw new Error("db unreachable");
      },
    };
    const onError = vi.fn();
    const out = await resolvePromptVersionTemplate(
      source,
      "fix.system",
      1,
      "HARDCODED",
      {},
      onError,
    );
    expect(out).toBe("HARDCODED");
    expect(onError).toHaveBeenCalledOnce();
  });
});

describe("MontrLlmGateway.resolvePromptVersion", () => {
  it("resolves a specific version, defaulting clientId to config.clientId", async () => {
    const registry = new InMemoryPromptVersionRegistry();
    registry.createVersion({ name: "triage.system", template: "V1", clientId: "client_a" });
    const v2 = registry.createVersion({
      name: "triage.system",
      template: "V2",
      clientId: "client_a",
    });
    registry.markActive(v2.id);
    const gateway = new MontrLlmGateway({
      config: cfg("client_a"),
      adapter: fakeAdapter(),
      promptSource: registry,
    });
    await expect(gateway.resolvePromptVersion("triage.system", 1, "HARDCODED")).resolves.toBe("V1");
    await expect(gateway.resolvePromptVersion("triage.system", 2, "HARDCODED")).resolves.toBe("V2");
  });

  it("falls back to hardcoded when constructed without a promptSource", async () => {
    const gateway = new MontrLlmGateway({ config: cfg(), adapter: fakeAdapter() });
    await expect(gateway.resolvePromptVersion("triage.system", 1, "HARDCODED")).resolves.toBe(
      "HARDCODED",
    );
  });
});

describe("InMemoryPromptVersionRegistry", () => {
  it("assigns monotonic versions per name, starting at 1, inactive until promoted", () => {
    const registry = new InMemoryPromptVersionRegistry();
    const v1 = registry.createVersion({ name: "confirm.static_review.system", template: "A" });
    const v2 = registry.createVersion({ name: "confirm.static_review.system", template: "B" });
    expect(v1.version).toBe(1);
    expect(v2.version).toBe(2);
    expect(v1.isActive).toBe(false);
    expect(v2.isActive).toBe(false);
  });

  it("markActive deactivates any other active row in the same (name, clientId) scope", async () => {
    const registry = new InMemoryPromptVersionRegistry();
    const v1 = registry.createVersion({ name: "n", template: "A" });
    const v2 = registry.createVersion({ name: "n", template: "B" });
    registry.markActive(v1.id);
    expect((await registry.getActive("n"))?.template).toBe("A");
    registry.markActive(v2.id);
    expect((await registry.getActive("n"))?.template).toBe("B");
    // Only one row in the scope may be active at a time.
    const versions = await registry.listVersions("n");
    const activeCount = versions.filter(
      (v) => (v as { isActive?: boolean }).isActive === true,
    ).length;
    expect(activeCount).toBe(1);
  });

  it("a client-scoped active row wins over a global active row", async () => {
    const registry = new InMemoryPromptVersionRegistry();
    const global = registry.createVersion({ name: "n", template: "GLOBAL" });
    const override = registry.createVersion({ name: "n", template: "OVERRIDE", clientId: "c1" });
    registry.markActive(global.id);
    registry.markActive(override.id);
    expect((await registry.getActive("n", "c1"))?.template).toBe("OVERRIDE");
    expect((await registry.getActive("n"))?.template).toBe("GLOBAL");
  });

  it("markActive throws on an unknown id", () => {
    const registry = new InMemoryPromptVersionRegistry();
    expect(() => registry.markActive("does-not-exist")).toThrow();
  });
});
