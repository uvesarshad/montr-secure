import { describe, it, expect } from "vitest";
import { CategorySchema } from "./compliance.js";
import { DetectionRuleSchema } from "./blue-team.js";
import {
  CATEGORY_MITRE_TECHNIQUES,
  MITRE_TECHNIQUE_CATALOG,
  mitreTechniquesForCategory,
  mitreTechniqueIdsForCategory,
  referencedMitreTechniqueIds,
} from "./mitre.js";

const CATEGORIES = CategorySchema.options;

describe("CATEGORY_MITRE_TECHNIQUES completeness", () => {
  it("has a non-empty entry for EVERY category in CategorySchema", () => {
    for (const category of CATEGORIES) {
      const ids = CATEGORY_MITRE_TECHNIQUES[category];
      expect(ids, `no MITRE mapping for category "${category}"`).toBeDefined();
      expect(ids.length, `empty MITRE mapping for category "${category}"`).toBeGreaterThan(0);
    }
  });

  it("does not have entries for categories outside CategorySchema", () => {
    const known = new Set<string>(CATEGORIES);
    for (const category of Object.keys(CATEGORY_MITRE_TECHNIQUES)) {
      expect(known.has(category)).toBe(true);
    }
  });

  it("every referenced technique id has a MITRE_TECHNIQUE_CATALOG entry", () => {
    for (const id of referencedMitreTechniqueIds()) {
      expect(
        MITRE_TECHNIQUE_CATALOG[id],
        `no catalog entry for technique id "${id}"`,
      ).toBeDefined();
    }
  });

  it("every category's technique ids are non-empty strings (matches DetectionRule.mitreTechniques shape)", () => {
    for (const category of CATEGORIES) {
      for (const id of CATEGORY_MITRE_TECHNIQUES[category]) {
        expect(typeof id).toBe("string");
        expect(id.length).toBeGreaterThan(0);
      }
    }
  });
});

describe("mitreTechniqueIdsForCategory", () => {
  it("returns real, specific ids for well-known categories", () => {
    expect(mitreTechniqueIdsForCategory("sql_injection")).toEqual(["T1190", "T1213"]);
    expect(mitreTechniqueIdsForCategory("hardcoded_secret")).toEqual(["T1552.001"]);
    expect(mitreTechniqueIdsForCategory("ssrf")).toEqual(["T1190", "T1552.005"]);
    expect(mitreTechniqueIdsForCategory("idor")).toEqual(["T1078"]);
    expect(mitreTechniqueIdsForCategory("prompt_injection")).toEqual(["AML.T0051"]);
    expect(mitreTechniqueIdsForCategory("insecure_configuration")).toEqual(["T1190", "T1611"]);
  });

  it("returns a fresh array each call (no shared-mutation hazard)", () => {
    const a = mitreTechniqueIdsForCategory("xss");
    const b = mitreTechniqueIdsForCategory("xss");
    expect(a).toEqual(b);
    expect(a).not.toBe(b);
    a.push("mutated");
    expect(mitreTechniqueIdsForCategory("xss")).not.toContain("mutated");
  });

  it("populates a valid DetectionRule.mitreTechniques for a confirmed finding's category", () => {
    const rule = DetectionRuleSchema.parse({
      id: "dr_1",
      clientId: "client_1",
      scanId: "scan_1",
      findingId: "finding_1",
      format: "sigma" as const,
      content: "title: Test Rule\nlogsource:\n  category: process_creation\n",
      mitreTechniques: mitreTechniqueIdsForCategory("sql_injection"),
      provenance: "static" as const,
      createdAt: "2026-08-22T00:00:00.000Z",
    });
    expect(rule.mitreTechniques).toEqual(["T1190", "T1213"]);
  });
});

describe("mitreTechniquesForCategory", () => {
  it("resolves ids into full descriptors with name/tactic/url", () => {
    const descriptors = mitreTechniquesForCategory("sql_injection");
    expect(descriptors).toEqual([
      {
        id: "T1190",
        name: "Exploit Public-Facing Application",
        tactic: "Initial Access",
        framework: "attack-enterprise",
        url: "https://attack.mitre.org/techniques/T1190/",
      },
      {
        id: "T1213",
        name: "Data from Information Repositories",
        tactic: "Collection",
        framework: "attack-enterprise",
        url: "https://attack.mitre.org/techniques/T1213/",
      },
    ]);
  });

  it("marks the prompt_injection technique as MITRE ATLAS, not Enterprise ATT&CK", () => {
    const [technique] = mitreTechniquesForCategory("prompt_injection");
    expect(technique?.id).toBe("AML.T0051");
    expect(technique?.framework).toBe("atlas");
    expect(technique?.url).toContain("atlas.mitre.org");
  });

  it("every descriptor has a non-empty name, tactic, and url", () => {
    for (const category of CATEGORIES) {
      for (const descriptor of mitreTechniquesForCategory(category)) {
        expect(descriptor.name.length).toBeGreaterThan(0);
        expect(descriptor.tactic.length).toBeGreaterThan(0);
        expect(descriptor.url.length).toBeGreaterThan(0);
      }
    }
  });
});

describe("referencedMitreTechniqueIds", () => {
  it("returns a sorted, de-duplicated list", () => {
    const ids = referencedMitreTechniqueIds();
    expect(ids).toEqual([...new Set(ids)].sort());
    expect(ids).toContain("T1190");
    expect(ids).toContain("AML.T0051");
  });
});
