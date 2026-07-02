/**
 * Persist a layer's output to the state store, validating it against the exact
 * @montr/contracts schema first (defense-in-depth: never trust a runner's shape
 * before it is written). Persisting each tier is what makes the pipeline
 * resumable — a resumed run reads these rows instead of re-running earlier
 * layers (§8.1).
 */
import {
  Layer0OutputSchema,
  Layer1OutputSchema,
  Layer2OutputSchema,
  Layer3OutputSchema,
  Layer4OutputSchema,
  Layer5OutputSchema,
  type LayerId,
  type LayerJobResultMap,
  type Scan,
} from "@montr/contracts";
import type { StateStore } from "@montr/state-store";
import type { PriorOutputs } from "./runner.js";

/**
 * Validate + persist one layer's output. Mutates `scan` in place for Layer 0
 * (appMapId / costEstimate / scope / commit) and updates it in the store.
 * Populates `cache` for in-process prior-output reuse.
 */
export async function persistLayerOutput(
  store: StateStore,
  clientId: string,
  layer: LayerId,
  rawOutput: LayerJobResultMap[LayerId],
  scan: Scan,
  cache: PriorOutputs,
): Promise<void> {
  switch (layer) {
    case "layer0": {
      const out = Layer0OutputSchema.parse(rawOutput);
      await store.appMaps.create(clientId, out.appMap);
      scan.appMapId = out.appMap.id;
      scan.costEstimate = out.costEstimate;
      scan.scope = out.scope;
      if (out.appMap.commitSha) scan.commitSha = out.appMap.commitSha;
      await store.scans.update(clientId, scan);
      cache.layer0 = out;
      return;
    }
    case "layer1": {
      const out = Layer1OutputSchema.parse(rawOutput);
      if (out.candidates.length > 0) await store.candidates.bulkCreate(clientId, out.candidates);
      cache.layer1 = out;
      return;
    }
    case "layer2": {
      const out = Layer2OutputSchema.parse(rawOutput);
      if (out.probable.length > 0) await store.probable.bulkCreate(clientId, out.probable);
      cache.layer2 = out;
      return;
    }
    case "layer3": {
      const out = Layer3OutputSchema.parse(rawOutput);
      if (out.confirmed.length > 0) await store.confirmed.bulkCreate(clientId, out.confirmed);
      if (out.unconfirmed.length > 0) await store.unconfirmed.bulkCreate(clientId, out.unconfirmed);
      cache.layer3 = out;
      return;
    }
    case "layer4": {
      const out = Layer4OutputSchema.parse(rawOutput);
      for (const fix of out.fixes) await store.fixes.create(clientId, fix);
      cache.layer4 = out;
      return;
    }
    case "layer5": {
      const out = Layer5OutputSchema.parse(rawOutput);
      // Link each opened PR back to its fixes (status → pr-open). PRs are opened
      // ONLY for auto-eligible fixes by Layer 5; here we just record the linkage.
      for (const pr of out.pullRequests) {
        for (const fixId of pr.fixIds) {
          const fix = await store.fixes.get(clientId, fixId);
          if (fix) {
            fix.status = "pr-open";
            fix.pullRequestId = pr.id;
            await store.fixes.update(clientId, fix);
          }
        }
      }
      cache.layer5 = out;
      return;
    }
  }
}
