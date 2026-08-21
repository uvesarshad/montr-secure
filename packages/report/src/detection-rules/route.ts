/**
 * Best-effort route resolution for a CONFIRMED finding. `ConfirmedFinding`
 * (unlike `ProbableFinding`) does not carry a `routeId` — Layer 3's
 * `assembleConfirmed` (packages/confirm/src/static.ts) does not propagate it
 * onto the confirmed record. File-location matching against the App Map's
 * `routes[].handler.file` (the same fallback `static.ts`'s own `findRoute`
 * uses when no `routeId` is available) is therefore the only signal left
 * post-confirmation. Reimplemented locally (not imported) since `findRoute`
 * itself isn't exported from @montr/confirm — this is a small, independent
 * read of the same `AppMap` shape, not a modification of that module.
 */
import type { AppMap, ConfirmedFinding, Route } from "@montr/contracts";

export function resolveRoute(
  appMap: AppMap | undefined,
  finding: ConfirmedFinding,
): Route | undefined {
  if (!appMap) return undefined;
  return appMap.routes.find((r) => r.handler?.file === finding.location.file);
}
