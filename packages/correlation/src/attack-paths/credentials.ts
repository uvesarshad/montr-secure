/**
 * Credential-shaped ORM field detection (B8) — the structural check behind
 * chain condition (b), "does an IDOR/broken-access-control finding's exposed
 * model contain credential-shaped fields". Deliberately narrower than
 * `@montr/security`'s `SENSITIVE_KEY_PATTERN`
 * (packages/security/src/scrubber.ts): that pattern is tuned for
 * log-scrubbing RECALL (over-redacting a benign field is fine, leaking a
 * secret is not) and additionally matches "code"/"body"/"content"/"evidence"/
 * bare "key", which would make almost any model look credential-bearing. A
 * chain condition needs PRECISION instead — a false match here manufactures a
 * fake kill-chain step — so this keeps only tokens that name an actual
 * authentication credential, and anchors the whole field name (not a
 * substring) to avoid matching e.g. a `tokenizerVersion` column.
 */
import type { AppMap, Route } from "@montr/contracts";

export const CREDENTIAL_FIELD_PATTERN =
  /^(password|passwd|pwd|secret|token|api[_-]?key|apikey|credential|private[_-]?key|access[_-]?key|refresh[_-]?token|session[_-]?id|auth[_-]?token)$/i;

/** True when `modelName`'s ORM fields (App Map Prisma DMMF extraction) include a credential-shaped column. */
export function modelHasCredentialField(appMap: AppMap, modelName: string): boolean {
  const model = appMap.ormModels.find((m) => m.name === modelName);
  if (!model) return false;
  return model.fields.some((f) => CREDENTIAL_FIELD_PATTERN.test(f.name));
}

/**
 * True when `route` statically READS (A18 route -> ORM-model fan-out,
 * `Route.referencedModels`) a model containing a credential-shaped field —
 * the checkable condition behind "this IDOR/broken-access-control finding
 * yields credentials".
 */
export function routeLeaksCredentials(appMap: AppMap, route: Route | undefined): boolean {
  if (!route?.referencedModels) return false;
  return route.referencedModels.some(
    (ref) => ref.operations.includes("read") && modelHasCredentialField(appMap, ref.modelName),
  );
}
