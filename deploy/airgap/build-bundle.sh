#!/usr/bin/env bash
#
# build-bundle.sh — build a Montr Secure air-gap update bundle (§10, §9.3).
#
# Packages deterministic-tool rulesets (Semgrep, gitleaks) and the CVE/OSV/GHSA
# database mirror into a single tarball with a manifest (per manifest.schema.json)
# that carries a SHA-256 for every artifact, then optionally emits an SBOM (syft)
# and signs the tarball (cosign). Run on a CONNECTED host; the resulting bundle +
# signature are carried to the air-gapped host and applied with import-bundle.sh.
#
# Usage:
#   build-bundle.sh --name <name> --version <semver> --out <dir> \
#       [--producer <s>] [--montr-min-version <s>] [--sbom] \
#       [--sign] [--key <cosign.key>] \
#       --add <src> <type> [installTo]   [--add <src> <type> [installTo]] ...
#
#   <type>      = semgrep-rules | gitleaks-rules | osv-mirror | ghsa-mirror | cve-db | other
#   [installTo] = semgrep | gitleaks | cve | custom   (optional; import target key)
#
# Signing:
#   --sign            cosign keyless (Fulcio/Rekor; needs OIDC, network at build time)
#   --sign --key K    cosign key-based signing with private key K
#   (omit both → an UNSIGNED bundle is produced with a loud warning)
#
# Requires: bash, jq, tar, sha256sum|shasum. Optional: cosign (--sign), syft (--sbom).
set -euo pipefail

die() { echo "build-bundle: ERROR: $*" >&2; exit 1; }
warn() { echo "build-bundle: WARNING: $*" >&2; }
info() { echo "build-bundle: $*" >&2; }

command -v jq >/dev/null 2>&1 || die "jq is required (JSON assembly)."
command -v tar >/dev/null 2>&1 || die "tar is required."

# Portable SHA-256 → lowercase hex.
sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}';
  elif command -v shasum >/dev/null 2>&1; then shasum -a 256 "$1" | awk '{print $1}';
  else die "no sha256sum/shasum available."; fi
}
size_of() { wc -c < "$1" | tr -d ' '; }

NAME="" VERSION="" OUT="" PRODUCER="" MONTR_MIN="" DO_SBOM=0 DO_SIGN=0 COSIGN_KEY=""
# Parallel arrays of pending artifacts.
ADD_SRC=() ADD_TYPE=() ADD_INSTALL=()

while [ $# -gt 0 ]; do
  case "$1" in
    --name) NAME="$2"; shift 2;;
    --version) VERSION="$2"; shift 2;;
    --out) OUT="$2"; shift 2;;
    --producer) PRODUCER="$2"; shift 2;;
    --montr-min-version) MONTR_MIN="$2"; shift 2;;
    --sbom) DO_SBOM=1; shift;;
    --sign) DO_SIGN=1; shift;;
    --key) COSIGN_KEY="$2"; shift 2;;
    --add)
      [ $# -ge 3 ] || die "--add needs <src> <type> [installTo]"
      ADD_SRC+=("$2"); ADD_TYPE+=("$3")
      # Optional installTo: consume a 4th token only if it isn't another flag.
      if [ $# -ge 4 ] && [ "${4#--}" = "$4" ]; then ADD_INSTALL+=("$4"); shift 4; else ADD_INSTALL+=(""); shift 3; fi
      ;;
    -h|--help) sed -n '2,30p' "$0"; exit 0;;
    *) die "unknown argument: $1";;
  esac
done

[ -n "$NAME" ] || die "--name is required."
[ -n "$VERSION" ] || die "--version is required."
[ -n "$OUT" ] || die "--out is required."
[ "${#ADD_SRC[@]}" -gt 0 ] || die "at least one --add <src> <type> is required."
echo "$VERSION" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+([-+].+)?$' || die "--version must be SemVer, got '$VERSION'."

VALID_TYPES="semgrep-rules gitleaks-rules osv-mirror ghsa-mirror cve-db other"
VALID_INSTALL="semgrep gitleaks cve custom"

mkdir -p "$OUT"
STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT
ROOT="$STAGE/bundle"
mkdir -p "$ROOT/artifacts"

# Assemble the artifacts[] array incrementally in jq.
ARTIFACTS_JSON="[]"
i=0
while [ "$i" -lt "${#ADD_SRC[@]}" ]; do
  src="${ADD_SRC[$i]}"; type="${ADD_TYPE[$i]}"; installTo="${ADD_INSTALL[$i]}"
  [ -e "$src" ] || die "artifact source not found: $src"
  echo "$VALID_TYPES" | grep -qw "$type" || die "invalid artifact type '$type' (want: $VALID_TYPES)."
  if [ -n "$installTo" ]; then
    echo "$VALID_INSTALL" | grep -qw "$installTo" || die "invalid installTo '$installTo' (want: $VALID_INSTALL)."
  fi

  base="$(basename "$src")"
  # A directory artifact is packed as a deterministic .tar.gz inside the bundle.
  if [ -d "$src" ]; then
    rel="artifacts/${base}.tar.gz"
    tar --sort=name --mtime='UTC 2020-01-01' -czf "$ROOT/$rel" -C "$(dirname "$src")" "$base" 2>/dev/null \
      || tar -czf "$ROOT/$rel" -C "$(dirname "$src")" "$base"
  else
    rel="artifacts/${base}"
    cp "$src" "$ROOT/$rel"
  fi

  sha="$(sha256_of "$ROOT/$rel")"
  size="$(size_of "$ROOT/$rel")"
  info "added $rel  ($type${installTo:+ → $installTo})  sha256=${sha:0:12}…  ${size}B"

  ARTIFACTS_JSON="$(jq -c \
    --arg path "$rel" --arg type "$type" --arg sha "$sha" \
    --argjson size "$size" --arg installTo "$installTo" \
    '. + [ ({path:$path, type:$type, sha256:$sha, sizeBytes:$size}
           + (if $installTo=="" then {} else {installTo:$installTo} end)) ]' \
    <<<"$ARTIFACTS_JSON")"
  i=$((i + 1))
done

CREATED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
SIGN_METHOD=""
[ "$DO_SIGN" -eq 1 ] && { [ -n "$COSIGN_KEY" ] && SIGN_METHOD="cosign-key" || SIGN_METHOD="cosign-keyless"; }
TARBALL_NAME="${NAME}-${VERSION}.tar.gz"

# Build + write the manifest (validated shape).
jq -n \
  --arg name "$NAME" --arg version "$VERSION" --arg createdAt "$CREATED_AT" \
  --arg producer "$PRODUCER" --arg montrMin "$MONTR_MIN" \
  --arg signMethod "$SIGN_METHOD" --arg tarball "$TARBALL_NAME" \
  --argjson artifacts "$ARTIFACTS_JSON" \
  '{schemaVersion:"1", name:$name, version:$version, createdAt:$createdAt, artifacts:$artifacts}
   + (if $producer=="" then {} else {producer:$producer} end)
   + (if $montrMin=="" then {} else {montrMinVersion:$montrMin} end)
   + (if $signMethod=="" then {} else {signing:{method:$signMethod, signatureFile:($tarball+".sig"), certificateFile:($tarball+".pem")}} end)' \
  > "$ROOT/manifest.json"
info "wrote manifest.json ($(jq '.artifacts|length' "$ROOT/manifest.json") artifact(s))"

# Deterministic tarball of the bundle root (manifest + artifacts).
TARBALL="$OUT/$TARBALL_NAME"
tar --sort=name --mtime='UTC 2020-01-01' -czf "$TARBALL" -C "$ROOT" . 2>/dev/null \
  || tar -czf "$TARBALL" -C "$ROOT" .
info "built bundle: $TARBALL ($(size_of "$TARBALL")B)"

# Optional SBOM.
if [ "$DO_SBOM" -eq 1 ]; then
  if command -v syft >/dev/null 2>&1; then
    syft "dir:$ROOT" -o spdx-json > "$OUT/${TARBALL_NAME}.sbom.spdx.json"
    info "wrote SBOM: $OUT/${TARBALL_NAME}.sbom.spdx.json"
  else
    warn "syft not found — skipping SBOM (install syft or drop --sbom)."
  fi
fi

# Optional signing (whole-tarball blob signature).
if [ "$DO_SIGN" -eq 1 ]; then
  command -v cosign >/dev/null 2>&1 || die "--sign requires cosign (not found)."
  if [ -n "$COSIGN_KEY" ]; then
    cosign sign-blob --yes --key "$COSIGN_KEY" --output-signature "$TARBALL.sig" "$TARBALL"
    info "signed (key): $TARBALL.sig"
  else
    COSIGN_EXPERIMENTAL=1 cosign sign-blob --yes \
      --output-signature "$TARBALL.sig" --output-certificate "$TARBALL.pem" "$TARBALL"
    info "signed (keyless): $TARBALL.sig + $TARBALL.pem"
  fi
else
  warn "bundle is UNSIGNED (no --sign). import-bundle.sh will refuse it unless --insecure-skip-verify is passed."
fi

echo "$TARBALL"
