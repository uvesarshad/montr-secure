#!/usr/bin/env bash
#
# deploy/airgap/import-bundle.sh — verify + install an offline update bundle
# produced by build-bundle.sh, on the air-gapped host.
#
# ⚠️  HONEST SCOPE: this repo does not yet have runtime code that reads
#     rulesets/advisory data from disk (packages/discovery still ships a
#     hardcoded advisory seed and live Semgrep Registry pack references —
#     see audit finding A8). This script stages verified artifacts at a
#     documented install path so that future wiring has something real to
#     read; it does NOT restart or reconfigure any running service.
#
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"

DEST_DIR="/opt/montr/airgap"
SKIP_VERIFY=0
COSIGN_PUBLIC_KEY="${COSIGN_PUBLIC_KEY:-}"
BUNDLE=""

usage() {
  cat <<EOF
Usage: $(basename "$0") <bundle.tar.gz> [options]

Verifies and installs an air-gap update bundle built by build-bundle.sh.

Looks for sibling files next to <bundle.tar.gz>, in this priority order:
  <bundle.tar.gz>.sig                cosign signature -> verified with
                                      'cosign verify-blob' (needs cosign
                                      installed; set COSIGN_PUBLIC_KEY to a
                                      real offline public key for cosign-key
                                      bundles — keyless verification needs
                                      Rekor/network and is not supported
                                      offline by this script).
  <bundle.tar.gz>.sha256             SHA-256 checksum -> integrity check
                                      ONLY, not a cryptographic signature
                                      (matches build-bundle.sh's unsigned
                                      fallback). A clear warning is printed.
  (neither present)                  Import is REFUSED unless
                                      --insecure-skip-verify is passed
                                      explicitly.

Options:
  --dest-dir DIR            Where to install verified artifacts
                             (default: /opt/montr/airgap).
  --insecure-skip-verify    Import without any signature/checksum check.
                             Requires explicit confirmation; never the
                             default.
  -h, --help                 Show this help and exit.

Example:
  $(basename "$0") montr-bundle-20260819.tar.gz --dest-dir /opt/montr/airgap
EOF
}

log()  { printf '[import-bundle] %s\n' "$*" >&2; }
warn() { printf '[import-bundle] WARNING: %s\n' "$*" >&2; }
die()  { printf '[import-bundle] ERROR: %s\n' "$*" >&2; exit 1; }

while [ $# -gt 0 ]; do
  case "$1" in
    --dest-dir) DEST_DIR="${2:?--dest-dir requires a value}"; shift 2 ;;
    --insecure-skip-verify) SKIP_VERIFY=1; shift ;;
    -h|--help) usage; exit 0 ;;
    -*) die "Unknown option: $1 (see --help)" ;;
    *)
      if [ -n "$BUNDLE" ]; then die "Unexpected extra argument: $1"; fi
      BUNDLE="$1"; shift ;;
  esac
done

[ -n "$BUNDLE" ] || { usage >&2; die "Missing required argument: <bundle.tar.gz>"; }
[ -f "$BUNDLE" ] || die "Bundle file not found: $BUNDLE"

# Be forgiving if the operator passes the .sig file instead of the tarball
# (DEPLOY.md's original example did this) — recover the real tarball path.
case "$BUNDLE" in
  *.sig)
    CANDIDATE="${BUNDLE%.sig}"
    if [ -f "$CANDIDATE" ]; then
      log "'$BUNDLE' looks like a signature file; using sibling tarball '$CANDIDATE' instead."
      BUNDLE="$CANDIDATE"
    else
      die "'$BUNDLE' is a .sig file but its tarball '$CANDIDATE' was not found alongside it."
    fi
    ;;
esac

command -v jq >/dev/null 2>&1 || die "jq is required (used to read/validate manifest.json)."
command -v tar >/dev/null 2>&1 || die "tar is required."

sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1" | awk '{print $1}'
  else
    die "Neither sha256sum nor shasum is available."
  fi
}

size_of() {
  if stat -f%z "$1" >/dev/null 2>&1; then
    stat -f%z "$1"       # BSD/macOS
  else
    stat -c%s "$1"        # GNU/Linux
  fi
}

SIG_FILE="${BUNDLE}.sig"
CERT_FILE="${BUNDLE}.cert"
SUM_FILE="${BUNDLE}.sha256"

VERIFIED=0
VERIFY_METHOD="none"

if [ "$SKIP_VERIFY" -eq 1 ]; then
  warn "--insecure-skip-verify was passed. Importing WITHOUT ANY verification," \
       "even if a .sig/.sha256 sibling file is present. This bundle's authenticity" \
       "and integrity are UNCHECKED."
  VERIFY_METHOD="skipped (--insecure-skip-verify)"
elif [ -f "$SIG_FILE" ]; then
  command -v cosign >/dev/null 2>&1 || die \
    "$SIG_FILE exists but cosign is not installed on this host — cannot verify" \
    "a real signature. Install cosign, or re-build the bundle with the" \
    "checksum-only fallback if that's an acceptable risk for your environment."
  log "verifying cosign signature: $SIG_FILE"
  if [ -n "$COSIGN_PUBLIC_KEY" ]; then
    cosign verify-blob --key "$COSIGN_PUBLIC_KEY" --signature "$SIG_FILE" "$BUNDLE" \
      || die "cosign signature verification FAILED. Refusing to import."
  elif [ -f "$CERT_FILE" ]; then
    warn "No COSIGN_PUBLIC_KEY set; attempting keyless verification with $CERT_FILE." \
         "Keyless verification normally needs Rekor/network access, which is a poor" \
         "fit for a genuinely air-gapped host. Prefer cosign-key signing/verification."
    cosign verify-blob --certificate "$CERT_FILE" --signature "$SIG_FILE" "$BUNDLE" \
      || die "cosign signature verification FAILED. Refusing to import."
  else
    die "$SIG_FILE exists but no COSIGN_PUBLIC_KEY is set and no $CERT_FILE was found —" \
        "cannot verify. Set COSIGN_PUBLIC_KEY to the offline public key used at sign time."
  fi
  log "cosign signature verified OK."
  VERIFIED=1
  VERIFY_METHOD="cosign"
elif [ -f "$SUM_FILE" ]; then
  log "no .sig found; checking SHA-256 checksum: $SUM_FILE"
  warn "This is INTEGRITY-ONLY verification, NOT a cryptographic signature" \
       "(matches build-bundle.sh's unsigned fallback). It proves the tarball" \
       "wasn't corrupted/altered since the checksum was written, but NOT who" \
       "produced it. Do not treat this bundle as provenance-verified."
  EXPECTED="$(awk '{print $1}' "$SUM_FILE")"
  ACTUAL="$(sha256_of "$BUNDLE")"
  [ "$EXPECTED" = "$ACTUAL" ] || die \
    "Checksum mismatch! expected=$EXPECTED actual=$ACTUAL. Refusing to import" \
    "a tarball that doesn't match its checksum file."
  log "checksum OK (integrity only — see warning above)."
  VERIFIED=1
  VERIFY_METHOD="sha256-checksum-only"
else
  die "No $SIG_FILE or $SUM_FILE found next to '$BUNDLE'. Refusing to import an" \
      "unverified bundle. Re-run with --insecure-skip-verify to override explicitly."
fi

WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/montr-airgap-import.XXXXXX")"
trap 'rm -rf "$WORK_DIR"' EXIT

log "extracting $BUNDLE ..."
tar -xzf "$BUNDLE" -C "$WORK_DIR"

MANIFEST="$WORK_DIR/manifest.json"
[ -f "$MANIFEST" ] || die "Bundle did not contain manifest.json — not a valid air-gap bundle."

SCHEMA_VERSION="$(jq -r '.schemaVersion // empty' "$MANIFEST")"
[ "$SCHEMA_VERSION" = "1" ] || die "manifest.json schemaVersion '$SCHEMA_VERSION' is not the supported '1'."

BUNDLE_NAME="$(jq -r '.name' "$MANIFEST")"
BUNDLE_VERSION="$(jq -r '.version' "$MANIFEST")"
CREATED_AT="$(jq -r '.createdAt' "$MANIFEST")"
ARTIFACT_COUNT="$(jq '.artifacts | length' "$MANIFEST")"

[ "$ARTIFACT_COUNT" -ge 1 ] || die "manifest.json has zero artifacts (schema requires minItems=1)."

log "manifest: name=$BUNDLE_NAME version=$BUNDLE_VERSION createdAt=$CREATED_AT artifacts=$ARTIFACT_COUNT"

# Per-artifact integrity check (defense in depth even when the outer tarball
# was already signature/checksum-verified above).
FAIL=0
i=0
while [ "$i" -lt "$ARTIFACT_COUNT" ]; do
  path="$(jq -r ".artifacts[$i].path" "$MANIFEST")"
  expected_sha="$(jq -r ".artifacts[$i].sha256" "$MANIFEST")"
  expected_size="$(jq -r ".artifacts[$i].sizeBytes" "$MANIFEST")"
  full_path="$WORK_DIR/$path"
  if [ ! -f "$full_path" ]; then
    warn "manifest lists '$path' but it is missing from the tarball."
    FAIL=1
  else
    actual_sha="$(sha256_of "$full_path")"
    if [ "$actual_sha" != "$expected_sha" ]; then
      warn "SHA-256 mismatch for '$path': manifest=$expected_sha actual=$actual_sha"
      FAIL=1
    fi
    actual_size="$(size_of "$full_path")"
    if [ "$actual_size" != "$expected_size" ]; then
      warn "size mismatch for '$path': manifest=$expected_size actual=$actual_size"
      FAIL=1
    fi
  fi
  i=$((i + 1))
done

[ "$FAIL" -eq 0 ] || die "One or more artifacts failed manifest verification. Refusing to install."
log "all $ARTIFACT_COUNT artifact(s) match their manifest hashes."

mkdir -p "$DEST_DIR"
INSTALLED_MANIFEST="$DEST_DIR/manifest.json"

i=0
while [ "$i" -lt "$ARTIFACT_COUNT" ]; do
  path="$(jq -r ".artifacts[$i].path" "$MANIFEST")"
  type="$(jq -r ".artifacts[$i].type" "$MANIFEST")"
  install_to="$(jq -r ".artifacts[$i].installTo // .artifacts[$i].type" "$MANIFEST")"
  target_dir="$DEST_DIR/$install_to"
  mkdir -p "$target_dir"
  cp -p "$WORK_DIR/$path" "$target_dir/$(basename "$path")"
  log "installed ($type -> $install_to): $(basename "$path")"
  i=$((i + 1))
done

cp -p "$MANIFEST" "$INSTALLED_MANIFEST"

log "done. verify method: $VERIFY_METHOD"
log ""
log "Installed under: $DEST_DIR"
find "$DEST_DIR" -mindepth 1 -maxdepth 2 | sed 's/^/[import-bundle]   /' >&2

cat >&2 <<EOF

[import-bundle] Next steps:
[import-bundle]   1. Review $DEST_DIR for the installed rulesets/mirror data.
[import-bundle]   2. NOTE: no service in this deployment currently reads from
[import-bundle]      $DEST_DIR automatically — packages/discovery still uses
[import-bundle]      live Semgrep Registry packs and a hardcoded advisory seed
[import-bundle]      (see audit finding A8). Wiring the worker to consume this
[import-bundle]      path is tracked separately; this import step only stages
[import-bundle]      verified artifacts for that future work.
[import-bundle]   3. Point the LLM gateway at your internal model proxy per
[import-bundle]      DEPLOY.md §4 — that remains the only permitted outbound
[import-bundle]      call on a true air-gapped host.
EOF
