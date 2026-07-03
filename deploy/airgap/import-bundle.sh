#!/usr/bin/env bash
#
# import-bundle.sh — verify + apply a Montr Secure air-gap update bundle (§10, §9.3).
#
# Runs on the AIR-GAPPED host. Verifies the bundle's cosign signature, then
# verifies every artifact's SHA-256 against the in-bundle manifest BEFORE
# installing each artifact to its resolved target (Semgrep rules, gitleaks rules,
# CVE/OSV mirror). Nothing is installed unless the signature AND every hash check
# pass (fail-closed).
#
# Usage:
#   import-bundle.sh <bundle.tar.gz> [verify options] [install options]
#
# Verify options (pick the one matching how it was signed):
#   --key <cosign.pub>                     key-based verification
#   --cert <file> --cert-identity <id> \
#       --cert-oidc-issuer <issuer>        keyless verification
#   --sig <file>                           signature file (default: <bundle>.sig)
#   --verify-only                          verify + hash-check, do NOT install
#   --insecure-skip-verify                 ⛔ skip signature verification (LOUD warning)
#
# Install options (targets for each artifact's installTo):
#   --semgrep-dir <dir>   --gitleaks-dir <dir>   --cve-dir <dir>   --custom-dir <dir>
#
# Requires: bash, jq, tar, sha256sum|shasum. cosign required unless --insecure-skip-verify.
set -euo pipefail

die() { echo "import-bundle: ERROR: $*" >&2; exit 1; }
warn() { echo "import-bundle: WARNING: $*" >&2; }
info() { echo "import-bundle: $*" >&2; }

command -v jq >/dev/null 2>&1 || die "jq is required."
command -v tar >/dev/null 2>&1 || die "tar is required."
sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}';
  elif command -v shasum >/dev/null 2>&1; then shasum -a 256 "$1" | awk '{print $1}';
  else die "no sha256sum/shasum available."; fi
}

BUNDLE="" KEY="" CERT="" CERT_ID="" CERT_ISSUER="" SIG="" VERIFY_ONLY=0 SKIP_VERIFY=0
SEMGREP_DIR="" GITLEAKS_DIR="" CVE_DIR="" CUSTOM_DIR=""
while [ $# -gt 0 ]; do
  case "$1" in
    --key) KEY="$2"; shift 2;;
    --cert) CERT="$2"; shift 2;;
    --cert-identity) CERT_ID="$2"; shift 2;;
    --cert-oidc-issuer) CERT_ISSUER="$2"; shift 2;;
    --sig) SIG="$2"; shift 2;;
    --verify-only) VERIFY_ONLY=1; shift;;
    --insecure-skip-verify) SKIP_VERIFY=1; shift;;
    --semgrep-dir) SEMGREP_DIR="$2"; shift 2;;
    --gitleaks-dir) GITLEAKS_DIR="$2"; shift 2;;
    --cve-dir) CVE_DIR="$2"; shift 2;;
    --custom-dir) CUSTOM_DIR="$2"; shift 2;;
    -h|--help) sed -n '2,32p' "$0"; exit 0;;
    -*) die "unknown option: $1";;
    *) [ -z "$BUNDLE" ] && BUNDLE="$1" || die "unexpected argument: $1"; shift;;
  esac
done
[ -n "$BUNDLE" ] || die "a bundle tarball path is required."
[ -f "$BUNDLE" ] || die "bundle not found: $BUNDLE"
[ -n "$SIG" ] || SIG="${BUNDLE}.sig"

# ── 1. Signature verification (fail-closed) ────────────────────────────────────
if [ "$SKIP_VERIFY" -eq 1 ]; then
  warn "⛔ SIGNATURE VERIFICATION SKIPPED (--insecure-skip-verify). Only do this if you"
  warn "   trust the transport channel completely — the bundle is NOT authenticated."
else
  command -v cosign >/dev/null 2>&1 || die "cosign is required to verify the bundle (or pass --insecure-skip-verify)."
  [ -f "$SIG" ] || die "signature file not found: $SIG (pass --sig, or --insecure-skip-verify)."
  if [ -n "$KEY" ]; then
    cosign verify-blob --key "$KEY" --signature "$SIG" "$BUNDLE" \
      || die "cosign key verification FAILED — refusing to import."
  elif [ -n "$CERT" ]; then
    [ -n "$CERT_ID" ] && [ -n "$CERT_ISSUER" ] || die "keyless verify needs --cert-identity and --cert-oidc-issuer."
    cosign verify-blob --certificate "$CERT" --signature "$SIG" \
      --certificate-identity "$CERT_ID" --certificate-oidc-issuer "$CERT_ISSUER" "$BUNDLE" \
      || die "cosign keyless verification FAILED — refusing to import."
  else
    die "provide --key <pub> (key mode) or --cert/--cert-identity/--cert-oidc-issuer (keyless)."
  fi
  info "signature verified ✓"
fi

# ── 2. Extract + read manifest ────────────────────────────────────────────────
WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT
tar -xzf "$BUNDLE" -C "$WORK"
MAN="$WORK/manifest.json"
[ -f "$MAN" ] || die "manifest.json missing from bundle."
[ "$(jq -r '.schemaVersion' "$MAN")" = "1" ] || die "unsupported manifest schemaVersion."
info "bundle: $(jq -r '.name' "$MAN") v$(jq -r '.version' "$MAN") ($(jq '.artifacts|length' "$MAN") artifact(s))"

# ── 3. Verify every artifact's SHA-256 BEFORE installing anything ──────────────
COUNT="$(jq '.artifacts|length' "$MAN")"
j=0
while [ "$j" -lt "$COUNT" ]; do
  path="$(jq -r ".artifacts[$j].path" "$MAN")"
  want="$(jq -r ".artifacts[$j].sha256" "$MAN")"
  case "$path" in /*|*..*) die "unsafe artifact path in manifest: $path";; esac
  [ -f "$WORK/$path" ] || die "artifact missing from bundle: $path"
  got="$(sha256_of "$WORK/$path")"
  [ "$got" = "$want" ] || die "SHA-256 MISMATCH for $path (bundle tampered?) want=$want got=$got"
  j=$((j + 1))
done
info "all $COUNT artifact hashes verified ✓"
[ "$VERIFY_ONLY" -eq 1 ] && { info "--verify-only: not installing. OK."; exit 0; }

# ── 4. Install each artifact to its resolved target ───────────────────────────
target_dir_for() {
  case "$1" in
    semgrep) echo "$SEMGREP_DIR";;
    gitleaks) echo "$GITLEAKS_DIR";;
    cve) echo "$CVE_DIR";;
    custom) echo "$CUSTOM_DIR";;
    *) echo "";;
  esac
}
installed=0 skipped=0
j=0
while [ "$j" -lt "$COUNT" ]; do
  path="$(jq -r ".artifacts[$j].path" "$MAN")"
  installTo="$(jq -r ".artifacts[$j].installTo // \"\"" "$MAN")"
  j=$((j + 1))
  if [ -z "$installTo" ]; then info "skip $path (no installTo)"; skipped=$((skipped+1)); continue; fi
  dest="$(target_dir_for "$installTo")"
  if [ -z "$dest" ]; then warn "skip $path — no --${installTo}-dir provided for installTo=$installTo"; skipped=$((skipped+1)); continue; fi
  mkdir -p "$dest"
  cp "$WORK/$path" "$dest/$(basename "$path")"
  info "installed $(basename "$path") → $dest ($installTo)"
  installed=$((installed+1))
done
info "done: $installed installed, $skipped skipped."
