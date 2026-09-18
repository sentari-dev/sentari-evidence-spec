#!/bin/sh
# Conformance runner — proves ALL THREE reference verifiers (Python + Go + the
# browser verifier in verify.html) agree with the documented verdict for every
# committed vector, with no Sentari deployment and no network. An auditor/CAB
# runs this to convince themselves the format is genuinely open and
# offline-verifiable; a reimplementer runs it to self-check.
#
# Exit 0 iff every vector produces its documented verdict in BOTH languages.
# See CONFORMANCE.md for the expected-verdict table this script enforces.
#
# Requirements: python3 + `pip install cryptography`; go (to build the Go
# verifier); node (to drive the browser verifier's core headlessly).
# Missing node is reported, never silently skipped.
set -eu

HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPO=$(CDPATH= cd -- "$HERE/.." && pwd)
VECTORS="$HERE/vectors"
PY="${PYTHON:-python3}"
PYV="$HERE/sentari_evidence_verify.py"

# Build the Go verifier into a temp binary.
GOBIN=$(mktemp -u /tmp/sentari-evidence-verify.XXXXXX)
( cd "$REPO/verifier-go" && go build -o "$GOBIN" . )
trap 'rm -f "$GOBIN" "$TAMPER"' EXIT
TAMPER=$(mktemp /tmp/sentari-conformance-tamper.XXXXXX.json)

fail=0
pass=0

# check <label> <expected-exit> <verifier-cmd...>
check() {
  label=$1; want=$2; shift 2
  "$@" >/dev/null 2>&1 && got=0 || got=$?
  if [ "$got" -eq "$want" ]; then
    pass=$((pass + 1)); printf '  PASS  %s (exit %s)\n' "$label" "$got"
  else
    fail=$((fail + 1)); printf '  FAIL  %s (got exit %s, want %s)\n' "$label" "$got" "$want"
  fi
}

# Every committed vector: verified (0) by default AND under its correct pinned
# key_id; key_unknown (3) under a wrong pin. Vocabulary/exit map: 0 verified,
# 2 tampered, 3 key_unknown (CONFORMANCE.md).
CYFUN_KID="ed25519:2c324e5afc47408739876dba4886ef19"
SIGNED_KID="ed25519:eb719d5bab969e9f243775b329a23ac6"
WRONG_KID="ed25519:00000000000000000000000000000000"

run_vector() {
  name=$1; kid=$2; f="$VECTORS/$name"
  echo "# $name"
  check "python  default            -> verified"    0 "$PY" "$PYV" "$f"
  check "python  correct key pin    -> verified"    0 "$PY" "$PYV" "$f" --expected-key-id "$kid"
  check "python  wrong key pin      -> key_unknown" 3 "$PY" "$PYV" "$f" --expected-key-id "$WRONG_KID"
  check "go      default            -> verified"    0 "$GOBIN" "$f"
  check "go      correct key pin    -> verified"    0 "$GOBIN" "$f" --expected-key-id "$kid"
  check "go      wrong key pin      -> key_unknown" 3 "$GOBIN" "$f" --expected-key-id "$WRONG_KID"
}

run_vector "cyfun-empty-fleet.golden.json"      "$CYFUN_KID"
run_vector "sbom-cyclonedx.signed.golden.json"  "$SIGNED_KID"
run_vector "vex-openvex.signed.golden.json"     "$SIGNED_KID"

# Tamper detection: flip one content byte in a signed document -> tampered (2)
# in BOTH languages. This is the property that makes a verified signature mean
# something.
echo "# tamper detection (mutated copy of the SBOM vector)"
"$PY" - "$VECTORS/sbom-cyclonedx.signed.golden.json" "$TAMPER" <<'PYEOF'
import json, sys
d = json.load(open(sys.argv[1]))
d["document"]["bomFormat"] = "CycloneDX-TAMPERED"
json.dump(d, open(sys.argv[2], "w"))
PYEOF
check "python  tampered document   -> tampered"    2 "$PY" "$PYV" "$TAMPER"
check "go      tampered document   -> tampered"    2 "$GOBIN" "$TAMPER"

# The browser verifier (verify.html). Its harness extracts the core block out of
# the shipped HTML — the exact bytes an auditor runs — and drives the same vector
# and mutation table in node. Counted as ONE check here because the harness
# prints and tallies its own; a non-zero exit means at least one disagreed.
echo "# browser verifier (verify.html, via node)"
if command -v node >/dev/null 2>&1; then
  if node "$REPO/verifier-web/conformance.mjs" >/dev/null 2>&1; then
    pass=$((pass + 1)); printf '  PASS  browser  full vector + mutation table\n'
  else
    fail=$((fail + 1)); printf '  FAIL  browser  full vector + mutation table\n'
    printf '        re-run for detail: node verifier-web/conformance.mjs\n'
  fi
else
  fail=$((fail + 1))
  printf '  FAIL  browser  node not found - cannot verify verify.html\n'
fi

# verify.html is handed around as a standalone file (emailed, copied to a USB
# stick), so its own SHA-256 is published alongside it. Checking it here means
# the recorded value can never silently drift from the shipped page.
# The render layer is not reached by any of the checks above, and two real
# defects lived there: a container type-swap that erased the verdict from the
# screen after it had been rendered, and a printed identity block that
# survived into the next file. Asserts the END STATE, not just "nothing threw".
echo "# render layer (verify.html, via node)"
if command -v node >/dev/null 2>&1; then
  if node "$REPO/verifier-web/render-test.mjs" >/dev/null 2>&1; then
    pass=$((pass + 1)); printf '  PASS  render  verdict survives every hostile field\n'
  else
    fail=$((fail + 1)); printf '  FAIL  render  a hostile field breaks the report\n'
    printf '        re-run for detail: node verifier-web/render-test.mjs\n'
  fi
else
  fail=$((fail + 1)); printf '  FAIL  render  node not found\n'
fi

echo "# published self-hash (verify.html.sha256)"
if [ -f "$REPO/verify.html.sha256" ]; then
  if ( cd "$REPO" && shasum -a 256 -c verify.html.sha256 >/dev/null 2>&1 ); then
    pass=$((pass + 1)); printf '  PASS  verify.html matches its published SHA-256\n'
  else
    fail=$((fail + 1))
    printf '  FAIL  verify.html does NOT match verify.html.sha256\n'
    printf '        regenerate: shasum -a 256 verify.html > verify.html.sha256\n'
  fi
else
  fail=$((fail + 1)); printf '  FAIL  verify.html.sha256 is missing\n'
fi

echo
if [ "$fail" -eq 0 ]; then
  printf 'CONFORMANCE PASS — %s checks, all three verifiers agree.\n' "$pass"
  exit 0
fi
printf 'CONFORMANCE FAIL — %s failed / %s passed.\n' "$fail" "$pass"
exit 1
