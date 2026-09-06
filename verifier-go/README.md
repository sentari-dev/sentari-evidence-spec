# Sentari evidence-pack — Go offline verifier (second, independent implementation)

A from-scratch **Go** reimplementation of the [open specification](../spec/spec-v0.1.md),
a peer to the [Python reference verifier](../verifier/sentari_evidence_verify.py).

Its reason to exist: **two independent implementations that agree on the same
golden vector — down to byte-identical canonical JSON — are the strongest possible
proof that the evidence-pack format is genuinely open** and reimplementable by any
auditor or conformity-assessment body (CAB), with no dependency on Sentari's code
or servers. This verifier verifies the shipped, real-server-signed vector
(`../verifier/vectors/cyfun-empty-fleet.golden.json`) to `verified`, reproducing
the server's `content_sha256` and Ed25519 envelope byte-for-byte.

**Standard library only** — `crypto/ed25519`, `crypto/sha256`, `encoding/json`,
`archive/zip`, `encoding/base64`. No external dependencies. Builds to a single
static binary.

## Build & run

```bash
go build -o sentari-evidence-verify .

./sentari-evidence-verify PACK [--pubkey B64] [--expected-key-id ID] [--json]
```

`PACK` is one of:
- a `.json` file — flat server download (payload fields at top level + a sibling
  `signature` block, optionally `frozen_inputs`) **or** a
  `{"payload":…,"signature":…,"frozen_inputs":…}` wrapper;
- a `.zip` artifact, or a directory, containing `manifest.json` + `evidence.json`
  + `signature.json` (+ `frozen_inputs.json`).

Exit codes match the Python CLI: **0** verified, **2** tampered, **3** key_unknown,
**4** usage/parse error.

## What it checks (spec §9 steps 1–4)

| Layer | Check |
|---|---|
| **1 — payload_intact** | blank `content_sha256`, canonicalise, sha256, compare |
| **2 — frozen_inputs_valid** | whole-blob hash + every per-source hash (row-list vs aggregate, §5.3); `None` if `frozen_inputs` not embedded |
| **Signature** | Ed25519 over `canonical_json({content_sha256, ctx, frozen_inputs_sha256})` (§6.1) |
| **key_id** | `ed25519:` + `hex(sha256(pubkey_raw))[:32]`; must equal the embedded material, and (if `--expected-key-id` given) the out-of-band anchor |
| **Manifest (zip/dir)** | the signed `manifest.json` envelope + every member's raw-bytes sha256, verified **before** trusting `evidence.json`/`signature.json` (§3.5) |

Layer 3 (collector re-derivation, §5.4) is intentionally **not** implemented — it
needs the framework collector code for the pack's `catalog_version`.

Verdict semantics mirror the Python reference exactly, including the two subtle
cases: an out-of-band anchor mismatch → `key_unknown` (a rotated/foreign key, not
tampering), while `key_id ≠ fingerprint(embedded key)` → `tampered` (the key
material was rewritten). Malformed base64 / JSON yields a deterministic verdict,
never a panic.

## The crux — canonical JSON (spec §4)

Canonical JSON is defined as the exact bytes of
`json.dumps(obj, sort_keys=True, separators=(",",":"), ensure_ascii=False)`.
Go's `encoding/json` does **not** produce these bytes by default, so
[`canonical.go`](canonical.go) is a hand-written serializer that:

- sorts object keys by Unicode code point (byte-wise sort of UTF-8 == code-point
  sort) and emits `{"k":v,…}` / `[v,…]` with no whitespace;
- escapes only `"`→`\"`, `\`→`\\`, and C0 controls (short forms `\b \t \n \f \r`,
  else `\u00XX` lowercase); emits `<` `>` `&` `/`, **U+2028/U+2029**, and all
  non-ASCII as **raw UTF-8** (Go escapes `<>&` and U+2028/U+2029 by default — we
  disable all of that);
- emits integers verbatim by parsing input with `json.Decoder.UseNumber()` so no
  float reformatting can diverge (spec forbids floats in hashed fields).

`verify_test.go` pins this with byte vectors (e.g.
`{"b":1,"a":"é","c":"<x>"}` → `{"a":"é","b":1,"c":"<x>"}`) and cross-validates
against the real server vector.

## Test

```bash
go vet ./...
gofmt -l .        # empty == formatted
go test ./...     # includes the byte-pin, golden-vector, tamper, and zip-manifest suites
```
