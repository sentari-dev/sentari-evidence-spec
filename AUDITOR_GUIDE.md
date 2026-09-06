# Verifying a Sentari evidence pack — a guide for auditors & CABs

This is for an **auditor, conformity-assessment body (CAB), customer, or regulator** who has
been handed a Sentari evidence pack and wants to establish, independently, that it is authentic
and untampered — **offline, with no dependency on Sentari**.

You do not need to trust Sentari's word, its servers, or even its software. The format is open
([`spec/spec-v0.1.md`](spec/spec-v0.1.md)) and the verifier is free and reimplementable — there are
two independent reference implementations in this repository ([Python](verifier/) and
[Go](verifier-go/)) that agree byte-for-byte on the same pack.

## What a pack is

A pack is a signed, self-describing bundle of regulatory-compliance evidence (e.g. CyFun / NIS2 /
DORA / CRA control results) computed from an organisation's own ground-truth system state. Each
control result carries:

- a **status** (compliant / at-risk / non-compliant / not-assessed),
- an **evidence grade** — `derived` (measured by Sentari's own collector), `observed` (read from a
  system of record — e.g. an identity directory — frozen and hashed), or `declared` (a human
  attestation), and
- an **honesty coverage block** stating exactly which controls were assessed and which were not.

A pack **supports** CyFun/NIS2/DORA/CRA verification or certification performed by the entity or a
BELAC-accredited CAB. It is **not** a certificate and asserts no presumption of conformity.

## The trust model — one thing you must do out-of-band

The pack is signed with an Ed25519 key. Verifying the signature proves the pack is internally
consistent, but **authenticity requires you to compare the signing key's fingerprint (`key_id`)
against the fingerprint the deployment publishes through a channel you already trust** (its
documentation, a signed email, a portal — not the pack itself). Ask the deployment operator for
their published `key_id`, and pass it as `--expected-key-id`. Without that anchor, the tool verifies
the maths but tells you authenticity is *not* established.

## Verify in three commands

```bash
pip install cryptography                          # the only dependency
python verifier/sentari_evidence_verify.py PACK \
    --expected-key-id ed25519:<the deployment's published fingerprint>
echo $?
```

`PACK` is the file you were handed — a `.json`, a `.zip` bundle, or a directory of its members.
(Prefer a single static binary? Build the Go verifier: `cd verifier-go && go build` — same result.)

## What the verdict means

| Verdict | Exit | Meaning | What to do |
|---|---|---|---|
| **verified** | 0 | Every hash recomputes, the signature checks out, and (if you supplied `--expected-key-id`) the key is the one you pinned. | Trust the pack's contents to the grade each control declares. |
| **tampered** | 2 | A hash, the signature, the signed zip manifest, or the key material failed. The pack was altered after signing. | Reject it. Ask for a freshly generated pack; treat the discrepancy as an incident. |
| **key_unknown** | 3 | The maths is consistent but the key is not the one you pinned (rotated / foreign / none supplied). | Not tampering — re-verify against the deployment's *current* published fingerprint, or obtain the anchor. |

## What the verifier checks (and what it doesn't)

- **Layer 1 — payload integrity:** recomputes `content_sha256` over the canonical payload.
- **Layer 2 — frozen inputs:** when the pack embeds `frozen_inputs`, recomputes the whole-blob hash
  and every per-source hash, so the numbers behind each control are checkable from the artifact alone.
- **Signature:** Ed25519 over a domain-separated envelope binding the payload hash + the frozen-inputs
  hash, against a key whose fingerprint you anchor out-of-band.
- **Zip manifest:** for `.zip` packs, verifies the signed `manifest.json` and every member's hash
  before trusting `evidence.json` — so a swapped file is caught even if the JSON pair is intact.
- **Layer 3 (re-derivation)** is intentionally *not* done offline — it needs the framework collector
  code for the pack's `catalog_version` and is a server-side check. Layers 1 + 2 + signature are
  what an offline auditor needs.

## Reproducibility

A pack is byte-reproducible: the same inputs, canonicalised the same way, produce the same
`content_sha256`. Two independent verifiers (this repository's Python and Go) reach the same verdict
on the same bytes. That is the point — the proof does not depend on any one implementation, vendor,
or machine.

## Conformance vector

`verifier/vectors/cyfun-empty-fleet.golden.json` is a **real Sentari-signed CyFun pack** (empty
fleet, no PII). Both reference verifiers verify it, cross-validating each other against the actual
producer. Run `pytest` (Python) or `go test ./...` (Go) to see it.

---

*Questions on the format or an independent reimplementation are welcome via the repository's issues.
The specification is a v0.1 draft, published precisely so that auditors and CABs can review and rely
on it.*
