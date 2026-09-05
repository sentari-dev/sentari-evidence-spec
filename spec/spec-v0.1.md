# Sentari Evidence-Pack Format — Open Specification v0.1 (DRAFT)

**Status:** DRAFT — for review with conformity-assessment bodies (CABs) and auditors. Not yet a frozen v1. Published so that any auditor, customer, or third party can **independently verify** a Sentari evidence pack **offline**, with no dependency on Sentari's servers, and so the format can become a shared standard for tool-generated regulatory evidence rather than a proprietary claim.

**Scope:** this document specifies (1) the byte-level structure of an evidence pack, (2) the canonicalisation and signing scheme, (3) the verification algorithm a conformant verifier MUST implement, and (4) the offline-verification and standards-alignment requirements. A companion **reference verifier CLI** and **conformance test-vector suite** accompany this spec (see [§10](#10-conformance)).

The key words MUST, MUST NOT, SHOULD, MAY are to be interpreted as in RFC 2119.

---

## 1. Overview

An **evidence pack** is a signed, content-addressed, reproducible snapshot of an organisation's compliance posture for one regulatory framework (e.g. CyFun, NIS2, DORA, CRA) at one instant, derived from that organisation's own fleet/system-of-record data. Its purpose is to let an auditor answer *"was control X satisfied on date D, and can I verify that without trusting the vendor?"* by **re-deriving** the pack's content hash from its frozen inputs and checking a signature.

Three properties define the format:

1. **Content-addressed** — the pack carries a `content_sha256` over its own canonical bytes; any change to the evidence changes the hash.
2. **Reproducible** — the pack freezes every input it was computed from, so the same inputs re-derive the same hash forever (no wall-clock, no live data).
3. **Signed** — an Ed25519 signature binds the content hash and the frozen-inputs hash under a domain-separated context, so neither can be swapped independently.

**Evidence is graded, not asserted.** Every control result carries an **evidence class** ([§7](#7-evidence-class)) — `derived` (measured from ground-truth system state), `observed` (read from a system of record and frozen), or `declared` (human attestation). A verifier and an auditor can see, per control, *how* each claim is substantiated.

---

## 2. Terminology

| Term | Meaning |
|---|---|
| **pack** | one evidence pack (one framework, one scope, one instant) |
| **payload** | the canonical JSON object that is content-hashed and whose hash is signed |
| **frozen inputs** | the exact source data the payload was computed from, captured once and hashed |
| **collector** | the deterministic function `f(frozen_inputs, generated_at) → controls[]` for a framework |
| **canonical JSON** | the byte encoding defined in [§4](#4-canonical-json) |
| **content hash** | `sha256(canonical_json(payload with content_sha256 blanked))` |
| **envelope** | the small signed object binding the two hashes ([§6](#6-signing)) |

---

## 3. Pack structure

### 3.1 Payload

The `payload` is a JSON object with these members (all REQUIRED unless noted). Member order is irrelevant to consumers but fixed by canonicalisation ([§4](#4-canonical-json)).

```jsonc
{
  "pack_id":            "<uuid>",
  "framework":          "CYFUN",                 // CYFUN | NIS2 | DORA | CRA | ...
  "framework_version":  "<string>",              // the regulation/catalog version
  "catalog_version":    "<string>",              // collector-output contract id (see §8)
  "generated_at":       "<RFC3339 UTC>",         // freeze instant; the ONLY clock the pack knows
  "generated_by":       "<uuid|null>",           // actor id
  "generated_by_email": "<string|null>",         // frozen for offline identity
  "content_sha256":     "<hex64>",               // hash of this payload with THIS field blanked (§5)
  "scope":              { "kind": "fleet" },     // subject scope
  "coverage": {
    "assessed_control_ids":      ["ID.AM-1", ...],
    "not_assessed_framework_refs": ["ID.AM-2", ...]   // the honesty ledger
  },
  "controls": [ <control-result>, ... ]
}
```

**Honesty ledger.** `coverage.not_assessed_framework_refs` MUST list every framework control the pack does **not** evidence. A conformant producer MUST NOT silently omit controls; unassessed controls are declared, not hidden.

### 3.2 Control result

Each entry of `controls[]`:

```jsonc
{
  "id":             "ID.AM-1",
  "article_ref":    "<string>",
  "title":          "<string>",
  "basis":          "automated",         // automated | attested | manual  (HOW assessed)
  "evidence_class": "derived",           // derived | observed | declared   (§7 — provenance grade)
  "status":         "compliant",         // compliant | at_risk | non_compliant | not_assessed
  "not_applicable": false,               // true = compliant rests on an approved N/A attestation
  "summary":        "<string>",
  "evidence_refs":  [ <evidence-ref> ],  // see §7.2
  "findings":       [ ... ]
}
```

### 3.3 Frozen inputs

`frozen_inputs` is the exact data `controls[]` was computed from:

```jsonc
{
  "sources": {
    "<SOURCE_NAME>": { "rows": [...], "sha256": "<hex64>", ...summary },
    ...
  },
  "scope": { "kind": "fleet" }
}
```

Two source shapes:
- **row-list source** — `{"rows": [...], "sha256": <sha256 of canonical_json(rows)>}`.
- **aggregate source** — `rows`/counts plus summary keys; `sha256` covers `canonical_json(inner minus "sha256")`.

Which sources appear is declared per framework by the collector. `frozen_inputs_sha256 = sha256(canonical_json(frozen_inputs))` is stored alongside and bound into the signature.

### 3.4 Artifact formats

A downloaded pack MUST be one of:
- **json** — the canonical `payload` plus a detached `signature` block ([§6.4](#64-detached-signature-block)) as a sibling (the signature is OUTSIDE the hashed payload).
- **pdf** — human-readable rendering plus the same detached block.
- **zip** — a deterministic archive containing `evidence.json` (the pure canonical payload the manifest signs), `evidence.pdf`, `signature.json` (detached block incl. public key), a `manifest.json` (Ed25519-signed, listing every member with its sha256), and `README.txt` (verification instructions). Archive timestamps MUST be fixed so the zip is byte-reproducible.

> **Offline-completeness:** the downloadable artifact **embeds `frozen_inputs`**, so [Layer 2](#53-layer-2--frozen-inputs) is checkable offline from the artifact alone. The **zip** carries a signed `frozen_inputs.json` member (covered by the manifest like every member); the **standalone json** embeds `frozen_inputs` as a sibling (outside the hashed payload, alongside `signature`). A conformant producer MUST embed it. All of Layers 1–2 + the signature are therefore verifiable with no server contact.

### 3.5 Signed manifest (zip)

The `zip` (and any directory-form) artifact carries a `manifest.json` that binds every member of the archive so a swapped or edited file is caught even when `evidence.json`/`signature.json` are internally intact. It is an **Ed25519-signed envelope** using the same signing key as the detached block ([§6.4](#64-detached-signature-block)) and the same `key_id` fingerprint scheme ([§6.2](#62-key_id)):

```jsonc
{
  "payload": {
    "domain": "compliance.evidence",
    "files": [
      { "name": "evidence.json",  "sha256": "<hex of the member's RAW bytes>", "description": "..." },
      { "name": "signature.json", "sha256": "<hex>", "description": "..." },
      { "name": "frozen_inputs.json", "sha256": "<hex>", "description": "..." }
      // ...one entry per archive member (evidence.pdf, README.txt, ...)
    ]
    // producers MAY add further payload fields (e.g. generated_at); all are covered by the signature
  },
  "signature": "<base64( Ed25519_sign( canonical_json(payload) ) )>",
  "key_id": "ed25519:..."
}
```

`sha256` is over each member's **raw bytes as stored in the archive** (NOT `canonical_json` — the archive bytes are what an extractor sees). The manifest `signature` is over `canonical_json(payload)` exactly as in [§6.1](#61-the-signed-envelope-domain-separated)/[§6.3](#63-signature-verification-verifier)) but with the manifest `payload` as the signed object (there is no domain-separated inner envelope for the manifest — the object itself is signed).

**Verifier requirement (zip/dir):** before trusting `evidence.json`/`signature.json`, a verifier MUST (1) verify the manifest's Ed25519 signature over `canonical_json(payload)` with the pack's public key, (2) recompute the raw-bytes sha256 of every listed member it holds and compare, and (3) require the trust-bearing members (`evidence.json`, `signature.json`) to be listed. Any failure ⇒ **tampered** ([§5.5](#55-tamper-vs-drift)).

---

## 4. Canonical JSON

`canonical_json(x)` is:

```
UTF-8 bytes of json.dumps(x, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
```

That is: object keys sorted lexicographically by Unicode code point; no insignificant whitespace; `,` and `:` separators with no spaces; non-ASCII characters emitted as raw UTF-8 (NOT `\u`-escaped); HTML-significant characters NOT escaped.

The byte string produced by the `json.dumps(...)` definition above is **normative** — it is the exact output a conformant implementation MUST reproduce. It is closely related to RFC 8785 (JCS) and coincides with JCS for the value space these payloads use, but this spec does **not** adopt RFC 8785's number-canonicalisation rules (payloads never emit floats — see below). Do not substitute a strict JCS library and assume identical bytes; reproduce the definition above.

A conformant implementation in another language MUST reproduce these bytes exactly. (Go: `json.Marshal` with a canonicalising encoder that sorts map keys and disables HTML escaping via `Encoder.SetEscapeHTML(false)`.)

Numbers: payloads use only integers and strings; producers MUST NOT emit floats in hashed fields (to avoid cross-language float formatting divergence).

---

## 5. Content hash & the three verification layers

### 5.1 content_sha256 derivation (producer)

1. Build the payload with `content_sha256` set to the empty string `""`.
2. `content_sha256 = hex(sha256(canonical_json(payload_with_blank_field)))`.
3. Re-emit the payload with `content_sha256` embedded.

### 5.2 Layer 1 — payload intact

`recompute`: set the payload's `content_sha256` back to `""`, `canonical_json`, `sha256`, and compare to the pack's stored `content_sha256`. MUST match. Cheap; a verifier runs this first.

### 5.3 Layer 2 — frozen inputs

- `sha256(canonical_json(frozen_inputs)) == frozen_inputs_sha256`, AND
- for every source in `frozen_inputs.sources`, recompute its inner `sha256` (row-list vs aggregate rule, [§3.3](#33-frozen-inputs)) and compare to the stored per-source `sha256`.

Every source MUST be checked, even ones the collector no longer reads. Requires the artifact to embed `frozen_inputs` ([§3.4](#34-artifact-formats) offline-completeness note).

### 5.4 Layer 3 — collector reproducible (online / optional offline)

Re-run the framework collector for `catalog_version` on `frozen_inputs`, using **only** the pack's frozen `generated_at` as its clock, rebuild the core payload with the pack's stored metadata (versions/scope/coverage/generated_at pinned — never a live registry), and confirm `sha256(canonical_json(core)) == content_sha256`. This requires the collector code for that `catalog_version` and is normally a server-side / reference-implementation check; an offline CLI MAY skip it.

### 5.5 Tamper vs. drift

A verifier MUST distinguish:
- **tampered** — Layer 1 or Layer 2 fails, the signed manifest fails ([§3.5](#35-signed-manifest-zip)), the detached-block metadata columns disagree with the hash-verified payload, the signature is invalid, **or** `key_id` does not equal the fingerprint of the *embedded* public key (the key material was rewritten). This is a hard failure.
- **collector_drift** — Layers 1 + 2 pass but Layer 3 fails: the shipped collector *code* changed since generation. This is NOT tampering and MUST NOT invalidate a historically-signed pack.
- **key_unknown** — the signature math is internally consistent but authenticity cannot be established: no signing key is available/decodable, **or** the key's fingerprint does not match the out-of-band anchor the verifier was given (a rotated, foreign, or not-the-one-you-pinned key). This is neither valid nor tampered; it is "re-verify against the archived/published key". The required verifier vocabulary uses the token `key_unknown` (see [§9](#9-offline-verification)).

---

## 6. Signing

### 6.1 The signed envelope (domain-separated)

The signature is **NOT** over the whole payload. It is over the canonical JSON of a three-key inner object:

```json
{"content_sha256":"<hex>","ctx":"sentari-evidence-pack/v1","frozen_inputs_sha256":"<hex>"}
```

`ctx` is a domain-separation tag; a signature from any other Sentari signing channel therefore cannot cross-verify as an evidence pack. Binding both hashes means neither the payload nor the frozen-inputs can be swapped independently.

`signature = base64( Ed25519_sign( canonical_json(inner) ) )`.

### 6.2 key_id

`key_id = "ed25519:" + hex(sha256(raw_32_byte_public_key))[:32]`. Because it is a fingerprint of the key material, a rotated/regenerated key yields a different `key_id`; historical packs then read as "key not known" rather than "tampered". An auditor confirms authenticity by comparing `key_id` to the deployment's **out-of-band-published** fingerprint.

### 6.3 Signature verification (verifier)

```
inner = {"ctx": "sentari-evidence-pack/v1",
         "content_sha256": pack.content_sha256,
         "frozen_inputs_sha256": pack.frozen_inputs_sha256}
assert Ed25519_verify(pubkey, base64_decode(pack.signature), canonical_json(inner))
assert pack.key_id == "ed25519:" + hex(sha256(pubkey_raw))[:32]
assert pack.key_id == expected_fingerprint   // out-of-band trust anchor
```

### 6.4 Detached signature block

json/pdf artifacts carry a sibling block (and the zip a `signature.json` member):

```jsonc
{
  "algorithm": "ed25519",
  "context": "sentari-evidence-pack/v1",
  "key_id": "ed25519:...",
  "content_sha256": "<hex>",
  "frozen_inputs_sha256": "<hex>",
  "value": "<base64 signature>",
  "public_key": "<base64 raw 32-byte key, when the pack's key_id matches the live key>",
  "note": "<human verification instructions>"
}
```

The embedded `public_key` proves internal consistency only; **authenticity requires comparing `key_id` to an out-of-band anchor** (or passing `--pubkey` to the verifier).

---

## 7. Evidence class

`evidence_class` grades the provenance of each control result, so ground truth becomes a *visible quality grade* rather than a binary the vendor asserts:

| Class | Meaning |
|---|---|
| **derived** | Measured from the organisation's ground-truth system state by Sentari's own collector (packages/runtimes/host/config). Highest grade. |
| **observed** | Read from a system of record (EDR / MDM / IdP / backup / SIEM) and captured as a frozen, hashed source — *not* re-scored or cross-source-deduped. |
| **declared** | Human attestation (e.g. a four-eyes control attestation). |

### 7.1 Placement

`evidence_class` is a per-control member of each control result ([§3.2](#32-control-result)), adjacent to `not_applicable`. It is content-hashed and signed like every other field.

### 7.2 Per-item classification (optional)

For per-*evidence-item* granularity, `evidence_refs` MAY be promoted from bare strings to objects `{ "ref": "<string>", "class": "derived|observed|declared" }`. A control's top-level `evidence_class` then reflects the lowest grade among its items. Producers MUST pick one representation per `catalog_version` and MUST bump `catalog_version` when changing it ([§8](#8-versioning)).

---

## 8. Versioning

`catalog_version` is the collector-output contract id. **Any change to the observable output of a collector — including adding `evidence_class` or changing `evidence_refs` shape — MUST bump `catalog_version`.** It is enforced by a golden-hash contract in the reference implementation. The `payload` schema version is this specification's version (`v0.1`); a `payload_schema` member SHOULD be added at v1.

---

## 9. Offline verification

A conformant **offline** verifier (e.g. a CAB running the reference CLI with no network) MUST:

1. Parse the artifact. For zip/dir: read `manifest.json` and verify the manifest's own Ed25519 envelope and each member's `sha256` per [§3.5](#35-signed-manifest-zip) **before** trusting the other members.
2. **Layer 1** — recompute `content_sha256` and compare.
3. **Layer 2** — recompute `frozen_inputs_sha256` and every per-source hash (requires embedded `frozen_inputs`, [§3.4](#34-artifact-formats)).
4. **Signature** — reconstruct the inner envelope, Ed25519-verify against the embedded/provided public key, and confirm `key_id` equals the key fingerprint AND an out-of-band trust anchor.
5. **Layer 3** is OPTIONAL offline (needs the collector for that `catalog_version`).

The verifier MUST report one of: `verified`, `tampered`, `collector_drift`, or `key_unknown` ([§5.5](#55-tamper-vs-drift)), never a bare boolean.

---

## 10. Conformance

A **conformant producer** MUST emit packs satisfying §§3–8 and embed `frozen_inputs` + the detached signature block in the artifact. A **conformant verifier** MUST implement §9 steps 1–4 and MAY implement step 5.

This spec ships with:
- a **reference verifier CLI** (offline; steps 1–4), and
- a **conformance test-vector suite**: known-good packs, and mutated packs that MUST be reported `tampered` (flipped payload byte, swapped frozen source, altered signature, wrong `key_id`), plus a `collector_drift` vector.

*(The reference CLI and test vectors are delivered alongside this spec; see the companion PR in this stack.)*

---

## 11. Standards alignment (informative)

The format is expressible as an **in-toto Statement v1** wrapped in a **DSSE** envelope, and v1 SHOULD adopt that framing so off-the-shelf `cosign`/in-toto verifiers can consume packs:

| This spec | in-toto / DSSE |
|---|---|
| `content_sha256` over payload | `subject[].digest.sha256` (the payload is the subject) |
| `ctx = "sentari-evidence-pack/v1"` | `predicateType` URI (e.g. `https://sentari.dev/evidence-pack/v1`) |
| `payload` (controls/coverage/scope) | the `predicate` |
| `frozen_inputs` + per-source sha256 | `resolvedDependencies[]` with `digest` |
| `key_id = ed25519:sha256(pubkey)[:32]` | DSSE `keyid` |

**The one real gap:** this spec signs a canonical JSON object directly, whereas DSSE signs `PAE(payloadType, payload)` (pre-authentication encoding). v1 MUST either adopt DSSE PAE or document the divergence explicitly. Everything else (content-addressing, keyid-as-fingerprint, per-source material digests, the honesty ledger, evidence-class grading) already aligns and, in the case of evidence-class + the not-assessed ledger, *extends* what the base standards offer.

---

## Appendix A — Change log
- **v0.1 (draft):** initial public draft. Adds `evidence_class`; **embeds `frozen_inputs` in the artifact** (signed `frozen_inputs.json` zip member + standalone-json sibling) so offline Layer 2 is checkable from the artifact alone; recommends in-toto/DSSE framing for v1. Open for CAB/auditor review.
