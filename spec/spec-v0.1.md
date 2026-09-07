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

> **On "not re-scored" (v0.1 clarification).** `evidence_class` grades the provenance of the
> *evidence*, not the verdict rule. "Not re-scored" means the producer does not re-derive or mutate
> the observed values — they are frozen and hashed exactly as read from the system of record. A
> control MAY still apply a **published, deterministic threshold** to that frozen observed evidence to
> reach its verdict (e.g. "privileged accounts without smartcard-required auth > 0 → at-risk")
> without downgrading the `observed` grade. What *would* break the grade is changing the observed
> numbers, cross-source deduplication, or re-deriving them. `basis` (how the verdict was reached —
> automated / attested / manual) stays orthogonal to `evidence_class` (the provenance grade of the
> evidence behind the verdict).

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

## 12. Signed exportable artifacts (SBOM / VEX)

The same signing primitives (§4 canonical JSON, §6 Ed25519, §6.2 `key_id`) also sign Sentari's **exportable artifacts** — its **SBOM** (CycloneDX 1.6 / SPDX 2.3) and **VEX** (OpenVEX / CycloneDX) downloads — so the *entire* evidence surface, not just compliance packs, is offline-verifiable with the same tool and the same published key fingerprint. An SBOM/VEX is a **standard-schema document**, so the signature model differs from a pack in a few deliberate ways.

### 12.1 The two contexts

Each artifact type has its own **domain-separated context**, distinct from the pack's `sentari-evidence-pack/v1`:

| Artifact | `ctx` |
|---|---|
| SBOM (CycloneDX or SPDX) | `sentari-sbom/v1` |
| VEX (OpenVEX or CycloneDX) | `sentari-vex/v1` |

The `ctx` is folded **inside** the Ed25519-signed envelope, so a signature can never cross-verify as a different artifact type — replaying an SBOM signature as a VEX (or as a pack) breaks the signature outright.

### 12.2 Document-as-is hashing (NOT blank-and-rehash)

A pack embeds its own `content_sha256` field and therefore hashes itself with that field **blanked** (§5.1). A standard-schema SBOM/VEX MUST NOT be mutated — injecting a `content_sha256` field would break schema conformance and downstream tool consumption. So the hash is over the **document exactly as emitted**:

```
content_sha256 = sha256( canonical_json(document) )     # no blanking, no field injection
```

The signature is **detached** (a sibling block, not a field of the document).

**No floats in the hashed document (invariant, carried from §4).** `canonical_json` does **not** canonicalise numbers, so cross-language (Python ↔ Go) byte-equality holds only for strings, integers, and nested maps/arrays of those — never floats. A float would split-brain the verifiers (`json.dumps(10.0)` → `"10.0"` vs a Go `float64` → `"10"`). Both surfaces are float-free today (`version` is the integer `1`; component versions are strings; the VEX serializers emit no CVSS/EPSS scores), and a **conformant producer's signer MUST reject** any `float` — or any integer outside the JS safe-integer range ±2⁵³ — anywhere in the document at sign time, so the landmine is closed at the source rather than left to a foreign verifier. (To sign CVSS-in-VEX later, emit scores as strings, or move to a JCS/number-canonical ctx — a separately-reviewed change.)

### 12.3 The 2-key signed envelope

Ed25519 signs the canonical JSON of a **2-key** envelope — there is no `frozen_inputs_sha256` because an SBOM/VEX is the artifact itself, not a value derived from frozen inputs:

```json
{"content_sha256": "<hex>", "ctx": "sentari-sbom/v1"}
```

This is deliberately **not** the pack's 3-key `{content_sha256, ctx, frozen_inputs_sha256}` envelope (§6.1).

### 12.4 The wrapper form & the detached block

A signed artifact is a single JSON file — a wrapper pairing the untouched document with its detached block:

```jsonc
{
  "document": { /* the CycloneDX / SPDX / OpenVEX document, byte-for-byte as exported */ },
  "signature": {
    "algorithm": "ed25519",
    "context": "sentari-sbom/v1",
    "key_id": "ed25519:…",
    "content_sha256": "<hex>",
    "value": "<base64 sig over canonical_json({content_sha256, ctx})>",
    "public_key": "<base64 raw 32-byte key>",
    "note": "<human verify instructions + attestation scope (§12.6)>"
  }
}
```

Extract `.document` for direct tool consumption; verify the whole wrapper for authenticity. (The raw, unsigned download remains available unchanged for tools that want only the document.)

### 12.5 Shared key, one fingerprint

SBOM/VEX are signed with the **same evidence Ed25519 key** that signs packs — so **one out-of-band-published `key_id` verifies packs, SBOMs and VEX alike**; no new key, no new trust anchor. **Accepted tradeoff (stated explicitly):** compromise or rotation of this one key invalidates trust in packs *and* SBOM *and* VEX together — inherent to a shared anchor, and the §12.1 `ctx` domain-separation is what makes sharing the key safe against cross-artifact replay.

### 12.6 Verifier obligations (offline)

A conformant offline verifier dispatches on the block's `context`. For an artifact `ctx` (`sentari-sbom/v1` / `sentari-vex/v1`) it MUST:

1. **Layer 1** — recompute `sha256(canonical_json(document))` over the document **as-is** (NOT the pack's blank-and-rehash: a document has no `content_sha256` field to blank, and injecting one would produce a hash outside the signed bytes → false `tampered`).
2. Compare that recomputed hash to the **block's** `content_sha256` (the document embeds none of its own).
3. **Signature** — Ed25519-verify `value` over `canonical_json({content_sha256, ctx})` — the **2-key** envelope — and confirm `key_id` equals the key fingerprint AND (for a real trust decision) an out-of-band anchor.
4. Recognize the `{"document":…, "signature":…}` **wrapper** before any flat-pack fallback, and **reject an unknown `ctx`** (neither the pack ctx nor a known artifact ctx) as `tampered` — an unknown format is never silently accepted.
5. Report **Layer 2 (frozen inputs)** and **Layer 3 (collector re-derivation)** as **N/A** — this artifact class has neither. This is deliberately distinct wording from the pack's "skipped", so an auditor never conflates "this class has no Layer 2" with "could have checked, didn't."

The verdict vocabulary (`verified` / `tampered` / `key_unknown`), exit codes, and the `key_id` trust model are exactly as for packs (§5.5, §9). The reference Python and Go verifiers both ship signed SBOM and VEX conformance vectors and verify them to `verified` byte-for-byte — the empirical proof the document path is reimplementable, not vendor-locked.

### 12.7 Attestation scope

A verified SBOM/VEX signature attests **integrity** (these exact bytes are unaltered) and **provenance / authenticity** (produced by this deployment's evidence key). It does **NOT** attest:

- **completeness** — that every installed component / applicable vulnerability is listed;
- **correctness** — that versions, licences, purls, or VEX statuses are accurate;
- **freshness** — an SBOM/VEX is a **point-in-time** export, not a live view of the current fleet.

The CycloneDX `compositions` known-unknowns buckets already signal content completeness honestly; the signature claim gets the same discipline. The detached block's `note` states this scope in-band.

### 12.8 A canonical-form footgun (informative)

Sentari's internal VEX-snapshot column hash uses `json.dumps(sort_keys, separators)` **without** `ensure_ascii=False`, whereas the signed `content_sha256` uses §4 `canonical_json` (**with** it). For non-ASCII content these two "canonical" hashes over the same document differ **by design** — they are intentionally independent. An auditor comparing a deployment's internal DB `sha256_hash` to the signed `content_sha256` MUST NOT read that mismatch as tampering; only the §12.6 recomputation is normative for a signed artifact.

### 12.9 Standards alignment

The §11 in-toto/DSSE framing applies unchanged: an SBOM/VEX maps to an in-toto Statement whose `subject[].digest.sha256` is the document hash and whose `predicateType` is the artifact `ctx` URI; the same DSSE-PAE gap and the same future-work stance hold.

---

## Appendix A — Change log
- **v0.1 (draft):** initial public draft. Adds `evidence_class`; **embeds `frozen_inputs` in the artifact** (signed `frozen_inputs.json` zip member + standalone-json sibling) so offline Layer 2 is checkable from the artifact alone; recommends in-toto/DSSE framing for v1. Open for CAB/auditor review.
- **v0.1 (draft), §12 addition:** extends signing to **exportable artifacts** — signed SBOM (`sentari-sbom/v1`) and VEX (`sentari-vex/v1`) downloads. Document-as-is hashing (no blank-and-rehash), a 2-key `{content_sha256, ctx}` envelope, the `{document, signature}` wrapper form, the no-floats-in-hashed-content invariant, the shared evidence key/`key_id` across the whole surface, the document-path verifier obligations (Layer 2/3 **N/A**), and an explicit attestation-scope statement. Both reference verifiers (Python + Go) ship signed SBOM/VEX conformance vectors and verify them byte-for-byte.
