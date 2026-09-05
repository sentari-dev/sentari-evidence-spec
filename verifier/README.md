# Sentari evidence-pack — reference offline verifier

A single-file, dependency-light tool that lets **any auditor or conformity-assessment
body (CAB) independently verify a Sentari evidence pack, offline, with no dependency
on Sentari's servers.** It is the reference implementation of the open specification in
[`spec/spec-v0.1.md`](../spec/spec-v0.1.md).

Anyone can reimplement this in any language; the point of the spec is that the format
is open and the proof is checkable by whoever needs to trust it.

## Install

```
pip install -r requirements.txt      # just 'cryptography'
```

## Use

```
python sentari_evidence_verify.py PACK [--pubkey B64] [--expected-key-id ID] [--json]
```

`PACK` is a downloaded evidence pack: a `.json` artifact, a `.zip` bundle, or a directory
of its members. Example:

```
python sentari_evidence_verify.py my-cyfun-pack.json \
    --expected-key-id ed25519:2c324e5afc47...     # your deployment's published key fingerprint
```

Exit code: `0` verified · `2` tampered · `3` key_unknown · `4` parse/usage error.

## What it checks (spec §9)

| Layer | Check |
|---|---|
| **1 — payload_intact** | recompute `content_sha256` over the canonical payload and compare |
| **2 — frozen_inputs_valid** | recompute the frozen-inputs hash and every per-source hash *(the download embeds `frozen_inputs`; older pre-embed packs skip this — see below)* |
| **signature** | Ed25519 over the domain-separated envelope `{content_sha256, ctx, frozen_inputs_sha256}`, plus a consistency check that the detached block's `algorithm` / `context` / `content_sha256` agree with the payload |
| **manifest** *(zip / dir packs)* | verify the signed `manifest.json` envelope and every listed member's raw-bytes SHA-256 **before** trusting `evidence.json` / `signature.json`, so a swapped member is caught even when the JSON pair is internally intact |
| **key_id** | confirm the key's own fingerprint (material), and (with `--expected-key-id`) an out-of-band trust anchor |

It reports one of `verified` / `tampered` / `key_unknown` — never a bare boolean:

- **`tampered`** — a checked integrity layer failed: payload, frozen-inputs, signature,
  the signed manifest, the key *material* (`key_id` ≠ fingerprint of the embedded key), or
  the detached-signature metadata disagreeing with the payload.
- **`key_unknown`** — the math is internally consistent but authenticity can't be
  established: no key available/decodable, **or** the key doesn't match your
  `--expected-key-id` anchor (a rotated / foreign / not-the-one-you-pinned key). A key
  you didn't pin is *unknown*, not *tampered*.
- **`verified`** — payload + signature verify and, if you supplied an anchor, the key matches it.

Malformed artefacts (bad base64 in a signature/key, a non-dict frozen source, a corrupt
manifest) resolve to a deterministic verdict — the tool never crashes out of its
exit-code contract.

**Layer 3** (collector re-derivation) is intentionally *not* implemented here: it needs
the framework collector code for the pack's `catalog_version` and is a server-side check
(spec §5.4). Layers 1 + 2 + signature are what an offline auditor needs.

## Trust anchor

The embedded public key proves only *internal consistency*. **Authenticity requires
comparing `key_id` to the deployment's out-of-band-published key fingerprint** — pass it
via `--expected-key-id` (or the key itself via `--pubkey`). Without an anchor the tool
verifies the math and warns that authenticity is not established.

## Offline Layer 2

The Sentari download **embeds `frozen_inputs`** — a signed `frozen_inputs.json` member in
the zip, and a sibling in the standalone json — so **Layer 2 is verifiable offline** from
the artifact alone (not just the payload hash + signature). If you verify an *older* pack
whose download predates this, the tool reports `frozen_inputs not embedded — Layer 2
skipped` and still checks Layers 1 + signature.

## Tests / conformance vectors

`test_verify.py` builds golden packs the way a producer would and asserts every tamper
mutation is caught, pins the canonical-JSON byte encoding, and — crucially —
verifies a **real Sentari-signed CyFun pack** committed under `vectors/`
(`cyfun-empty-fleet.golden.json`, an empty-fleet pack with no PII), cross-validating this
verifier against the actual server implementation.

```
pip install cryptography pytest && pytest
```
