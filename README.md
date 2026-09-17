# Sentari evidence-pack — open format & reference verifier

A **Sentari evidence pack** is a signed, self-describing bundle of regulatory-compliance
evidence (e.g. CyFun / NIS2 / DORA / CRA control results) generated from an
organisation's own ground-truth system state.

This repository publishes two things so that a pack's authenticity and integrity are
checkable by **whoever needs to trust it** — an auditor, a conformity-assessment body
(CAB), a customer, a regulator — with **no dependency on Sentari's servers and no network
at all**:

0. **[`verify.html`](verify.html)** — a **single self-contained page** that verifies a pack
   and then *renders the assessment*. No install, no terminal, no dependencies, and no
   network at any point: save it to a USB stick, double-click it, and it works from
   `file://` on a machine that has never been online. This is what to hand an auditor or a
   CAB. Its whole source is readable with View Source, and its own SHA-256 is published in
   [`verify.html.sha256`](verify.html.sha256).
1. **[`spec/spec-v0.1.md`](spec/spec-v0.1.md)** — the open specification of the pack
   format: canonical JSON, the content hash, the domain-separated Ed25519 signature
   envelope, the frozen-inputs model, the signed zip manifest, and the evidence-class
   grading (derived / observed / declared). **§12** extends the same primitives to
   Sentari's signed **SBOM and VEX** exports, so the whole evidence surface — not just
   compliance packs — is offline-verifiable with the same tool and the same key.
2. **[`verifier/`](verifier/)** — a single-file, dependency-light **reference offline
   verifier** (Python + `cryptography`). It re-derives every hash and checks every
   signature independently of the server.
3. **[`verifier-go/`](verifier-go/)** — a **third** independent verifier in Go (standard
   library only, a single static binary — ideal for an air-gapped auditor).

All three agree *byte-for-byte* on every committed vector, and `verifier/conformance.sh`
proves it in one command. Three independent implementations, in three languages, agreeing
is the strongest evidence the format is genuinely open and not vendor-locked — and one of
them is auditable by View Source.

New to this? **[`AUDITOR_GUIDE.md`](AUDITOR_GUIDE.md)** is a one-page "verify it yourself"
guide for auditors and conformity-assessment bodies.

## Why publish this

Tool-generated regulatory evidence is only as trustworthy as your ability to *check it
yourself*. A PDF a vendor hands you proves nothing. An evidence pack whose format is
open, whose signature you can verify offline against a key you pinned out-of-band, and
whose numbers you can recompute from the frozen inputs — that is evidence you can stand
behind in front of a regulator. Sentari would rather the format be a **shared standard**
than a proprietary claim.

## Verify a pack

**Without installing anything:** open [`verify.html`](verify.html) and drop the file in. It
checks the file on your own machine and then renders the assessment — what is compliant,
what needs remediation, and the source records behind each result — and prints as a
document for an evidence file.

**From a terminal:**

```bash
pip install -r verifier/requirements.txt        # just 'cryptography'
python verifier/sentari_evidence_verify.py my-pack.json \
    --expected-key-id ed25519:<your deployment's published key fingerprint>
echo $?     # 0 verified · 2 tampered · 3 key_unknown · 4 parse/usage error
```

`my-pack.json` (or a `.zip` bundle, or a directory of its members) is a pack downloaded
from a Sentari deployment. The verifier reports one of `verified` / `tampered` /
`key_unknown` — never a bare boolean — and distinguishes **tampering** (a hard failure)
from a merely **unknown key** (rotated / foreign / not the one you pinned).

## What "offline" really means here

- **Layer 1** — the payload's `content_sha256` is recomputed over the canonical JSON.
- **Layer 2** — the pack embeds its `frozen_inputs`, so every per-source hash the numbers
  were derived from is recomputable **from the artifact alone**.
- **Signature** — Ed25519 over a domain-separated `{content_sha256, ctx,
  frozen_inputs_sha256}` envelope, against a key whose fingerprint (`key_id`) you compare
  to an out-of-band-published anchor.
- **Zip packs** additionally carry a signed `manifest.json` binding every member's hash,
  so a swapped file is caught even when the JSON pair is internally intact.

Layer 3 (re-deriving the numbers by re-running the collector) needs the collector code
for the pack's `catalog_version` and is out of scope for this offline tool.

## Conformance vectors

[`verifier/test_verify.py`](verifier/test_verify.py) builds golden packs the way a
conformant producer would, asserts every tamper mutation is caught, pins the canonical
byte encoding, and — crucially — verifies a **real Sentari-signed CyFun pack** committed
under [`verifier/vectors/`](verifier/vectors/) (an empty-fleet pack, no PII), cross-
validating the reference verifier against the actual producer. It also verifies committed
**signed SBOM and VEX** vectors (`sbom-cyclonedx.signed.golden.json`,
`vex-openvex.signed.golden.json`) through the §12 document path — and **both** the Python
and Go verifiers verify **both** artifacts to `verified` byte-for-byte, which is the
empirical proof the format is genuinely reimplementable across languages.

```bash
pip install cryptography pytest && (cd verifier && pytest)
```

**[`CONFORMANCE.md`](CONFORMANCE.md)** is the published contract: the exact verdict every
committed vector must produce (default, correct/wrong `--expected-key-id`, tampered), the
mutation matrix a conformant verifier must catch, and a reimplementer's checklist. Prove the
whole thing — both verifiers, every vector, plus tamper detection — in one command:

```bash
verifier/conformance.sh      # all three verifiers, every vector, prints PASS/FAIL
```

A deeper cross-check, for anyone changing a verification core: [`verifier-web/differential.mjs`](verifier-web/differential.mjs) mutates and deletes
every field of every committed artifact in turn and requires the browser and Python
verifiers to return the *same* verdict on all of them — not merely the right verdict on
the curated cases.

## Status

**v0.1 DRAFT** — published for review with auditors and CABs; not yet a frozen v1. Issues
and independent reimplementations are welcome.

## License

[Apache-2.0](LICENSE). The specification and the reference verifier are free to use,
implement, and redistribute.

---

Sentari is a sovereign, on-premise software supply-chain and regulatory-compliance
evidence platform. This repository is the **open** part: the evidence format and the
means to verify it. The product itself lives elsewhere.
