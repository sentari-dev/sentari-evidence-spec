# Conformance — verify Sentari evidence offline, and self-check a reimplementation

This document is the **conformance contract** for the Sentari evidence format. It lets
you do two things with **no Sentari deployment and no network**:

1. **Verify a real Sentari artifact yourself** — an evidence pack, or a signed SBOM/VEX.
2. **Self-check a reimplementation** — if you rewrite the verifier in your own language,
   run it against the committed vectors and confirm it produces the verdicts below.

Three independent reference verifiers ship here — [`verify.html`](../verify.html) (a
dependency-free browser page), `verifier/` (Python) and `verifier-go/` (Go, single static
binary). They agree **byte-for-byte** on every vector; that agreement is the strongest
evidence the format is genuinely open and not vendor-locked.

The browser verifier is held to this same table by `verifier-web/conformance.mjs`, which
extracts the verification core out of the shipped HTML — the exact bytes an auditor runs —
and drives the vectors and the mutation matrix through it.

## Verify without deploying (3 commands)

```sh
pip install -r verifier/requirements.txt                      # just 'cryptography'
python verifier/sentari_evidence_verify.py verifier/vectors/cyfun-empty-fleet.golden.json
echo $?     # 0 verified · 2 tampered · 3 key_unknown · 4 parse/usage error
```

Or prove the **whole** contract — both verifiers, every vector, plus tamper detection — in
one command:

```sh
verifier/conformance.sh      # all three verifiers, every vector, prints PASS/FAIL
```

## Verdict vocabulary

A conformant verifier reports exactly one verdict — never a bare boolean — and maps it to an
exit code:

| Verdict | Exit | Meaning |
|---|---|---|
| `verified` | `0` | Content hash recomputes, signature checks out, and (if `--expected-key-id` was given) the signing key matches your out-of-band anchor. |
| `tampered` | `2` | A hard integrity failure — the bytes were altered, the signature doesn't verify, or an internal hash disagrees. |
| `key_unknown` | `3` | The signature is internally valid, but the `key_id` is **not** the one you pinned (rotated / foreign / not yours). Not tampering — an unknown signer. |
| _(usage)_ | `4` | Parse or CLI-usage error (not a verdict about the artifact). |

Trust rule: a bare run checks **internal consistency** only. For a real trust decision, pass
`--expected-key-id <the key_id your deployment published out-of-band>` so a foreign or rotated
key surfaces as `key_unknown` instead of `verified`.

## Committed vectors and their expected verdicts

All three vectors are **real, PII-free** Sentari artifacts.

| Vector | Kind | `context` | `key_id` |
|---|---|---|---|
| `verifier/vectors/cyfun-empty-fleet.golden.json` | evidence pack (CyFun, empty fleet) | `sentari-evidence-pack/v1` | `ed25519:2c324e5afc47408739876dba4886ef19` |
| `verifier/vectors/sbom-cyclonedx.signed.golden.json` | signed SBOM (CycloneDX + detached sig) | `sentari-sbom/v1` | `ed25519:eb719d5bab969e9f243775b329a23ac6` |
| `verifier/vectors/vex-openvex.signed.golden.json` | signed VEX (OpenVEX + detached sig) | `sentari-vex/v1` | `ed25519:eb719d5bab969e9f243775b329a23ac6` |

For **every** vector, a conformant verifier MUST produce:

| Invocation | Verdict | Exit |
|---|---|---|
| no `--expected-key-id` | `verified` | `0` |
| `--expected-key-id <the vector's own key_id>` | `verified` | `0` |
| `--expected-key-id <any other id>` | `key_unknown` | `3` |
| any single content byte flipped | `tampered` | `2` |

(The SBOM and VEX vectors share one signing key — the same fingerprint verifies packs, SBOMs
and VEX; one published `key_id` is all an auditor needs to pin.)

## Mutation matrix — what a conformant verifier MUST catch

Each mutation below must move the verdict away from `verified`. The reference suite
`verifier/test_verify.py` exercises every one; the named tests are the authority.

| Mutation | Required verdict | Reference test |
|---|---|---|
| Flip a byte in the packed content / signed document | `tampered` | `test_tampered_*` / signed-document tamper cases |
| Replace / truncate the signature value | `tampered` | signature-field tamper cases |
| Swap the `content_sha256` for a valid-looking but wrong hash | `tampered` | Layer-1 recompute cases |
| Pin a `--expected-key-id` that isn't the signer | `key_unknown` | expected-key-id anchor cases |
| Relabel a signed SBOM/VEX with the pack context (or vice-versa) | `tampered` | cross-context replay cases (§12) |
| Swap a member inside a `.zip` pack so its hash no longer matches `manifest.json` | `tampered` | zip-manifest cases |
| Replace any field with a value of the **wrong JSON type** (`{}`, `[]`, a number, a boolean, `null`) | `tampered` — **never a crash** | type-substitution cases |

**On wrong-typed fields.** Every field in this format is declared somewhere as a string, a
number, a boolean or a container, and handing a verifier an object where a string belongs is
the cheapest hostile input there is. It had no row here until the implementations were
actually compared on it — and they disagreed, one reporting `tampered` and one exiting with
an unhandled traceback. A conformant verifier MUST report a verdict for such an artifact and
MUST NOT raise: an exception is not one of the four values in the vocabulary above, and for
an auditor *"could not be read"* and *"this was altered"* are very different statements.

`verifier-web/differential.mjs` enforces this by substituting `{}`, `[]`, `0`, `true` and
`null` at **every path** — containers as well as leaves, since `x || []` guards against a
field being absent and never against it being the wrong type — and by failing the run
outright when a verifier throws, rather than recording the throw as if it were a verdict.

## Canonical-JSON rule a reimplementation MUST reproduce

Hashes are computed over **canonical JSON**: keys sorted, no insignificant whitespace,
`ensure_ascii=false` (UTF-8, not `\uXXXX`), and **no number canonicalization**. The last point
matters: because numbers are serialized as-authored, the signed content must be **float-free**
(integers within the IEEE-754 safe range only) so the canonical bytes are reproducible across
languages — a Go verifier unmarshals every JSON number as `float64`, so `10.0` vs `10` would
split-brain otherwise. Sentari enforces this float-free invariant at signing time; a
reimplementer's canonicalizer must match it byte-for-byte. The empirical proof that this is
achievable across languages: the Python and Go verifiers here agree on every vector.

Signature envelope (domain-separated, Ed25519):
- **Evidence pack:** `{content_sha256, ctx, frozen_inputs_sha256}` with `ctx = sentari-evidence-pack/v1`.
- **Signed SBOM/VEX:** the detached 2-key envelope `{content_sha256, ctx}` with
  `ctx = sentari-sbom/v1` or `sentari-vex/v1`, over the document hashed **as-is** (no field
  injection / blank-and-rehash). See `spec/spec-v0.1.md` §12.

## Reimplementer's checklist

To claim conformance, your verifier must:

1. Report the four-value vocabulary (`verified` / `tampered` / `key_unknown` / usage-error) with
   exit codes `0 / 2 / 3 / 4`.
2. Recompute `content_sha256` over canonical JSON (rules above) and reject any mismatch as
   `tampered`.
3. Verify the domain-separated Ed25519 envelope for each artifact class (pack vs signed
   SBOM/VEX), rejecting a cross-context relabel as `tampered`.
4. For a pack, recompute every `frozen_inputs` per-source hash from the artifact alone (Layer 2);
   for a `.zip` pack, verify the signed `manifest.json` member hashes.
5. Honor `--expected-key-id`: a signer that isn't the pinned anchor is `key_unknown`, never
   `verified`.
6. Produce the **exact verdicts in the table above** for all three committed vectors, and
   `tampered` for any single-byte mutation. Running `verifier/conformance.sh` (after pointing it
   at your binary) is the intended self-check.

Independent reimplementations are welcome — open an issue with your results.
