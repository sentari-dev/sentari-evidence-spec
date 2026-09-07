#!/usr/bin/env python3
"""Sentari evidence-pack — reference OFFLINE verifier.

Implements the open specification (docs/evidence-pack/spec-v0.1.md) so an
auditor / CAB can verify a Sentari evidence pack with NO dependency on Sentari's
servers. Pure standard library plus ``cryptography`` (Ed25519 only).

It reproduces, independently of the server, spec §9 steps 1–4:

  Layer 1  payload_intact       recompute content_sha256
  Layer 2  frozen_inputs_valid  recompute frozen_inputs_sha256 + every per-source hash
  Signature                     Ed25519 over the domain-separated envelope
  key_id                        confirm key fingerprint (+ optional out-of-band anchor)

For a .zip / directory pack it additionally verifies the signed ``manifest.json``
(its own Ed25519 envelope + every listed member's SHA-256) BEFORE trusting
``evidence.json`` / ``signature.json`` — so a swapped or edited member is caught
even if the JSON pair is internally intact (spec §3.4).

Layer 3 (collector re-derivation) is intentionally NOT implemented here — it
requires the framework collector code for the pack's ``catalog_version`` and is a
server-side / reference-implementation check (spec §5.4).

Verdict is one of: ``verified`` | ``tampered`` | ``key_unknown`` (never a bare bool):
  * tampered     — a checked integrity layer failed (payload, frozen-inputs,
                   signature, manifest, key-material self-consistency, or the
                   detached-signature metadata disagreeing with the payload).
  * key_unknown  — the math is internally consistent but authenticity cannot be
                   established: no key available, OR the key's fingerprint does
                   not match the out-of-band ``--expected-key-id`` anchor
                   (a rotated / foreign / not-the-one-you-pinned key).
  * verified     — payload + signature verify and (if an anchor was supplied) the
                   key matches it.

The same tool also verifies Sentari's signed **exportable artifacts** — SBOM
(CycloneDX/SPDX) and VEX (OpenVEX/CycloneDX) downloads (spec §12). These are a
wrapper ``{"document": <doc>, "signature": <block>}`` whose block ``context`` is
``sentari-sbom/v1`` / ``sentari-vex/v1``. For them the document is hashed AS-IS
(no blank-and-rehash), the signed envelope is 2-key ``{content_sha256, ctx}``,
and Layer 2/3 are reported **N/A**. The SAME published ``key_id`` verifies packs,
SBOMs and VEX alike.

Usage:
    sentari_evidence_verify.py ARTIFACT [--pubkey B64] [--expected-key-id ID] [--json]

ARTIFACT is either:
  * an evidence pack — a .json file with {"payload":..., "signature":...,
    "frozen_inputs":...}, or the flat server-download form (payload fields at top
    level + sibling blocks), or a .zip / directory containing manifest.json +
    evidence.json + signature.json (+ frozen_inputs.json), or
  * a signed SBOM/VEX — a .json wrapper {"document":..., "signature":...}.

Exit code: 0 = verified, 2 = tampered, 3 = key_unknown, 4 = usage/parse error.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import sys
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

try:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
except ImportError:  # pragma: no cover - dependency hint
    sys.stderr.write(
        "This verifier requires the 'cryptography' package: pip install cryptography\n"
    )
    raise

SIGNING_CONTEXT = "sentari-evidence-pack/v1"
SIGNING_ALGORITHM = "ed25519"

# Signed *exportable artifacts* (SBOM / VEX) — spec §12. Unlike an evidence pack
# these are standard-schema documents (CycloneDX / SPDX / OpenVEX) we MUST NOT
# mutate, so the signature is detached and the hash is over the document AS-IS
# (no blank-and-rehash), the signed envelope is 2-key ``{content_sha256, ctx}``
# (no frozen_inputs_sha256), and Layer 2/3 do not exist. The context is
# domain-separated per artifact type so a signature can never cross-verify as a
# different artifact — even though the SAME evidence key (one published key_id)
# signs packs, SBOMs and VEX alike.
SBOM_CONTEXT = "sentari-sbom/v1"
VEX_CONTEXT = "sentari-vex/v1"
ARTIFACT_CONTEXTS = {SBOM_CONTEXT: "SBOM", VEX_CONTEXT: "VEX"}


# --------------------------------------------------------------------------- #
# Canonicalisation & hashing (spec §4, §5)
# --------------------------------------------------------------------------- #
def canonical_json(obj: Any) -> bytes:
    """Spec §4 canonical JSON: sorted keys, no whitespace, UTF-8, no ASCII/HTML escaping.

    This exact byte encoding — ``json.dumps(sort_keys, separators=(",",":"),
    ensure_ascii=False)`` — is the normative definition; a conformant verifier in
    any language MUST reproduce these bytes. It is closely related to RFC 8785
    (JCS) but the spec does not adopt JCS's number-canonicalisation rules, so do
    not substitute a strict JCS library and assume identical output.
    """
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def _sha256_hex(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def _decode_b64(value: str) -> bytes | None:
    """Strict base64 decode that never raises — returns None on malformed input.

    Malformed base64 in a signature / key / manifest field is a corrupt or
    tampered artefact, not a crash: callers map ``None`` to a deterministic
    verdict rather than letting ``binascii.Error`` escape the exit-code contract.
    """
    if not isinstance(value, str):
        return None
    try:
        return base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError):
        return None


def recompute_content_hash(payload: dict) -> str:
    """Spec §5.1/§5.2: blank ``content_sha256``, canonicalise, sha256."""
    core = dict(payload)
    core["content_sha256"] = ""
    return _sha256_hex(canonical_json(core))


def key_id_for(pubkey_raw: bytes) -> str:
    """Spec §6.2: ``ed25519:`` + first 32 hex chars of sha256(raw 32-byte pubkey)."""
    return "ed25519:" + _sha256_hex(pubkey_raw)[:32]


# --------------------------------------------------------------------------- #
# Verification layers
# --------------------------------------------------------------------------- #
@dataclass
class Result:
    payload_intact: bool | None = None
    frozen_inputs_valid: bool | None = (
        None  # None = not checkable offline (no frozen_inputs)
    )
    signature_valid: bool | None = None  # None = key unavailable / unknown
    sig_fields_consistent: bool | None = None  # detached block agrees with payload
    manifest_valid: bool | None = None  # None = no manifest (bare .json pack)
    key_id_matches_material: bool | None = None
    key_id_matches_anchor: bool | None = None  # None = no anchor supplied
    per_source: dict[str, bool] = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)

    @property
    def verdict(self) -> str:
        # Any hard-failing integrity layer that WAS checked → tampered.
        if self.payload_intact is False:
            return "tampered"
        if self.sig_fields_consistent is False:
            return "tampered"
        if self.frozen_inputs_valid is False:
            return "tampered"
        if self.manifest_valid is False:
            return "tampered"
        if self.signature_valid is False:
            return "tampered"
        # key_id != fingerprint(embedded public_key): the key material was
        # rewritten — that is tampering, not a merely unknown key.
        if self.key_id_matches_material is False:
            return "tampered"
        # Signature couldn't be evaluated (no/unknown/undecodable key) → not
        # verified, not tampered.
        if self.signature_valid is None:
            return "key_unknown"
        # Authenticity anchor: a self-consistent, correctly-signed pack whose key
        # is simply not the one the auditor pinned is UNKNOWN, not tampered — the
        # signer may have rotated keys or the pack may come from a foreign
        # deployment (spec §5.5 trust model).
        if self.key_id_matches_anchor is False:
            return "key_unknown"
        # payload + signature verified (frozen-inputs may be None if not embedded).
        if self.payload_intact and self.signature_valid:
            return "verified"
        return "key_unknown"


def verify_frozen_inputs(
    frozen: dict, expected_frozen_sha256: str
) -> tuple[bool, dict[str, bool]]:
    """Spec §5.3: whole-blob hash + every per-source inner hash (row-list vs aggregate).

    Malformed frozen_inputs — a non-dict ``sources`` map, a non-dict source
    entry, a missing ``sha256`` — is treated as an integrity failure (that source
    marked ``False``), never a crash.
    """
    per_source: dict[str, bool] = {}
    whole_ok = _sha256_hex(canonical_json(frozen)) == expected_frozen_sha256
    sources = frozen.get("sources")
    if not isinstance(sources, dict):
        # No sources map (or a malformed one) → nothing per-source to confirm;
        # the whole-blob hash still gates validity.
        if sources is not None:
            return False, per_source
        return whole_ok, per_source
    for name, src in sources.items():
        if not isinstance(src, dict):
            per_source[name] = False
            continue
        stored = src.get("sha256")
        if "rows" in src and set(src.keys()) - {"rows", "sha256"} == set():
            # row-list source → hash the rows only
            recomputed = _sha256_hex(canonical_json(src["rows"]))
        else:
            # aggregate source → hash the inner dict minus 'sha256'
            inner = {k: v for k, v in src.items() if k != "sha256"}
            recomputed = _sha256_hex(canonical_json(inner))
        per_source[name] = bool(stored) and recomputed == stored
    return whole_ok and all(per_source.values()), per_source


def verify_signature(
    content_sha256: str,
    frozen_inputs_sha256: str,
    signature_b64: str,
    pubkey_raw: bytes,
) -> bool:
    """Spec §6.1/§6.3: Ed25519 over canonical_json of the domain-separated envelope."""
    sig_raw = _decode_b64(signature_b64)
    if sig_raw is None:
        return False
    inner = {
        "content_sha256": content_sha256,
        "ctx": SIGNING_CONTEXT,
        "frozen_inputs_sha256": frozen_inputs_sha256,
    }
    try:
        Ed25519PublicKey.from_public_bytes(pubkey_raw).verify(
            sig_raw, canonical_json(inner)
        )
        return True
    except (InvalidSignature, ValueError):
        return False


def verify_document_signature(
    content_sha256: str,
    ctx: str,
    signature_b64: str,
    pubkey_raw: bytes,
) -> bool:
    """Spec §12: Ed25519 over canonical_json of the 2-key ``{content_sha256, ctx}``
    envelope — deliberately NOT the pack's 3-key ``{content_sha256, ctx,
    frozen_inputs_sha256}`` (a signed SBOM/VEX is the artifact itself, not derived
    from frozen inputs; reusing the 3-key envelope with ``frozen=""`` would sign a
    different object that never matches the 2-key signed bytes)."""
    sig_raw = _decode_b64(signature_b64)
    if sig_raw is None:
        return False
    inner = {"content_sha256": content_sha256, "ctx": ctx}
    try:
        Ed25519PublicKey.from_public_bytes(pubkey_raw).verify(
            sig_raw, canonical_json(inner)
        )
        return True
    except (InvalidSignature, ValueError):
        return False


def verify_manifest(
    manifest_envelope: dict,
    members_raw: dict[str, bytes],
    pubkey_raw: bytes,
) -> tuple[bool, list[str]]:
    """Verify a signed audit-pack ``manifest.json`` (spec §3.4, zip/dir packs).

    The manifest is an Ed25519 ``sign_envelope`` — ``{payload, signature, key_id}``
    — whose ``payload.files`` lists every member with its raw-bytes SHA-256. We:
      1. verify the manifest's own Ed25519 signature over ``canonical_json(payload)``;
      2. recompute the SHA-256 of every listed member we actually hold and compare;
      3. require the trust-bearing members (evidence.json, signature.json) to be
         listed — a manifest that omits them cannot vouch for them.
    Any failure → ``(False, notes)`` so the caller renders ``tampered``.
    """
    notes: list[str] = []
    if not isinstance(manifest_envelope, dict):
        return False, ["manifest.json is not a JSON object"]
    payload = manifest_envelope.get("payload")
    sig_b64 = manifest_envelope.get("signature")
    if not isinstance(payload, dict) or not isinstance(sig_b64, str):
        return False, ["manifest.json missing signed payload / signature"]

    sig_raw = _decode_b64(sig_b64)
    if sig_raw is None:
        return False, ["manifest.json signature is not valid base64"]
    try:
        Ed25519PublicKey.from_public_bytes(pubkey_raw).verify(
            sig_raw, canonical_json(payload)
        )
    except (InvalidSignature, ValueError):
        return False, ["manifest.json Ed25519 signature verification failed"]

    files = payload.get("files")
    if not isinstance(files, list):
        return False, ["manifest.json payload has no 'files' list"]
    listed: set[str] = set()
    ok = True
    for entry in files:
        if not isinstance(entry, dict):
            ok = False
            notes.append("manifest 'files' entry is not an object")
            continue
        name = entry.get("name")
        declared = entry.get("sha256")
        if not isinstance(name, str) or not isinstance(declared, str):
            ok = False
            notes.append("manifest file entry missing name / sha256")
            continue
        listed.add(name)
        raw = members_raw.get(name)
        if raw is None:
            # A member listed in the manifest that this pack does not carry (e.g.
            # evidence.pdf when only json members were extracted) is not an
            # integrity failure — we only cross-check members we actually hold.
            continue
        if _sha256_hex(raw) != declared:
            ok = False
            notes.append(f"member {name!r} sha256 does not match the signed manifest")

    for required in ("evidence.json", "signature.json"):
        if required in members_raw and required not in listed:
            ok = False
            notes.append(f"{required} is not covered by the signed manifest")
    return ok, notes


# --------------------------------------------------------------------------- #
# Artifact loading (spec §3.4)
# --------------------------------------------------------------------------- #
def _load_artifact(
    path: Path,
) -> tuple[dict, dict, dict | None, dict | None]:
    """Return (payload, signature_block, frozen_inputs|None, manifest_ctx|None).

    ``manifest_ctx`` (zip/dir packs that carry a manifest.json) is
    ``{"envelope": <signed manifest>, "members": {name: raw_bytes}}`` and drives
    the signed-manifest verification; it is ``None`` for a bare .json pack.
    """

    def _members_from(reader, names: list[str]):
        raw: dict[str, bytes] = {}
        for n in names:
            try:
                raw[n] = reader(n)
            except (KeyError, FileNotFoundError):
                continue
        if "evidence.json" not in raw or "signature.json" not in raw:
            raise KeyError("pack is missing evidence.json / signature.json")
        payload = json.loads(raw["evidence.json"])
        sig = json.loads(raw["signature.json"])
        frozen = json.loads(raw["frozen_inputs.json"]) if "frozen_inputs.json" in raw else None
        manifest_ctx = None
        if "manifest.json" in raw:
            manifest_ctx = {
                "envelope": json.loads(raw["manifest.json"]),
                "members": raw,
            }
        return payload, sig, frozen, manifest_ctx

    member_names = [
        "manifest.json",
        "evidence.json",
        "signature.json",
        "frozen_inputs.json",
        "evidence.pdf",
        "README.txt",
    ]

    if path.is_dir():
        return _members_from(lambda n: (path / n).read_bytes(), member_names)
    if zipfile.is_zipfile(path):
        with zipfile.ZipFile(path) as zf:
            return _members_from(lambda n: zf.read(n), member_names)

    # single .json. Two accepted shapes:
    #   wrapper: {"payload": {...}, "signature": {...}, "frozen_inputs": {...}}
    #   flat (server download, spec §3.4): the canonical payload fields at the top
    #     level PLUS a sibling "signature" block (the signature sits OUTSIDE the
    #     hashed payload, so the payload = the doc minus the sibling blocks).
    doc = json.loads(path.read_text())
    if "payload" in doc and "signature" in doc:
        return doc["payload"], doc["signature"], doc.get("frozen_inputs"), None
    # Signed exportable artifact (SBOM / VEX), spec §12: a wrapper
    #   {"document": <cyclonedx/spdx/openvex doc>, "signature": <detached block>}.
    # Recognize the top-level "document" key BEFORE the flat-pack fallback below —
    # otherwise the flat path would treat the whole wrapper as a pack payload of
    # {"document": …} and blank-and-rehash it (false tampered). The document is
    # returned unchanged as the first tuple element; verify_pack dispatches to the
    # document path on the block's artifact ``context``.
    if "document" in doc:
        sig = doc.get("signature")
        if not isinstance(sig, dict):
            raise KeyError("artifact has a 'document' but no 'signature' block")
        return doc["document"], sig, None, None
    sig = doc.get("signature")
    if sig is None:
        raise KeyError("no 'signature' block found in artifact")
    frozen = doc.get("frozen_inputs")
    payload = {k: v for k, v in doc.items() if k not in ("signature", "frozen_inputs")}
    return payload, sig, frozen, None


# --------------------------------------------------------------------------- #
# Orchestration
# --------------------------------------------------------------------------- #
def _verify_document(
    document: dict,
    signature: dict,
    *,
    pubkey_b64: str | None = None,
    expected_key_id: str | None = None,
) -> Result:
    """Verify a signed exportable artifact (SBOM/VEX) — spec §12, the five
    document-path obligations of the design §4.

    Distinct from the pack path in exactly the ways a standard-schema document
    demands:
      1. hashes the document AS-IS — NOT ``recompute_content_hash`` (which would
         inject a ``content_sha256`` key the document never carried → false hash);
      2. compares the block's ``content_sha256`` to that recomputed document hash
         (the document embeds no ``content_sha256`` to read);
      3. verifies the 2-key ``{content_sha256, ctx}`` envelope (not the 3-key one);
      5. reports Layer 2/3 as **N/A** — this artifact class has neither.
    (Obligation 4 — the loader wrapper branch + unknown-ctx rejection — lives in
    ``_load_artifact`` / the ``verify_pack`` dispatch.)
    """
    r = Result()
    ctx = signature.get("context")
    artifact_name = ARTIFACT_CONTEXTS[ctx]
    r.notes.append(f"signed {artifact_name} artifact (context {ctx})")

    # Layer 1 — hash the document AS-IS (obligation 1). NO blank-and-rehash.
    recomputed = _sha256_hex(canonical_json(document))
    # Obligation 2 — compare against the block's content_sha256, not a
    # (non-existent) document field.
    block_content = signature.get("content_sha256", "")
    r.payload_intact = bool(block_content) and block_content == recomputed
    if not r.payload_intact:
        r.notes.append(
            f"content_sha256 mismatch: block={str(block_content)[:12]}… "
            f"recomputed={recomputed[:12]}…"
        )

    # Detached-block metadata consistency. The context is already a known artifact
    # ctx (we only get here by dispatch); the content_sha256 agreement is Layer 1
    # above, so only the algorithm remains to cross-check.
    field_notes: list[str] = []
    algo = signature.get("algorithm")
    if algo is not None and algo != SIGNING_ALGORITHM:
        field_notes.append(
            f"signature.algorithm={algo!r} (expected {SIGNING_ALGORITHM!r})"
        )
    r.sig_fields_consistent = not field_notes
    r.notes.extend(field_notes)

    # Layers 2 & 3 do not exist for this artifact class (obligation 5): report
    # **N/A**, a deliberately distinct word from the pack's "skipped" so an auditor
    # never conflates "this class has no Layer 2" with "could have checked, didn't."
    r.frozen_inputs_valid = None
    r.manifest_valid = None
    r.notes.append(
        f"Layer 2 (frozen inputs) N/A — a signed {artifact_name} is the artifact "
        "itself, not derived from frozen inputs (spec §12)"
    )
    r.notes.append(
        f"Layer 3 (collector re-derivation) N/A — no collector for a signed "
        f"{artifact_name} (spec §12)"
    )

    # Key resolution — identical policy to the pack path: --pubkey wins, else the
    # block's embedded public_key.
    raw_b64 = pubkey_b64 or signature.get("public_key")
    if not raw_b64:
        r.signature_valid = None
        r.notes.append(
            "no public key available (not embedded, none supplied) — signature unchecked"
        )
        return r
    pubkey_raw = _decode_b64(raw_b64)
    if pubkey_raw is None:
        r.signature_valid = None
        r.notes.append(
            "public key is not valid base64 — signature unchecked (supply a valid --pubkey)"
        )
        return r

    computed_kid = key_id_for(pubkey_raw)
    r.key_id_matches_material = computed_kid == signature.get("key_id")
    if not r.key_id_matches_material:
        r.notes.append(
            f"key_id != fingerprint(public_key): {signature.get('key_id')} vs {computed_kid}"
        )
    if expected_key_id is not None:
        r.key_id_matches_anchor = computed_kid == expected_key_id
        if not r.key_id_matches_anchor:
            r.notes.append(
                f"key_id != out-of-band anchor: {computed_kid} vs {expected_key_id} "
                "— authenticity NOT established (rotated / foreign / wrong key)"
            )
    else:
        r.notes.append(
            "no out-of-band key_id anchor supplied — authenticity NOT established, only "
            "internal consistency (pass --expected-key-id for a real trust decision)"
        )

    # Signature — Ed25519 over the 2-key envelope (obligation 3). The signed hash
    # is the block's content_sha256 (Layer 1 already proved it equals the document
    # hash when intact); a tampered document fails Layer 1 regardless.
    r.signature_valid = verify_document_signature(
        block_content, ctx, signature.get("value", ""), pubkey_raw
    )
    if not r.signature_valid:
        r.notes.append("Ed25519 signature verification failed")
    return r


def verify_pack(
    payload: dict,
    signature: dict,
    frozen_inputs: dict | None = None,
    *,
    manifest_ctx: dict | None = None,
    pubkey_b64: str | None = None,
    expected_key_id: str | None = None,
) -> Result:
    # Dispatch on the detached block's context (spec §12). A signed exportable
    # artifact (SBOM/VEX) takes the document path — hash the document AS-IS, verify
    # the 2-key envelope, report Layer 2/3 as N/A. Everything else (the pack ctx, a
    # missing ctx, or an UNKNOWN ctx) takes the pack path below, where an
    # unrecognised context is caught as ``tampered`` by the sig-fields check (and a
    # relabelled document, lacking a content_sha256 field, additionally fails
    # Layer 1) — an unknown format is never silently accepted.
    block_ctx = signature.get("context") if isinstance(signature, dict) else None
    if block_ctx in ARTIFACT_CONTEXTS:
        return _verify_document(
            payload,
            signature,
            pubkey_b64=pubkey_b64,
            expected_key_id=expected_key_id,
        )

    r = Result()

    # Layer 1 — payload intact
    stored = payload.get("content_sha256", "")
    recomputed = recompute_content_hash(payload)
    r.payload_intact = bool(stored) and stored == recomputed
    if not r.payload_intact:
        r.notes.append(
            f"content_sha256 mismatch: stored={stored[:12]}… recomputed={recomputed[:12]}…"
        )

    # The hashes the signature binds come from the pack's own signed columns.
    content_sha256 = payload.get("content_sha256", "")
    frozen_sha256 = signature.get("frozen_inputs_sha256", "")

    # Detached-signature metadata must agree with the payload it claims to sign.
    # A block whose algorithm/context/content_sha256 disagree is inconsistent —
    # treat as tampering even if 'value' happens to verify (spec §5.5).
    field_notes: list[str] = []
    algo = signature.get("algorithm")
    if algo is not None and algo != SIGNING_ALGORITHM:
        field_notes.append(f"signature.algorithm={algo!r} (expected {SIGNING_ALGORITHM!r})")
    ctx = signature.get("context")
    if ctx is not None and ctx != SIGNING_CONTEXT:
        field_notes.append(f"signature.context={ctx!r} (expected {SIGNING_CONTEXT!r})")
    block_content = signature.get("content_sha256")
    if block_content is not None and block_content != content_sha256:
        field_notes.append("signature.content_sha256 disagrees with the payload")
    r.sig_fields_consistent = not field_notes
    r.notes.extend(field_notes)

    # Layer 2 — frozen inputs (only if embedded; else None = not checkable offline)
    if frozen_inputs is not None:
        ok, per_source = verify_frozen_inputs(frozen_inputs, frozen_sha256)
        r.frozen_inputs_valid = ok
        r.per_source = per_source
        if not ok:
            r.notes.append("frozen_inputs hash / per-source hash mismatch")
    else:
        r.notes.append(
            "frozen_inputs not embedded in artifact — Layer 2 skipped (spec §3.4)"
        )

    # Key resolution: --pubkey wins; else the block's embedded public_key.
    raw_b64 = pubkey_b64 or signature.get("public_key")
    if not raw_b64:
        r.signature_valid = None
        r.notes.append(
            "no public key available (not embedded, none supplied) — signature unchecked"
        )
        return r
    pubkey_raw = _decode_b64(raw_b64)
    if pubkey_raw is None:
        r.signature_valid = None
        r.notes.append(
            "public key is not valid base64 — signature unchecked (supply a valid --pubkey)"
        )
        return r

    # key_id must be the fingerprint of the key we're about to trust.
    computed_kid = key_id_for(pubkey_raw)
    r.key_id_matches_material = computed_kid == signature.get("key_id")
    if not r.key_id_matches_material:
        r.notes.append(
            f"key_id != fingerprint(public_key): {signature.get('key_id')} vs {computed_kid}"
        )
    if expected_key_id is not None:
        r.key_id_matches_anchor = computed_kid == expected_key_id
        if not r.key_id_matches_anchor:
            r.notes.append(
                f"key_id != out-of-band anchor: {computed_kid} vs {expected_key_id} "
                "— authenticity NOT established (rotated / foreign / wrong key)"
            )
    else:
        r.notes.append(
            "no out-of-band key_id anchor supplied — authenticity NOT established, only "
            "internal consistency (pass --expected-key-id for a real trust decision)"
        )

    # Signed manifest (zip / dir packs): verify the manifest envelope + every
    # member hash BEFORE trusting evidence.json / signature.json.
    if manifest_ctx is not None:
        m_ok, m_notes = verify_manifest(
            manifest_ctx["envelope"], manifest_ctx["members"], pubkey_raw
        )
        r.manifest_valid = m_ok
        r.notes.extend(m_notes)

    # Signature — Ed25519 over the envelope.
    r.signature_valid = verify_signature(
        content_sha256, frozen_sha256, signature.get("value", ""), pubkey_raw
    )
    if not r.signature_valid:
        r.notes.append("Ed25519 signature verification failed")
    return r


_EXIT = {"verified": 0, "tampered": 2, "key_unknown": 3}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="Verify a Sentari evidence pack or signed SBOM/VEX offline (spec v0.1)."
    )
    ap.add_argument(
        "pack",
        type=Path,
        help="evidence pack (.json / .zip / directory) OR signed SBOM/VEX (.json wrapper)",
    )
    ap.add_argument(
        "--pubkey", help="base64 raw 32-byte Ed25519 public key (overrides embedded)"
    )
    ap.add_argument("--expected-key-id", help="out-of-band key_id trust anchor")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    args = ap.parse_args(argv)

    try:
        payload, signature, frozen, manifest_ctx = _load_artifact(args.pack)
    except (OSError, KeyError, ValueError, json.JSONDecodeError) as e:
        sys.stderr.write(f"could not read pack: {e}\n")
        return 4

    r = verify_pack(
        payload,
        signature,
        frozen,
        manifest_ctx=manifest_ctx,
        pubkey_b64=args.pubkey,
        expected_key_id=args.expected_key_id,
    )
    verdict = r.verdict

    if args.json:
        print(
            json.dumps(
                {
                    "verdict": verdict,
                    "payload_intact": r.payload_intact,
                    "frozen_inputs_valid": r.frozen_inputs_valid,
                    "signature_valid": r.signature_valid,
                    "sig_fields_consistent": r.sig_fields_consistent,
                    "manifest_valid": r.manifest_valid,
                    "key_id_matches_material": r.key_id_matches_material,
                    "key_id_matches_anchor": r.key_id_matches_anchor,
                    "per_source": r.per_source,
                    "notes": r.notes,
                },
                indent=2,
            )
        )
    else:
        print(f"verdict: {verdict.upper()}")
        print(f"  payload_intact       : {r.payload_intact}")
        print(f"  frozen_inputs_valid  : {r.frozen_inputs_valid}")
        print(f"  signature_valid      : {r.signature_valid}")
        print(f"  sig_fields_consistent: {r.sig_fields_consistent}")
        print(f"  manifest_valid       : {r.manifest_valid}")
        print(f"  key_id (material)    : {r.key_id_matches_material}")
        print(f"  key_id (anchor)      : {r.key_id_matches_anchor}")
        for n in r.notes:
            print(f"  · {n}")

    return _EXIT.get(verdict, 3)


if __name__ == "__main__":
    raise SystemExit(main())
