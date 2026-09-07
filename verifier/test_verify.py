"""Conformance tests for the reference evidence-pack verifier.

Builds a golden pack the way a conformant PRODUCER would (spec §5/§6, using the
same Ed25519 + canonical-JSON primitives), then asserts:
  * the golden pack verifies,
  * the canonical-JSON encoding matches a pinned byte vector,
  * every tamper mutation is caught with the correct verdict.
"""

from __future__ import annotations

import base64
import copy

import sentari_evidence_verify as V
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


# --------------------------------------------------------------------------- #
# Golden producer (mirrors the spec's producer side)
# --------------------------------------------------------------------------- #
def _sha(obj) -> str:
    return V._sha256_hex(V.canonical_json(obj))


def build_golden() -> tuple[dict, dict, dict, bytes]:
    priv = Ed25519PrivateKey.generate()
    pub_raw = priv.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )

    # frozen_inputs — one aggregate source (extra 'count' key) + one row-list source
    frozen: dict = {
        "sources": {
            "cve_findings": {
                "rows": [{"cve_id": "CVE-2026-0001", "severity": "high"}],
                "count": 1,
            },
            "runtime_eol": {
                "rows": [{"product": "python", "eol": "2025-10-01"}],
            },
        },
        "scope": {"kind": "fleet"},
    }
    # per-source hashes: aggregate → inner-minus-sha256; row-list → rows only
    frozen["sources"]["cve_findings"]["sha256"] = _sha(
        {k: v for k, v in frozen["sources"]["cve_findings"].items() if k != "sha256"}
    )
    frozen["sources"]["runtime_eol"]["sha256"] = _sha(
        frozen["sources"]["runtime_eol"]["rows"]
    )
    frozen_sha = _sha(frozen)

    payload: dict = {
        "pack_id": "11111111-1111-1111-1111-111111111111",
        "framework": "CYFUN",
        "framework_version": "cyfun-be-2023",
        "catalog_version": "cyfun-be-v1",
        "generated_at": "2026-09-04T00:00:00+00:00",
        "generated_by": None,
        "generated_by_email": None,
        "content_sha256": "",
        "scope": {"kind": "fleet"},
        "coverage": {
            "assessed_control_ids": ["ID.AM-1"],
            "not_assessed_framework_refs": ["ID.AM-2"],
        },
        "controls": [
            {
                "id": "ID.AM-1",
                "article_ref": "ID.AM-1",
                "title": "Asset inventory",
                "basis": "automated",
                "evidence_class": "derived",
                "status": "compliant",
                "not_applicable": False,
                "summary": "All fleet assets inventoried.",
                "evidence_refs": ["sbom:fleet"],
                "findings": [],
            }
        ],
    }
    payload["content_sha256"] = V.recompute_content_hash(payload)

    inner = {
        "content_sha256": payload["content_sha256"],
        "ctx": V.SIGNING_CONTEXT,
        "frozen_inputs_sha256": frozen_sha,
    }
    signature = {
        "algorithm": "ed25519",
        "context": V.SIGNING_CONTEXT,
        "key_id": V.key_id_for(pub_raw),
        "content_sha256": payload["content_sha256"],
        "frozen_inputs_sha256": frozen_sha,
        "value": base64.b64encode(priv.sign(V.canonical_json(inner))).decode(),
        "public_key": base64.b64encode(pub_raw).decode(),
    }
    return payload, signature, frozen, pub_raw


# --------------------------------------------------------------------------- #
# Encoding pin
# --------------------------------------------------------------------------- #
def test_canonical_json_pins_the_encoding():
    # sorted keys, no whitespace, raw UTF-8 (é NOT \u-escaped), no HTML escaping
    assert (
        V.canonical_json({"b": 1, "a": "é", "c": "<x>"})
        == b'{"a":"\xc3\xa9","b":1,"c":"<x>"}'
    )


# --------------------------------------------------------------------------- #
# Happy path
# --------------------------------------------------------------------------- #
def test_golden_pack_verifies():
    payload, sig, frozen, pub = build_golden()
    r = V.verify_pack(payload, sig, frozen, expected_key_id=V.key_id_for(pub))
    assert r.verdict == "verified"
    assert r.payload_intact is True
    assert r.frozen_inputs_valid is True
    assert r.signature_valid is True
    assert r.key_id_matches_material is True
    assert r.key_id_matches_anchor is True
    assert all(r.per_source.values())


def test_verifies_without_frozen_inputs_but_layer2_skipped():
    payload, sig, _frozen, pub = build_golden()
    r = V.verify_pack(payload, sig, None, expected_key_id=V.key_id_for(pub))
    assert r.verdict == "verified"  # payload + signature suffice
    assert r.frozen_inputs_valid is None  # not checkable offline without the blob


# --------------------------------------------------------------------------- #
# Tamper detection
# --------------------------------------------------------------------------- #
def test_flipped_payload_is_tampered():
    payload, sig, frozen, _pub = build_golden()
    bad = copy.deepcopy(payload)
    bad["controls"][0]["status"] = "non_compliant"  # change evidence, keep old hash
    r = V.verify_pack(bad, sig, frozen)
    assert r.verdict == "tampered"
    assert r.payload_intact is False


def test_corrupted_frozen_source_is_tampered():
    payload, sig, frozen, _pub = build_golden()
    bad = copy.deepcopy(frozen)
    bad["sources"]["cve_findings"]["rows"][0]["severity"] = (
        "low"  # alter row, keep sha256
    )
    r = V.verify_pack(payload, sig, bad)
    assert r.verdict == "tampered"
    assert r.frozen_inputs_valid is False
    assert r.per_source["cve_findings"] is False
    assert r.per_source["runtime_eol"] is True  # the untouched source still validates


def test_bad_signature_is_tampered():
    payload, sig, frozen, pub = build_golden()
    bad = dict(sig)
    raw = bytearray(base64.b64decode(bad["value"]))
    raw[0] ^= 0x01
    bad["value"] = base64.b64encode(bytes(raw)).decode()
    r = V.verify_pack(payload, bad, frozen, expected_key_id=V.key_id_for(pub))
    assert r.verdict == "tampered"
    assert r.signature_valid is False


def test_swapped_public_key_is_tampered():
    payload, sig, frozen, _pub = build_golden()
    other = (
        Ed25519PrivateKey.generate()
        .public_key()
        .public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    )
    bad = dict(sig)
    bad["public_key"] = base64.b64encode(
        other
    ).decode()  # key_id no longer matches material
    r = V.verify_pack(payload, bad, frozen)
    assert r.verdict == "tampered"
    assert r.key_id_matches_material is False


def test_anchor_mismatch_is_key_unknown():
    """A self-consistent, correctly-signed pack whose key is simply not the one
    the auditor pinned is NOT tampering — the signer may have rotated keys or the
    pack may be from a foreign deployment. The spec's trust model reports this as
    key_unknown (authenticity not established), never tampered."""
    payload, sig, frozen, _pub = build_golden()
    r = V.verify_pack(
        payload, sig, frozen, expected_key_id="ed25519:deadbeefdeadbeefdeadbeefdeadbeef"
    )
    assert r.verdict == "key_unknown"
    assert r.key_id_matches_anchor is False
    assert r.signature_valid is True  # the math still verifies; only the anchor differs


def test_no_public_key_is_key_unknown():
    payload, sig, frozen, _pub = build_golden()
    bad = {k: v for k, v in sig.items() if k != "public_key"}
    r = V.verify_pack(payload, bad, frozen)  # no --pubkey, none embedded
    assert r.verdict == "key_unknown"
    assert r.signature_valid is None


# --------------------------------------------------------------------------- #
# Crash-hardening: malformed artefacts must produce a verdict, never an exception
# --------------------------------------------------------------------------- #
def test_malformed_base64_signature_is_tampered():
    payload, sig, frozen, pub = build_golden()
    bad = dict(sig)
    bad["value"] = "!!!not base64!!!"
    r = V.verify_pack(payload, bad, frozen, expected_key_id=V.key_id_for(pub))
    assert r.verdict == "tampered"
    assert r.signature_valid is False


def test_malformed_base64_pubkey_is_key_unknown():
    payload, sig, frozen, _pub = build_golden()
    bad = dict(sig)
    bad["public_key"] = "@@@ not valid base64 @@@"
    r = V.verify_pack(payload, bad, frozen)
    assert r.verdict == "key_unknown"  # cannot establish a key, but not tampering
    assert r.signature_valid is None


def test_non_dict_frozen_source_is_tampered_not_crash():
    payload, sig, frozen, pub = build_golden()
    bad = copy.deepcopy(frozen)
    bad["sources"]["cve_findings"] = "not-a-dict"  # malformed source entry
    r = V.verify_pack(payload, sig, bad, expected_key_id=V.key_id_for(pub))
    assert r.verdict == "tampered"
    assert r.frozen_inputs_valid is False
    assert r.per_source["cve_findings"] is False


def test_signature_field_disagreeing_with_payload_is_tampered():
    """The detached block advertises algorithm/context/content_sha256; if those
    metadata disagree with the payload the block is inconsistent → tampered, even
    if 'value' would verify over the (real) envelope."""
    payload, sig, frozen, pub = build_golden()
    bad = dict(sig)
    bad["content_sha256"] = "0" * 64  # lie about which payload this signs
    r = V.verify_pack(payload, bad, frozen, expected_key_id=V.key_id_for(pub))
    assert r.verdict == "tampered"
    assert r.sig_fields_consistent is False


def test_wrong_context_in_signature_block_is_tampered():
    payload, sig, frozen, pub = build_golden()
    bad = dict(sig)
    bad["context"] = "sentari-evidence-pack/v99"
    r = V.verify_pack(payload, bad, frozen, expected_key_id=V.key_id_for(pub))
    assert r.verdict == "tampered"
    assert r.sig_fields_consistent is False


# --------------------------------------------------------------------------- #
# Real server-generated conformance vector (cross-validation)
# --------------------------------------------------------------------------- #
import json as _json  # noqa: E402
import pathlib  # noqa: E402

_VECTOR = pathlib.Path(__file__).parent / "vectors" / "cyfun-empty-fleet.golden.json"


def test_real_server_vector_verifies():
    """A REAL Sentari-signed CyFun pack (flat json artifact, 18 controls) verifies
    offline against its embedded key. This cross-validates that this verifier's
    canonical_json + Ed25519 envelope + key_id reproduce the actual server output
    byte-for-byte — the strongest correctness check in the suite."""
    payload, sig, frozen, _manifest = V._load_artifact(_VECTOR)
    r = V.verify_pack(payload, sig, frozen)
    assert r.verdict == "verified"
    assert r.payload_intact is True
    assert r.signature_valid is True
    assert r.key_id_matches_material is True
    assert r.frozen_inputs_valid is None  # current server download omits it (spec §3.4)


def test_flat_loader_strips_the_signature_sibling():
    """Flat artifact = payload fields at top level + a sibling 'signature'; the
    loader must reconstruct the payload as the doc minus that sibling."""
    doc = _json.loads(_VECTOR.read_text())
    payload, sig, _frozen, _manifest = V._load_artifact(_VECTOR)
    assert "signature" not in payload
    assert sig == doc["signature"]
    assert payload["content_sha256"] == doc["content_sha256"]


def test_tampered_real_vector_is_tampered(tmp_path):
    doc = _json.loads(_VECTOR.read_text())
    doc["controls"][0]["status"] = "non_compliant"  # flip a real control's verdict
    p = tmp_path / "tampered.json"
    p.write_text(_json.dumps(doc))
    payload, sig, frozen, _manifest = V._load_artifact(p)
    r = V.verify_pack(payload, sig, frozen)
    assert r.verdict == "tampered"
    assert r.payload_intact is False


# --------------------------------------------------------------------------- #
# Signed-manifest zip packs (spec §3.4): a swapped member is caught even when the
# JSON pair is internally intact.
# --------------------------------------------------------------------------- #
import zipfile  # noqa: E402


def _build_zip_pack(tmp_path, *, mutate_evidence=False):
    """Build a zip the way the server's audit-pack builder does: a signed
    manifest.json whose payload.files lists every member's raw-bytes sha256,
    signed with the SAME Ed25519 key as the evidence signature."""
    priv = Ed25519PrivateKey.generate()
    pub_raw = priv.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    payload, sig, frozen, _ = build_golden()
    # Re-sign golden with THIS key so manifest + evidence share one signer.
    key_id = V.key_id_for(pub_raw)
    frozen_sha = sig["frozen_inputs_sha256"]
    inner = {
        "content_sha256": payload["content_sha256"],
        "ctx": V.SIGNING_CONTEXT,
        "frozen_inputs_sha256": frozen_sha,
    }
    sig = dict(sig)
    sig["key_id"] = key_id
    sig["value"] = base64.b64encode(priv.sign(V.canonical_json(inner))).decode()
    sig["public_key"] = base64.b64encode(pub_raw).decode()

    evidence_bytes = V.canonical_json(payload)
    if mutate_evidence:
        # Swap the member bytes AFTER the manifest is computed — the manifest's
        # signed sha256 will no longer match.
        tampered = copy.deepcopy(payload)
        tampered["controls"][0]["status"] = "non_compliant"
        evidence_bytes = V.canonical_json(tampered)
    signature_bytes = _json.dumps(sig).encode()
    frozen_bytes = _json.dumps(frozen).encode()

    members = {
        "evidence.json": V.canonical_json(payload),  # honest bytes in the manifest
        "signature.json": signature_bytes,
        "frozen_inputs.json": frozen_bytes,
    }
    files = [
        {"name": n, "sha256": V._sha256_hex(b), "description": n}
        for n, b in members.items()
    ]
    manifest_payload = {"files": files, "domain": "compliance.evidence"}
    manifest = {
        "payload": manifest_payload,
        "signature": base64.b64encode(priv.sign(V.canonical_json(manifest_payload))).decode(),
        "key_id": key_id,
    }

    p = tmp_path / "pack.zip"
    with zipfile.ZipFile(p, "w") as zf:
        zf.writestr("manifest.json", _json.dumps(manifest))
        zf.writestr("evidence.json", evidence_bytes)  # possibly tampered
        zf.writestr("signature.json", signature_bytes)
        zf.writestr("frozen_inputs.json", frozen_bytes)
    return p, key_id


def test_zip_pack_with_signed_manifest_verifies(tmp_path):
    p, key_id = _build_zip_pack(tmp_path)
    payload, sig, frozen, manifest_ctx = V._load_artifact(p)
    assert manifest_ctx is not None
    r = V.verify_pack(payload, sig, frozen, manifest_ctx=manifest_ctx, expected_key_id=key_id)
    assert r.verdict == "verified"
    assert r.manifest_valid is True
    assert r.frozen_inputs_valid is True  # zip embeds frozen_inputs.json


def test_zip_with_swapped_member_is_tampered_via_manifest(tmp_path):
    """The evidence.json bytes are swapped but the manifest still carries the
    ORIGINAL sha256 — manifest verification must catch it (the swapped payload
    also fails Layer 1, but the manifest is the member-integrity backstop)."""
    p, key_id = _build_zip_pack(tmp_path, mutate_evidence=True)
    payload, sig, frozen, manifest_ctx = V._load_artifact(p)
    r = V.verify_pack(payload, sig, frozen, manifest_ctx=manifest_ctx, expected_key_id=key_id)
    assert r.verdict == "tampered"
    assert r.manifest_valid is False


# --------------------------------------------------------------------------- #
# Signed exportable artifacts (SBOM / VEX) — spec §12, design §4 obligations.
# Each of these is a REGRESSION test: reusing the pack path verbatim would
# false-`tampered` a valid SBOM/VEX. The two golden vectors are REAL signed
# artifacts (2-key envelope, shared evidence key) — both verifiers verifying both
# is the Python↔Go byte-equality merge gate.
# --------------------------------------------------------------------------- #
_SBOM_VECTOR = (
    pathlib.Path(__file__).parent / "vectors" / "sbom-cyclonedx.signed.golden.json"
)
_VEX_VECTOR = (
    pathlib.Path(__file__).parent / "vectors" / "vex-openvex.signed.golden.json"
)


def _artifact_key_id(vector: pathlib.Path) -> str:
    return _json.loads(vector.read_text())["signature"]["key_id"]


def test_signed_sbom_vector_verifies():
    """A REAL signed CycloneDX SBOM verifies: document hashed AS-IS (not blanked),
    2-key {content_sha256, ctx} envelope, key anchored to its own key_id."""
    payload, sig, frozen, manifest = V._load_artifact(_SBOM_VECTOR)
    r = V.verify_pack(payload, sig, frozen, expected_key_id=_artifact_key_id(_SBOM_VECTOR))
    assert r.verdict == "verified"
    assert r.payload_intact is True
    assert r.signature_valid is True
    assert r.key_id_matches_material is True
    assert r.key_id_matches_anchor is True


def test_signed_vex_vector_verifies():
    """A REAL signed OpenVEX document verifies through the same document path."""
    payload, sig, frozen, manifest = V._load_artifact(_VEX_VECTOR)
    r = V.verify_pack(payload, sig, frozen, expected_key_id=_artifact_key_id(_VEX_VECTOR))
    assert r.verdict == "verified"
    assert r.payload_intact is True
    assert r.signature_valid is True


def test_signed_artifact_layer2_and_layer3_reported_na_not_skipped():
    """Obligation 5: Layer 2/3 are N/A for this artifact class (no frozen_inputs,
    no collector) — distinct wording from the pack's "skipped"."""
    payload, sig, frozen, _manifest = V._load_artifact(_SBOM_VECTOR)
    assert frozen is None  # no frozen_inputs sibling at all
    r = V.verify_pack(payload, sig, frozen)
    assert r.frozen_inputs_valid is None
    assert r.manifest_valid is None
    joined = " ".join(r.notes)
    assert "N/A" in joined
    assert "skipped" not in joined  # must NOT reuse the pack's word


def test_signed_artifact_wrapper_recognized_before_flat_fallback():
    """Obligation 4: the loader must recognize {"document":…, "signature":…} as a
    wrapper and return the document unchanged — NOT misread it as a flat pack whose
    payload is {"document":…}."""
    doc = _json.loads(_SBOM_VECTOR.read_text())
    payload, sig, frozen, manifest = V._load_artifact(_SBOM_VECTOR)
    assert payload == doc["document"]  # the document itself, not a {"document":…} wrap
    assert "document" not in payload
    assert sig == doc["signature"]
    assert frozen is None and manifest is None


def test_signed_sbom_tampered_document_byte_is_tampered(tmp_path):
    """Flip one byte of the signed document → the recomputed hash no longer matches
    the block's content_sha256 → tampered (Layer 1 fails)."""
    doc = _json.loads(_SBOM_VECTOR.read_text())
    doc["document"]["components"][0]["version"] = "9.9.9"  # was 2.32.3
    p = tmp_path / "tampered.json"
    p.write_text(_json.dumps(doc))
    payload, sig, frozen, _manifest = V._load_artifact(p)
    r = V.verify_pack(payload, sig, frozen)
    assert r.verdict == "tampered"
    assert r.payload_intact is False


def test_signed_sbom_relabelled_with_pack_ctx_is_tampered(tmp_path):
    """Cross-ctx replay: relabel an SBOM block with the pack ctx. The ctx is folded
    inside the signed envelope, so this can never verify — the dispatch routes it to
    the pack path where the document (no content_sha256 field) fails Layer 1."""
    doc = _json.loads(_SBOM_VECTOR.read_text())
    doc["signature"]["context"] = V.SIGNING_CONTEXT  # sentari-evidence-pack/v1
    p = tmp_path / "relabelled.json"
    p.write_text(_json.dumps(doc))
    payload, sig, frozen, _manifest = V._load_artifact(p)
    r = V.verify_pack(payload, sig, frozen)
    assert r.verdict == "tampered"


def test_evidence_pack_relabelled_with_sbom_ctx_is_tampered(tmp_path):
    """The reverse cross-ctx replay: relabel a real evidence pack's block with the
    SBOM ctx. The document path hashes the pack payload AS-IS (no blanking), which
    never matches the pack's blanked content_sha256 → tampered."""
    doc = _json.loads(_VECTOR.read_text())  # the real CyFun pack (flat form)
    doc["signature"]["context"] = V.SBOM_CONTEXT
    p = tmp_path / "relabelled-pack.json"
    p.write_text(_json.dumps(doc))
    payload, sig, frozen, _manifest = V._load_artifact(p)
    r = V.verify_pack(payload, sig, frozen)
    assert r.verdict == "tampered"


def test_signed_artifact_unknown_ctx_is_tampered(tmp_path):
    """Obligation 4: a block whose context is neither the pack ctx nor a known
    artifact ctx is an unknown format → tampered, never silently accepted."""
    doc = _json.loads(_SBOM_VECTOR.read_text())
    doc["signature"]["context"] = "sentari-mystery/v1"
    p = tmp_path / "unknown-ctx.json"
    p.write_text(_json.dumps(doc))
    payload, sig, frozen, _manifest = V._load_artifact(p)
    r = V.verify_pack(payload, sig, frozen)
    assert r.verdict == "tampered"


def test_signed_sbom_anchor_mismatch_is_key_unknown():
    """A correctly-signed SBOM whose key is not the pinned one is key_unknown
    (authenticity not established), never tampered — same trust model as packs."""
    payload, sig, frozen, _manifest = V._load_artifact(_SBOM_VECTOR)
    r = V.verify_pack(
        payload, sig, frozen, expected_key_id="ed25519:deadbeefdeadbeefdeadbeefdeadbeef"
    )
    assert r.verdict == "key_unknown"
    assert r.key_id_matches_anchor is False
    assert r.signature_valid is True  # the math verifies; only the anchor differs


def test_one_key_id_verifies_both_a_pack_and_a_signed_artifact():
    """The SAME key_id fingerprint anchors packs, SBOMs and VEX — one published
    fingerprint covers the whole evidence surface. Both golden signed artifacts
    share a key_id; assert an SBOM and a VEX verify under the one anchor."""
    kid = _artifact_key_id(_SBOM_VECTOR)
    assert kid == _artifact_key_id(_VEX_VECTOR)  # one key across the surface
    for vec in (_SBOM_VECTOR, _VEX_VECTOR):
        payload, sig, frozen, _m = V._load_artifact(vec)
        assert V.verify_pack(payload, sig, frozen, expected_key_id=kid).verdict == "verified"
