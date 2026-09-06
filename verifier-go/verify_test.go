package main

import (
	"archive/zip"
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// _sha is the producer-side hash helper (sha256 of canonical JSON), matching the
// Python test's V._sha256_hex(V.canonical_json(obj)).
func _sha(obj interface{}) string { return sha256Hex(canonicalJSON(obj)) }

func strp(s string) *string { return &s }

// buildGolden mirrors test_verify.py::build_golden — a conformant PRODUCER using
// the same Ed25519 + canonical-JSON primitives — so we test against a pack we
// generated the spec way, not just the shipped vector.
func buildGolden(t *testing.T) (payload, signature, frozen map[string]interface{}, pubRaw []byte) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	pubRaw = pub

	frozen = map[string]interface{}{
		"sources": map[string]interface{}{
			"cve_findings": map[string]interface{}{
				"rows":  []interface{}{map[string]interface{}{"cve_id": "CVE-2026-0001", "severity": "high"}},
				"count": 1,
			},
			"runtime_eol": map[string]interface{}{
				"rows": []interface{}{map[string]interface{}{"product": "python", "eol": "2025-10-01"}},
			},
		},
		"scope": map[string]interface{}{"kind": "fleet"},
	}
	sources := frozen["sources"].(map[string]interface{})
	// aggregate source → inner minus sha256 ({rows, count})
	cve := sources["cve_findings"].(map[string]interface{})
	cve["sha256"] = _sha(map[string]interface{}{"rows": cve["rows"], "count": cve["count"]})
	// row-list source → rows only
	rt := sources["runtime_eol"].(map[string]interface{})
	rt["sha256"] = _sha(rt["rows"])
	frozenSha := _sha(frozen)

	payload = map[string]interface{}{
		"pack_id":            "11111111-1111-1111-1111-111111111111",
		"framework":          "CYFUN",
		"framework_version":  "cyfun-be-2023",
		"catalog_version":    "cyfun-be-v1",
		"generated_at":       "2026-09-04T00:00:00+00:00",
		"generated_by":       nil,
		"generated_by_email": nil,
		"content_sha256":     "",
		"scope":              map[string]interface{}{"kind": "fleet"},
		"coverage": map[string]interface{}{
			"assessed_control_ids":        []interface{}{"ID.AM-1"},
			"not_assessed_framework_refs": []interface{}{"ID.AM-2"},
		},
		"controls": []interface{}{
			map[string]interface{}{
				"id":             "ID.AM-1",
				"article_ref":    "ID.AM-1",
				"title":          "Asset inventory",
				"basis":          "automated",
				"evidence_class": "derived",
				"status":         "compliant",
				"not_applicable": false,
				"summary":        "All fleet assets inventoried.",
				"evidence_refs":  []interface{}{"sbom:fleet"},
				"findings":       []interface{}{},
			},
		},
	}
	payload["content_sha256"] = recomputeContentHash(payload)

	inner := map[string]interface{}{
		"content_sha256":       payload["content_sha256"],
		"ctx":                  signingContext,
		"frozen_inputs_sha256": frozenSha,
	}
	signature = map[string]interface{}{
		"algorithm":            "ed25519",
		"context":              signingContext,
		"key_id":               keyIDFor(pubRaw),
		"content_sha256":       payload["content_sha256"],
		"frozen_inputs_sha256": frozenSha,
		"value":                base64.StdEncoding.EncodeToString(ed25519.Sign(priv, canonicalJSON(inner))),
		"public_key":           base64.StdEncoding.EncodeToString(pubRaw),
	}
	return payload, signature, frozen, pubRaw
}

// --------------------------------------------------------------------------- //
// The crux: canonical-JSON byte pins.
// --------------------------------------------------------------------------- //

// Matches Python test_canonical_json_pins_the_encoding exactly.
func TestCanonicalJSONPinsTheEncoding(t *testing.T) {
	got := canonicalJSON(map[string]interface{}{"b": json.Number("1"), "a": "é", "c": "<x>"})
	want := []byte("{\"a\":\"\xc3\xa9\",\"b\":1,\"c\":\"<x>\"}")
	if !bytes.Equal(got, want) {
		t.Fatalf("canonical mismatch\n got=%q\nwant=%q", got, want)
	}
}

// Pins the escaping rules that diverge from Go's encoding/json defaults:
//   - \t \n and " \ use the short forms; other C0 controls → \u00XX;
//   - U+2028 / U+2029 emitted RAW (Go escapes them by default — we must not);
//   - `/` and HTML-significant `<` `&` `>` NOT escaped; non-ASCII raw UTF-8.
func TestCanonicalEscapingRules(t *testing.T) {
	got := string(canonicalJSON(map[string]interface{}{
		"a": "tab\tnl\nq\"bs\\", // short forms
		"b": "",                // other C0 control → 
		"c": "  ",               // line/para separators stay raw
		"d": "a/b<&>é",          // slash, HTML chars, non-ASCII all raw
	}))
	want := "{" +
		"\"a\":\"tab\\tnl\\nq\\\"bs\\\\\"," +
		"\"b\":\"\\u0001\"," +
		"\"c\":\"  \"," +
		"\"d\":\"a/b<&>é\"" +
		"}"
	if got != want {
		t.Fatalf("escaping mismatch\n got=%q\nwant=%q", got, want)
	}
}

// --------------------------------------------------------------------------- //
// Happy path
// --------------------------------------------------------------------------- //
func TestGoldenPackVerifies(t *testing.T) {
	payload, sig, frozen, pub := buildGolden(t)
	r := verifyPack(payload, sig, frozen, nil, nil, strp(keyIDFor(pub)))
	if r.verdict() != "verified" {
		t.Fatalf("verdict=%s notes=%v", r.verdict(), r.Notes)
	}
	if !isTrue(r.PayloadIntact) || !isTrue(r.FrozenInputsValid) || !isTrue(r.SignatureValid) ||
		!isTrue(r.KeyIDMatchesMaterial) || !isTrue(r.KeyIDMatchesAnchor) {
		t.Fatalf("unexpected flags: %+v", r)
	}
	for name, ok := range r.PerSource {
		if !ok {
			t.Fatalf("per_source %s not ok", name)
		}
	}
}

func TestVerifiesWithoutFrozenInputsLayer2Skipped(t *testing.T) {
	payload, sig, _, pub := buildGolden(t)
	r := verifyPack(payload, sig, nil, nil, nil, strp(keyIDFor(pub)))
	if r.verdict() != "verified" {
		t.Fatalf("verdict=%s", r.verdict())
	}
	if r.FrozenInputsValid != nil {
		t.Fatalf("expected nil frozen_inputs_valid, got %v", *r.FrozenInputsValid)
	}
}

// --------------------------------------------------------------------------- //
// Tamper detection (mirrors the Python suite)
// --------------------------------------------------------------------------- //
func TestFlippedPayloadIsTampered(t *testing.T) {
	payload, sig, frozen, _ := buildGolden(t)
	payload["controls"].([]interface{})[0].(map[string]interface{})["status"] = "non_compliant"
	r := verifyPack(payload, sig, frozen, nil, nil, nil)
	if r.verdict() != "tampered" || !isFalse(r.PayloadIntact) {
		t.Fatalf("verdict=%s payload_intact=%v", r.verdict(), r.PayloadIntact)
	}
}

func TestCorruptedFrozenSourceIsTampered(t *testing.T) {
	payload, sig, frozen, _ := buildGolden(t)
	rows := frozen["sources"].(map[string]interface{})["cve_findings"].(map[string]interface{})["rows"].([]interface{})
	rows[0].(map[string]interface{})["severity"] = "low" // alter row, keep sha256
	r := verifyPack(payload, sig, frozen, nil, nil, nil)
	if r.verdict() != "tampered" || !isFalse(r.FrozenInputsValid) {
		t.Fatalf("verdict=%s frozen=%v", r.verdict(), r.FrozenInputsValid)
	}
	if r.PerSource["cve_findings"] {
		t.Fatal("cve_findings should be false")
	}
	if !r.PerSource["runtime_eol"] {
		t.Fatal("runtime_eol should still validate")
	}
}

func TestBadSignatureIsTampered(t *testing.T) {
	payload, sig, frozen, pub := buildGolden(t)
	raw, _ := base64.StdEncoding.DecodeString(sig["value"].(string))
	raw[0] ^= 0x01
	sig["value"] = base64.StdEncoding.EncodeToString(raw)
	r := verifyPack(payload, sig, frozen, nil, nil, strp(keyIDFor(pub)))
	if r.verdict() != "tampered" || !isFalse(r.SignatureValid) {
		t.Fatalf("verdict=%s sig=%v", r.verdict(), r.SignatureValid)
	}
}

func TestSwappedPublicKeyIsTampered(t *testing.T) {
	payload, sig, frozen, _ := buildGolden(t)
	other, _, _ := ed25519.GenerateKey(nil)
	sig["public_key"] = base64.StdEncoding.EncodeToString(other) // key_id no longer matches material
	r := verifyPack(payload, sig, frozen, nil, nil, nil)
	if r.verdict() != "tampered" || !isFalse(r.KeyIDMatchesMaterial) {
		t.Fatalf("verdict=%s material=%v", r.verdict(), r.KeyIDMatchesMaterial)
	}
}

func TestAnchorMismatchIsKeyUnknown(t *testing.T) {
	payload, sig, frozen, _ := buildGolden(t)
	r := verifyPack(payload, sig, frozen, nil, nil, strp("ed25519:deadbeefdeadbeefdeadbeefdeadbeef"))
	if r.verdict() != "key_unknown" {
		t.Fatalf("verdict=%s", r.verdict())
	}
	if !isFalse(r.KeyIDMatchesAnchor) || !isTrue(r.SignatureValid) {
		t.Fatalf("anchor=%v sig=%v", r.KeyIDMatchesAnchor, r.SignatureValid)
	}
}

func TestNoPublicKeyIsKeyUnknown(t *testing.T) {
	payload, sig, frozen, _ := buildGolden(t)
	delete(sig, "public_key")
	r := verifyPack(payload, sig, frozen, nil, nil, nil)
	if r.verdict() != "key_unknown" || r.SignatureValid != nil {
		t.Fatalf("verdict=%s sig=%v", r.verdict(), r.SignatureValid)
	}
}

func TestMalformedBase64SignatureIsTampered(t *testing.T) {
	payload, sig, frozen, pub := buildGolden(t)
	sig["value"] = "!!!not base64!!!"
	r := verifyPack(payload, sig, frozen, nil, nil, strp(keyIDFor(pub)))
	if r.verdict() != "tampered" || !isFalse(r.SignatureValid) {
		t.Fatalf("verdict=%s sig=%v", r.verdict(), r.SignatureValid)
	}
}

func TestMalformedBase64PubkeyIsKeyUnknown(t *testing.T) {
	payload, sig, frozen, _ := buildGolden(t)
	sig["public_key"] = "@@@ not valid base64 @@@"
	r := verifyPack(payload, sig, frozen, nil, nil, nil)
	if r.verdict() != "key_unknown" || r.SignatureValid != nil {
		t.Fatalf("verdict=%s sig=%v", r.verdict(), r.SignatureValid)
	}
}

func TestNonDictFrozenSourceIsTamperedNotCrash(t *testing.T) {
	payload, sig, frozen, pub := buildGolden(t)
	frozen["sources"].(map[string]interface{})["cve_findings"] = "not-a-dict"
	r := verifyPack(payload, sig, frozen, nil, nil, strp(keyIDFor(pub)))
	if r.verdict() != "tampered" || !isFalse(r.FrozenInputsValid) {
		t.Fatalf("verdict=%s frozen=%v", r.verdict(), r.FrozenInputsValid)
	}
	if r.PerSource["cve_findings"] {
		t.Fatal("cve_findings should be false")
	}
}

func TestSignatureFieldDisagreeingWithPayloadIsTampered(t *testing.T) {
	payload, sig, frozen, pub := buildGolden(t)
	sig["content_sha256"] = "0000000000000000000000000000000000000000000000000000000000000000"
	r := verifyPack(payload, sig, frozen, nil, nil, strp(keyIDFor(pub)))
	if r.verdict() != "tampered" || !isFalse(r.SigFieldsConsistent) {
		t.Fatalf("verdict=%s consistent=%v", r.verdict(), r.SigFieldsConsistent)
	}
}

func TestWrongContextInSignatureBlockIsTampered(t *testing.T) {
	payload, sig, frozen, pub := buildGolden(t)
	sig["context"] = "sentari-evidence-pack/v99"
	r := verifyPack(payload, sig, frozen, nil, nil, strp(keyIDFor(pub)))
	if r.verdict() != "tampered" || !isFalse(r.SigFieldsConsistent) {
		t.Fatalf("verdict=%s consistent=%v", r.verdict(), r.SigFieldsConsistent)
	}
}

// --------------------------------------------------------------------------- //
// Real server-generated conformance vector — the byte-exact cross-validation
// with the Python impl AND the real Sentari server. This is the strongest proof
// that this second, independent implementation reproduces the format exactly.
// --------------------------------------------------------------------------- //
var vectorPath = filepath.Join("..", "verifier", "vectors", "cyfun-empty-fleet.golden.json")

func TestRealServerVectorVerifies(t *testing.T) {
	payload, sig, frozen, mc, err := loadArtifact(vectorPath)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	r := verifyPack(payload, sig, frozen, mc, nil, nil)
	if r.verdict() != "verified" {
		t.Fatalf("verdict=%s notes=%v", r.verdict(), r.Notes)
	}
	if !isTrue(r.PayloadIntact) || !isTrue(r.SignatureValid) || !isTrue(r.KeyIDMatchesMaterial) {
		t.Fatalf("flags: intact=%v sig=%v material=%v", r.PayloadIntact, r.SignatureValid, r.KeyIDMatchesMaterial)
	}
	if r.FrozenInputsValid != nil {
		t.Fatalf("expected nil frozen_inputs_valid (server download omits it), got %v", *r.FrozenInputsValid)
	}
}

func TestFlatLoaderStripsTheSignatureSibling(t *testing.T) {
	raw, err := os.ReadFile(vectorPath)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	docV, _ := parseJSON(raw)
	doc := docV.(map[string]interface{})
	payload, sig, _, _, err := loadArtifact(vectorPath)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if _, present := payload["signature"]; present {
		t.Fatal("payload must not contain the signature sibling")
	}
	if payload["content_sha256"] != doc["content_sha256"] {
		t.Fatal("content_sha256 mismatch after strip")
	}
	if sig["key_id"] != doc["signature"].(map[string]interface{})["key_id"] {
		t.Fatal("signature block not preserved")
	}
}

func TestTamperedRealVectorIsTampered(t *testing.T) {
	raw, err := os.ReadFile(vectorPath)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	docV, _ := parseJSON(raw)
	doc := docV.(map[string]interface{})
	doc["controls"].([]interface{})[0].(map[string]interface{})["status"] = "non_compliant"
	out, _ := json.Marshal(doc)
	p := filepath.Join(t.TempDir(), "tampered.json")
	if err := os.WriteFile(p, out, 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	payload, sig, frozen, mc, err := loadArtifact(p)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	r := verifyPack(payload, sig, frozen, mc, nil, nil)
	if r.verdict() != "tampered" || !isFalse(r.PayloadIntact) {
		t.Fatalf("verdict=%s intact=%v", r.verdict(), r.PayloadIntact)
	}
}

// --------------------------------------------------------------------------- //
// Signed-manifest zip packs (spec §3.5)
// --------------------------------------------------------------------------- //
func buildZipPack(t *testing.T, dir string, mutateEvidence bool) (string, string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	payload, sig, frozen, _ := buildGolden(t)
	keyID := keyIDFor(pub)
	frozenSha := sig["frozen_inputs_sha256"].(string)
	inner := map[string]interface{}{
		"content_sha256":       payload["content_sha256"],
		"ctx":                  signingContext,
		"frozen_inputs_sha256": frozenSha,
	}
	// Re-sign golden with THIS key so manifest + evidence share one signer.
	sig["key_id"] = keyID
	sig["value"] = base64.StdEncoding.EncodeToString(ed25519.Sign(priv, canonicalJSON(inner)))
	sig["public_key"] = base64.StdEncoding.EncodeToString(pub)

	evidenceBytes := canonicalJSON(payload) // honest bytes hashed into the manifest
	storedEvidence := evidenceBytes
	if mutateEvidence {
		tampered := map[string]interface{}{}
		for k, v := range payload {
			tampered[k] = v
		}
		c0 := map[string]interface{}{}
		for k, v := range payload["controls"].([]interface{})[0].(map[string]interface{}) {
			c0[k] = v
		}
		c0["status"] = "non_compliant"
		tampered["controls"] = []interface{}{c0}
		// swap the member bytes AFTER the manifest sha is computed
		storedEvidence = canonicalJSON(tampered)
	}
	signatureBytes, _ := json.Marshal(sig)
	frozenBytes, _ := json.Marshal(frozen)

	members := map[string][]byte{
		"evidence.json":      evidenceBytes,
		"signature.json":     signatureBytes,
		"frozen_inputs.json": frozenBytes,
	}
	var files []interface{}
	for _, n := range []string{"evidence.json", "signature.json", "frozen_inputs.json"} {
		files = append(files, map[string]interface{}{"name": n, "sha256": sha256Hex(members[n]), "description": n})
	}
	manifestPayload := map[string]interface{}{"files": files, "domain": "compliance.evidence"}
	manifest := map[string]interface{}{
		"payload":   manifestPayload,
		"signature": base64.StdEncoding.EncodeToString(ed25519.Sign(priv, canonicalJSON(manifestPayload))),
		"key_id":    keyID,
	}
	manifestBytes, _ := json.Marshal(manifest)

	p := filepath.Join(dir, "pack.zip")
	f, err := os.Create(p)
	if err != nil {
		t.Fatalf("create zip: %v", err)
	}
	defer f.Close()
	zw := zip.NewWriter(f)
	writeZipMember(t, zw, "manifest.json", manifestBytes)
	writeZipMember(t, zw, "evidence.json", storedEvidence) // possibly tampered
	writeZipMember(t, zw, "signature.json", signatureBytes)
	writeZipMember(t, zw, "frozen_inputs.json", frozenBytes)
	if err := zw.Close(); err != nil {
		t.Fatalf("zip close: %v", err)
	}
	return p, keyID
}

func writeZipMember(t *testing.T, zw *zip.Writer, name string, data []byte) {
	t.Helper()
	w, err := zw.Create(name)
	if err != nil {
		t.Fatalf("zip create %s: %v", name, err)
	}
	if _, err := w.Write(data); err != nil {
		t.Fatalf("zip write %s: %v", name, err)
	}
}

func TestZipPackWithSignedManifestVerifies(t *testing.T) {
	p, keyID := buildZipPack(t, t.TempDir(), false)
	payload, sig, frozen, mc, err := loadArtifact(p)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if mc == nil {
		t.Fatal("expected a manifest context")
	}
	r := verifyPack(payload, sig, frozen, mc, nil, strp(keyID))
	if r.verdict() != "verified" || !isTrue(r.ManifestValid) || !isTrue(r.FrozenInputsValid) {
		t.Fatalf("verdict=%s manifest=%v frozen=%v notes=%v", r.verdict(), r.ManifestValid, r.FrozenInputsValid, r.Notes)
	}
}

func TestZipWithSwappedMemberIsTamperedViaManifest(t *testing.T) {
	p, keyID := buildZipPack(t, t.TempDir(), true)
	payload, sig, frozen, mc, err := loadArtifact(p)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	r := verifyPack(payload, sig, frozen, mc, nil, strp(keyID))
	if r.verdict() != "tampered" || !isFalse(r.ManifestValid) {
		t.Fatalf("verdict=%s manifest=%v", r.verdict(), r.ManifestValid)
	}
}

// CLI exit-code smoke test over the real vector.
func TestRunExitCodes(t *testing.T) {
	if code := run([]string{vectorPath}, os.Stdout, os.Stderr); code != 0 {
		t.Fatalf("verified vector should exit 0, got %d", code)
	}
	if code := run([]string{vectorPath, "--expected-key-id", "ed25519:deadbeefdeadbeefdeadbeefdeadbeef"}, os.Stdout, os.Stderr); code != 3 {
		t.Fatalf("anchor mismatch should exit 3, got %d", code)
	}
	if code := run([]string{filepath.Join(t.TempDir(), "nope.json")}, os.Stdout, os.Stderr); code != 4 {
		t.Fatalf("missing pack should exit 4, got %d", code)
	}
}
