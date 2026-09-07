// Sentari evidence-pack — SECOND, INDEPENDENT offline verifier (Go).
//
// This is a from-scratch Go reimplementation of the open specification
// (spec/spec-v0.1.md) and a peer of the Python reference verifier
// (../verifier/sentari_evidence_verify.py). It exists to prove the format is
// genuinely open: two independent implementations that agree on the same
// golden vector — down to byte-identical canonical JSON — is the strongest
// evidence any auditor/CAB can have that a Sentari pack is reimplementable.
//
// Standard library only: crypto/ed25519, crypto/sha256, encoding/json,
// archive/zip. No external dependencies.
//
// It reproduces spec §9 steps 1–4:
//
//	Layer 1  payload_intact       recompute content_sha256
//	Layer 2  frozen_inputs_valid  recompute frozen_inputs_sha256 + per-source hashes
//	Signature                     Ed25519 over the domain-separated envelope
//	key_id                        key fingerprint (+ optional out-of-band anchor)
//
// Layer 3 (collector re-derivation, spec §5.4) is intentionally NOT implemented
// — it needs the framework collector code for the pack's catalog_version.
package main

import (
	"archive/zip"
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

const (
	signingContext   = "sentari-evidence-pack/v1"
	signingAlgorithm = "ed25519"

	// Signed exportable artifacts (SBOM / VEX) — spec §12. A wrapper
	// {"document": <doc>, "signature": <block>} whose block context is one of
	// these. The document is hashed AS-IS (no blank-and-rehash), the signed
	// envelope is 2-key {content_sha256, ctx} (no frozen_inputs_sha256), and
	// Layer 2/3 do not exist. The SAME evidence key (one key_id) signs packs,
	// SBOMs and VEX; the domain-separated ctx is what makes sharing it safe.
	sbomContext = "sentari-sbom/v1"
	vexContext  = "sentari-vex/v1"
)

// artifactName maps a known artifact context to its display name; ok is false for
// the pack ctx, a missing ctx, or an unknown ctx (all of which take the pack path).
func artifactName(ctx string) (string, bool) {
	switch ctx {
	case sbomContext:
		return "SBOM", true
	case vexContext:
		return "VEX", true
	}
	return "", false
}

// --------------------------------------------------------------------------- //
// Hashing / encoding primitives (spec §5, §6)
// --------------------------------------------------------------------------- //

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// decodeB64 is a strict base64 decode that never errors out of band: malformed
// input yields (nil, false) so callers map it to a deterministic verdict rather
// than a crash (mirrors the Python _decode_b64 contract).
func decodeB64(s string) ([]byte, bool) {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, false
	}
	return b, true
}

// recomputeContentHash blanks content_sha256, canonicalises, sha256 (spec §5.1/§5.2).
func recomputeContentHash(payload map[string]interface{}) string {
	core := make(map[string]interface{}, len(payload)+1)
	for k, v := range payload {
		core[k] = v
	}
	core["content_sha256"] = ""
	return sha256Hex(canonicalJSON(core))
}

// keyIDFor is "ed25519:" + first 32 hex chars of sha256(raw 32-byte pubkey) (spec §6.2).
func keyIDFor(pubkeyRaw []byte) string {
	sum := sha256.Sum256(pubkeyRaw)
	return "ed25519:" + hex.EncodeToString(sum[:])[:32]
}

func getStr(m map[string]interface{}, key string) (string, bool) {
	if m == nil {
		return "", false
	}
	v, ok := m[key]
	if !ok {
		return "", false
	}
	s, ok := v.(string)
	if !ok {
		return "", false
	}
	return s, true
}

// --------------------------------------------------------------------------- //
// Result & verdict (spec §5.5)
// --------------------------------------------------------------------------- //

// Result carries tri-state (*bool: nil = "not checked / unknown") layer outcomes,
// exactly like the Python dataclass's `bool | None` fields.
type Result struct {
	PayloadIntact        *bool
	FrozenInputsValid    *bool // nil = not checkable offline (no frozen_inputs)
	SignatureValid       *bool // nil = key unavailable / unknown
	SigFieldsConsistent  *bool
	ManifestValid        *bool // nil = no manifest (bare .json pack)
	KeyIDMatchesMaterial *bool
	KeyIDMatchesAnchor   *bool // nil = no anchor supplied
	PerSource            map[string]bool
	Notes                []string
}

func newResult() *Result {
	return &Result{PerSource: map[string]bool{}, Notes: []string{}}
}

func boolPtr(b bool) *bool { return &b }
func isTrue(p *bool) bool  { return p != nil && *p }
func isFalse(p *bool) bool { return p != nil && !*p }

// verdict mirrors the Python Result.verdict property precisely, including the
// exact ordering of the checks.
func (r *Result) verdict() string {
	// Any hard-failing integrity layer that WAS checked → tampered.
	if isFalse(r.PayloadIntact) {
		return "tampered"
	}
	if isFalse(r.SigFieldsConsistent) {
		return "tampered"
	}
	if isFalse(r.FrozenInputsValid) {
		return "tampered"
	}
	if isFalse(r.ManifestValid) {
		return "tampered"
	}
	if isFalse(r.SignatureValid) {
		return "tampered"
	}
	// key_id != fingerprint(embedded public_key): key material was rewritten →
	// tampering, not merely an unknown key.
	if isFalse(r.KeyIDMatchesMaterial) {
		return "tampered"
	}
	// Signature couldn't be evaluated (no/unknown/undecodable key).
	if r.SignatureValid == nil {
		return "key_unknown"
	}
	// Correctly-signed but not the pinned key → unknown, not tampered.
	if isFalse(r.KeyIDMatchesAnchor) {
		return "key_unknown"
	}
	if isTrue(r.PayloadIntact) && isTrue(r.SignatureValid) {
		return "verified"
	}
	return "key_unknown"
}

// --------------------------------------------------------------------------- //
// Verification layers
// --------------------------------------------------------------------------- //

// verifyFrozenInputs implements spec §5.3: whole-blob hash + every per-source
// inner hash (row-list vs aggregate idiom). Malformed input is an integrity
// failure, never a crash.
func verifyFrozenInputs(frozen map[string]interface{}, expectedFrozenSha string) (bool, map[string]bool) {
	perSource := map[string]bool{}
	wholeOK := sha256Hex(canonicalJSON(frozen)) == expectedFrozenSha

	rawSources, present := frozen["sources"]
	sources, ok := rawSources.(map[string]interface{})
	if !ok {
		// No sources map (or a malformed one). A present-but-malformed sources
		// value fails; an absent one leaves the whole-blob hash as the gate.
		if present && rawSources != nil {
			return false, perSource
		}
		return wholeOK, perSource
	}

	allOK := true
	for name, rawSrc := range sources {
		src, ok := rawSrc.(map[string]interface{})
		if !ok {
			perSource[name] = false
			allOK = false
			continue
		}
		stored, hasStored := getStr(src, "sha256")

		_, hasRows := src["rows"]
		onlyRowsSha := true
		for k := range src {
			if k != "rows" && k != "sha256" {
				onlyRowsSha = false
				break
			}
		}

		var recomputed string
		if hasRows && onlyRowsSha {
			// row-list source → hash the rows only
			recomputed = sha256Hex(canonicalJSON(src["rows"]))
		} else {
			// aggregate source → hash the inner dict minus 'sha256'
			inner := make(map[string]interface{}, len(src))
			for k, v := range src {
				if k != "sha256" {
					inner[k] = v
				}
			}
			recomputed = sha256Hex(canonicalJSON(inner))
		}
		ok = hasStored && stored != "" && recomputed == stored
		perSource[name] = ok
		if !ok {
			allOK = false
		}
	}
	return wholeOK && allOK, perSource
}

// verifySignature implements spec §6.1/§6.3: Ed25519 over the canonical JSON of
// the domain-separated inner envelope.
func verifySignature(contentSha, frozenSha, sigB64 string, pubkeyRaw []byte) bool {
	sigRaw, ok := decodeB64(sigB64)
	if !ok {
		return false
	}
	if len(pubkeyRaw) != ed25519.PublicKeySize {
		return false
	}
	inner := map[string]interface{}{
		"content_sha256":       contentSha,
		"ctx":                  signingContext,
		"frozen_inputs_sha256": frozenSha,
	}
	return ed25519.Verify(ed25519.PublicKey(pubkeyRaw), canonicalJSON(inner), sigRaw)
}

// verifyManifest verifies a signed zip/dir manifest.json (spec §3.5): its own
// Ed25519 signature over canonical_json(payload), then every listed member's
// raw-bytes sha256, and requires the trust-bearing members to be listed.
func verifyManifest(envelope interface{}, membersRaw map[string][]byte, pubkeyRaw []byte) (bool, []string) {
	env, ok := envelope.(map[string]interface{})
	if !ok {
		return false, []string{"manifest.json is not a JSON object"}
	}
	payload, pok := env["payload"].(map[string]interface{})
	sigB64, sok := getStr(env, "signature")
	if !pok || !sok {
		return false, []string{"manifest.json missing signed payload / signature"}
	}
	sigRaw, dok := decodeB64(sigB64)
	if !dok {
		return false, []string{"manifest.json signature is not valid base64"}
	}
	if len(pubkeyRaw) != ed25519.PublicKeySize ||
		!ed25519.Verify(ed25519.PublicKey(pubkeyRaw), canonicalJSON(payload), sigRaw) {
		return false, []string{"manifest.json Ed25519 signature verification failed"}
	}

	filesRaw, fok := payload["files"].([]interface{})
	if !fok {
		return false, []string{"manifest.json payload has no 'files' list"}
	}
	listed := map[string]bool{}
	ok = true
	notes := []string{}
	for _, e := range filesRaw {
		entry, eok := e.(map[string]interface{})
		if !eok {
			ok = false
			notes = append(notes, "manifest 'files' entry is not an object")
			continue
		}
		name, nok := getStr(entry, "name")
		declared, dok := getStr(entry, "sha256")
		if !nok || !dok {
			ok = false
			notes = append(notes, "manifest file entry missing name / sha256")
			continue
		}
		listed[name] = true
		raw, has := membersRaw[name]
		if !has {
			// A member listed but not carried in this pack is not a failure —
			// only cross-check members we actually hold.
			continue
		}
		if sha256Hex(raw) != declared {
			ok = false
			notes = append(notes, fmt.Sprintf("member %q sha256 does not match the signed manifest", name))
		}
	}
	for _, required := range []string{"evidence.json", "signature.json"} {
		if _, has := membersRaw[required]; has && !listed[required] {
			ok = false
			notes = append(notes, fmt.Sprintf("%s is not covered by the signed manifest", required))
		}
	}
	return ok, notes
}

// --------------------------------------------------------------------------- //
// Orchestration (spec §9)
// --------------------------------------------------------------------------- //

// ManifestCtx is the signed-manifest context for zip/dir packs (nil for bare json).
type ManifestCtx struct {
	Envelope interface{}
	Members  map[string][]byte
}

// verifyDocumentSignature implements spec §12: Ed25519 over the canonical JSON of
// the 2-key {content_sha256, ctx} envelope — deliberately NOT the pack's 3-key
// {content_sha256, ctx, frozen_inputs_sha256} (a signed SBOM/VEX is the artifact
// itself, not derived from frozen inputs).
func verifyDocumentSignature(contentSha, ctx, sigB64 string, pubkeyRaw []byte) bool {
	sigRaw, ok := decodeB64(sigB64)
	if !ok {
		return false
	}
	if len(pubkeyRaw) != ed25519.PublicKeySize {
		return false
	}
	inner := map[string]interface{}{"content_sha256": contentSha, "ctx": ctx}
	return ed25519.Verify(ed25519.PublicKey(pubkeyRaw), canonicalJSON(inner), sigRaw)
}

// verifyDocument is the document path for signed exportable artifacts (SBOM/VEX)
// — spec §12, the five obligations of the design §4. It mirrors the Python
// _verify_document exactly:
//  1. hashes the document AS-IS (NOT recomputeContentHash — which would inject a
//     content_sha256 key the document never carried → false hash);
//  2. compares the block's content_sha256 to that recomputed document hash;
//  3. verifies the 2-key {content_sha256, ctx} envelope (not the 3-key one);
//  5. reports Layer 2/3 as N/A — this artifact class has neither.
func verifyDocument(
	document map[string]interface{},
	signature map[string]interface{},
	pubkeyB64 *string,
	expectedKeyID *string,
) *Result {
	r := newResult()
	ctxS, _ := getStr(signature, "context")
	name, _ := artifactName(ctxS)
	r.Notes = append(r.Notes, fmt.Sprintf("signed %s artifact (context %s)", name, ctxS))

	// Layer 1 — hash the document AS-IS (obligation 1). NO blank-and-rehash.
	recomputed := sha256Hex(canonicalJSON(document))
	// Obligation 2 — compare against the block's content_sha256, not a
	// (non-existent) document field.
	blockContent, _ := getStr(signature, "content_sha256")
	r.PayloadIntact = boolPtr(blockContent != "" && blockContent == recomputed)
	if !isTrue(r.PayloadIntact) {
		r.Notes = append(r.Notes, fmt.Sprintf(
			"content_sha256 mismatch: block=%s… recomputed=%s…", head(blockContent), head(recomputed)))
	}

	// Detached-block metadata consistency. The context is already a known artifact
	// ctx (we only get here by dispatch); the content_sha256 agreement is Layer 1
	// above, so only the algorithm remains to cross-check.
	var fieldNotes []string
	if algo, present := signature["algorithm"]; present && algo != nil && algo != interface{}(signingAlgorithm) {
		fieldNotes = append(fieldNotes, fmt.Sprintf("signature.algorithm=%v (expected %q)", algo, signingAlgorithm))
	}
	r.SigFieldsConsistent = boolPtr(len(fieldNotes) == 0)
	r.Notes = append(r.Notes, fieldNotes...)

	// Layers 2 & 3 do not exist for this artifact class (obligation 5): report
	// N/A, a deliberately distinct word from the pack's "skipped".
	r.FrozenInputsValid = nil
	r.ManifestValid = nil
	r.Notes = append(r.Notes, fmt.Sprintf(
		"Layer 2 (frozen inputs) N/A — a signed %s is the artifact itself, not derived from frozen inputs (spec §12)", name))
	r.Notes = append(r.Notes, fmt.Sprintf(
		"Layer 3 (collector re-derivation) N/A — no collector for a signed %s (spec §12)", name))

	// Key resolution — identical policy to the pack path.
	rawB64 := ""
	if pubkeyB64 != nil && *pubkeyB64 != "" {
		rawB64 = *pubkeyB64
	} else if embedded, ok := getStr(signature, "public_key"); ok {
		rawB64 = embedded
	}
	if rawB64 == "" {
		r.SignatureValid = nil
		r.Notes = append(r.Notes, "no public key available (not embedded, none supplied) — signature unchecked")
		return r
	}
	pubkeyRaw, ok := decodeB64(rawB64)
	if !ok {
		r.SignatureValid = nil
		r.Notes = append(r.Notes, "public key is not valid base64 — signature unchecked (supply a valid --pubkey)")
		return r
	}

	computedKID := keyIDFor(pubkeyRaw)
	blockKID, _ := getStr(signature, "key_id")
	r.KeyIDMatchesMaterial = boolPtr(computedKID == blockKID)
	if !isTrue(r.KeyIDMatchesMaterial) {
		r.Notes = append(r.Notes, fmt.Sprintf("key_id != fingerprint(public_key): %s vs %s", blockKID, computedKID))
	}
	if expectedKeyID != nil {
		r.KeyIDMatchesAnchor = boolPtr(computedKID == *expectedKeyID)
		if !isTrue(r.KeyIDMatchesAnchor) {
			r.Notes = append(r.Notes, fmt.Sprintf(
				"key_id != out-of-band anchor: %s vs %s — authenticity NOT established (rotated / foreign / wrong key)",
				computedKID, *expectedKeyID))
		}
	} else {
		r.Notes = append(r.Notes, "no out-of-band key_id anchor supplied — authenticity NOT established, only "+
			"internal consistency (pass --expected-key-id for a real trust decision)")
	}

	// Signature — Ed25519 over the 2-key envelope (obligation 3). The signed hash
	// is the block's content_sha256; a tampered document fails Layer 1 regardless.
	sigValue, _ := getStr(signature, "value")
	r.SignatureValid = boolPtr(verifyDocumentSignature(blockContent, ctxS, sigValue, pubkeyRaw))
	if !isTrue(r.SignatureValid) {
		r.Notes = append(r.Notes, "Ed25519 signature verification failed")
	}
	return r
}

func verifyPack(
	payload map[string]interface{},
	signature map[string]interface{},
	frozenInputs map[string]interface{},
	manifestCtx *ManifestCtx,
	pubkeyB64 *string,
	expectedKeyID *string,
) *Result {
	// Dispatch on the detached block's context (spec §12). A signed exportable
	// artifact (SBOM/VEX) takes the document path — hash the document AS-IS, verify
	// the 2-key envelope, report Layer 2/3 as N/A. Everything else (the pack ctx, a
	// missing ctx, or an UNKNOWN ctx) takes the pack path below, where an
	// unrecognised context is caught as tampered by the sig-fields check (and a
	// relabelled document, lacking a content_sha256 field, additionally fails
	// Layer 1) — an unknown format is never silently accepted.
	if ctxS, ok := getStr(signature, "context"); ok {
		if _, isArtifact := artifactName(ctxS); isArtifact {
			return verifyDocument(payload, signature, pubkeyB64, expectedKeyID)
		}
	}

	r := newResult()

	// Layer 1 — payload intact.
	stored, _ := getStr(payload, "content_sha256")
	recomputed := recomputeContentHash(payload)
	r.PayloadIntact = boolPtr(stored != "" && stored == recomputed)
	if !isTrue(r.PayloadIntact) {
		r.Notes = append(r.Notes, fmt.Sprintf(
			"content_sha256 mismatch: stored=%s… recomputed=%s…", head(stored), head(recomputed)))
	}

	// The hashes the signature binds come from the pack's own signed columns.
	contentSha, _ := getStr(payload, "content_sha256")
	frozenSha, _ := getStr(signature, "frozen_inputs_sha256")

	// Detached-signature metadata must agree with the payload it claims to sign.
	var fieldNotes []string
	if algo, present := signature["algorithm"]; present && algo != nil && algo != interface{}(signingAlgorithm) {
		fieldNotes = append(fieldNotes, fmt.Sprintf("signature.algorithm=%v (expected %q)", algo, signingAlgorithm))
	}
	if ctx, present := signature["context"]; present && ctx != nil && ctx != interface{}(signingContext) {
		fieldNotes = append(fieldNotes, fmt.Sprintf("signature.context=%v (expected %q)", ctx, signingContext))
	}
	if bc, present := signature["content_sha256"]; present && bc != nil && bc != interface{}(contentSha) {
		fieldNotes = append(fieldNotes, "signature.content_sha256 disagrees with the payload")
	}
	r.SigFieldsConsistent = boolPtr(len(fieldNotes) == 0)
	r.Notes = append(r.Notes, fieldNotes...)

	// Layer 2 — frozen inputs (only if embedded; else nil = not checkable offline).
	if frozenInputs != nil {
		ok, perSource := verifyFrozenInputs(frozenInputs, frozenSha)
		r.FrozenInputsValid = boolPtr(ok)
		r.PerSource = perSource
		if !ok {
			r.Notes = append(r.Notes, "frozen_inputs hash / per-source hash mismatch")
		}
	} else {
		r.Notes = append(r.Notes, "frozen_inputs not embedded in artifact — Layer 2 skipped (spec §3.4)")
	}

	// Key resolution: --pubkey wins; else the block's embedded public_key.
	rawB64 := ""
	if pubkeyB64 != nil && *pubkeyB64 != "" {
		rawB64 = *pubkeyB64
	} else if embedded, ok := getStr(signature, "public_key"); ok {
		rawB64 = embedded
	}
	if rawB64 == "" {
		r.SignatureValid = nil
		r.Notes = append(r.Notes, "no public key available (not embedded, none supplied) — signature unchecked")
		return r
	}
	pubkeyRaw, ok := decodeB64(rawB64)
	if !ok {
		r.SignatureValid = nil
		r.Notes = append(r.Notes, "public key is not valid base64 — signature unchecked (supply a valid --pubkey)")
		return r
	}

	// key_id must be the fingerprint of the key we're about to trust.
	computedKID := keyIDFor(pubkeyRaw)
	blockKID, _ := getStr(signature, "key_id")
	r.KeyIDMatchesMaterial = boolPtr(computedKID == blockKID)
	if !isTrue(r.KeyIDMatchesMaterial) {
		r.Notes = append(r.Notes, fmt.Sprintf("key_id != fingerprint(public_key): %s vs %s", blockKID, computedKID))
	}
	if expectedKeyID != nil {
		r.KeyIDMatchesAnchor = boolPtr(computedKID == *expectedKeyID)
		if !isTrue(r.KeyIDMatchesAnchor) {
			r.Notes = append(r.Notes, fmt.Sprintf(
				"key_id != out-of-band anchor: %s vs %s — authenticity NOT established (rotated / foreign / wrong key)",
				computedKID, *expectedKeyID))
		}
	} else {
		r.Notes = append(r.Notes, "no out-of-band key_id anchor supplied — authenticity NOT established, only "+
			"internal consistency (pass --expected-key-id for a real trust decision)")
	}

	// Signed manifest (zip / dir packs): verify BEFORE trusting evidence/signature.
	if manifestCtx != nil {
		mOK, mNotes := verifyManifest(manifestCtx.Envelope, manifestCtx.Members, pubkeyRaw)
		r.ManifestValid = boolPtr(mOK)
		r.Notes = append(r.Notes, mNotes...)
	}

	// Signature — Ed25519 over the envelope.
	sigValue, _ := getStr(signature, "value")
	r.SignatureValid = boolPtr(verifySignature(contentSha, frozenSha, sigValue, pubkeyRaw))
	if !isTrue(r.SignatureValid) {
		r.Notes = append(r.Notes, "Ed25519 signature verification failed")
	}
	return r
}

func head(s string) string {
	if len(s) > 12 {
		return s[:12]
	}
	return s
}

// --------------------------------------------------------------------------- //
// Artifact loading (spec §3.4)
// --------------------------------------------------------------------------- //

var memberNames = []string{
	"manifest.json", "evidence.json", "signature.json",
	"frozen_inputs.json", "evidence.pdf", "README.txt",
}

// loadArtifact returns (payload, signature, frozenInputs|nil, manifestCtx|nil).
func loadArtifact(path string) (map[string]interface{}, map[string]interface{}, map[string]interface{}, *ManifestCtx, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	if info.IsDir() {
		reader := func(n string) ([]byte, bool) {
			b, e := os.ReadFile(filepath.Join(path, n))
			if e != nil {
				return nil, false
			}
			return b, true
		}
		return membersFrom(reader)
	}

	if zr, e := zip.OpenReader(path); e == nil {
		defer zr.Close()
		byName := map[string]*zip.File{}
		for _, f := range zr.File {
			byName[f.Name] = f
		}
		reader := func(n string) ([]byte, bool) {
			f, ok := byName[n]
			if !ok {
				return nil, false
			}
			rc, e := f.Open()
			if e != nil {
				return nil, false
			}
			defer rc.Close()
			b, e := io.ReadAll(rc)
			if e != nil {
				return nil, false
			}
			return b, true
		}
		return membersFrom(reader)
	}

	// single .json — wrapper {payload,signature,frozen_inputs} OR flat form.
	data, e := os.ReadFile(path)
	if e != nil {
		return nil, nil, nil, nil, e
	}
	docV, e := parseJSON(data)
	if e != nil {
		return nil, nil, nil, nil, e
	}
	doc, ok := docV.(map[string]interface{})
	if !ok {
		return nil, nil, nil, nil, errors.New("artifact is not a JSON object")
	}

	_, hasPayload := doc["payload"]
	_, hasSignature := doc["signature"]
	if hasPayload && hasSignature {
		payload, _ := doc["payload"].(map[string]interface{})
		sig, _ := doc["signature"].(map[string]interface{})
		frozen, _ := doc["frozen_inputs"].(map[string]interface{})
		return payload, sig, frozen, nil, nil
	}

	// Signed exportable artifact (SBOM / VEX), spec §12: a wrapper
	//   {"document": <cyclonedx/spdx/openvex doc>, "signature": <detached block>}.
	// Recognize the top-level "document" key BEFORE the flat-pack fallback below —
	// otherwise the flat path would treat the whole wrapper as a pack payload of
	// {"document": …} and blank-and-rehash it (false tampered). The document is
	// returned unchanged as the payload; verifyPack dispatches to the document path
	// on the block's artifact context.
	if _, hasDoc := doc["document"]; hasDoc {
		document, _ := doc["document"].(map[string]interface{})
		sig, sok := doc["signature"].(map[string]interface{})
		if !sok {
			return nil, nil, nil, nil, errors.New("artifact has a 'document' but no 'signature' block")
		}
		return document, sig, nil, nil, nil
	}

	sigV := doc["signature"]
	if sigV == nil {
		return nil, nil, nil, nil, errors.New("no 'signature' block found in artifact")
	}
	sig, _ := sigV.(map[string]interface{})
	frozen, _ := doc["frozen_inputs"].(map[string]interface{})
	payload := map[string]interface{}{}
	for k, v := range doc {
		if k != "signature" && k != "frozen_inputs" {
			payload[k] = v
		}
	}
	return payload, sig, frozen, nil, nil
}

func membersFrom(reader func(string) ([]byte, bool)) (map[string]interface{}, map[string]interface{}, map[string]interface{}, *ManifestCtx, error) {
	raw := map[string][]byte{}
	for _, n := range memberNames {
		if b, ok := reader(n); ok {
			raw[n] = b
		}
	}
	if _, ok := raw["evidence.json"]; !ok {
		return nil, nil, nil, nil, errors.New("pack is missing evidence.json / signature.json")
	}
	if _, ok := raw["signature.json"]; !ok {
		return nil, nil, nil, nil, errors.New("pack is missing evidence.json / signature.json")
	}

	pv, e := parseJSON(raw["evidence.json"])
	if e != nil {
		return nil, nil, nil, nil, e
	}
	payload, _ := pv.(map[string]interface{})

	sv, e := parseJSON(raw["signature.json"])
	if e != nil {
		return nil, nil, nil, nil, e
	}
	sig, _ := sv.(map[string]interface{})

	var frozen map[string]interface{}
	if fb, ok := raw["frozen_inputs.json"]; ok {
		fv, e := parseJSON(fb)
		if e != nil {
			return nil, nil, nil, nil, e
		}
		frozen, _ = fv.(map[string]interface{})
	}

	var mc *ManifestCtx
	if mb, ok := raw["manifest.json"]; ok {
		mv, e := parseJSON(mb)
		if e != nil {
			return nil, nil, nil, nil, e
		}
		mc = &ManifestCtx{Envelope: mv, Members: raw}
	}
	return payload, sig, frozen, mc, nil
}

// parseJSON decodes JSON preserving integer forms via json.Number (spec §4).
func parseJSON(data []byte) (interface{}, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var v interface{}
	if err := dec.Decode(&v); err != nil {
		return nil, err
	}
	return v, nil
}
