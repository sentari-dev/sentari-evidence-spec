#!/usr/bin/env node
/**
 * Conformance harness for the BROWSER verifier (verify.html).
 *
 * This is the gate that stops the browser verifier from becoming a fourth
 * source of spec drift. It extracts the core block out of the shipped
 * verify.html — the exact bytes an auditor runs, not a parallel copy — and
 * drives it through the published verdict table in CONFORMANCE.md:
 *
 *   every committed vector x {no pin, correct pin, wrong pin}  +  tamper
 *
 * The expected verdicts here are the SAME ones verifier/conformance.sh
 * enforces for the Python and Go verifiers. If all three agree, the format is
 * genuinely reimplementable in three languages by three code paths.
 *
 * Usage:  node verifier-web/conformance.mjs      (exit 0 = PASS)
 */
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO = join(HERE, '..');
const VECTORS = join(REPO, 'verifier', 'vectors');

/* --- Load the core straight out of verify.html ---------------------------- */
const html = readFileSync(join(REPO, 'verify.html'), 'utf8');
const start = html.indexOf('/* CORE-BEGIN');
const end = html.indexOf('/* CORE-END */');
if (start < 0 || end < 0) {
  console.error('FAIL: could not find the CORE-BEGIN/CORE-END markers in verify.html');
  process.exit(1);
}
// Slice from the END of the begin-marker comment (it spans more than one
// line, so slicing from the next newline would leak comment text into the
// evaluated source).
const afterMarker = html.indexOf('*/', start) + 2;
const source = html.slice(afterMarker, end);
// eslint-disable-next-line no-new-func
const EvidenceCore = new Function(source + '\n;return EvidenceCore;')();

const CYFUN_KID = 'ed25519:2c324e5afc47408739876dba4886ef19';
const SIGNED_KID = 'ed25519:eb719d5bab969e9f243775b329a23ac6';
const WRONG_KID = 'ed25519:00000000000000000000000000000000';

let pass = 0;
let fail = 0;

function check(label, want, got) {
  if (got === want) {
    pass++;
    console.log(`  PASS  ${label} -> ${got}`);
  } else {
    fail++;
    console.log(`  FAIL  ${label} -> got ${got}, want ${want}`);
  }
}

function verdict(obj, anchor) {
  try {
    return EvidenceCore.verdictOf(EvidenceCore.verifyJson(obj, anchor || null));
  } catch (e) {
    return 'error: ' + e.message;
  }
}

function load(name) {
  return JSON.parse(readFileSync(join(VECTORS, name), 'utf8'));
}

function runVector(name, kid) {
  console.log(`# ${name}`);
  check('default (no pin)', 'verified', verdict(load(name), null));
  check('correct key pin', 'verified', verdict(load(name), kid));
  check('wrong key pin', 'key_unknown', verdict(load(name), WRONG_KID));
}

runVector('cyfun-empty-fleet.golden.json', CYFUN_KID);
runVector('sbom-cyclonedx.signed.golden.json', SIGNED_KID);
runVector('vex-openvex.signed.golden.json', SIGNED_KID);

/* --- The mutation matrix (CONFORMANCE.md) --------------------------------- */
console.log('# mutation matrix');

// Flip a byte of a signed document.
const sbom = load('sbom-cyclonedx.signed.golden.json');
sbom.document.bomFormat = 'CycloneDX-TAMPERED';
check('SBOM: tampered document', 'tampered', verdict(sbom, null));

// Flip a byte of a pack payload.
const p1 = load('cyfun-empty-fleet.golden.json');
p1.framework_version = 'CyFun 2023 (CCB) TAMPERED';
check('pack: tampered payload', 'tampered', verdict(p1, null));

// Swap content_sha256 for a valid-looking but wrong hash.
const p2 = load('cyfun-empty-fleet.golden.json');
p2.content_sha256 = 'f'.repeat(64);
check('pack: wrong content_sha256', 'tampered', verdict(p2, null));

// Truncate / replace the signature value.
const p3 = load('cyfun-empty-fleet.golden.json');
p3.signature.value = 'AA' + p3.signature.value.slice(2);
check('pack: replaced signature', 'tampered', verdict(p3, null));

// Rewrite the key MATERIAL so key_id no longer fingerprints it. Spec 5.5:
// that is tampering, NOT a merely unrecognised signer.
const p4 = load('cyfun-empty-fleet.golden.json');
p4.signature.key_id = 'ed25519:11111111111111111111111111111111';
check('pack: key_id != fingerprint(public_key)', 'tampered', verdict(p4, null));

// Cross-context replay: relabel a signed SBOM with the pack context.
const x1 = load('sbom-cyclonedx.signed.golden.json');
x1.signature.context = EvidenceCore.PACK_CTX;
check('SBOM relabelled as a pack ctx', 'tampered', verdict(x1, null));

// ...and an entirely unknown ctx must be refused, never silently accepted.
const x2 = load('vex-openvex.signed.golden.json');
x2.signature.context = 'sentari-not-a-real-thing/v9';
check('unknown signature context', 'tampered', verdict(x2, null));

// A float anywhere in hashed content is unreproducible across languages
// (spec 4 / 12.2) and must never reach a verified verdict.
const f1 = load('sbom-cyclonedx.signed.golden.json');
f1.document.specVersion = 1.6;
check('float in hashed document', 'tampered', verdict(f1, null));

console.log('');
if (fail === 0) {
  console.log(`CONFORMANCE PASS — ${pass} checks, browser verifier agrees with the published table.`);
  process.exit(0);
}
console.log(`CONFORMANCE FAIL — ${fail} failed / ${pass} passed.`);
process.exit(1);
