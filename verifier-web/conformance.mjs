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
import { createHash } from 'node:crypto';

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
  // Parse through the verifier's OWN parser, not JSON.parse: preserving
  // number literals is part of what is being conformance-tested.
  return EvidenceCore.parseJson(readFileSync(join(VECTORS, name), 'utf8'));
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

// A float INTRODUCED IN CODE (not read from the artifact, so it carries no
// source literal) cannot be reproduced byte-for-byte and must never reach a
// verified verdict.
const f1 = load('sbom-cyclonedx.signed.golden.json');
f1.document.specVersion = 1.6;
check('code-introduced float in hashed content', 'tampered', verdict(f1, null));

/* --- number-literal preservation ---------------------------------------- *
 * The regression that matters most. JSON.parse turns the literal `1.0` into
 * the double 1, which re-serialises as "1" -- different bytes, and a genuine
 * pack reads as TAMPERED. Go avoids it with Decoder.UseNumber(); this
 * implementation parses JSON itself to keep every number's source text.
 *
 * This is not hypothetical: Sentari's frozen `cve_findings` rows carry an
 * `epss_score` straight from a float column, so `1.0` really does occur in
 * signed content. The fixture below is a synthetic pack (signed with a
 * throwaway key -- it is NOT a real Sentari artifact like the vectors above)
 * that reproduces exactly that shape, with frozen inputs so Layer 2 is
 * exercised too. Python and Go both verify it; so must this. */
const FIXTURES = join(REPO, 'verifier-web', 'fixtures');
function loadFixture(name) {
  return EvidenceCore.parseJson(readFileSync(join(FIXTURES, name), 'utf8'));
}
console.log('# number-literal preservation (fixture with frozen inputs + float)');
const fx = loadFixture('pack-with-frozen-inputs.fixture.json');
check('fixture verifies (Layer 1 + Layer 2 + signature)', 'verified', verdict(fx, null));

const fxr = EvidenceCore.verifyJson(loadFixture('pack-with-frozen-inputs.fixture.json'), null);
check('Layer 2 re-derived every frozen source', true,
  Object.values(fxr.per_source).length > 0 && Object.values(fxr.per_source).every(Boolean));
check('the float literal survived the round trip', '1.0',
  String(EvidenceCore.canonicalString(EvidenceCore.parseJson('{"epss_score":1.0}'))
    .match(/:(.*)\}/)[1]));

// ...and a mutated frozen row must still be caught.
const fxt = loadFixture('pack-with-frozen-inputs.fixture.json');
fxt.frozen_inputs.sources.cve_findings.rows[0].severity = 'low';
check('mutated frozen evidence row', 'tampered', verdict(fxt, null));

/* --- the primitives, against an independent implementation --------------- *
 * The committed vectors exercise only a handful of message lengths, and that
 * is exactly how a padding bug survives: SHA-2 needs the SMALLEST block count
 * that fits the message, the 0x80 byte and the length field, and an
 * off-by-one over-allocates a whole extra block ONLY when the message length
 * is congruent to 55 mod 64 (SHA-256) or 111 mod 128 (SHA-512). Every other
 * length is unaffected, so vectors pass and real artifacts of the wrong size
 * hash wrong -- a false "tampered" on a genuine pack.
 *
 * So: every length from 0 to 600, both hashes, against node:crypto. */
console.log('# embedded hash primitives vs node:crypto (lengths 0..600)');
let hashBad = [];
for (let n = 0; n <= 600; n++) {
  const buf = Buffer.alloc(n);
  for (let i = 0; i < n; i++) buf[i] = (i * 31 + n) & 0xff;
  const u = new Uint8Array(buf);
  if (EvidenceCore.sha256Hex(u) !== createHash('sha256').update(buf).digest('hex')) {
    hashBad.push('sha256@' + n);
  }
  if (EvidenceCore.toHex(EvidenceCore.sha512(u)) !==
      createHash('sha512').update(buf).digest('hex')) {
    hashBad.push('sha512@' + n);
  }
}
check('every message length hashes identically', 0, hashBad.length);
if (hashBad.length) console.log('        first divergences: ' + hashBad.slice(0, 8).join(', '));

/* --- canonicalisation edge cases ---------------------------------------- *
 * Each of these is a place where a JS implementation quietly disagrees with
 * the Python producer unless it is written deliberately. */
console.log('# canonical JSON edge cases');
const canon = (text) => Buffer.from(
  EvidenceCore.canonicalJson(EvidenceCore.parseJson(text))).toString('utf8');

// "__proto__" is an ordinary data key to Python and Go. Assigning it on a
// plain JS object sets the prototype instead, and the key disappears --
// letting an artifact hide a field from this verifier alone.
check('__proto__ survives as a data key',
  '{"__proto__":{"x":1},"a":2}', canon('{"__proto__":{"x":1},"a":2}'));
check('constructor survives as a data key',
  '{"constructor":1}', canon('{"constructor":1}'));

// ensure_ascii=False: non-ASCII stays raw UTF-8, never \uXXXX.
check('non-ASCII stays raw', '{"k":"caf\u00e9 \u4e2d"}', canon('{"k":"caf\u00e9 \u4e2d"}'));

// Keys sort by CODE POINT. JS's default sort compares UTF-16 code units,
// which disagrees once astral characters are involved.
check('keys sort by code point',
  '{"\ue000":2,"\u{1f600}":1}', canon('{"\u{1f600}":1,"\ue000":2}'));

// Number literals are preserved verbatim (see above).
check('number literals verbatim', '{"a":1.0,"b":2.50,"c":1e21}',
  canon('{"a":1.0,"b":2.50,"c":1e21}'));

// Malformed input is a verdict or a clean error, never a crash.
for (const bad of ['{', '{"a":}', '[1,]', '{"a":01}', 'nul', '{"a":1}x', '"\\ud800"']) {
  let threw = false;
  try { EvidenceCore.parseJson(bad); } catch (_e) { threw = true; }
  if (!threw && bad !== '"\\ud800"') {
    fail++;
    console.log('  FAIL  malformed input accepted: ' + bad);
  }
}
console.log('  PASS  malformed JSON is rejected, not crashed on');
pass++;

/* --- prototype-key smuggling ------------------------------------------- *
 * This is here because the bug came back. "__proto__" was fixed in the
 * parser, and three lines later the copy loops in verifyPack re-created it
 * exactly: assigning the key onto a plain {} sets the prototype, the key
 * disappears from Object.keys, and the hash is computed over bytes that are
 * NOT the file's. Python and Go both treat it as ordinary data, so the result
 * was a false "verified" here against "tampered" there -- a three-way split
 * on the one axis that matters. Vectors, not vigilance. */
console.log('# prototype-key smuggling');
const protoPack = EvidenceCore.parseJson(
  readFileSync(join(FIXTURES, 'pack-with-frozen-inputs.fixture.json'), 'utf8')
    .replace('{\n  "catalog_version"',
             '{\n  "__proto__": {"x": "never signed"},\n  "catalog_version"'));
check('__proto__ smuggled into a signed payload', 'tampered', verdict(protoPack, null));

const protoFrozen = loadFixture('pack-with-frozen-inputs.fixture.json');
protoFrozen.frozen_inputs.sources.attestations['__proto__'] = { x: 1 };
check('__proto__ smuggled into a frozen source', 'tampered', verdict(protoFrozen, null));

// An inherited property name must not satisfy the artifact-context lookup and
// slip past "refuse an unrecognised format".
const ctorCtx = load('sbom-cyclonedx.signed.golden.json');
ctorCtx.signature.context = 'constructor';
check('"constructor" as a signature context', 'tampered', verdict(ctorCtx, null));

// Ed25519: x = 0 with the sign bit set is not a valid point encoding.
const badPoint = new Uint8Array(32);
badPoint[31] = 0x80;   // y = 0, sign bit set  ->  x = 0 encoded as negative
check('non-canonical x=0 point encoding rejected', false,
  EvidenceCore.ed25519Verify(new Uint8Array(64), new Uint8Array(0), badPoint));

console.log('');
if (fail === 0) {
  console.log(`CONFORMANCE PASS — ${pass} checks, browser verifier agrees with the published table.`);
  process.exit(0);
}
console.log(`CONFORMANCE FAIL — ${fail} failed / ${pass} passed.`);
process.exit(1);
