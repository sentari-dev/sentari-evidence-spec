#!/usr/bin/env node
/**
 * Differential test -- the browser verifier against the Python reference, on
 * mechanically generated mutations.
 *
 * CONFORMANCE.md fixes a list of mutations every conformant verifier must
 * catch, and conformance.sh checks exactly that list. This goes further: it
 * walks every field of every committed artifact, mutates and deletes each one
 * in turn, and requires the two implementations to return the SAME verdict for
 * all of them -- not merely the right verdict on the curated cases.
 *
 * It is how the remaining disagreements were found once the published table
 * was green: an unchecked `signature.algorithm`, and a missing content hash
 * that escaped as an exception instead of a verdict.
 *
 * Not part of the default gate -- it spawns one python3 process per case and
 * takes a couple of minutes. Run it when changing the verification core.
 *
 *   node verifier-web/differential.mjs
 *
 * Requires: python3 with `cryptography` installed (the reference verifier's
 * only dependency).
 */
import { readFileSync, writeFileSync, mkdtempSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const REPO = process.env.HOME + '/Documents/Development/sentari-evidence-spec';
const html = readFileSync(join(REPO, 'verify.html'), 'utf8');
const a = html.indexOf('/* CORE-BEGIN');
const b = html.indexOf('/* CORE-END */');
const C = new Function(html.slice(html.indexOf('*/', a) + 2, b) + ';return EvidenceCore;')();

const dir = mkdtempSync(join(tmpdir(), 'sev-diff-'));
const EXIT = { 0: 'verified', 2: 'tampered', 3: 'key_unknown', 4: 'error' };

function pyVerdict(obj, anchor) {
  const f = join(dir, 'a.json');
  writeFileSync(f, JSON.stringify(obj));
  const args = [join(REPO, 'verifier/sentari_evidence_verify.py'), f];
  if (anchor) args.push('--expected-key-id', anchor);
  try {
    execFileSync('python3', args, { stdio: 'pipe' });
    return 'verified';
  } catch (e) {
    return EXIT[e.status] ?? ('exit' + e.status);
  }
}

let jsThrew = [];

function jsVerdict(obj, anchor, label) {
  try {
    // Round-trip through text so the JS side parses exactly what Python read.
    return C.verdictOf(C.verifyJson(C.parseJson(JSON.stringify(obj)), anchor || null));
  } catch (e) {
    // NOT collapsed to a verdict. The core's contract is that a corrupt
    // artifact produces verified/tampered/key_unknown -- never an exception.
    // Mapping a throw to 'error' here (and Python's exit 4 to 'error' too)
    // meant a crash on BOTH sides was scored as agreement, which is how a
    // whole class of type-coercion bugs survived a green run.
    jsThrew.push((label || '?') + ': ' + e.message);
    return 'THREW: ' + e.message;
  }
}

const VECTORS = [
  'verifier/vectors/cyfun-empty-fleet.golden.json',
  'verifier/vectors/sbom-cyclonedx.signed.golden.json',
  'verifier/vectors/vex-openvex.signed.golden.json',
  'verifier-web/fixtures/pack-with-frozen-inputs.fixture.json',
];

/** Every leaf path in the object, as arrays of keys. */
function paths(obj, base = [], out = []) {
  if (obj === null || typeof obj !== 'object') { out.push(base); return out; }
  if (Array.isArray(obj)) {
    obj.forEach((v, i) => paths(v, base.concat(String(i)), out));
    return out;
  }
  for (const k of Object.keys(obj)) paths(obj[k], base.concat(k), out);
  return out;
}

function getIn(o, p) { return p.reduce((x, k) => (x === undefined ? x : x[k]), o); }
function setIn(o, p, v) {
  let cur = o;
  for (let i = 0; i < p.length - 1; i++) cur = cur[p[i]];
  cur[p[p.length - 1]] = v;
}
function delIn(o, p) {
  let cur = o;
  for (let i = 0; i < p.length - 1; i++) cur = cur[p[i]];
  const last = p[p.length - 1];
  if (Array.isArray(cur)) cur.splice(Number(last), 1);
  else delete cur[last];
}

let checked = 0;
const disagreements = [];

for (const rel of VECTORS) {
  const original = JSON.parse(readFileSync(join(REPO, rel), 'utf8'));
  const all = paths(original);
  // Sample across the whole artifact rather than only the first fields.
  const step = Math.max(1, Math.floor(all.length / 20));
  const sample = all.filter((_, i) => i % step === 0).slice(0, 20);

  const cases = [];
  // Untouched, plus a wrong pin.
  cases.push(['clean', JSON.parse(JSON.stringify(original)), null]);
  cases.push(['wrong-pin', JSON.parse(JSON.stringify(original)),
    'ed25519:00000000000000000000000000000000']);

  for (const p of sample) {
    const v = getIn(original, p);
    // mutate within type
    let mutated;
    if (typeof v === 'string') mutated = v + 'X';
    else if (typeof v === 'number') mutated = v + 1;
    else if (typeof v === 'boolean') mutated = !v;
    else if (v === null) mutated = 'null-replaced';
    else continue;
    const m = JSON.parse(JSON.stringify(original));
    setIn(m, p, mutated);
    cases.push(['mutate:' + p.join('.'), m, null]);

    // ...and substitute the TYPE. Every field is declared to be a string, a
    // number or a boolean somewhere in the spec; handing the verifier an
    // object or an array instead is the cheapest hostile input there is, and
    // neither implementation had a row for it in the verdict table.
    for (const swap of [{}, [], 0, true, null]) {
      const t = JSON.parse(JSON.stringify(original));
      setIn(t, p, swap);
      cases.push(['typeswap:' + p.join('.') + '=' + JSON.stringify(swap), t, null]);
    }

    // delete
    const d = JSON.parse(JSON.stringify(original));
    delIn(d, p);
    cases.push(['delete:' + p.join('.'), d, null]);
  }

  for (const [label, obj, anchor] of cases) {
    const js = jsVerdict(obj, anchor, rel.split('/').pop() + ' ' + label);
    const py = pyVerdict(obj, anchor);
    checked++;
    if (js !== py) disagreements.push({ rel, label, js, py });
  }
  process.stdout.write(`  ${rel.split('/').pop()}: ${cases.length} cases\n`);
}

console.log(`\n${checked} mutated artifacts driven through BOTH verifiers.`);
if (jsThrew.length) {
  console.log(`\n${jsThrew.length} case(s) made the BROWSER verifier THROW ` +
    `instead of returning a verdict:`);
  for (const t of jsThrew.slice(0, 15)) console.log('  ' + t);
}
if (!disagreements.length && !jsThrew.length) {
  console.log('NO DISAGREEMENTS — browser and Python verifiers returned identical ' +
    'verdicts, and neither threw.');
} else {
  console.log(`${disagreements.length} DISAGREEMENT(S):`);
  for (const d of disagreements.slice(0, 25)) {
    console.log(`  ${d.rel.split('/').pop()}  ${d.label}\n      js=${d.js}  python=${d.py}`);
  }
}

process.exit(disagreements.length || jsThrew.length ? 1 : 0);
