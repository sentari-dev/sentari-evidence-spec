#!/usr/bin/env node
/**
 * Render-layer test for verify.html — no dependencies, no browser.
 *
 * WHY THIS EXISTS. The conformance and differential harnesses only ever call
 * the verification CORE. The render layer is never executed by either, and
 * that is where two real defects lived:
 *
 *   - a container type-swap (`"controls": []` -> `{}`) made `summarise()`
 *     throw AFTER the verdict had been rendered, so `fail()` then hid the
 *     whole results block and the auditor was shown "this does not look like a
 *     Sentari evidence pack" for a file the core had correctly judged
 *     TAMPERED;
 *   - `#print-head` was never cleared, so after a failed render the printed
 *     identity block still described the PREVIOUS file — its framework, pack
 *     id, content hash and verification result.
 *
 * Neither is visible to a test that only asks "did an exception escape?",
 * because the first one paints a verdict and then erases it. So this asserts
 * the END STATE: the results block is still visible, and the print head
 * belongs to the file just checked.
 *
 * It also mutates CONTAINERS, not just leaves. `x || []` guards against a
 * field being absent and never against it being the wrong type, which is the
 * whole of that bug class.
 *
 * The DOM stub below is deliberately tiny: just the dozen methods the UI
 * actually touches. A dependency (jsdom) would break the "read this one file,
 * it needs nothing" property the repository sells.
 *
 *   node verifier-web/render-test.mjs
 */
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO = join(HERE, '..');
// An explicit path lets this be pointed at a deliberately-broken copy, which
// is how you confirm the gate can actually fail.
const TARGET = process.argv[2] || join(REPO, 'verify.html');
const html = readFileSync(TARGET, 'utf8');

/* ---- extract the two script blocks from the shipped page ---------------- */
function block(startMarker, endMarker) {
  const a = html.indexOf(startMarker);
  const b = html.indexOf(endMarker, a);
  if (a < 0 || b < 0) throw new Error('could not find ' + startMarker);
  return html.slice(html.indexOf('\n', a) + 1, b);
}
const coreSrc = html.slice(
  html.indexOf('*/', html.indexOf('/* CORE-BEGIN')) + 2,
  html.indexOf('/* CORE-END */'),
);
const EvidenceCore = new Function(coreSrc + '\n;return EvidenceCore;')();

let uiSrc = block('<script id="evidence-ui">', '</script>');
// Export the functions under test from inside the IIFE.
const EXPORTS = "\n;globalThis.__ui = { show, summarise, renderPack, renderFrozen, " +
  "renderPrintHead, renderDocPrintHead, renderTrust, fail };\n";
const lastClose = uiSrc.lastIndexOf('})();');
if (lastClose < 0) throw new Error('could not find the UI IIFE close');
uiSrc = uiSrc.slice(0, lastClose) + EXPORTS + uiSrc.slice(lastClose);

/* ---- the smallest DOM the UI actually touches --------------------------- */
function makeEl(id) {
  const el = {
    id,
    _classes: new Set(id === 'results' || id === 'busy' || id === 'parse-error' ||
      id === 'filebar' ? ['hidden'] : []),
    innerHTML: '',
    textContent: '',
    value: '',
    dataset: {},
    open: false,
    style: {},
    parentElement: null,
    firstElementChild: null,
    classList: {
      add: (c) => el._classes.add(c),
      remove: (c) => el._classes.delete(c),
      toggle: (c, on) => (on === undefined
        ? (el._classes.has(c) ? el._classes.delete(c) : el._classes.add(c))
        : (on ? el._classes.add(c) : el._classes.delete(c))),
      contains: (c) => el._classes.has(c),
    },
    addEventListener() {},
    removeEventListener() {},
    focus() {},
    remove() {},
    click() {},
    appendChild() {},
    replaceWith() {},
    closest: () => null,
    getAttribute: () => null,
    setAttribute() {},
    querySelector: () => null,
    querySelectorAll: () => [],
    scrollIntoView() {},
    getBoundingClientRect: () => ({ left: 0, top: 0, width: 0, height: 0 }),
    dispatchEvent() {},
  };
  return el;
}

const IDS = ['drop', 'file', 'choose', 'another', 'busy', 'parse-error', 'results',
  'intro', 'filebar', 'filename', 'trust', 'report', 'assurance', 'print-head',
  'announce', 'anchor', 'pinstate', 'filterstate', 'expandall', 'changepin',
  'clearfilter', 'verdict-head', 'sec-attention', 'frozen'];
let els = {};
function resetDom() {
  els = {};
  for (const id of IDS) els[id] = makeEl(id);
}
resetDom();

globalThis.document = {
  getElementById: (id) => els[id] || null,
  querySelector: () => null,
  querySelectorAll: () => [],
  createElement: () => makeEl('created'),
  body: makeEl('body'),
  activeElement: null,
  styleSheets: [],
};
globalThis.window = { addEventListener() {}, removeEventListener() {}, dispatchEvent() {} };
globalThis.requestAnimationFrame = (fn) => fn();
globalThis.DragEvent = class {};
globalThis.Event = class {};
globalThis.DataTransfer = class { constructor() { this.items = { add() {} }; } };
globalThis.EvidenceCore = EvidenceCore;

new Function(uiSrc)();
const UI = globalThis.__ui;
if (!UI || typeof UI.show !== 'function') throw new Error('UI did not export show()');

/* ---- corpus: every path, leaves AND containers, type-substituted -------- */
const FIXTURE = join(REPO, 'verifier-web', 'fixtures', 'pack-with-frozen-inputs.fixture.json');
const base = JSON.parse(readFileSync(FIXTURE, 'utf8'));

function paths(obj, cur = [], out = []) {
  if (cur.length) out.push(cur);
  if (obj === null || typeof obj !== 'object') return out;
  if (Array.isArray(obj)) {
    obj.forEach((v, i) => paths(v, cur.concat(String(i)), out));
    return out;
  }
  for (const k of Object.keys(obj)) paths(obj[k], cur.concat(k), out);
  return out;
}
function setIn(o, p, v) {
  let cur = o;
  for (let i = 0; i < p.length - 1; i++) cur = cur[p[i]];
  cur[p[p.length - 1]] = v;
}

const SWAPS = [{}, [], 0, true, null, 'a-string', { '__proto__': { x: 1 } }, [null]];
const all = paths(base);

let checked = 0;
const failures = [];

function runOne(label, artifact) {
  checked++;
  resetDom();
  let r;
  try {
    r = EvidenceCore.verifyJson(EvidenceCore.parseJson(JSON.stringify(artifact)), null, {});
  } catch (e) {
    if (e instanceof EvidenceCore.NotAnArtifact) return;   // a rejection, not a render case
    failures.push(`${label}: CORE THREW ${e.message}`);
    return;
  }
  const verdict = EvidenceCore.verdictOf(r);
  try {
    UI.show(EvidenceCore.parseJson(JSON.stringify(artifact)), r, {}, null, 'x.json');
  } catch (e) {
    failures.push(`${label}: show() THREW ${e.message}`);
    return;
  }
  // THE assertion the browser run lacked: the verdict must still be on screen.
  if (els['results'].classList.contains('hidden')) {
    failures.push(`${label}: verdict ERASED (#results hidden) though core said ${verdict}`);
  }
  if (!els['trust'].innerHTML) {
    failures.push(`${label}: no trust band rendered though core said ${verdict}`);
  }
}

console.log('# render layer: every path x 8 type substitutions');
for (const p of all) {
  for (const swap of SWAPS) {
    const m = JSON.parse(JSON.stringify(base));
    try { setIn(m, p, swap); } catch (_e) { continue; }
    runOne(`${p.join('.')}=${JSON.stringify(swap)}`, m);
  }
}

/* ---- the print head must never describe the PREVIOUS file -------------- */
console.log('# printed identity block does not survive into the next file');
// Guarded, so a regression is REPORTED rather than crashing the runner — the
// point of a gate is that it tells you what broke.
function safeShow(label, obj, r, name) {
  try {
    UI.show(obj, r, {}, null, name);
    return true;
  } catch (e) {
    failures.push(`${label}: show() THREW ${e.message}`);
    return false;
  }
}

resetDom();
const goodObj = EvidenceCore.parseJson(readFileSync(FIXTURE, 'utf8'));
safeShow('good pack', goodObj, EvidenceCore.verifyJson(goodObj, null, {}), 'good.json');
const firstHead = els['print-head'].innerHTML;
if (!firstHead) failures.push('print head: nothing rendered for a good pack');

const broken = JSON.parse(readFileSync(FIXTURE, 'utf8'));
broken.controls = {};                       // container swap -> report render fails
const brokenObj = EvidenceCore.parseJson(JSON.stringify(broken));
if (safeShow('"controls": {}', brokenObj,
    EvidenceCore.verifyJson(brokenObj, null, {}), 'broken.json')) {
  if (els['print-head'].innerHTML === firstHead && firstHead) {
    failures.push('print head: still describes the PREVIOUS file after a failed render');
  }
  if (els['results'].classList.contains('hidden')) {
    failures.push('"controls": {} erased the verdict from the screen');
  }
}
checked += 2;

console.log('');
if (!failures.length) {
  console.log(`RENDER TEST PASS — ${checked} cases, the verdict survived every one.`);
  process.exit(0);
}
console.log(`RENDER TEST FAIL — ${failures.length} of ${checked} cases:`);
for (const f of failures.slice(0, 25)) console.log('  ' + f);
process.exit(1);
