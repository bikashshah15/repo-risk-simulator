// Dependency-free checks of a rendered report's actual script using a minimal DOM.
// Expectations are derived from the report's own embedded data, so this works on
// demo and live reports alike. It does not verify browser layout or CSP enforcement.
const fs = require('fs');
const vm = require('vm');
const assert = require('assert');
const reportPath = process.argv[2];
if (!reportPath) { console.error('Usage: node test_report.js /absolute/path/report.html'); process.exit(1); }
const html = fs.readFileSync(reportPath, 'utf8');

class Element {
  constructor(tag = 'div') {
    this.tagName = tag; this.children = []; this.listeners = {}; this.style = {};
    this.value = ''; this.textContent = ''; this.disabled = false; this.open = false; this.className = '';
  }
  append(...items) { this.children.push(...items); }
  replaceChildren(...items) { this.children = items; }
  addEventListener(name, handler) { this.listeners[name] = handler; }
  setAttribute(name, value) { this[name] = value; }
  showModal() { this.open = true; }
  close() { this.open = false; }
  fire(name) { this.listeners[name]?.(); }
}
const walk = (node, out = []) => { out.push(node); (node.children || []).forEach(c => c instanceof Element && walk(c, out)); return out; };
const findAll = (root, pred) => walk(root).filter(pred);
const button = (root, text) => findAll(root, n => n.tagName === 'button' && n.textContent === text)[0];

const elems = new Map([...html.matchAll(/\bid="([^"]+)"/g)].map(m => [m[1], new Element()]));
const raw = html.match(/<script id="report-data" type="application\/json">([\s\S]*?)<\/script>/)[1];
elems.get('report-data').textContent = raw;
elems.get('filter').value = 'all';
const document = { getElementById: id => elems.get(id), createElement: tag => new Element(tag) };
const window = {};
const js = [...html.matchAll(/<script(?:\s[^>]*)?>([\s\S]*?)<\/script>/g)][1][1];
vm.runInNewContext(js, { document, window, Map, Set, Blob, URL, setTimeout });
const DATA = JSON.parse(raw), R = DATA.run, A = DATA.analysis;
const checks = [];
const ok = (cond, label) => { assert(cond, label); checks.push(label); };
const rows = () => elems.get('packages').children.length;

// Inventory search and every status filter.
ok(rows() === R.packages.length, 'all packages listed');
if (R.packages.length) {
  const term = R.packages[0].name.toLowerCase().slice(0, 12);
  elems.get('search').value = term.toUpperCase(); elems.get('search').fire('input');
  const expected = R.packages.filter(p => [p.name, p.version, p.purl].join(' ').toLowerCase().includes(term)).length;
  ok(rows() === expected && expected >= 1, 'case-insensitive search');
}
elems.get('search').value = 'no-such-package-zz9'; elems.get('search').fire('input');
ok(rows() === 0, 'non-matching search shows zero rows');
elems.get('search').value = '';
for (const status of ['matched', 'no_match', 'unsupported', 'error', 'pending', 'root', 'all']) {
  elems.get('filter').value = status; elems.get('filter').fire('change');
  ok(rows() === (status === 'all' ? R.packages.length : R.packages.filter(p => p.status === status).length), 'filter ' + status);
}

// Evidence index lists every evidence item; dialog opens and closes.
const indexButtons = findAll(elems.get('evidenceIndex'), n => n.tagName === 'button');
ok(indexButtons.length === R.evidence.length, 'evidence index lists all evidence');
for (const kind of new Set(R.evidence.map(e => e.kind))) {
  const id = R.evidence.find(e => e.kind === kind).id;
  indexButtons.find(b => b.textContent === id).fire('click');
  ok(elems.get('evidenceDialog').open && elems.get('evidenceTitle').textContent === id, 'evidence dialog opens for ' + kind);
  elems.get('closeEvidence').fire('click');
  ok(!elems.get('evidenceDialog').open, 'evidence dialog closes for ' + kind);
}

// Findings and scenarios.
ok(elems.get('findingCards').children.length === Math.max(1, R.findings.length), 'finding cards or empty-state message');
const cards = elems.get('scenarioCards').children;
if (!A.scenarios.length) {
  ok(cards.length === 1 && cards[0].className === 'empty', 'zero-scenario message');
} else {
  ok(cards.length === A.scenarios.length, 'one card per scenario');
  A.scenarios.forEach((s, i) => {
    const card = cards[i];
    const selects = findAll(card, n => n.tagName === 'select');
    const status = findAll(card, n => n.className.startsWith('status'))[0];
    const baseline = Object.fromEntries(s.prerequisites.map(p => [p.id, p.initial]));
    ok(status.className === 'status ' + window.RepoRisk.evaluate(s.prerequisites, baseline), s.id + ' baseline outcome');
    s.prerequisites.forEach((p, j) => { selects[j].value = String(p.required_value); selects[j].fire('change'); });
    ok(status.className === 'status satisfied', s.id + ' all prerequisites met -> satisfied');
    selects[0].value = String(!s.prerequisites[0].required_value); selects[0].fire('change');
    ok(status.className === 'status blocked', s.id + ' contradicted prerequisite -> blocked');
    button(card, 'Reset evidence baseline').fire('click');
    ok(selects.every((sel, j) => sel.value === s.prerequisites[j].initial) && status.className === 'status ' + window.RepoRisk.evaluate(s.prerequisites, baseline), s.id + ' reset restores baseline');
    const trace = findAll(card, n => n.tagName === 'ol')[0];
    const next = button(card, 'Next step'), prev = button(card, 'Previous step'), restart = button(card, 'Restart steps');
    ok(prev.disabled, s.id + ' previous disabled at start');
    next.fire('click'); ok(trace.children[0].className === 'active', s.id + ' next activates step 1');
    for (let k = 1; k < s.steps.length; k++) next.fire('click');
    ok(next.disabled && trace.children[s.steps.length - 1].className === 'active', s.id + ' next stops at last step');
    prev.fire('click'); ok(trace.children[s.steps.length - 2].className === 'active', s.id + ' previous steps back');
    restart.fire('click'); ok(trace.children.every(li => li.className === ''), s.id + ' restart clears steps');
  });
}
if ((A.context_notes || []).length) ok(findAll(elems.get('limitations'), n => n.tagName === 'button').length >= A.context_notes.length, 'context notes carry evidence buttons');

console.log('Report script passed ' + checks.length + ' mocked-DOM checks derived from embedded data (' + R.packages.length + ' packages, ' + R.evidence.length + ' evidence items, ' + A.scenarios.length + ' scenarios). This does not verify browser rendering or CSP enforcement.');
