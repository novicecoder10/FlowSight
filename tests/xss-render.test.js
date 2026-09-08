// Load the REAL theme.js escapeHtml + the REAL app.js render(), against a DOM shim.
const fs = require('fs');
const vm = require('vm');

const store = {};
const mkEl = (id) => ({ id, _html: '', _text: '',
  set innerHTML(v) { this._html = String(v); }, get innerHTML() { return this._html; },
  set textContent(v) { this._text = String(v); }, get textContent() { return this._text; },
  classList: { toggle() {}, add() {}, remove() {} }, getContext: () => ({ scale(){}, clearRect(){}, beginPath(){}, moveTo(){}, lineTo(){}, stroke(){}, fill(){}, fillText(){}, fillRect(){}, closePath(){}, arc(){}, createLinearGradient: () => ({ addColorStop(){} }), set font(v){}, set fillStyle(v){}, set strokeStyle(v){}, set lineWidth(v){} }),
  clientWidth: 100, clientHeight: 100, addEventListener() {}, closest: () => null, dataset: {},
  setAttribute() {}, getAttribute: () => null, appendChild() {}, style: {} });

const sandbox = {
  console,
  document: {
    querySelector: (sel) => (store[sel] = store[sel] || mkEl(sel)),
    querySelectorAll: () => [],
    getElementById: (id) => (store['#'+id] = store['#'+id] || mkEl(id)),
    addEventListener() {}, documentElement: { setAttribute() {}, getAttribute: () => null },
    body: mkEl('body'),
  },
  window: { setTimeout: () => 0, devicePixelRatio: 1, matchMedia: () => ({ matches: false, addEventListener() {} }), addEventListener() {} },
  setTimeout: () => 0, setInterval: () => 0,
  localStorage: { getItem: () => null, setItem() {} },
  EventSource: function () { this.addEventListener = () => {}; this.onerror = null; },
  fetch: () => Promise.resolve({ ok: false }),
  Number, Math, Date, JSON, String, Object, Array, Set, Map, isNaN, parseInt, parseFloat,
  URLSearchParams, location: { search: '' }, requestAnimationFrame: () => 0,
};
sandbox.globalThis = sandbox;
vm.createContext(sandbox);

// theme.js defines the shared escapeHtml
vm.runInContext(fs.readFileSync(__dirname + '/../public/theme.js', 'utf8'), sandbox);
// app.js defines render()/addPacket() and reads elements at load time
vm.runInContext(fs.readFileSync(__dirname + '/../public/app.js', 'utf8'), sandbox);

const PAYLOAD = '<img src=x onerror=window.__XSS__=1>';
sandbox.addPacket({
  id: 1, timestamp: new Date().toISOString(),
  source: '10.6.6.6', destination: '10.0.0.1', protocol: 'TCP',
  sourcePort: 4444, destinationPort: 80, bytes: 120,
  metadata: 'app=HTTP;host=evil.test;user_agent=' + PAYLOAD,
});
sandbox.render();

const html = store['#flow-table'].innerHTML;
console.log('rendered cell:\n  ' + (html.match(/<td title=[^>]*>[^<]*/) || ['(no match)'])[0].slice(0, 160));

let failed = false;
if (html.includes(PAYLOAD)) { console.log('\nFAIL: raw payload present in innerHTML -> XSS'); failed = true; }
if (/<img\s/i.test(html)) { console.log('FAIL: live <img> tag injected into DOM -> XSS'); failed = true; }
if (!html.includes('&lt;img src=x onerror=')) { console.log('FAIL: payload not HTML-escaped'); failed = true; }
// attribute-context check: payload must not break out of title="..."
if (/title="[^"]*<img/i.test(html)) { console.log('FAIL: attribute-context escape'); failed = true; }
console.log(failed ? '\n=== XSS TEST FAILED ===' : '\n=== XSS TEST PASSED: payload rendered inert ===');
process.exit(failed ? 1 : 0);
