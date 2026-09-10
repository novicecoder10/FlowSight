/* ── FlowSight Theme Toggle ── */
(function() {
  const STORAGE_KEY = 'flowsight-theme';

  function getPreferred() {
    const saved = localStorage.getItem(STORAGE_KEY);
    if (saved === 'dark' || saved === 'light') return saved;
    return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
  }

  function apply(theme) {
    document.documentElement.setAttribute('data-theme', theme);
    localStorage.setItem(STORAGE_KEY, theme);
    // Update toggle button icon
    const btn = document.getElementById('theme-toggle');
    if (btn) {
      btn.setAttribute('aria-label', theme === 'dark' ? 'Switch to light mode' : 'Switch to dark mode');
      btn.innerHTML = theme === 'dark'
        ? '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="5"/><line x1="12" y1="1" x2="12" y2="3"/><line x1="12" y1="21" x2="12" y2="23"/><line x1="4.22" y1="4.22" x2="5.64" y2="5.64"/><line x1="18.36" y1="18.36" x2="19.78" y2="19.78"/><line x1="1" y1="12" x2="3" y2="12"/><line x1="21" y1="12" x2="23" y2="12"/><line x1="4.22" y1="19.78" x2="5.64" y2="18.36"/><line x1="18.36" y1="5.64" x2="19.78" y2="4.22"/></svg>'
        : '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/></svg>';
    }
  }

  // Apply immediately to prevent flash
  apply(getPreferred());

  // Set up toggle button once DOM is ready
  document.addEventListener('DOMContentLoaded', () => {
    const btn = document.getElementById('theme-toggle');
    if (btn) {
      // Re-apply to update button icon
      apply(getPreferred());
      btn.addEventListener('click', () => {
        const current = document.documentElement.getAttribute('data-theme') || 'light';
        apply(current === 'dark' ? 'light' : 'dark');
      });
    }
  });
})();

// ── Capture status ──────────────────────────────────────────────────────────
// One vocabulary for the state of the packet stream, shared by every page. Pages
// used to invent their own wording — "Live", "LIVE STREAM", "Demo Stream",
// "Engine Warning" — and one page hardcoded "Live Capture" regardless of what the
// server said. The status readout is the one element that must never lie: it is
// how you tell a dead capture from quiet traffic.
//
// Call with the payload of the SSE `status` event, or the string 'offline' when
// the stream itself drops.
function setCaptureStatus(status) {
  const dot = document.getElementById('status-dot');
  const state = document.getElementById('live-label');
  const detail = document.getElementById('status-detail');
  const readout = document.getElementById('capture-status');
  if (!dot || !state) return;

  let tone = 'idle';
  let label = 'Connecting';
  let note = 'waiting for stream';
  let full = '';

  if (status === 'offline') {
    tone = 'down'; label = 'Reconnecting'; note = 'stream interrupted';
  } else if (status && status.mode === 'demo') {
    tone = 'demo'; label = 'Demo data'; note = 'synthetic generator';
    full = 'Traffic is generated in the server process, not captured from an interface.';
  } else if (status && status.running) {
    tone = 'live'; label = 'Capturing';
    note = status.device ? 'interface ' + status.device : 'packets arriving';
  } else if (status) {
    tone = 'down'; label = 'No capture';
    full = (status.error || '').replace(/^\[FlowSight\]\s*/, '').replace(/^Unable to start sniffer:\s*/, '');
    note = full ? (full.length > 34 ? full.slice(0, 33) + '…' : full) : 'sniffer not running';
  }

  dot.className = 'status-dot tone-' + tone;
  state.textContent = label;
  if (detail) detail.textContent = note;
  if (readout) readout.title = full || (label + ' — ' + note);
}

// Shared HTML escaper. Every page loads theme.js, so this is available globally.
// Packet metadata, SNI, User-Agent and hostnames all originate from monitored
// traffic and are attacker-controlled — never interpolate them raw into innerHTML.
function escapeHtml(value) {
  if (value === null || value === undefined) return '';
  return String(value).replace(/[&<>"']/g, (character) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[character]);
}
