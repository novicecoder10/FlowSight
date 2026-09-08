const endpoints = new Map();
let renderQueued = false;
const statusDot = document.querySelector('#status-dot');
const statusLabel = document.querySelector('#status-label');
function publicIp(ip) { const parts = ip.split('.').map(Number); return parts.length === 4 && parts.every((part) => part >= 0 && part <= 255) && !(parts[0] === 10 || parts[0] === 127 || parts[0] === 192 && parts[1] === 168 || parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31); }
function setStatus(connected) { statusDot.classList.toggle('connected', connected); statusLabel.textContent = connected ? 'Live capture' : 'Capture unavailable'; }
function scheduleRender() { if (renderQueued) return; renderQueued = true; window.setTimeout(() => { renderQueued = false; render(); }, 200); }
function render() { const ordered = [...endpoints.values()].sort((left, right) => right.events - left.events); const named = ordered.filter((endpoint) => endpoint.ptr.length); document.querySelector('#ip-count').textContent = ordered.length; document.querySelector('#ptr-count').textContent = named.reduce((sum, endpoint) => sum + endpoint.ptr.length, 0); document.querySelector('#named-count').textContent = named.length; document.querySelector('#dns-tag').textContent = `${ordered.length} IPS`; document.querySelector('#dns-list').innerHTML = ordered.slice(0, 50).map((endpoint) => `<div class="application-row"><div class="application-header"><div><strong>${escapeHtml(endpoint.ip)}</strong><span class="application-protocol">${endpoint.ptr.length ? 'PTR' : 'NO PTR'}</span></div><b>${endpoint.events}</b></div><div class="application-meta"><span>${escapeHtml(endpoint.ptr.join(', ')) || 'No reverse-DNS record'}</span><span>observed endpoint</span></div></div>`).join('') || '<p class="empty">Waiting for public IPs...</p>'; }
function lookup(ip) { if (endpoints.has(ip)) { endpoints.get(ip).events += 1; return; } const endpoint = { ip, ptr: [], events: 1 }; endpoints.set(ip, endpoint); fetch(`/api/dns?ip=${encodeURIComponent(ip)}`).then((response) => response.json()).then((result) => { endpoint.ptr = result.ptr || []; scheduleRender(); }).catch(() => scheduleRender()); }
async function hydrateHistory() {
  try {
    const res = await fetch('/api/history?limit=500');
    if (!res.ok) return;
    const packets = await res.json();
    for (const packet of packets) {
      if (publicIp(packet.source)) lookup(packet.source);
      if (publicIp(packet.destination)) lookup(packet.destination);
    }
  } catch (err) {
    console.error('Failed to fetch packet history:', err);
  }
}

const stream = new EventSource('/api/stream');
stream.addEventListener('status', (event) => setStatus(JSON.parse(event.data).running));
stream.addEventListener('packet', (event) => { const packet = JSON.parse(event.data); if (publicIp(packet.source)) lookup(packet.source); if (publicIp(packet.destination)) lookup(packet.destination); setStatus(true); scheduleRender(); });
stream.onerror = () => setStatus(false);

render();
hydrateHistory();