const ips = new Set();
const networks = new Map();
let renderQueued = false;
function publicIp(ip) { const parts = ip.split('.').map(Number); return parts.length === 4 && parts.every((part) => part >= 0 && part <= 255) && !(parts[0] === 10 || parts[0] === 127 || parts[0] === 192 && parts[1] === 168 || parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31); }
function scheduleRender() { if (renderQueued) return; renderQueued = true; window.setTimeout(() => { renderQueued = false; render(); }, 200); }
function escapeHtml(value) { return String(value).replace(/[&<>"']/g, (character) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[character]); }
function render() { const openAsns = new Set([...document.querySelectorAll('.asn-details[open]')].map((details) => details.closest('.application-row')?.dataset.asn)); const ordered = [...networks.values()].sort((left, right) => right.events - left.events); const maximum = ordered[0]?.events || 1; document.querySelector('#ip-count').textContent = ips.size; document.querySelector('#asn-count').textContent = ordered.length; document.querySelector('#asn-tag').textContent = `${ordered.length} ASNS`; document.querySelector('#top-asn').textContent = ordered[0]?.asn || '--'; document.querySelector('#top-asn-holder').textContent = ordered[0]?.holder || 'waiting for data'; if (openAsns.size) return; document.querySelector('#asn-list').innerHTML = ordered.slice(0, 50).map((network) => `<div class="application-row" data-asn="${escapeHtml(network.asn)}"><div class="application-header"><div><strong>AS${escapeHtml(network.asn)}</strong><span class="application-protocol">${escapeHtml(network.prefix || 'prefix unknown')}</span></div><b>${network.events}</b></div><div class="bar"><span style="width:${network.events / maximum * 100}%"></span></div><div class="application-meta"><span>${escapeHtml(network.holder || 'Unknown holder')} | ${network.ips} IPs</span><details class="asn-details"><summary>Details</summary><pre>${escapeHtml(JSON.stringify(network.data, null, 2))}</pre></details></div></div>`).join('') || '<p class="empty">Waiting for public IPs...</p>'; }
function lookup(ip) { if (ips.has(ip)) return; ips.add(ip); fetch(`/api/asn?ip=${encodeURIComponent(ip)}`).then((response) => response.json()).then((result) => { const data = result.data; if (!data || !data.asns?.length) return; data.asns.forEach((entry) => { const asnValue = typeof entry === 'object' ? entry.asn : entry; const holder = typeof entry === 'object' && entry.holder ? entry.holder : (data.holder || 'Unknown holder'); const prefix = data.resource || data.prefix || ''; const key = String(asnValue); const network = networks.get(key) || { asn: key, holder, prefix, ips: 0, events: 0, data }; network.ips += 1; network.events += 1; network.holder = holder; network.prefix = prefix; network.data = { ...data, asn: entry }; networks.set(key, network); }); scheduleRender(); }).catch(() => scheduleRender()); }
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
stream.addEventListener('status', (event) => setCaptureStatus(JSON.parse(event.data)));
stream.addEventListener('packet', (event) => { const packet = JSON.parse(event.data); if (publicIp(packet.source)) lookup(packet.source); if (publicIp(packet.destination)) lookup(packet.destination); scheduleRender(); });
stream.onerror = () => setCaptureStatus('offline');
document.addEventListener('toggle', (event) => { if (event.target instanceof HTMLDetailsElement) scheduleRender(); }, true);

render();
hydrateHistory();