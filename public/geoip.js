const addresses = new Map();
const locations = new Map();
let renderQueued = false;
let eventCount = 0;

function scheduleRender() { if (renderQueued) return; renderQueued = true; window.setTimeout(() => { renderQueued = false; render(); }, 200); }
function render() {
  const ordered = [...locations.values()].sort((left, right) => right.count - left.count);
  const countries = new Set(ordered.map((location) => location.country));
  const maximum = ordered[0]?.count || 1;
  document.querySelector('#known-count').textContent = addresses.size;
  document.querySelector('#country-count').textContent = countries.size;
  document.querySelector('#top-country').textContent = ordered[0]?.country || '--';
  document.querySelector('#top-country-count').textContent = ordered[0] ? `${ordered[0].count} endpoints` : 'waiting for data';
  document.querySelector('#location-tag').textContent = `${ordered.length} LOCATIONS`;
  document.querySelector('#location-list').innerHTML = ordered.slice(0, 30).map((location) => `<div class="application-row"><div class="application-header"><div><strong>${location.city}, ${location.country}</strong><span class="application-protocol">${location.count} IPs</span></div><b>${location.events.toLocaleString()}</b></div><div class="bar"><span style="width:${location.events / maximum * 100}%"></span></div><div class="application-meta"><span>${location.events.toLocaleString()} observed events</span><span>${location.latitude ?? '--'}, ${location.longitude ?? '--'}</span></div></div>`).join('') || '<p class="empty">Waiting for MMDB results...</p>';
}
function lookup(ip) { if (addresses.has(ip)) return; addresses.set(ip, null); fetch(`/api/geoip?ip=${encodeURIComponent(ip)}`).then((response) => response.json()).then((result) => { if (result.error) { document.querySelector('#database-state').textContent = 'MISSING'; document.querySelector('#database-path').textContent = result.database || 'Set GEOIP_MMDB'; return; } document.querySelector('#database-state').textContent = 'READY'; document.querySelector('#database-path').textContent = result.database; const value = result.location; addresses.set(ip, value); if (!value) return; const key = `${value.city}|${value.country}`; const location = locations.get(key) || { ...value, count: 0, events: 0 }; location.count += 1; location.events += 1; locations.set(key, location); scheduleRender(); }).catch(() => { document.querySelector('#database-state').textContent = 'ERROR'; }); }
async function hydrateHistory() {
  try {
    const res = await fetch('/api/history?limit=500');
    if (!res.ok) return;
    const packets = await res.json();
    for (const packet of packets) {
      eventCount += 1;
      lookup(packet.source);
      lookup(packet.destination);
    }
  } catch (err) {
    console.error('Failed to fetch packet history:', err);
  }
}

const stream = new EventSource('/api/stream');
stream.addEventListener('status', (event) => setCaptureStatus(JSON.parse(event.data)));
stream.addEventListener('packet', (event) => { const packet = JSON.parse(event.data); eventCount += 1; lookup(packet.source); lookup(packet.destination); });
stream.onerror = () => setCaptureStatus('offline');

render();
hydrateHistory();