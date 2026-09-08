document.addEventListener('DOMContentLoaded', () => {
  const stream = new EventSource('/api/stream');

  const statusDot = document.getElementById('status-dot');
  const liveLabel = document.getElementById('live-label');
  const metricStatus = document.getElementById('metric-status');
  const valNormalPps = document.getElementById('val-normal-pps');
  const valNormalBps = document.getElementById('val-normal-bps');
  const valDdosPps = document.getElementById('val-ddos-pps');
  const valDdosBps = document.getElementById('val-ddos-bps');
  const valActiveTargets = document.getElementById('val-active-targets');
  const metricStatusCard = document.getElementById('metric-status-card');

  const eventsTable = document.getElementById('ddos-events-table');
  const sourcesTable = document.getElementById('ddos-sources-table');
  const targetsTable = document.getElementById('ddos-targets-table');

  const canvas = document.getElementById('ddos-chart');
  const ctx = canvas ? canvas.getContext('2d') : null;

  const maxPoints = 120;
  let currentUnit = 'pps'; // 'pps' or 'bps'

  // Pre-fill initial 30 zero points so graph always renders grid and baseline
  const now = Date.now();
  let chartData = Array.from({ length: 30 }, (_, i) => ({
    timestamp: new Date(now - (30 - i) * 1000).toISOString(),
    normal_pps: 0,
    ddos_pps: 0,
    normal_bps: 0,
    ddos_bps: 0,
    active_attacks: 0
  }));

  // Toggle buttons
  const toggleBtns = document.querySelectorAll('.btn-toggle');
  toggleBtns.forEach(btn => {
    btn.addEventListener('click', (e) => {
      toggleBtns.forEach(b => b.classList.remove('active'));
      e.target.classList.add('active');
      currentUnit = e.target.dataset.unit;
      drawChart();
    });
  });

  function resizeCanvas() {
    if (!canvas) return;
    const parent = canvas.parentElement;
    canvas.width = Math.max(parent.clientWidth - 48, 300);
    canvas.height = 280;
    drawChart();
  }
  window.addEventListener('resize', resizeCanvas);
  setTimeout(resizeCanvas, 50);

  function formatBits(bps) {
    if (!bps || bps === 0) return '0 Mbps';
    const mbps = bps / 1000000;
    if (mbps >= 1000) return (mbps / 1000).toFixed(2) + ' Gbps';
    return mbps.toFixed(2) + ' Mbps';
  }

  function formatYAxis(value) {
    if (value === 0) return '0';
    if (currentUnit === 'bps') {
      const mbps = value / 1000000;
      if (mbps >= 1000) return (mbps / 1000).toFixed(1) + 'G';
      return mbps.toFixed(1) + 'M';
    } else {
      if (value >= 1000000) return (value / 1000000).toFixed(1) + 'M';
      if (value >= 1000) return (value / 1000).toFixed(1) + 'K';
      return Math.round(value).toString();
    }
  }

  stream.addEventListener('status', e => {
    try {
      const data = JSON.parse(e.data);
      if (statusDot) {
        statusDot.className = data.running ? 'status-dot connected' : 'status-dot';
      }
      if (liveLabel) {
        liveLabel.textContent = data.running ? 'Live' : (data.error ? 'Error' : 'Connecting');
      }
    } catch (err) {}
  });

  stream.addEventListener('ddos_metrics', e => {
    try {
      const data = JSON.parse(e.data);

      if (valNormalPps) valNormalPps.textContent = `${(data.normal_pps || 0).toLocaleString()} pps`;
      if (valNormalBps) valNormalBps.textContent = formatBits(data.normal_bps);

      if (valDdosPps) valDdosPps.textContent = `${(data.ddos_pps || 0).toLocaleString()} pps`;
      if (valDdosBps) valDdosBps.textContent = formatBits(data.ddos_bps);

      if (valActiveTargets) valActiveTargets.textContent = data.active_attacks || 0;

      if (metricStatus) {
        if (data.active_attacks > 0) {
          metricStatus.textContent = 'UNDER ATTACK';
          metricStatus.className = 'status-under-attack';
        } else {
          metricStatus.textContent = 'NORMAL';
          metricStatus.className = 'status-normal';
        }
      }

      chartData.push({
        timestamp: data.timestamp || new Date().toISOString(),
        normal_pps: data.normal_pps || 0,
        ddos_pps: data.ddos_pps || 0,
        normal_bps: data.normal_bps || 0,
        ddos_bps: data.ddos_bps || 0,
        active_attacks: data.active_attacks || 0
      });

      if (chartData.length > maxPoints) {
        chartData.shift();
      }

      drawChart();
    } catch (err) {}
  });

  stream.addEventListener('ddos_alert', e => {
    try {
      const data = JSON.parse(e.data);

      if (metricStatusCard) {
        metricStatusCard.classList.add('pulse');
        setTimeout(() => metricStatusCard.classList.remove('pulse'), 2000);
      }

      const tr = document.createElement('tr');
      const time = new Date(data.started_at || data.timestamp || Date.now()).toLocaleTimeString();
      tr.innerHTML = `
        <td>${data.target_ip || data.target}</td>
        <td><span class="ddos-vector-tag">${data.attack_type || data.vector}</span></td>
        <td>${(data.peak_pps || 0).toLocaleString()}</td>
        <td>${formatBits(data.peak_bps || 0)}</td>
        <td>${data.unique_sources || data.sources || 0}</td>
        <td>${time}</td>
        <td class="${data.status === 'ACTIVE' || data.status === 'ONGOING' ? 'status-under-attack' : ''}">${data.status}</td>
      `;

      if (eventsTable && eventsTable.querySelector('.empty')) {
        eventsTable.innerHTML = '';
      }
      if (eventsTable) {
        eventsTable.prepend(tr);
        if (eventsTable.children.length > 50) {
          eventsTable.removeChild(eventsTable.lastChild);
        }
      }
    } catch (err) {}
  });

  // Load history
  fetch('/api/ddos/history?limit=120')
    .then(res => res.json())
    .then(data => {
      if (data && Array.isArray(data.history) && data.history.length > 0) {
        chartData = data.history.slice(-maxPoints);
      }
      drawChart();
    }).catch(() => {
      drawChart();
    });

  // Load events
  fetch('/api/ddos/events')
    .then(res => res.json())
    .then(data => {
      const events = data.events || [];
      if (eventsTable && Array.isArray(events) && events.length > 0) {
        eventsTable.innerHTML = events.map(ev => `
          <tr>
            <td>${ev.target_ip || ev.target}</td>
            <td><span class="ddos-vector-tag">${ev.attack_type || ev.vector}</span></td>
            <td>${(ev.peak_pps || 0).toLocaleString()}</td>
            <td>${formatBits(ev.peak_bps || 0)}</td>
            <td>${ev.unique_sources || ev.sources || 0}</td>
            <td>${new Date(ev.started_at || ev.timestamp).toLocaleTimeString()}</td>
            <td class="${ev.status === 'ACTIVE' || ev.status === 'ONGOING' ? 'status-under-attack' : ''}">${ev.status}</td>
          </tr>
        `).join('');
      }
    }).catch(() => {});

  // Load stats periodically
  function loadStats() {
    fetch('/api/ddos/stats')
      .then(res => res.json())
      .then(data => {
        const attackers = data.top_attackers || [];
        if (sourcesTable) {
          if (Array.isArray(attackers) && attackers.length > 0) {
            sourcesTable.innerHTML = attackers.map(s => `
              <tr>
                <td>${s.ip}</td>
                <td>${(s.packets || 0).toLocaleString()}</td>
                <td>${formatBits(s.bytes ? s.bytes * 8 : 0)}</td>
                <td>${s.country || 'Unknown'}</td>
              </tr>
            `).join('');
          } else {
            sourcesTable.innerHTML = '<tr><td colspan="4" class="empty">No active attack sources</td></tr>';
          }
        }

        const targets = data.top_targets || [];
        if (targetsTable) {
          if (Array.isArray(targets) && targets.length > 0) {
            targetsTable.innerHTML = targets.map(t => `
              <tr>
                <td>${t.target_ip}</td>
                <td><span class="ddos-vector-tag">${t.vector}</span></td>
                <td>${(t.pps || 0).toLocaleString()} pps</td>
                <td>${formatBits(t.bytes ? t.bytes * 8 : 0)}</td>
              </tr>
            `).join('');
          } else {
            targetsTable.innerHTML = '<tr><td colspan="4" class="empty">No active attack targets</td></tr>';
          }
        }
      }).catch(() => {});
  }

  loadStats();
  setInterval(loadStats, 3000);

  function drawChart() {
    if (!ctx || !canvas || canvas.width === 0) return;

    ctx.clearRect(0, 0, canvas.width, canvas.height);

    const width = canvas.width;
    const height = canvas.height;
    const padding = { top: 25, right: 25, bottom: 35, left: 65 };
    const plotWidth = width - padding.left - padding.right;
    const plotHeight = height - padding.top - padding.bottom;

    const isDark = document.documentElement.getAttribute('data-theme') === 'dark';
    const colorGrid = isDark ? 'rgba(255,255,255,0.06)' : 'rgba(0,0,0,0.06)';
    const colorText = isDark ? '#7a9a80' : '#70807a';
    const colorNormal = '#00e5a3'; // teal
    const colorDdos = '#ff3b30'; // coral

    let maxVal = 0;
    chartData.forEach(d => {
      const val1 = currentUnit === 'pps' ? (d.normal_pps || 0) : (d.normal_bps || 0);
      const val2 = currentUnit === 'pps' ? (d.ddos_pps || 0) : (d.ddos_bps || 0);
      if (val1 > maxVal) maxVal = val1;
      if (val2 > maxVal) maxVal = val2;
    });

    maxVal = maxVal * 1.15;
    if (maxVal === 0) maxVal = currentUnit === 'pps' ? 100 : 1000000; // default 100 pps or 1 Mbps scale

    // Y Axis & Grid lines
    ctx.beginPath();
    ctx.strokeStyle = colorGrid;
    ctx.lineWidth = 1;
    ctx.fillStyle = colorText;
    ctx.font = "11px 'DM Mono', monospace";
    ctx.textAlign = "right";
    ctx.textBaseline = "middle";

    const ySteps = 4;
    for (let i = 0; i <= ySteps; i++) {
      const y = padding.top + plotHeight - (i / ySteps) * plotHeight;
      const val = (i / ySteps) * maxVal;

      ctx.moveTo(padding.left, y);
      ctx.lineTo(width - padding.right, y);
      ctx.fillText(formatYAxis(val), padding.left - 10, y);
    }
    ctx.stroke();

    // X Axis Labels
    ctx.textAlign = "center";
    ctx.textBaseline = "top";
    ctx.fillText("-2m", padding.left, height - padding.bottom + 10);
    ctx.fillText("-1m", padding.left + plotWidth / 2, height - padding.bottom + 10);
    ctx.fillText("Now", width - padding.right, height - padding.bottom + 10);

    if (chartData.length < 2) return;

    // Helper to draw series
    const drawSeries = (key, color) => {
      ctx.beginPath();
      ctx.strokeStyle = color;
      ctx.lineWidth = 2;

      const total = chartData.length;
      chartData.forEach((d, i) => {
        const x = padding.left + (i / (total - 1)) * plotWidth;
        const rawVal = currentUnit === 'pps' ? (d[key] || 0) : (d[key.replace('pps', 'bps')] || 0);
        const y = padding.top + plotHeight - (rawVal / maxVal) * plotHeight;

        if (i === 0) ctx.moveTo(x, y);
        else ctx.lineTo(x, y);
      });

      ctx.stroke();

      // Area Gradient
      ctx.lineTo(padding.left + plotWidth, padding.top + plotHeight);
      ctx.lineTo(padding.left, padding.top + plotHeight);
      ctx.closePath();

      const grad = ctx.createLinearGradient(0, padding.top, 0, height - padding.bottom);
      grad.addColorStop(0, color === colorNormal ? 'rgba(0,229,163,0.18)' : 'rgba(255,59,48,0.22)');
      grad.addColorStop(1, 'rgba(0,0,0,0.0)');
      ctx.fillStyle = grad;
      ctx.fill();
    };

    drawSeries('normal_pps', colorNormal);
    drawSeries('ddos_pps', colorDdos);
  }
});
