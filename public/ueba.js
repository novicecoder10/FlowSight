(() => {
    let anomaliesList = [];
    let currentFilter = 'all';
    let entitiesData = [];
    let statsData = { total_anomalies: 0, by_type: [], by_severity: [], top_risky_host: null };

    const tableBody = document.querySelector('#ueba-log-table tbody');
    const entitiesBox = document.getElementById('ueba-entities-list');
    const metricTotal = document.getElementById('metric-total-anomalies');
    const metricTopEntity = document.getElementById('metric-top-entity');
    const metricTopScore = document.getElementById('metric-top-score');
    const metricScanCount = document.getElementById('metric-scan-count');
    const metricC2Count = document.getElementById('metric-c2-count');
    const distChartCanvas = document.getElementById('ueba-dist-chart');
    const filterButtons = document.querySelectorAll('.type-filter-buttons .filter-btn');

    // ── Helper Functions ──
    function formatTime(isoStr) {
        if (!isoStr) return '—';
        const d = new Date(isoStr);
        return isNaN(d.getTime()) ? isoStr : d.toLocaleTimeString([], { hour12: false });
    }

    function formatTypeName(type) {
        switch (type) {
            case 'port_scan': return 'Port Scan';
            case 'bandwidth_spike': return 'Bandwidth Spike';
            case 'c2_beacon': return 'C2 Beacon';
            case 'port_mismatch': return 'Port Mismatch';
            default: return type.replace('_', ' ').toUpperCase();
        }
    }

    function getSeverityClass(sev) {
        const s = (sev || 'low').toLowerCase();
        if (s === 'critical') return 'severity-critical';
        if (s === 'high') return 'severity-high';
        if (s === 'medium') return 'severity-medium';
        return 'severity-low';
    }

    function getScoreBadgeClass(score) {
        if (score >= 80) return 'score-critical';
        if (score >= 60) return 'score-high';
        if (score >= 40) return 'score-medium';
        return 'score-low';
    }

    // ── Filter Handlers ──
    filterButtons.forEach((btn) => {
        btn.addEventListener('click', () => {
            filterButtons.forEach((b) => b.classList.remove('active'));
            btn.classList.add('active');
            currentFilter = btn.getAttribute('data-type') || 'all';
            renderTable();
        });
    });

    // ── Table Renderer ──
    function renderTable() {
        if (!tableBody) return;
        const filtered = currentFilter === 'all'
            ? anomaliesList
            : anomaliesList.filter((a) => a.anomaly_type === currentFilter);

        if (filtered.length === 0) {
            tableBody.innerHTML = `<tr><td colspan="7" class="empty-state">No ${currentFilter === 'all' ? '' : formatTypeName(currentFilter)} anomalies detected</td></tr>`;
            return;
        }

        const html = filtered.slice(0, 100).map((a) => {
            const timeStr = formatTime(a.observed_at);
            const sevClass = getSeverityClass(a.severity);
            const typeName = formatTypeName(a.anomaly_type);
            const scoreClass = getScoreBadgeClass(a.risk_score);

            return `<tr class="ueba-row-${a.severity || 'low'}">
                <td>${timeStr}</td>
                <td><span class="${sevClass}">${(a.severity || 'LOW').toUpperCase()}</span></td>
                <td><span class="ueba-type-tag type-${a.anomaly_type}">${typeName}</span></td>
                <td><a href="/forensics.html?q=${encodeURIComponent('src_ip="' + a.source_ip + '"')}" class="ip-link">${a.source_ip}</a></td>
                <td>${a.destination_ip ? `<a href="/forensics.html?q=${encodeURIComponent('dst_ip="' + a.destination_ip + '"')}" class="ip-link">${a.destination_ip}</a>` : '—'}</td>
                <td><span class="risk-score-pill ${scoreClass}">${a.risk_score}/100</span></td>
                <td class="details-cell">${a.details || ''}</td>
            </tr>`;
        }).join('');

        tableBody.innerHTML = html;
    }

    // ── Entities Scoreboard Renderer ──
    function renderEntities() {
        if (!entitiesBox) return;
        if (!entitiesData || entitiesData.length === 0) {
            entitiesBox.innerHTML = '<p class="empty-state">No anomalous entities detected</p>';
            return;
        }

        const html = entitiesData.slice(0, 8).map((e) => {
            const scoreClass = getScoreBadgeClass(e.risk_score);
            const barWidth = Math.min(100, Math.max(8, e.risk_score));
            const primaryType = formatTypeName(e.primary_type);

            return `<div class="entity-card">
                <div class="entity-header">
                    <a href="/forensics.html?q=${encodeURIComponent('src_ip="' + e.ip + '"')}" class="entity-ip">${e.ip}</a>
                    <span class="risk-score-pill ${scoreClass}">${e.risk_score} pts</span>
                </div>
                <div class="entity-meta">
                    <span class="entity-type-badge">${primaryType}</span>
                    <span class="entity-count">${e.anomaly_count} anomaly event${e.anomaly_count > 1 ? 's' : ''}</span>
                </div>
                <div class="risk-bar-track">
                    <div class="risk-bar-fill ${scoreClass}" style="width: ${barWidth}%"></div>
                </div>
            </div>`;
        }).join('');

        entitiesBox.innerHTML = html;
    }

    // ── Metrics Bar Updater ──
    function updateMetrics() {
        if (metricTotal) metricTotal.textContent = anomaliesList.length;

        const scanEvents = anomaliesList.filter((a) => a.anomaly_type === 'port_scan');
        const c2Events = anomaliesList.filter((a) => a.anomaly_type === 'c2_beacon');

        if (metricScanCount) metricScanCount.textContent = scanEvents.length;
        if (metricC2Count) metricC2Count.textContent = c2Events.length;

        if (entitiesData && entitiesData.length > 0) {
            const top = entitiesData[0];
            if (metricTopEntity) metricTopEntity.textContent = top.ip;
            if (metricTopScore) metricTopScore.textContent = `Risk Score: ${top.risk_score}/100 (${top.anomaly_count} events)`;
        }
    }

    // ── Canvas Anomaly Distribution Chart ──
    function renderDistributionChart() {
        if (!distChartCanvas) return;
        const ctx = distChartCanvas.getContext('2d');
        if (!ctx) return;

        const rect = distChartCanvas.getBoundingClientRect();
        const width = rect.width || 320;
        const height = 200;
        const dpr = window.devicePixelRatio || 1;

        distChartCanvas.width = width * dpr;
        distChartCanvas.height = height * dpr;
        ctx.scale(dpr, dpr);

        ctx.clearRect(0, 0, width, height);

        // Compute counts per type
        const counts = {
            'Port Scan': 0,
            'Bandwidth Spike': 0,
            'C2 Beacon': 0,
            'Port Mismatch': 0,
        };

        anomaliesList.forEach((a) => {
            const label = formatTypeName(a.anomaly_type);
            counts[label] = (counts[label] || 0) + 1;
        });

        const labels = Object.keys(counts);
        const values = Object.values(counts);
        const maxValue = Math.max(...values, 5);

        const isDark = document.documentElement.getAttribute('data-theme') === 'dark';
        const labelColor = isDark ? '#94a3b8' : '#64748b';
        const gridColor = isDark ? 'rgba(255,255,255,0.06)' : 'rgba(0,0,0,0.06)';

        const barColors = ['#ff9500', '#00e5a3', '#ff3b30', '#af52de'];

        const paddingLeft = 110;
        const paddingRight = 40;
        const paddingTop = 15;
        const paddingBottom = 20;
        const chartWidth = width - paddingLeft - paddingRight;
        const barHeight = 24;
        const gap = 16;

        labels.forEach((label, i) => {
            const val = values[i];
            const y = paddingTop + i * (barHeight + gap);
            const barW = Math.max(4, (val / maxValue) * chartWidth);

            // Draw label
            ctx.font = '500 11px "DM Mono", monospace';
            ctx.fillStyle = labelColor;
            ctx.textAlign = 'right';
            ctx.textBaseline = 'middle';
            ctx.fillText(label, paddingLeft - 10, y + barHeight / 2);

            // Draw background track
            ctx.fillStyle = gridColor;
            ctx.fillRect(paddingLeft, y, chartWidth, barHeight);

            // Draw bar
            ctx.fillStyle = barColors[i % barColors.length];
            ctx.beginPath();
            ctx.roundRect(paddingLeft, y, barW, barHeight, 3);
            ctx.fill();

            // Draw value label
            ctx.font = '600 11px "DM Mono", monospace';
            ctx.fillStyle = labelColor;
            ctx.textAlign = 'left';
            ctx.fillText(val.toString(), paddingLeft + barW + 8, y + barHeight / 2);
        });
    }

    // ── Fetch Initial History & Entities ──
    async function loadData() {
        try {
            const [resAnomalies, resEntities] = await Promise.all([
                fetch('/api/ueba/anomalies?limit=100'),
                fetch('/api/ueba/entities'),
            ]);

            if (resAnomalies.ok) {
                const data = await resAnomalies.json();
                anomaliesList = data.anomalies || [];
                renderTable();
            }

            if (resEntities.ok) {
                const data = await resEntities.json();
                entitiesData = data.entities || [];
                renderEntities();
            }

            updateMetrics();
            renderDistributionChart();
        } catch (e) {
            console.error('Error loading UEBA data:', e);
        }
    }

    // ── SSE Real-Time Event Stream Listener ──
    function connectSSE() {
        const statusDot = document.getElementById('status-dot');
        const liveLabel = document.getElementById('live-label');

        const es = new EventSource('/api/stream');

        es.onopen = () => {
            if (statusDot) statusDot.className = 'status-dot online';
            if (liveLabel) liveLabel.textContent = 'LIVE STREAM';
        };

        es.onerror = () => {
            if (statusDot) statusDot.className = 'status-dot offline';
            if (liveLabel) liveLabel.textContent = 'OFFLINE';
        };

        es.addEventListener('ueba_anomaly', (evt) => {
            try {
                const anomaly = JSON.parse(evt.data);
                anomaliesList.unshift(anomaly);
                if (anomaliesList.length > 300) anomaliesList.pop();

                renderTable();
                updateMetrics();
                renderDistributionChart();
            } catch (err) {
                console.error('Failed to parse ueba_anomaly SSE event:', err);
            }
        });
    }

    // Initialize
    document.addEventListener('DOMContentLoaded', () => {
        loadData();
        connectSSE();
        setInterval(loadData, 10000);
        window.addEventListener('resize', renderDistributionChart);
    });
})();
