(function () {
    const matrixGrid = document.getElementById('mitre-matrix-grid');
    const huntingTableBody = document.querySelector('#hunting-table tbody');

    const metricTotalDetections = document.getElementById('metric-total-detections');
    const metricTacticsCovered = document.getElementById('metric-tactics-covered');
    const metricTopTechnique = document.getElementById('metric-top-technique');
    const metricTopCount = document.getElementById('metric-top-count');
    const metricHuntingLeads = document.getElementById('metric-hunting-leads');


    // Drawer Elements
    const drawer = document.getElementById('technique-drawer');
    const drawerCloseBtn = document.getElementById('drawer-close-btn');
    const drawerTechId = document.getElementById('drawer-tech-id');
    const drawerTechName = document.getElementById('drawer-tech-name');
    const drawerTacticTag = document.getElementById('drawer-tactic-tag');
    const drawerDescription = document.getElementById('drawer-description');
    const drawerLogic = document.getElementById('drawer-logic');
    const drawerHosts = document.getElementById('drawer-hosts');
    const drawerEventsTableBody = document.querySelector('#drawer-events-table tbody');
    const drawerMitigations = document.getElementById('drawer-mitigations');

    let loadedTactics = [];

    function formatDate(isoStr) {
        if (!isoStr) return '—';
        const d = new Date(isoStr);
        return isNaN(d.getTime()) ? isoStr : d.toLocaleDateString() + ' ' + d.toLocaleTimeString([], { hour12: false, hour: '2-digit', minute: '2-digit' });
    }

    function escapeHtml(str) {
        if (!str) return '';
        return String(str)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;');
    }

    // Drawer Controls
    function openDrawer() {
        if (drawer) drawer.style.display = 'flex';
    }

    function closeDrawer() {
        if (drawer) drawer.style.display = 'none';
    }

    if (drawerCloseBtn) drawerCloseBtn.addEventListener('click', closeDrawer);
    if (drawer) {
        drawer.addEventListener('click', (e) => {
            if (e.target === drawer) closeDrawer();
        });
    }

    // Fetch Technique Details & Open Drawer
    async function inspectTechnique(techId) {
        try {
            const res = await fetch(`/api/mitre/techniques/${techId}`);
            if (!res.ok) return;
            const data = await res.json();

            drawerTechId.textContent = data.id;
            drawerTechName.textContent = data.name;
            drawerTacticTag.textContent = data.tactic_name;
            drawerDescription.textContent = data.description || 'No description available.';
            drawerLogic.textContent = data.detection_logic || 'No detection logic specified.';

            // Render Hosts
            if (data.affected_hosts && data.affected_hosts.length > 0) {
                drawerHosts.innerHTML = data.affected_hosts.map(ip => `
                    <a class="host-pill" href="/forensics.html?q=${encodeURIComponent('ip:' + ip)}">${escapeHtml(ip)}</a>
                `).join('');
            } else {
                drawerHosts.innerHTML = '<span class="no-hosts">No host IPs recorded</span>';
            }

            // Render Events Timeline
            if (data.events && data.events.length > 0) {
                drawerEventsTableBody.innerHTML = data.events.map(ev => `
                    <tr>
                        <td style="font-family:'DM Mono',monospace;font-size:11px;color:var(--muted);">${formatDate(ev.time)}</td>
                        <td><a href="/forensics.html?q=${encodeURIComponent('src:' + ev.src)}" class="ip-link">${escapeHtml(ev.src)}</a></td>
                        <td><a href="/forensics.html?q=${encodeURIComponent('dst:' + ev.dst)}" class="ip-link">${escapeHtml(ev.dst)}</a></td>
                        <td style="font-size:12px;">${escapeHtml(ev.desc)}</td>
                        <td><span class="severity-${ev.severity || 'low'}">${ev.severity || 'low'}</span></td>
                    </tr>
                `).join('');
            } else {
                drawerEventsTableBody.innerHTML = '<tr><td colspan="5" class="empty-cell">No event timeline recorded</td></tr>';
            }

            // Render Mitigations
            if (data.mitigations && data.mitigations.length > 0) {
                drawerMitigations.innerHTML = data.mitigations.map(m => `
                    <li>${escapeHtml(m)}</li>
                `).join('');
            } else {
                drawerMitigations.innerHTML = '<li>No mitigation guidance specified</li>';
            }

            openDrawer();
        } catch (err) {
            console.error('Failed to load technique details:', err);
        }
    }

    // Fetch & Render Matrix
    async function fetchMatrix() {
        try {
            const res = await fetch('/api/mitre/matrix');
            const data = await res.json();
            loadedTactics = data.tactics || [];
            renderMatrix();
        } catch (err) {
            console.error('Failed to load MITRE matrix:', err);
        }
    }

    function renderMatrix() {
        if (!matrixGrid) return;
        if (loadedTactics.length === 0) {
            matrixGrid.innerHTML = '<div class="empty-cell" style="padding:40px;">No ATT&CK matrix tactics available</div>';
            return;
        }

        matrixGrid.innerHTML = loadedTactics.map(tac => {
            const techCards = (tac.techniques || []).map(tech => {
                let heatClass = 'mitre-zero';
                if (tech.count > 0) {
                    if (tech.severity === 'critical') heatClass = 'mitre-crit';
                    else if (tech.severity === 'high') heatClass = 'mitre-high';
                    else if (tech.severity === 'medium') heatClass = 'mitre-med';
                    else heatClass = 'mitre-low';
                }

                return `
                    <div class="mitre-card ${heatClass}" data-id="${tech.id}">
                        <div class="card-header">
                            <span class="tech-id">${tech.id}</span>
                            <span class="tech-count">${tech.count}</span>
                        </div>
                        <div class="tech-name">${escapeHtml(tech.name)}</div>
                        ${tech.affected_hosts && tech.affected_hosts.length > 0 ? `
                            <div class="tech-hosts-count">${tech.affected_hosts.length} hosts</div>
                        ` : ''}
                    </div>
                `;
            }).join('');

            return `
                <div class="mitre-column">
                    <div class="tactic-header">
                        <span class="tactic-id">${tac.id}</span>
                        <span class="tactic-title">${escapeHtml(tac.name)}</span>
                    </div>
                    <div class="cards-list">
                        ${techCards}
                    </div>
                </div>
            `;
        }).join('');

        // Attach Card Click Handlers
        matrixGrid.querySelectorAll('.mitre-card').forEach(card => {
            card.addEventListener('click', () => {
                const id = card.getAttribute('data-id');
                if (id) inspectTechnique(id);
            });
        });
    }

    // Fetch Stats & Hunting Leads
    async function fetchStats() {
        try {
            const res = await fetch('/api/mitre/stats');
            const data = await res.json();

            if (metricTotalDetections) metricTotalDetections.textContent = data.total_detections || 0;
            if (metricTacticsCovered) metricTacticsCovered.textContent = `${data.tactics_covered || 0} / ${data.total_tactics || 7}`;
            if (metricTopTechnique) metricTopTechnique.textContent = data.top_technique?.id ? `${data.top_technique.id} — ${data.top_technique.name}` : '—';
            if (metricTopCount) metricTopCount.textContent = `${data.top_technique?.count || 0} occurrences`;
            if (metricHuntingLeads) metricHuntingLeads.textContent = data.hunting_leads?.length || 0;

            // Render Hunting Leads Table
            if (huntingTableBody && data.hunting_leads) {
                huntingTableBody.innerHTML = data.hunting_leads.map(lead => `
                    <tr>
                        <td><strong style="color:var(--ink);">${escapeHtml(lead.title)}</strong></td>
                        <td><code class="code-sm">${escapeHtml(lead.query)}</code></td>
                        <td style="font-size:12px;color:var(--muted);">${escapeHtml(lead.recommendation)}</td>
                        <td style="text-align:right;">
                            <a class="btn-hunt" href="/forensics.html?q=${encodeURIComponent(lead.query)}">Launch Search</a>
                        </td>
                    </tr>
                `).join('');
            }
        } catch (err) {
            console.error('Failed to load MITRE stats:', err);
        }
    }

    // Connect SSE Stream
    function initSSE() {
        const evSource = new EventSource('/api/stream');

        evSource.addEventListener('status', (e) => {
            try { setCaptureStatus(JSON.parse(e.data)); } catch (err) {}
        });

        // Trigger matrix refresh when new security events arrive
        let refreshTimer;
        function scheduleRefresh() {
            clearTimeout(refreshTimer);
            refreshTimer = setTimeout(() => {
                fetchMatrix();
                fetchStats();
            }, 1000);
        }

        evSource.addEventListener('threat', scheduleRefresh);
        evSource.addEventListener('ddos_alert', scheduleRefresh);
        evSource.addEventListener('ueba_anomaly', scheduleRefresh);
        evSource.addEventListener('vpn_detection', scheduleRefresh);

        evSource.onerror = () => setCaptureStatus('offline');
    }

    // Init Page
    fetchMatrix();
    fetchStats();
    initSSE();
})();
