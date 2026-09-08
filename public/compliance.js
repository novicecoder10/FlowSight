(function () {
    let complianceData = null;
    let historyData = [];

    // DOM Elements
    const metricOverallScore = document.getElementById('metric-overall-score');
    const metricPassedSummary = document.getElementById('metric-passed-summary');
    const metricPciScore = document.getElementById('metric-pci-score');
    const metricIsoScore = document.getElementById('metric-iso-score');
    const metricNistScore = document.getElementById('metric-nist-score');

    const fwPciBadge = document.getElementById('fw-pci-badge');
    const fwPciBar = document.getElementById('fw-pci-bar');
    const fwIsoBadge = document.getElementById('fw-iso-badge');
    const fwIsoBar = document.getElementById('fw-iso-bar');
    const fwNistBadge = document.getElementById('fw-nist-badge');
    const fwNistBar = document.getElementById('fw-nist-bar');
    const fwCisBadge = document.getElementById('fw-cis-badge');
    const fwCisBar = document.getElementById('fw-cis-bar');

    const complianceTableBody = document.querySelector('#compliance-table tbody');
    const filterFramework = document.getElementById('filter-framework');
    const filterStatus = document.getElementById('filter-status');
    const complianceSearch = document.getElementById('compliance-search');

    const retentionForm = document.getElementById('retention-form');
    const retentionDaysSelect = document.getElementById('retention-days-select');
    const autoPurgeCheck = document.getElementById('auto-purge-check');
    const retentionMsg = document.getElementById('retention-msg');

    const btnExportHtml = document.getElementById('btn-export-html');
    const btnExportCsv = document.getElementById('btn-export-csv');

    // Drawer Elements
    const drawerBackdrop = document.getElementById('compliance-drawer');
    const drawerCloseBtn = document.getElementById('compliance-drawer-close');
    const drawerControlId = document.getElementById('drawer-control-id');
    const drawerControlTitle = document.getElementById('drawer-control-title');
    const drawerControlFramework = document.getElementById('drawer-control-framework');
    const drawerControlRef = document.getElementById('drawer-control-ref');
    const drawerControlDesc = document.getElementById('drawer-control-desc');
    const drawerControlEvidence = document.getElementById('drawer-control-evidence');
    const drawerControlRemediation = document.getElementById('drawer-control-remediation');

    // ── SSE Live Status Listener ──
    const statusDot = document.getElementById('status-dot');
    const liveLabel = document.getElementById('live-label');

    const evtSource = new EventSource('/api/stream');
    evtSource.addEventListener('status', (e) => {
        try {
            const data = JSON.parse(e.data);
            if (statusDot) statusDot.classList.add('active');
            if (liveLabel) liveLabel.textContent = `Live (${data.active_connections || 1} flows/s)`;
        } catch { }
    });
    evtSource.onerror = () => {
        if (statusDot) statusDot.classList.remove('active');
        if (liveLabel) liveLabel.textContent = 'Disconnected';
    };

    // ── Data Fetching ──
    async function loadComplianceStatus() {
        try {
            const res = await fetch('/api/compliance/status');
            if (!res.ok) return;
            complianceData = await res.json();
            renderMetrics();
            renderFrameworkCards();
            renderTable();
            updateRetentionForm();
        } catch (err) {
            console.error('Error fetching compliance status:', err);
        }
    }

    async function loadComplianceHistory() {
        try {
            const res = await fetch('/api/compliance/history?limit=30');
            if (!res.ok) return;
            historyData = await res.json();
            renderTrendChart();
        } catch (err) {
            console.error('Error fetching compliance history:', err);
        }
    }

    // ── Render Metrics Overview Bar ──
    function renderMetrics() {
        if (!complianceData) return;
        const score = complianceData.overall_score;
        metricOverallScore.textContent = `${score}%`;
        metricOverallScore.className = score >= 85 ? 'stat-green' : score >= 70 ? 'stat-yellow' : 'stat-coral';
        metricPassedSummary.textContent = `${complianceData.passed_controls} / ${complianceData.total_controls} Controls Passing`;

        metricPciScore.textContent = `${complianceData.pci_score}%`;
        metricIsoScore.textContent = `${complianceData.iso_score}%`;
        metricNistScore.textContent = `${complianceData.nist_score}%`;
    }

    // ── Render Framework Cards ──
    function renderFrameworkCards() {
        if (!complianceData) return;

        fwPciBadge.textContent = `${complianceData.pci_score}%`;
        fwPciBar.style.width = `${complianceData.pci_score}%`;

        fwIsoBadge.textContent = `${complianceData.iso_score}%`;
        fwIsoBar.style.width = `${complianceData.iso_score}%`;

        fwNistBadge.textContent = `${complianceData.nist_score}%`;
        fwNistBar.style.width = `${complianceData.nist_score}%`;

        fwCisBadge.textContent = `${complianceData.cis_score}%`;
        fwCisBar.style.width = `${complianceData.cis_score}%`;
    }

    // ── Render Control Audit Findings Table ──
    function renderTable() {
        if (!complianceData || !complianceData.controls) return;

        const fwFilter = filterFramework.value;
        const statusFilter = filterStatus.value;
        const q = complianceSearch.value.toLowerCase().trim();

        const filtered = complianceData.controls.filter(c => {
            if (fwFilter !== 'ALL' && !c.framework.includes(fwFilter)) return false;
            if (statusFilter !== 'ALL' && c.status !== statusFilter) return false;
            if (q) {
                const matchStr = `${c.id} ${c.framework} ${c.title} ${c.description} ${c.category}`.toLowerCase();
                if (!matchStr.includes(q)) return false;
            }
            return true;
        });

        if (filtered.length === 0) {
            complianceTableBody.innerHTML = `<tr><td colspan="8" class="empty-cell">No security controls match the selected filters.</td></tr>`;
            return;
        }

        complianceTableBody.innerHTML = filtered.map(c => {
            const statusClass = c.status === 'PASS' ? 'pill-pass' : c.status === 'WARNING' ? 'pill-warning' : 'pill-fail';
            return `
                <tr class="compliance-row" data-id="${c.id}" style="cursor:pointer;">
                    <td><strong class="code-tag">${c.id}</strong></td>
                    <td><span class="fw-tag">${c.framework}</span></td>
                    <td>
                        <strong>${escapeHtml(c.title)}</strong><br>
                        <small class="muted-text">${escapeHtml(c.requirement_ref)}</small>
                    </td>
                    <td><span class="cat-pill">${escapeHtml(c.category)}</span></td>
                    <td><span class="compliance-pill ${statusClass}">${c.status}</span></td>
                    <td><strong>${c.score}%</strong></td>
                    <td><small class="evidence-preview">${escapeHtml(c.evidence)}</small></td>
                    <td style="text-align:right;">
                        <button type="button" class="btn-inspect-control" data-id="${c.id}">View Audit</button>
                    </td>
                </tr>
            `;
        }).join('');

        // Attach click handlers to open drawer
        document.querySelectorAll('.compliance-row, .btn-inspect-control').forEach(el => {
            el.addEventListener('click', (e) => {
                e.stopPropagation();
                const controlId = el.getAttribute('data-id');
                if (controlId) openDrawer(controlId);
            });
        });
    }

    // ── Update Retention Form Fields ──
    function updateRetentionForm() {
        if (!complianceData) return;
        if (retentionDaysSelect) retentionDaysSelect.value = String(complianceData.retention_days);
        if (autoPurgeCheck) autoPurgeCheck.checked = Boolean(complianceData.auto_purge);
    }

    // ── Retention Form Submit Handler ──
    if (retentionForm) {
        retentionForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const retentionDays = parseInt(retentionDaysSelect.value, 10);
            const autoPurge = autoPurgeCheck.checked ? 1 : 0;

            try {
                const res = await fetch('/api/compliance/retention', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ retention_days: retentionDays, auto_purge: autoPurge }),
                });
                if (res.ok) {
                    retentionMsg.style.display = 'inline-block';
                    setTimeout(() => { retentionMsg.style.display = 'none'; }, 3000);
                    loadComplianceStatus();
                }
            } catch (err) {
                alert('Error saving retention settings: ' + err.message);
            }
        });
    }

    // ── Drawer Open/Close ──
    function openDrawer(id) {
        if (!complianceData || !complianceData.controls) return;
        const c = complianceData.controls.find(ctrl => ctrl.id === id);
        if (!c) return;

        drawerControlId.textContent = c.id;
        drawerControlTitle.textContent = c.title;
        drawerControlFramework.textContent = c.framework;
        drawerControlRef.textContent = `${c.framework} — ${c.requirement_ref}`;
        drawerControlDesc.textContent = c.description;
        drawerControlEvidence.textContent = c.evidence;
        drawerControlRemediation.textContent = c.remediation;

        drawerBackdrop.style.display = 'flex';
    }

    if (drawerCloseBtn) {
        drawerCloseBtn.addEventListener('click', () => {
            drawerBackdrop.style.display = 'none';
        });
    }
    if (drawerBackdrop) {
        drawerBackdrop.addEventListener('click', (e) => {
            if (e.target === drawerBackdrop) drawerBackdrop.style.display = 'none';
        });
    }

    // ── Export Report Event Handlers ──
    if (btnExportHtml) {
        btnExportHtml.addEventListener('click', () => {
            const fw = filterFramework.value;
            window.open(`/api/compliance/report?format=html&framework=${fw}`, '_blank');
        });
    }
    if (btnExportCsv) {
        btnExportCsv.addEventListener('click', () => {
            const fw = filterFramework.value;
            window.location.href = `/api/compliance/report?format=csv&framework=${fw}`;
        });
    }

    // ── Filter Controls Event Listeners ──
    filterFramework.addEventListener('change', renderTable);
    filterStatus.addEventListener('change', renderTable);
    complianceSearch.addEventListener('input', renderTable);

    // ── Canvas Score History Trend Chart Renderer ──
    function renderTrendChart() {
        const canvas = document.getElementById('compliance-chart');
        if (!canvas) return;
        const ctx = canvas.getContext('2d');
        if (!ctx) return;

        const rect = canvas.parentElement.getBoundingClientRect();
        canvas.width = rect.width;
        canvas.height = rect.height || 210;

        const width = canvas.width;
        const height = canvas.height;

        ctx.clearRect(0, 0, width, height);

        if (historyData.length === 0) {
            ctx.fillStyle = '#8e8e93';
            ctx.font = '13px "DM Mono", monospace';
            ctx.textAlign = 'center';
            ctx.fillText('No history data', width / 2, height / 2);
            return;
        }

        const padding = { top: 20, right: 20, bottom: 35, left: 45 };
        const chartW = width - padding.left - padding.right;
        const chartH = height - padding.top - padding.bottom;

        // Draw grid lines
        ctx.strokeStyle = getComputedStyle(document.body).getPropertyValue('--line') || '#333';
        ctx.lineWidth = 1;

        const yTicks = [0, 25, 50, 75, 100];
        ctx.fillStyle = getComputedStyle(document.body).getPropertyValue('--muted') || '#888';
        ctx.font = '10px "DM Mono", monospace';
        ctx.textAlign = 'right';

        yTicks.forEach(val => {
            const y = padding.top + chartH - (val / 100) * chartH;
            ctx.beginPath();
            ctx.moveTo(padding.left, y);
            ctx.lineTo(width - padding.right, y);
            ctx.stroke();
            ctx.fillText(`${val}%`, padding.left - 8, y + 3);
        });

        // Draw score trendline
        const stepX = chartW / Math.max(1, historyData.length - 1);
        const tealColor = getComputedStyle(document.body).getPropertyValue('--teal') || '#34c759';

        ctx.beginPath();
        historyData.forEach((pt, i) => {
            const x = padding.left + i * stepX;
            const y = padding.top + chartH - (pt.overall_score / 100) * chartH;
            if (i === 0) ctx.moveTo(x, y);
            else ctx.lineTo(x, y);
        });

        ctx.strokeStyle = tealColor;
        ctx.lineWidth = 3;
        ctx.stroke();

        // Draw area fill below trendline
        const lastX = padding.left + (historyData.length - 1) * stepX;
        ctx.lineTo(lastX, padding.top + chartH);
        ctx.lineTo(padding.left, padding.top + chartH);
        ctx.closePath();

        const grad = ctx.createLinearGradient(0, padding.top, 0, padding.top + chartH);
        grad.addColorStop(0, 'rgba(52, 199, 89, 0.25)');
        grad.addColorStop(1, 'rgba(52, 199, 89, 0.0)');
        ctx.fillStyle = grad;
        ctx.fill();

        // Draw point dots and x-axis labels
        ctx.textAlign = 'center';
        historyData.forEach((pt, i) => {
            const x = padding.left + i * stepX;
            const y = padding.top + chartH - (pt.overall_score / 100) * chartH;

            ctx.fillStyle = tealColor;
            ctx.beginPath();
            ctx.arc(x, y, 4, 0, Math.PI * 2);
            ctx.fill();

            // X-axis date label
            const d = new Date(pt.timestamp);
            const dateStr = `${d.getMonth() + 1}/${d.getDate()}`;
            ctx.fillStyle = getComputedStyle(document.body).getPropertyValue('--muted') || '#888';
            ctx.fillText(dateStr, x, height - 10);
        });
    }

    function escapeHtml(str) {
        if (!str) return '';
        return String(str)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;');
    }

    // Initial fetch and 10s poll
    loadComplianceStatus();
    loadComplianceHistory();
    setInterval(() => {
        loadComplianceStatus();
        loadComplianceHistory();
    }, 10000);

    window.addEventListener('resize', renderTrendChart);
})();
