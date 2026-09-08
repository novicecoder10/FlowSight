(function () {
    const rulesTableBody = document.querySelector('#rules-table tbody');
    const execTableBody = document.querySelector('#exec-table tbody');

    const metricActiveRules = document.getElementById('metric-active-rules');
    const metricTotalExecs = document.getElementById('metric-total-execs');
    const metricActiveShuns = document.getElementById('metric-active-shuns');
    const metricLastTrigger = document.getElementById('metric-last-trigger');
    const metricLastRule = document.getElementById('metric-last-rule');

    const rulesCountBadge = document.getElementById('rules-count-badge');
    const execsCountBadge = document.getElementById('execs-count-badge');

    const statusDot = document.getElementById('status-dot');
    const liveLabel = document.getElementById('live-label');

    const btnCreateRule = document.getElementById('btn-create-rule');
    const ruleModal = document.getElementById('rule-modal');
    const modalCloseBtn = document.getElementById('modal-close-btn');
    const modalCancelBtn = document.getElementById('modal-cancel-btn');
    const ruleForm = document.getElementById('rule-form');

    let loadedRules = [];
    let loadedExecs = [];

    // Format ISO Timestamp
    function formatTime(isoStr) {
        if (!isoStr) return '—';
        const d = new Date(isoStr);
        return isNaN(d.getTime()) ? isoStr : d.toLocaleTimeString([], { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' });
    }

    function formatDate(isoStr) {
        if (!isoStr) return '—';
        const d = new Date(isoStr);
        return isNaN(d.getTime()) ? isoStr : d.toLocaleDateString() + ' ' + d.toLocaleTimeString([], { hour12: false, hour: '2-digit', minute: '2-digit' });
    }

    // Modal Handlers
    function openModal() {
        ruleModal.style.display = 'flex';
    }

    function closeModal() {
        ruleModal.style.display = 'none';
        ruleForm.reset();
    }

    if (btnCreateRule) btnCreateRule.addEventListener('click', openModal);
    if (modalCloseBtn) modalCloseBtn.addEventListener('click', closeModal);
    if (modalCancelBtn) modalCancelBtn.addEventListener('click', closeModal);

    window.addEventListener('click', (e) => {
        if (e.target === ruleModal) closeModal();
    });

    // Form Submit
    ruleForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        const name = document.getElementById('rule-name').value.trim();
        const condition_type = document.getElementById('rule-condition').value;
        const operator = document.getElementById('rule-operator').value;
        const value = document.getElementById('rule-value').value.trim();
        const severity = document.getElementById('rule-severity').value;
        const webhook_url = document.getElementById('rule-webhook').value.trim() || undefined;

        const actionCbs = document.querySelectorAll('input[name="actions"]:checked');
        const actions = Array.from(actionCbs).map(cb => cb.value);

        if (!name || !value) {
            alert('Please complete required rule fields');
            return;
        }

        try {
            const res = await fetch('/api/soar/rules', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    name,
                    condition_type,
                    target_field: condition_type === 'bandwidth_threshold' ? 'bytes' : condition_type === 'threat_severity' ? 'severity' : condition_type === 'condition_type' ? 'anomaly_type' : 'metadata',
                    operator,
                    value,
                    severity,
                    actions,
                    webhook_url
                })
            });

            if (res.ok) {
                closeModal();
                await fetchRules();
            } else {
                const err = await res.json();
                alert(`Error creating rule: ${err.error || 'Server error'}`);
            }
        } catch (err) {
            console.error('Failed to save rule:', err);
        }
    });

    // Fetch & Render Rules
    async function fetchRules() {
        try {
            const res = await fetch('/api/soar/rules');
            const data = await res.json();
            loadedRules = data.rules || [];
            renderRules();
        } catch (err) {
            console.error('Failed to load SOAR rules:', err);
        }
    }

    function renderRules() {
        if (!rulesTableBody) return;
        const activeCount = loadedRules.filter(r => r.enabled === 1).length;
        if (metricActiveRules) metricActiveRules.textContent = activeCount;
        if (rulesCountBadge) rulesCountBadge.textContent = `${loadedRules.length} rules`;

        if (loadedRules.length === 0) {
            rulesTableBody.innerHTML = '<tr><td colspan="9" class="empty-cell">No playbook rules defined. Click "New Playbook Rule" to create one.</td></tr>';
            return;
        }

        rulesTableBody.innerHTML = loadedRules.map(r => {
            const isEnabled = r.enabled === 1;
            const statusBadge = isEnabled
                ? '<span class="status-pill active-pill">Active</span>'
                : '<span class="status-pill disabled-pill">Disabled</span>';

            const actionsList = (r.actions || []).map(a => {
                if (a === 'webhook') return '<span class="action-tag webhook">Webhook</span>';
                if (a === 'auto_incident') return '<span class="action-tag incident">Auto Incident</span>';
                if (a === 'blocklist') return '<span class="action-tag shun">IP Shun</span>';
                return `<span class="action-tag">${a}</span>`;
            }).join(' ');

            return `
                <tr class="${isEnabled ? '' : 'disabled-row'}">
                    <td>${statusBadge}</td>
                    <td><strong style="color:var(--ink);">${escapeHtml(r.name)}</strong></td>
                    <td><code class="code-sm">${escapeHtml(r.condition_type)}</code></td>
                    <td><code>${escapeHtml(r.target_field || '')} ${escapeHtml(r.operator)}</code></td>
                    <td><span class="value-highlight">${escapeHtml(r.value)}</span></td>
                    <td><span class="severity-${r.severity}">${r.severity}</span></td>
                    <td>${actionsList}</td>
                    <td style="font-size:12px;color:var(--muted);">${formatDate(r.created_at)}</td>
                    <td style="text-align:right;">
                        <button type="button" class="btn-toggle-rule ${isEnabled ? 'on' : 'off'}" data-id="${r.id}">
                            ${isEnabled ? 'Disable' : 'Enable'}
                        </button>
                        <button type="button" class="btn-delete-rule" data-id="${r.id}">&times;</button>
                    </td>
                </tr>
            `;
        }).join('');

        // Attach Rule Action Listeners
        rulesTableBody.querySelectorAll('.btn-toggle-rule').forEach(btn => {
            btn.addEventListener('click', async () => {
                const id = btn.getAttribute('data-id');
                await fetch(`/api/soar/rules/${id}/toggle`, { method: 'PATCH' });
                await fetchRules();
            });
        });

        rulesTableBody.querySelectorAll('.btn-delete-rule').forEach(btn => {
            btn.addEventListener('click', async () => {
                const id = btn.getAttribute('data-id');
                if (confirm('Delete this playbook rule?')) {
                    await fetch(`/api/soar/rules/${id}`, { method: 'DELETE' });
                    await fetchRules();
                }
            });
        });
    }

    // Fetch & Render Executions Log
    async function fetchExecutions() {
        try {
            const res = await fetch('/api/soar/history?limit=100');
            const data = await res.json();
            loadedExecs = data.history || [];
            renderExecutions();
        } catch (err) {
            console.error('Failed to load SOAR history:', err);
        }
    }

    function renderExecutions() {
        if (!execTableBody) return;
        if (metricTotalExecs) metricTotalExecs.textContent = loadedExecs.length;
        if (execsCountBadge) execsCountBadge.textContent = `${loadedExecs.length} executions`;

        if (loadedExecs.length > 0) {
            const latest = loadedExecs[0];
            if (metricLastTrigger) metricLastTrigger.textContent = formatTime(latest.timestamp);
            if (metricLastRule) metricLastRule.textContent = latest.rule_name;
        }

        if (loadedExecs.length === 0) {
            execTableBody.innerHTML = '<tr><td colspan="6" class="empty-cell">No playbook executions recorded yet</td></tr>';
            return;
        }

        execTableBody.innerHTML = loadedExecs.map(ex => {
            const statusPill = ex.status === 'SUCCESS'
                ? '<span class="severity-low">SUCCESS</span>'
                : '<span class="severity-critical">FAILED</span>';

            return `
                <tr>
                    <td style="font-family:'DM Mono',monospace;font-size:12px;color:var(--muted);">${formatDate(ex.timestamp)}</td>
                    <td><strong>${escapeHtml(ex.rule_name)}</strong></td>
                    <td style="font-size:13px;">${escapeHtml(ex.trigger_event)}</td>
                    <td><span class="action-tag">${escapeHtml(ex.action_taken)}</span></td>
                    <td>${statusPill}</td>
                    <td style="font-size:12px;color:var(--muted);">${escapeHtml(ex.response_details)}</td>
                </tr>
            `;
        }).join('');
    }

    // Fetch Active Shuns Count
    async function fetchShuns() {
        try {
            const res = await fetch('/api/soar/export-blocklist?format=text');
            const text = await res.text();
            const lines = text.split('\n').filter(l => l.trim().length > 0);
            if (metricActiveShuns) metricActiveShuns.textContent = lines.length;
        } catch (err) {
            console.error('Failed to fetch shun count:', err);
        }
    }

    function escapeHtml(str) {
        if (!str) return '';
        return String(str)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;');
    }

    // Connect SSE Stream
    function initSSE() {
        const evSource = new EventSource('/api/stream');

        evSource.addEventListener('status', (e) => {
            try {
                const data = JSON.parse(e.data);
                if (statusDot) {
                    statusDot.className = 'status-dot' + (data.running ? ' online' : ' error');
                }
                if (liveLabel) {
                    liveLabel.textContent = data.running ? 'Live Capture' : data.error ? 'Engine Warning' : 'Demo Stream';
                }
            } catch (err) {}
        });

        evSource.addEventListener('soar_execution', (e) => {
            try {
                const exec = JSON.parse(e.data);
                loadedExecs.unshift(exec);
                if (loadedExecs.length > 200) loadedExecs.pop();
                renderExecutions();
                fetchShuns();
            } catch (err) {}
        });

        evSource.onerror = () => {
            if (statusDot) statusDot.className = 'status-dot error';
            if (liveLabel) liveLabel.textContent = 'Disconnected';
        };
    }

    // Init Page
    fetchRules();
    fetchExecutions();
    fetchShuns();
    initSSE();
})();
