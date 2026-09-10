let incidents = [];
let selectedIncidentId = null;
let currentStatusFilter = 'ALL';
let currentSeverityFilter = 'ALL';
let currentCategoryFilter = 'ALL';
let statsData = null;

const stream = new EventSource('/api/stream');

stream.addEventListener('status', (event) => setCaptureStatus(JSON.parse(event.data)));

stream.addEventListener('incident_new', (event) => {
  const item = JSON.parse(event.data);
  const idx = incidents.findIndex(i => i.id === item.id);
  if (idx >= 0) incidents[idx] = item;
  else incidents.unshift(item);
  fetchStats();
  render();
});

stream.addEventListener('incident_update', (event) => {
  const item = JSON.parse(event.data);
  const idx = incidents.findIndex(i => i.id === item.id);
  if (idx >= 0) incidents[idx] = item;
  else incidents.unshift(item);
  if (selectedIncidentId === item.id) {
    renderInspector(item);
  }
  fetchStats();
  render();
});

stream.onerror = () => setCaptureStatus('offline');

const formatTime = (value) => new Date(value).toLocaleTimeString([], { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' });
const formatFullDate = (value) => new Date(value).toLocaleString();

async function fetchStats() {
  try {
    const res = await fetch('/api/incidents/stats');
    if (res.ok) {
      statsData = await res.json();
      document.querySelector('#val-open-incidents').textContent = statsData.open || 0;
      document.querySelector('#val-critical-incidents').textContent = statsData.critical || 0;
      document.querySelector('#val-in-progress-incidents').textContent = statsData.in_progress || 0;
      document.querySelector('#val-resolved-incidents').textContent = statsData.resolved || 0;
    }
  } catch (e) {
    console.error('Failed to fetch incident stats:', e);
  }
}

async function fetchIncidents() {
  let url = `/api/incidents?limit=150&status=${currentStatusFilter}&severity=${currentSeverityFilter}&category=${currentCategoryFilter}`;
  try {
    const res = await fetch(url);
    if (res.ok) {
      const data = await res.json();
      incidents = data.incidents || [];
      render();
    }
  } catch (e) {
    console.error('Failed to fetch incidents:', e);
  }
}

function render() {
  document.querySelector('#incidents-count-tag').textContent = `${incidents.length} INCIDENTS`;

  const tbody = document.querySelector('#incidents-table tbody');
  if (incidents.length === 0) {
    tbody.innerHTML = '<tr><td colspan="8" class="empty-state">No matching incidents found</td></tr>';
    return;
  }

  tbody.innerHTML = incidents.map(inc => {
    const isSelected = inc.id === selectedIncidentId ? 'selected-incident-row' : '';
    const sevClass = `severity-${(inc.severity || 'low').toLowerCase()}`;
    const statusClass = `inc-status-${(inc.status || 'new').toLowerCase()}`;

    return `<tr class="incident-row ${isSelected}" data-id="${inc.id}">
      <td>#${inc.id}</td>
      <td>${formatTime(inc.created_at)}</td>
      <td><span class="${sevClass}">${inc.severity}</span></td>
      <td><strong>${inc.title}</strong></td>
      <td><span class="vpn-proto-pill">${inc.category}</span></td>
      <td><code>${inc.source_ip}</code></td>
      <td><span class="inc-status-badge ${statusClass}">${inc.status.replace('_', ' ')}</span></td>
      <td><small class="vpn-method-tag">${inc.assigned_to}</small></td>
    </tr>`;
  }).join('');

  tbody.querySelectorAll('.incident-row').forEach(row => {
    row.addEventListener('click', () => {
      const id = Number(row.getAttribute('data-id'));
      selectIncident(id);
    });
  });
}

function selectIncident(id) {
  selectedIncidentId = id;
  render();
  const inc = incidents.find(i => i.id === id);
  if (inc) renderInspector(inc);
}

function renderInspector(inc) {
  const inspectorBody = document.querySelector('#inspector-body');
  const badge = document.querySelector('#inspector-status-badge');
  badge.textContent = `INCIDENT #${inc.id}`;

  const notesHtml = (inc.notes || []).map(n => `
    <div class="analyst-note-item">
      <div class="note-header">
        <span class="note-author">${n.author}</span>
        <span class="note-time">${formatTime(n.timestamp)}</span>
      </div>
      <div class="note-content">${n.note}</div>
    </div>
  `).join('') || '<div class="subtle-text">No notes added yet</div>';

  const eventsHtml = (inc.related_event_ids || []).map(eid => `
    <div class="correlated-event-chip">
      <span class="event-id-tag">${eid}</span>
    </div>
  `).join('');

  inspectorBody.innerHTML = `
    <div class="inspector-header-box">
      <h3 class="inspector-title">${inc.title}</h3>
      <p class="inspector-desc">${inc.description}</p>
      <div class="inspector-meta-row">
        <div><strong>Source IP:</strong> <code>${inc.source_ip}</code></div>
        <div><strong>Dest IP:</strong> <code>${inc.destination_ip}</code></div>
        <div><strong>Created:</strong> ${formatFullDate(inc.created_at)}</div>
      </div>
    </div>

    <!-- Triage Workflow Actions -->
    <div class="inspector-actions-box">
      <div class="action-field">
        <label>Status:</label>
        <select id="update-status-select" class="forensics-select">
          <option value="NEW" ${inc.status === 'NEW' ? 'selected' : ''}>NEW</option>
          <option value="IN_PROGRESS" ${inc.status === 'IN_PROGRESS' ? 'selected' : ''}>IN PROGRESS</option>
          <option value="RESOLVED" ${inc.status === 'RESOLVED' ? 'selected' : ''}>RESOLVED</option>
          <option value="FALSE_POSITIVE" ${inc.status === 'FALSE_POSITIVE' ? 'selected' : ''}>FALSE POSITIVE</option>
        </select>
      </div>

      <div class="action-field">
        <label>Severity:</label>
        <select id="update-severity-select" class="forensics-select">
          <option value="critical" ${inc.severity === 'critical' ? 'selected' : ''}>Critical</option>
          <option value="high" ${inc.severity === 'high' ? 'selected' : ''}>High</option>
          <option value="medium" ${inc.severity === 'medium' ? 'selected' : ''}>Medium</option>
          <option value="low" ${inc.severity === 'low' ? 'selected' : ''}>Low</option>
        </select>
      </div>

      <div class="action-field">
        <label>Assignee:</label>
        <input type="text" id="update-assignee-input" class="forensics-input" value="${inc.assigned_to || 'Unassigned'}" style="padding: 6px 10px;">
      </div>

      <button type="button" id="btn-save-triage" class="btn-primary" style="margin-top: 10px; width: 100%;">Save Incident Triage</button>
    </div>

    <!-- Pivot to Forensics Search Link -->
    <div style="margin: 16px 0;">
      <a href="/forensics.html?q=src:${encodeURIComponent(inc.source_ip)}" class="btn-secondary" style="display: block; text-align: center; text-decoration: none;">
        🔍 Pivot to Forensics Search (Source IP: ${inc.source_ip})
      </a>
    </div>

    <!-- Correlated Events Feed -->
    <div class="inspector-section">
      <div class="section-title">Correlated Alert Events (${inc.related_event_ids.length})</div>
      <div class="correlated-events-grid">${eventsHtml}</div>
    </div>

    <!-- Analyst Notes Section -->
    <div class="inspector-section">
      <div class="section-title">Analyst Investigation Notes</div>
      <div id="notes-feed" class="notes-feed-box">${notesHtml}</div>
      <div class="add-note-box" style="margin-top: 12px;">
        <textarea id="new-note-text" class="forensics-input" placeholder="Type analyst investigation note..." rows="2" style="padding: 8px; width: 100%;"></textarea>
        <button type="button" id="btn-add-note" class="btn-secondary" style="margin-top: 8px; float: right;">Add Note</button>
      </div>
    </div>
  `;

  // Attach Event Handlers
  document.querySelector('#btn-save-triage').addEventListener('click', async () => {
    const status = document.querySelector('#update-status-select').value;
    const severity = document.querySelector('#update-severity-select').value;
    const assigned_to = document.querySelector('#update-assignee-input').value.trim();

    try {
      const res = await fetch(`/api/incidents/${inc.id}`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ status, severity, assigned_to }),
      });
      if (res.ok) {
        fetchIncidents();
        fetchStats();
      }
    } catch (e) {
      console.error('Failed to update incident:', e);
    }
  });

  document.querySelector('#btn-add-note').addEventListener('click', async () => {
    const noteText = document.querySelector('#new-note-text').value.trim();
    if (!noteText) return;

    try {
      const res = await fetch(`/api/incidents/${inc.id}/notes`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ note: noteText, author: 'SecOps Analyst' }),
      });
      if (res.ok) {
        document.querySelector('#new-note-text').value = '';
        const data = await res.json();
        if (data.incident) renderInspector(data.incident);
        fetchIncidents();
      }
    } catch (e) {
      console.error('Failed to add note:', e);
    }
  });
}

// Filter Controls
document.querySelectorAll('#status-filter-tabs .tab-btn').forEach(btn => {
  btn.addEventListener('click', () => {
    document.querySelectorAll('#status-filter-tabs .tab-btn').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    currentStatusFilter = btn.getAttribute('data-status');
    fetchIncidents();
  });
});

document.querySelector('#severity-filter').addEventListener('change', (e) => {
  currentSeverityFilter = e.target.value;
  fetchIncidents();
});

document.querySelector('#category-filter').addEventListener('change', (e) => {
  currentCategoryFilter = e.target.value;
  fetchIncidents();
});

// Initialization
async function init() {
  await fetchStats();
  await fetchIncidents();
}

init();
