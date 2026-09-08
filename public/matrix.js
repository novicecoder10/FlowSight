(function() {
    'use strict';

    let currentWindow = '15m';
    let currentTop = 15;
    let activeView = 'sankey'; // 'sankey' | 'matrix'

    let sankeyData = null;
    let matrixData = null;

    let hoveredNode = null;
    let hoveredLink = null;

    const canvas = document.getElementById('sankey-canvas');
    const ctx = canvas ? canvas.getContext('2d') : null;
    const tooltip = document.getElementById('sankey-tooltip');

    // Utility formatting helpers
    function formatBytes(bytes) {
        if (!bytes || bytes === 0) return '0 B';
        const k = 1024;
        const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
    }

    function formatNumber(num) {
        return (num || 0).toLocaleString();
    }

    // Initialize Page
    document.addEventListener('DOMContentLoaded', () => {
        setupEventListeners();
        setupSSE();
        fetchData();
        setupCanvasInteractivity();
    });

    function setupEventListeners() {
        const btnSankey = document.getElementById('btn-view-sankey');
        const btnMatrix = document.getElementById('btn-view-matrix');
        const panelSankey = document.getElementById('sankey-panel');
        const panelMatrix = document.getElementById('matrix-panel');

        btnSankey.addEventListener('click', () => {
            activeView = 'sankey';
            btnSankey.classList.add('active');
            btnMatrix.classList.remove('active');
            panelSankey.style.display = 'block';
            panelMatrix.style.display = 'none';
            if (sankeyData) renderSankey();
        });

        btnMatrix.addEventListener('click', () => {
            activeView = 'matrix';
            btnMatrix.classList.add('active');
            btnSankey.classList.remove('active');
            panelMatrix.style.display = 'block';
            panelSankey.style.display = 'none';
            if (matrixData) renderMatrix();
        });

        document.getElementById('select-window').addEventListener('change', (e) => {
            currentWindow = e.target.value;
            fetchData();
        });

        document.getElementById('select-top').addEventListener('change', (e) => {
            currentTop = Number(e.target.value);
            fetchData();
        });

        document.getElementById('btn-refresh-flow').addEventListener('click', fetchData);

        window.addEventListener('resize', () => {
            if (activeView === 'sankey' && sankeyData) renderSankey();
        });
    }

    function setupSSE() {
        const statusDot = document.getElementById('status-dot');
        const liveLabel = document.getElementById('live-label');
        const source = new EventSource('/api/stream');

        source.addEventListener('status', () => {
            if (statusDot) statusDot.classList.add('online');
            if (liveLabel) liveLabel.textContent = 'Live Capture';
        });

        let sseDebounce = null;
        source.addEventListener('packet', () => {
            if (sseDebounce) return;
            sseDebounce = setTimeout(() => {
                sseDebounce = null;
                fetchData();
            }, 5000);
        });
        window.addEventListener('beforeunload', () => source.close());
    }

    function fetchData() {
        Promise.all([
            fetch(`/api/flows/sankey?window=${currentWindow}&limit=1000`).then(r => r.json()),
            fetch(`/api/flows/matrix?window=${currentWindow}&top=${currentTop}`).then(r => r.json())
        ]).then(([sData, mData]) => {
            sankeyData = sData;
            matrixData = mData;

            updateMetrics();

            if (activeView === 'sankey') renderSankey();
            else renderMatrix();
        }).catch(err => console.error('Failed to fetch flow matrix data:', err));
    }

    function updateMetrics() {
        if (!sankeyData) return;

        const valActiveFlows = document.getElementById('val-active-flows');
        const valTopSource = document.getElementById('val-top-source');
        const valTopTarget = document.getElementById('val-top-target');
        const valTotalVolume = document.getElementById('val-total-volume');

        if (valActiveFlows) valActiveFlows.textContent = formatNumber(sankeyData.stats.flow_count);
        if (valTotalVolume) valTotalVolume.textContent = formatBytes(sankeyData.stats.total_bytes);

        // Find top source
        const sources = sankeyData.nodes.filter(n => n.tier === 1).sort((a, b) => b.value - a.value);
        if (sources.length > 0 && valTopSource) {
            valTopSource.textContent = sources[0].name;
            const desc = document.getElementById('desc-top-source');
            if (desc) desc.textContent = `${formatBytes(sources[0].value)} transferred`;
        }

        // Find top target
        const targets = sankeyData.nodes.filter(n => n.tier === 3).sort((a, b) => b.value - a.value);
        if (targets.length > 0 && valTopTarget) {
            valTopTarget.textContent = targets[0].name;
            const desc = document.getElementById('desc-top-target');
            if (desc) desc.textContent = `${formatBytes(targets[0].value)} received`;
        }
    }

    // ── Sankey Diagram Canvas Renderer ──
    let nodeRects = [];
    let ribbonPaths = [];

    function renderSankey() {
        if (!canvas || !ctx) return;

        const rect = canvas.parentElement ? canvas.parentElement.getBoundingClientRect() : { width: 1200 };
        const dpr = window.devicePixelRatio || 1;
        const width = rect.width || 1200;
        const height = 540;

        canvas.width = width * dpr;
        canvas.height = height * dpr;
        canvas.style.width = width + 'px';
        canvas.style.height = height + 'px';

        ctx.resetTransform();
        ctx.scale(dpr, dpr);
        ctx.clearRect(0, 0, width, height);

        if (!sankeyData) {
            ctx.fillStyle = '#2eb89e';
            ctx.font = '500 14px "DM Mono", monospace';
            ctx.textAlign = 'center';
            ctx.fillText('Loading flow topology & active ribbons...', width / 2, height / 2);
            return;
        }

        const nodes = sankeyData.nodes || [];
        const links = sankeyData.links || [];

        if (nodes.length === 0) {
            ctx.fillStyle = '#888';
            ctx.font = '14px "DM Mono", monospace';
            ctx.textAlign = 'center';
            ctx.fillText('No flow traffic recorded in selected time window', width / 2, height / 2);
            return;
        }

        // Separate nodes into 3 Tiers
        const tier1 = nodes.filter(n => n.tier === 1).sort((a, b) => b.value - a.value).slice(0, 12);
        const tier2 = nodes.filter(n => n.tier === 2).sort((a, b) => b.value - a.value).slice(0, 10);
        const tier3 = nodes.filter(n => n.tier === 3).sort((a, b) => b.value - a.value).slice(0, 12);

        const validNodeIds = new Set([...tier1, ...tier2, ...tier3].map(n => n.id));
        const activeLinks = links.filter(l => validNodeIds.has(l.source) && validNodeIds.has(l.target));

        const xPositions = {
            1: width * 0.08,
            2: width * 0.50,
            3: width * 0.92
        };

        const nodeWidth = 14;
        const paddingY = 16;
        const marginTop = 40;
        const availHeight = height - marginTop - 40;

        // Position nodes vertically per tier
        nodeRects = [];
        const nodePosMap = new Map();

        [1, 2, 3].forEach(tierNum => {
            const list = tierNum === 1 ? tier1 : (tierNum === 2 ? tier2 : tier3);
            const totalVal = list.reduce((sum, n) => sum + n.value, 0);

            let currentY = marginTop;
            const gap = (availHeight - list.reduce((s, n) => s + Math.max(18, (n.value / totalVal) * (availHeight - list.length * paddingY)), 0)) / (list.length + 1);

            list.forEach(n => {
                const nHeight = Math.max(18, (n.value / Math.max(1, totalVal)) * (availHeight - list.length * paddingY));
                const x = xPositions[tierNum] - nodeWidth / 2;
                const rectInfo = {
                    node: n,
                    x,
                    y: currentY,
                    w: nodeWidth,
                    h: nHeight,
                    outY: currentY,
                    inY: currentY
                };
                nodeRects.push(rectInfo);
                nodePosMap.set(n.id, rectInfo);
                currentY += nHeight + paddingY;
            });
        });

        // Compute Ribbon Links
        ribbonPaths = [];
        activeLinks.forEach(link => {
            const srcPos = nodePosMap.get(link.source);
            const dstPos = nodePosMap.get(link.target);
            if (!srcPos || !dstPos) return;

            const srcShare = (link.value / srcPos.node.value) || 0;
            const dstShare = (link.value / dstPos.node.value) || 0;

            const ribbonH1 = Math.max(2, srcPos.h * srcShare);
            const ribbonH2 = Math.max(2, dstPos.h * dstShare);

            const y0 = srcPos.outY;
            const y1 = dstPos.inY;

            srcPos.outY += ribbonH1;
            dstPos.inY += ribbonH2;

            ribbonPaths.push({
                link,
                x0: srcPos.x + nodeWidth,
                y0_top: y0,
                y0_bot: y0 + ribbonH1,
                x1: dstPos.x,
                y1_top: y1,
                y1_bot: y1 + ribbonH2,
                srcNode: srcPos.node,
                dstNode: dstPos.node
            });
        });

        const isDarkMode = document.documentElement.getAttribute('data-theme') !== 'light';

        // Draw Ribbon Flows
        ribbonPaths.forEach(r => {
            const isHighlighted = (hoveredNode && (r.srcNode.id === hoveredNode.id || r.dstNode.id === hoveredNode.id)) ||
                                  (hoveredLink && r.link === hoveredLink);
            const isDimmed = (hoveredNode || hoveredLink) && !isHighlighted;

            ctx.beginPath();
            ctx.moveTo(r.x0, r.y0_top);
            const dx = r.x1 - r.x0;
            ctx.bezierCurveTo(r.x0 + dx * 0.45, r.y0_top, r.x1 - dx * 0.45, r.y1_top, r.x1, r.y1_top);
            ctx.lineTo(r.x1, r.y1_bot);
            ctx.bezierCurveTo(r.x1 - dx * 0.45, r.y1_bot, r.x0 + dx * 0.45, r.y0_bot, r.x0, r.y0_bot);
            ctx.closePath();

            const grad = ctx.createLinearGradient(r.x0, 0, r.x1, 0);
            if (isDimmed) {
                grad.addColorStop(0, isDarkMode ? 'rgba(255,255,255,0.03)' : 'rgba(0,0,0,0.03)');
                grad.addColorStop(1, isDarkMode ? 'rgba(255,255,255,0.03)' : 'rgba(0,0,0,0.03)');
            } else if (isHighlighted) {
                grad.addColorStop(0, '#00e5a3');
                grad.addColorStop(1, '#cbf36b');
            } else {
                grad.addColorStop(0, isDarkMode ? 'rgba(46, 184, 158, 0.22)' : 'rgba(46, 184, 158, 0.35)');
                grad.addColorStop(1, isDarkMode ? 'rgba(203, 243, 107, 0.25)' : 'rgba(203, 243, 107, 0.40)');
            }

            ctx.fillStyle = grad;
            ctx.fill();
            ctx.strokeStyle = isHighlighted ? 'rgba(203, 243, 107, 0.8)' : (isDimmed ? 'transparent' : 'rgba(46, 184, 158, 0.15)');
            ctx.lineWidth = isHighlighted ? 1.5 : 0.5;
            ctx.stroke();
        });

        // Draw Nodes & Labels
        nodeRects.forEach(nr => {
            const isHovered = hoveredNode && nr.node.id === hoveredNode.id;

            // Node pill bar
            ctx.beginPath();
            ctx.roundRect(nr.x, nr.y, nr.w, nr.h, 3);

            let nodeColor = '#2eb89e';
            if (nr.node.tier === 2) nodeColor = '#cbf36b';
            if (nr.node.tier === 3) nodeColor = '#ff765f';

            ctx.fillStyle = isHovered ? '#ffffff' : nodeColor;
            ctx.fill();

            if (isHovered) {
                ctx.strokeStyle = '#ffffff';
                ctx.lineWidth = 2;
                ctx.stroke();
            }

            // Text Label
            ctx.font = '500 11px "Space Grotesk", sans-serif';
            ctx.fillStyle = isDarkMode ? '#e2e8f0' : '#1e293b';

            if (nr.node.tier === 1) {
                ctx.textAlign = 'right';
                ctx.fillText(nr.node.name, nr.x - 8, nr.y + Math.min(nr.h / 2 + 4, nr.h - 2));
            } else if (nr.node.tier === 2) {
                ctx.textAlign = 'center';
                ctx.fillText(nr.node.name, nr.x + nr.w / 2, nr.y - 5);
            } else {
                ctx.textAlign = 'left';
                ctx.fillText(nr.node.name, nr.x + nr.w + 8, nr.y + Math.min(nr.h / 2 + 4, nr.h - 2));
            }
        });
    }

    // Canvas Mouse Interactivity
    function setupCanvasInteractivity() {
        if (!canvas) return;

        canvas.addEventListener('mousemove', (e) => {
            const rect = canvas.getBoundingClientRect();
            const mouseX = e.clientX - rect.left;
            const mouseY = e.clientY - rect.top;

            let foundNode = null;
            let foundRibbon = null;

            // Check Node Hover
            for (const nr of nodeRects) {
                if (mouseX >= nr.x - 10 && mouseX <= nr.x + nr.w + 10 &&
                    mouseY >= nr.y && mouseY <= nr.y + nr.h) {
                    foundNode = nr.node;
                    break;
                }
            }

            // Check Ribbon Hover
            if (!foundNode) {
                for (const r of ribbonPaths) {
                    if (mouseX >= r.x0 && mouseX <= r.x1) {
                        const t = (mouseX - r.x0) / (r.x1 - r.x0);
                        const expectedYTop = (1 - t) * r.y0_top + t * r.y1_top;
                        const expectedYBot = (1 - t) * r.y0_bot + t * r.y1_bot;
                        if (mouseY >= expectedYTop - 3 && mouseY <= expectedYBot + 3) {
                            foundRibbon = r;
                            break;
                        }
                    }
                }
            }

            if (foundNode !== hoveredNode || (foundRibbon && foundRibbon.link !== hoveredLink)) {
                hoveredNode = foundNode;
                hoveredLink = foundRibbon ? foundRibbon.link : null;
                renderSankey();
            }

            // Show Tooltip Popover
            if (foundNode) {
                tooltip.style.display = 'block';
                tooltip.style.left = `${e.clientX - rect.left + 15}px`;
                tooltip.style.top = `${e.clientY - rect.top + 15}px`;
                tooltip.innerHTML = `
                    <div style="font-weight:700;color:var(--lime);">${foundNode.name}</div>
                    <div style="font-size:11px;color:var(--muted);margin-top:2px;">Category: ${foundNode.category.toUpperCase()}</div>
                    <div style="font-size:12px;margin-top:4px;">Volume: <strong style="color:var(--teal);">${formatBytes(foundNode.value)}</strong></div>
                `;
            } else if (foundRibbon) {
                tooltip.style.display = 'block';
                tooltip.style.left = `${e.clientX - rect.left + 15}px`;
                tooltip.style.top = `${e.clientY - rect.top + 15}px`;
                tooltip.innerHTML = `
                    <div style="font-weight:700;color:var(--lime);">${foundRibbon.srcNode.name} → ${foundRibbon.dstNode.name}</div>
                    <div style="font-size:11px;color:var(--muted);margin-top:2px;">Protocol: ${foundRibbon.link.protocol}</div>
                    <div style="font-size:12px;margin-top:4px;">Volume: <strong style="color:var(--teal);">${formatBytes(foundRibbon.link.value)}</strong> (${formatNumber(foundRibbon.link.packets)} pkts)</div>
                `;
            } else {
                tooltip.style.display = 'none';
            }
        });

        canvas.addEventListener('mouseleave', () => {
            hoveredNode = null;
            hoveredLink = null;
            tooltip.style.display = 'none';
            renderSankey();
        });
    }

    // ── Traffic Heatmap Matrix Renderer ──
    function renderMatrix() {
        const container = document.getElementById('matrix-grid-container');
        if (!container || !matrixData) return;

        const { sources, destinations, cells, max_cell_bytes } = matrixData;

        if (!sources || sources.length === 0 || !destinations || destinations.length === 0) {
            container.innerHTML = '<div class="empty-state" style="padding:60px;">No traffic matrix data available for selected window</div>';
            return;
        }

        // Build Cell Map: key = `${src}_${dst}`
        const cellMap = new Map();
        (cells || []).forEach(c => cellMap.set(`${c.src}_${c.dst}`, c));

        let html = '<table class="matrix-table"><thead><tr><th class="matrix-corner">Source \\ Target</th>';

        destinations.forEach(d => {
            html += `<th class="matrix-header-col" title="${d.ip}">${d.ip}</th>`;
        });
        html += '</tr></thead><tbody>';

        sources.forEach(s => {
            html += `<tr><th class="matrix-header-row" title="${s.ip}">${s.ip}</th>`;

            destinations.forEach(d => {
                const cell = cellMap.get(`${s.ip}_${d.ip}`);
                if (!cell || cell.bytes === 0) {
                    html += '<td class="matrix-cell cell-empty" title="No traffic">—</td>';
                } else {
                    const ratio = cell.bytes / (max_cell_bytes || 1);
                    let intensityClass = 'cell-int-1';
                    if (ratio > 0.6) intensityClass = 'cell-int-5';
                    else if (ratio > 0.3) intensityClass = 'cell-int-4';
                    else if (ratio > 0.1) intensityClass = 'cell-int-3';
                    else if (ratio > 0.02) intensityClass = 'cell-int-2';

                    html += `
                        <td class="matrix-cell ${intensityClass}" data-src="${s.ip}" data-dst="${d.ip}" data-bytes="${cell.bytes}" data-pkts="${cell.packets}" data-proto="${cell.top_protocol}">
                            <div class="cell-val">${formatBytes(cell.bytes)}</div>
                            <div class="cell-sub">${cell.top_protocol}</div>
                        </td>
                    `;
                }
            });
            html += '</tr>';
        });

        html += '</tbody></table>';
        container.innerHTML = html;

        // Cell Click Handler for Forensics Jump
        container.querySelectorAll('.matrix-cell:not(.cell-empty)').forEach(td => {
            td.addEventListener('click', (e) => {
                const src = td.getAttribute('data-src');
                const dst = td.getAttribute('data-dst');
                const bytes = formatBytes(Number(td.getAttribute('data-bytes')));
                const pkts = formatNumber(Number(td.getAttribute('data-pkts')));
                const proto = td.getAttribute('data-proto');

                if (confirm(`Inspect traffic flow in Forensics Search?\n\nSource: ${src}\nDestination: ${dst}\nProtocol: ${proto}\nVolume: ${bytes} (${pkts} packets)`)) {
                    window.location.href = `/forensics.html?q=src:${src} dst:${dst}`;
                }
            });
        });
    }
})();
