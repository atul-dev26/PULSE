// =========================================================================
// PULSE Events Page - JavaScript
// =========================================================================

const API_BASE = window.location.origin;

let currentPage = 1;
let currentPageSize = 25;
let currentFilters = { source: '', format: '', severity: '', status: '', search: '' };
let totalEvents = 0;

let severityChartInstance = null;
let formatChartInstance = null;
let allEventsCache = []; // Cache for current page to power drawer

// Global Chart settings
Chart.defaults.font.family = "'Inter', -apple-system, sans-serif";
Chart.defaults.color = "#6B6860";
Chart.defaults.scale.grid.color = "#D4D0C6";

// ── Initialization ──────────────────────────────────────────────
async function init() {
    // Rely on auth.js to handle redirects if not logged in
    const user = await PulseAuth.requireAuth();
    if (!user) return;
    
    await populateFilters();
    await fetchEvents();
    
    // Setup event listeners for filters
    document.getElementById('filterSearch').addEventListener('input', debounce(() => {
        currentFilters.search = document.getElementById('filterSearch').value;
        currentPage = 1;
        fetchEvents();
    }, 500));
    
    ['Source', 'Format', 'Severity', 'Status'].forEach(f => {
        document.getElementById(`filter${f}`).addEventListener('change', (e) => {
            currentFilters[f.toLowerCase()] = e.target.value;
            currentPage = 1;
            fetchEvents();
        });
    });

    document.getElementById('pageSizeSelect').addEventListener('change', (e) => {
        currentPageSize = parseInt(e.target.value);
        currentPage = 1;
        fetchEvents();
    });
}

function debounce(func, wait) {
    let timeout;
    return function executedFunction(...args) {
        const later = () => { clearTimeout(timeout); func(...args); };
        clearTimeout(timeout);
        timeout = setTimeout(later, wait);
    };
}

// ── API Fetching ──────────────────────────────────────────────
async function populateFilters() {
    try {
        const res = await PulseAuth.fetch(`${API_BASE}/api/v1/events/filters`);
        if (!res.ok) throw new Error('Failed to load filters');
        const data = await res.json();

        
        const populateSelect = (id, options) => {
            const select = document.getElementById(id);
            options.forEach(opt => {
                if (opt) {
                    const el = document.createElement('option');
                    el.value = opt;
                    el.textContent = opt;
                    select.appendChild(el);
                }
            });
        };
        
        populateSelect('filterSource', data.sources);
        populateSelect('filterFormat', data.formats);
        populateSelect('filterSeverity', data.severities);
        populateSelect('filterStatus', data.statuses);
    } catch (err) {
        console.error("Filters error:", err);
    }
}

async function fetchEvents() {
    const tbody = document.getElementById('eventsTableBody');
    tbody.innerHTML = `<tr><td colspan="11" style="padding: 30px; text-align: center; color: var(--text-muted);">Loading events...</td></tr>`;
    
    try {
        const params = new URLSearchParams({ page: currentPage, page_size: currentPageSize });
        if (currentFilters.source) params.append('source_id', currentFilters.source);
        if (currentFilters.format) params.append('format', currentFilters.format);
        if (currentFilters.severity) params.append('severity', currentFilters.severity);
        if (currentFilters.status) params.append('status', currentFilters.status);
        if (currentFilters.search) params.append('search', currentFilters.search);

        const res = await PulseAuth.fetch(`${API_BASE}/api/v1/events?${params.toString()}`);
        if (!res.ok) throw new Error('Failed to fetch events');
        const data = await res.json();
        
        allEventsCache = data.events || [];
        renderTable(allEventsCache);
        renderPagination(data.pagination);
        updateCharts(allEventsCache);
        
    } catch (err) {
        console.error(err);
        tbody.innerHTML = `<tr><td colspan="11" style="padding: 30px; text-align: center; color: var(--sev-high);">Failed to load data</td></tr>`;
    }
}

// ── Rendering ────────────────────────────────────────────────
function renderTable(events) {
    const tbody = document.getElementById('eventsTableBody');
    tbody.innerHTML = '';
    
    if (events.length === 0) {
        tbody.innerHTML = `<tr><td colspan="11" style="padding: 30px; text-align: center; color: var(--text-muted);">No events found matching filters</td></tr>`;
        return;
    }
    
    events.forEach(ev => {
        const tr = document.createElement('tr');
        tr.className = 'event-row';
        const sevClass = (ev.severity || '').toLowerCase();
        if (sevClass === 'critical' || sevClass === 'high' || sevClass === 'alert') {
            tr.classList.add('sev-high');
        }
        tr.id = `row-${ev.event_id}`;
        
        // Short ID
        const shortId = ev.event_id.substring(0, 8);
        
        // Time
        const time = new Date(ev.timestamp).toLocaleString();
        
        // Source
        const src = ev.source?.device_id || ev.source?.vendor || ev.source_ip || 'Unknown';
        
        // Action
        const action = ev.action || ev.security?.action || 'Unknown';
        
        // Severity Badge
        const sevColorClass = ['high', 'critical'].includes(sevClass) ? 'severity-high' : 
                             ['medium'].includes(sevClass) ? 'severity-medium' : 'severity-low';
        const sevBadge = `<span class="badge ${sevColorClass}" style="padding: 4px 8px; border-radius: 4px; font-size: 11px; font-weight: 600; text-transform: uppercase;">${ev.severity}</span>`;
        
        // Status Badge
        const stat = (ev.status || '').toUpperCase();
        let statHtml = '';
        if (stat === 'SUCCESS') statHtml = `<span style="color: var(--status-normalized); font-weight: 600; font-size: 12px; background: rgba(74, 124, 63, 0.1); padding: 4px 8px; border-radius: 4px;">✔ Verified</span>`;
        else if (stat === 'FAILED') statHtml = `<span style="color: var(--sev-high); font-weight: 600; font-size: 12px; background: rgba(184, 59, 59, 0.1); padding: 4px 8px; border-radius: 4px;">✘ Tampered</span>`;
        else statHtml = `<span style="color: var(--sev-medium); font-weight: 600; font-size: 12px; background: rgba(200, 146, 42, 0.1); padding: 4px 8px; border-radius: 4px;">Pending</span>`;

        // Trust Score
        const ts = ev.trust_score;
        let tsClass = 'low';
        if (ts >= 80) tsClass = 'high';
        else if (ts >= 40) tsClass = 'medium';
        const tsHtml = ts != null ? 
            `<span style="display:flex;align-items:center;gap:6px;font-family:var(--mono);font-weight:600;"><span class="legend-dot ${tsClass}"></span>${ts}</span>` : 
            `<span style="color:var(--text-muted)">--</span>`;

        // Format
        const fmtBadge = `<span style="background: rgba(0,0,0,0.05); padding: 4px 8px; border-radius: 4px; font-family: var(--mono); font-size: 11px;">${(ev.format || ev.parser_id || 'unknown').replace('_parser','')}</span>`;
        
        // Batch
        const batch = ev.merkle_batch_id ? 
            `<span style="font-family:var(--mono);font-size:12px;">${ev.merkle_batch_id.substring(0,8)}</span>` : 
            `<span style="color:var(--sev-medium);font-size:11px;">Pending</span>`;

        tr.innerHTML = `
            <td style="padding: 12px 16px; font-family: var(--mono);">${shortId}</td>
            <td style="padding: 12px 16px; font-family: var(--mono); font-size: 12px;">${time}</td>
            <td style="padding: 12px 16px;">${src}</td>
            <td style="padding: 12px 16px; font-weight: 500;">${action}</td>
            <td style="padding: 12px 16px;">${sevBadge}</td>
            <td style="padding: 12px 16px;" id="status-cell-${ev.event_id}">${statHtml}</td>
            <td style="padding: 12px 16px;" id="ts-cell-${ev.event_id}">${tsHtml}</td>
            <td style="padding: 12px 16px;">${fmtBadge}</td>
            <td style="padding: 12px 16px; font-size: 12px; color: var(--text-muted);">${(ev.parser_id||'').replace('_parser','')}</td>
            <td style="padding: 12px 16px;">${batch}</td>
            <td class="action-cell" style="padding: 12px 16px;">
                <div style="display:flex; gap:8px;">
                    <button class="page-btn" onclick="verifyEvent('${ev.event_id}', event)">Verify</button>
                </div>
            </td>
        `;
        
        tr.addEventListener('click', (e) => {
            if (e.target.tagName === 'BUTTON' || e.target.closest('button')) return;
            openDrawer(ev);
        });
        
        tbody.appendChild(tr);
    });
}

function renderPagination(pg) {
    document.getElementById('paginationInfo').textContent = `Showing page ${pg.page} of ${pg.total_pages} (${pg.total_events} total events)`;
    const container = document.getElementById('paginationControls');
    container.innerHTML = '';
    
    if (pg.total_pages <= 1) return;
    
    // Prev
    const prev = document.createElement('button');
    prev.className = 'page-btn';
    prev.textContent = '‹';
    prev.disabled = pg.page === 1;
    prev.onclick = () => { currentPage--; fetchEvents(); };
    container.appendChild(prev);
    
    // Pages (simplified)
    const pages = [1, pg.page-1, pg.page, pg.page+1, pg.total_pages];
    const uniquePages = [...new Set(pages)].filter(p => p >= 1 && p <= pg.total_pages).sort((a,b)=>a-b);
    
    let lastP = 0;
    uniquePages.forEach(p => {
        if (p - lastP > 1) {
            const el = document.createElement('span');
            el.textContent = '...';
            el.style.color = 'var(--text-muted)';
            container.appendChild(el);
        }
        const btn = document.createElement('button');
        btn.className = 'page-btn' + (p === pg.page ? ' active' : '');
        btn.textContent = p;
        btn.onclick = () => { currentPage = p; fetchEvents(); };
        container.appendChild(btn);
        lastP = p;
    });
    
    // Next
    const next = document.createElement('button');
    next.className = 'page-btn';
    next.textContent = '›';
    next.disabled = pg.page >= pg.total_pages;
    next.onclick = () => { currentPage++; fetchEvents(); };
    container.appendChild(next);
}

// ── Charts ──────────────────────────────────────────────────
function updateCharts(events) {
    // Count Severities
    const sevCounts = {};
    const fmtCounts = {};
    
    events.forEach(e => {
        const s = (e.severity || 'unknown').toUpperCase();
        const f = (e.format || e.parser_id || 'unknown').replace('_parser','');
        sevCounts[s] = (sevCounts[s] || 0) + 1;
        fmtCounts[f] = (fmtCounts[f] || 0) + 1;
    });
    
    // Severity Chart
    const sLabels = Object.keys(sevCounts);
    const sData = Object.values(sevCounts);
    const sColors = sLabels.map(l => {
        if (l === 'CRITICAL' || l === 'HIGH') return '#B83B3B';
        if (l === 'MEDIUM') return '#C8922A';
        return '#4A7C3F';
    });
    
    if (severityChartInstance) severityChartInstance.destroy();
    severityChartInstance = new Chart(document.getElementById('severityChart'), {
        type: 'doughnut',
        data: {
            labels: sLabels,
            datasets: [{
                data: sData,
                backgroundColor: sColors,
                borderWidth: 2,
                borderColor: '#F4F1EA'
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            cutout: '55%',
            layout: { padding: 30 },
            plugins: {
                legend: { position: 'right', labels: { boxWidth: 12, font: {size: 11}, padding: 12 } },
                // Custom plugin to render outer labels
                outlabels: false
            }
        },
        plugins: [{
            id: 'doughnutOuterLabels',
            afterDraw(chart) {
                const { ctx, chartArea } = chart;
                const meta = chart.getDatasetMeta(0);
                const dataset = chart.data.datasets[0];
                const total = dataset.data.reduce((s, v) => s + v, 0);
                if (total === 0) return;
                
                meta.data.forEach((arc, i) => {
                    const val = dataset.data[i];
                    const pct = Math.round((val / total) * 100);
                    const label = chart.data.labels[i];
                    const angle = (arc.startAngle + arc.endAngle) / 2;
                    const r = arc.outerRadius + 18;
                    const cx = arc.x + Math.cos(angle) * r;
                    const cy = arc.y + Math.sin(angle) * r;

                    ctx.save();
                    ctx.font = '600 11px Inter, sans-serif';
                    ctx.textAlign = Math.cos(angle) > 0 ? 'left' : 'right';
                    ctx.textBaseline = 'middle';
                    ctx.fillStyle = dataset.backgroundColor[i];
                    ctx.fillText(`${label} (${pct}%)`, cx, cy);
                    ctx.restore();
                });
            }
        }]
    });
    
    // Format Chart
    const fLabels = Object.keys(fmtCounts);
    const fData = Object.values(fmtCounts);
    
    if (formatChartInstance) formatChartInstance.destroy();
    formatChartInstance = new Chart(document.getElementById('formatChart'), {
        type: 'bar',
        data: {
            labels: fLabels,
            datasets: [{
                label: 'Events',
                data: fData,
                backgroundColor: '#4A5D23',
                borderRadius: 4
            }]
        },
        options: {
            indexAxis: 'y',
            responsive: true,
            maintainAspectRatio: false,
            plugins: { legend: { display: false } },
            scales: {
                x: { beginAtZero: true, grid: { display: false } },
                y: { grid: { display: false }, ticks: { font: { size: 11 } } }
            }
        }
    });
}

// ── Actions ──────────────────────────────────────────────────
async function verifyEvent(id, e) {
    if (e) e.stopPropagation();
    try {
        const res = await PulseAuth.fetch(`${API_BASE}/api/v1/events/${id}/verify`, { method: 'POST' });
        if (!res.ok) throw new Error('Verify failed');
        const data = await res.json();
        
        // Update row visually inline
        const statHtml = data.overall === 'VERIFIED' ? 
            `<span style="color: var(--status-normalized); font-weight: 600; font-size: 12px; background: rgba(74, 124, 63, 0.1); padding: 4px 8px; border-radius: 4px;">✔ Verified</span>` : 
            `<span style="color: var(--sev-high); font-weight: 600; font-size: 12px; background: rgba(184, 59, 59, 0.1); padding: 4px 8px; border-radius: 4px;">✘ Tampered</span>`;
        
        document.getElementById(`status-cell-${id}`).innerHTML = statHtml;
        
        // Refresh trust score too
        const tsRes = await PulseAuth.fetch(`${API_BASE}/api/v1/events/${id}/trust-score`);
        if (tsRes.ok) {
            const tsData = await tsRes.json();
            const ts = tsData.trust_score;
            let tsClass = 'low';
            if (ts >= 80) tsClass = 'high';
            else if (ts >= 40) tsClass = 'medium';
            document.getElementById(`ts-cell-${id}`).innerHTML = 
                `<span style="display:flex;align-items:center;gap:6px;font-family:var(--mono);font-weight:600;"><span class="legend-dot ${tsClass}"></span>${ts}</span>`;
        }
        
    } catch (err) {
        console.error("Verification error:", err);
    }
}

// ── Drawer & Details ─────────────────────────────────────────
let currentDrawerEventId = null;
let confidenceChartInstance = null;

async function openDrawer(ev) {
    currentDrawerEventId = ev.event_id;
    document.getElementById('drawerOverlay').classList.add('active');
    document.getElementById('eventDrawer').classList.add('active');
    
    // Boost smooth-cursor z-index above drawer
    const cursorEl = document.getElementById('magic-cursor-container');
    if (cursorEl) cursorEl.style.zIndex = '10000';
    
    // Reset state
    document.getElementById('drawerEventId').textContent = ev.event_id;
    document.getElementById('gaugeScore').textContent = '--';
    document.getElementById('gaugeArc').style.strokeDashoffset = 339.292;
    document.getElementById('gaugeArc').style.stroke = 'var(--text-muted)';
    
    document.getElementById('drawerStatusBanner').className = 'status-banner pending';
    document.getElementById('drawerStatusBanner').innerHTML = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="width: 18px; height: 18px;"><circle cx="12" cy="12" r="10"></circle><polyline points="12 6 12 12 16 14"></polyline></svg><span>Loading...</span>`;
    
    document.getElementById('gaugeChecklist').innerHTML = '';
    ['step-raw', 'step-detect', 'step-parse', 'step-norm', 'step-enrich', 'step-valid'].forEach(id => {
        document.getElementById(id).classList.remove('visible', 'completed');
    });
    
    // Hashes
    document.getElementById('metaParser').textContent = '--';
    document.getElementById('metaVersions').textContent = '--';
    document.getElementById('metaBatch').textContent = '--';
    document.getElementById('metaRawHash').textContent = '--';
    document.getElementById('metaNormHash').textContent = '--';
    
    document.getElementById('rawPayloadContent').textContent = 'Loading...';
    document.getElementById('normPayloadContent').textContent = 'Loading...';
    document.getElementById('rawPanel').classList.remove('open');
    document.getElementById('normPanel').classList.remove('open');
    
    document.getElementById('drawerIncidentLink').style.display = 'none';

    try {
        // Fetch Trace/Score
        const [traceRes, scoreRes, rawRes, incRes] = await Promise.all([
            PulseAuth.fetch(`${API_BASE}/api/v1/events/${ev.event_id}/trace`),
            PulseAuth.fetch(`${API_BASE}/api/v1/events/${ev.event_id}/trust-score`),
            PulseAuth.fetch(`${API_BASE}/api/v1/events/${ev.event_id}/raw`),
            PulseAuth.fetch(`${API_BASE}/api/v1/incidents?page=1&page_size=100`)
        ]);
        
        if (traceRes.ok) {
            const trace = await traceRes.json();
            document.getElementById('metaParser').textContent = trace.parser_id || '--';
            document.getElementById('metaVersions').textContent = `${trace.parser_version||'--'} / ${trace.mapping_version||'--'}`;
            document.getElementById('metaBatch').textContent = trace.merkle_batch_id || 'Pending';
            document.getElementById('metaRawHash').textContent = trace.raw_hash || '--';
            document.getElementById('metaNormHash').textContent = trace.normalized_hash || '--';
        }
        
        if (scoreRes.ok) {
            const scoreData = await scoreRes.json();
            const ts = scoreData.trust_score;
            document.getElementById('gaugeScore').textContent = ts;
            
            // Animation
            const r = 54;
            const c = 2 * Math.PI * r;
            const offset = c - (ts / 100) * c;
            
            let color = 'var(--status-normalized)';
            if (ts < 40) color = 'var(--sev-high)';
            else if (ts < 80) color = 'var(--sev-medium)';
            
            const arc = document.getElementById('gaugeArc');
            // Trigger reflow
            void arc.offsetWidth;
            arc.style.strokeDashoffset = offset;
            arc.style.stroke = color;
            
            // Status banner
            const banner = document.getElementById('drawerStatusBanner');
            if (scoreData.tampering_detected) {
                banner.className = 'status-banner tampered';
                banner.innerHTML = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="width: 18px; height: 18px;"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"></path><line x1="12" y1="9" x2="12" y2="13"></line><line x1="12" y1="17" x2="12.01" y2="17"></line></svg><span>Tampering Detected</span>`;
            } else if (ts >= 80) {
                banner.className = 'status-banner verified';
                banner.innerHTML = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="width: 18px; height: 18px;"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"></path><polyline points="22 4 12 14.01 9 11.01"></polyline></svg><span>Fully Verified</span>`;
            } else {
                banner.className = 'status-banner pending';
                banner.innerHTML = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="width: 18px; height: 18px;"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="8" x2="12" y2="12"></line><line x1="12" y1="16" x2="12.01" y2="16"></line></svg><span>Pending / Low Trust</span>`;
            }

            // Checklist
            const cl = document.getElementById('gaugeChecklist');
            scoreData.checks.forEach(chk => {
                const div = document.createElement('div');
                div.className = 'check-item';
                let icon = '';
                if (chk.passed === true) {
                    icon = `<svg class="check-pass" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="20 6 9 17 4 12"></polyline></svg>`;
                } else if (chk.passed === false) {
                    icon = `<svg class="check-fail" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="18" y1="6" x2="6" y2="18"></line><line x1="6" y1="6" x2="18" y2="18"></line></svg>`;
                } else {
                    icon = `<svg class="check-pending" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"></circle><polyline points="12 6 12 12 16 14"></polyline></svg>`;
                }
                div.innerHTML = `${icon} <span>${chk.label}</span> <span style="margin-left:auto;font-family:var(--mono);font-size:11px;color:var(--text-muted);">+${chk.weight}</span>`;
                cl.appendChild(div);
            });

            // Confidence Donut
            const breakdown = scoreData.score_breakdown || {};
            if (confidenceChartInstance) confidenceChartInstance.destroy();
            
            // Generate dummy breakdown based on checks if breakdown obj is flat
            const cLabels = [];
            const cData = [];
            scoreData.checks.forEach(c => {
                if(c.passed === true) {
                    cLabels.push(c.label);
                    cData.push(c.weight);
                }
            });
            
            confidenceChartInstance = new Chart(document.getElementById('confidenceChart'), {
                type: 'doughnut',
                data: {
                    labels: cLabels,
                    datasets: [{
                        data: cData,
                        backgroundColor: ['#4A7C3F', '#5C7330', '#768c4a', '#8fa663', '#a8bf7c'],
                        borderWidth: 0
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    cutout: '60%',
                    plugins: { legend: { display: false } }
                }
            });
            
            // Stepper animation
            const steps = ['step-raw', 'step-detect', 'step-parse', 'step-norm', 'step-enrich', 'step-valid'];
            steps.forEach((s, idx) => {
                setTimeout(() => {
                    const el = document.getElementById(s);
                    el.classList.add('visible');
                    // Simple completion logic based on MVP
                    if (s === 'step-raw' || s === 'step-detect' || s === 'step-parse' || s === 'step-norm') {
                        el.classList.add('completed');
                    }
                    if (s === 'step-enrich' && ev.enrichment) {
                        el.classList.add('completed');
                    }
                    if (s === 'step-valid' && ts >= 80) {
                        el.classList.add('completed');
                    }
                }, 100 + (idx * 150));
            });
        }
        
        if (rawRes.ok) {
            const txt = await rawRes.text();
            try {
                const j = JSON.parse(txt);
                document.getElementById('rawPayloadContent').textContent = JSON.stringify(j, null, 2);
            } catch {
                document.getElementById('rawPayloadContent').textContent = txt;
            }
        }
        
        // Show normalized payload
        document.getElementById('normPayloadContent').textContent = JSON.stringify(ev, null, 2);
        
        // Incident Link
        if (incRes.ok) {
            const incData = await incRes.json();
            const incidents = incData.incidents || [];
            const found = incidents.find(inc => inc.event_ids && inc.event_ids.includes(ev.event_id));
            if (found) {
                const link = document.getElementById('drawerIncidentLink');
                link.style.display = 'inline-flex';
                link.innerHTML = `<a href="/analytics" style="background: rgba(184, 59, 59, 0.1); color: var(--sev-high); padding: 4px 10px; border-radius: 20px; font-size: 11px; font-weight: 600; text-decoration: none; display: flex; align-items: center; gap: 6px;"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="width:14px;height:14px;"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"></path></svg> Part of Incident #${found.incident_id.substring(0,8)} — ${found.technique}</a>`;
            }
        }

    } catch (err) {
        console.error("Drawer load error:", err);
    }
}

function closeDrawer() {
    document.getElementById('drawerOverlay').classList.remove('active');
    document.getElementById('eventDrawer').classList.remove('active');
    currentDrawerEventId = null;
    
    // Restore smooth-cursor z-index
    const cursorEl = document.getElementById('magic-cursor-container');
    if (cursorEl) cursorEl.style.zIndex = '100';
}

function copyText(elemId) {
    const txt = document.getElementById(elemId).textContent;
    if (txt !== '--') {
        navigator.clipboard.writeText(txt);
        // Show toast or visual feedback
        const btn = document.getElementById(elemId).nextElementSibling;
        const originalHtml = btn.innerHTML;
        btn.innerHTML = `<span style="color:var(--status-normalized);font-size:10px;">Copied</span>`;
        setTimeout(() => { btn.innerHTML = originalHtml; }, 2000);
    }
}

async function downloadCertificate() {
    if (!currentDrawerEventId) return;
    try {
        const res = await PulseAuth.fetch(`${API_BASE}/api/v1/events/${currentDrawerEventId}/custody-certificate`);
        if (!res.ok) throw new Error('Cert generation failed');
        
        // Return is JSON containing the cert data, we create a text blob
        const data = await res.json();
        const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `custody_cert_${currentDrawerEventId.substring(0,8)}.json`;
        document.body.appendChild(a);
        a.click();
        window.URL.revokeObjectURL(url);
        document.body.removeChild(a);
    } catch (err) {
        console.error("Certificate download error", err);
        alert("Failed to download custody certificate.");
    }
}

// ── Kickoff ─────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', init);
document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') closeDrawer();
});
