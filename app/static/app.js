/**
 * SecOps AI Assistant — Frontend Logic
 * Vanilla JS app for routing, API interaction, and real-time UI updates.
 */

document.addEventListener('DOMContentLoaded', () => {
    // State
    const state = {
        samples: [],
        alerts: [],
        currentAlertId: null,
        isDemoMode: false
    };

    // DOM Elements
    const views = {
        dashboard: document.getElementById('view-dashboard'),
        analyze: document.getElementById('view-analyze'),
        investigation: document.getElementById('view-investigation')
    };
    
    // UI Elements
    const alertsTbody = document.getElementById('alerts-tbody');
    const jsonInput = document.getElementById('alert-json-input');
    const sampleSelect = document.getElementById('sample-select');
    
    // Init
    init();

    async function init() {
        setupNavigation();
        setupEventListeners();
        await loadSamples();
        await loadDashboard();
        setupWebSocket();
    }

    // --- Navigation ---
    function setupNavigation() {
        // Sidebar nav
        document.querySelectorAll('.nav-item').forEach(item => {
            item.addEventListener('click', (e) => {
                e.preventDefault();
                document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
                item.classList.add('active');
                switchView(item.dataset.view);
            });
        });

        // Other buttons
        document.getElementById('btn-new-alert').addEventListener('click', () => {
            document.querySelector('[data-view="analyze"]').click();
        });
        
        document.querySelectorAll('.back-btn').forEach(btn => {
            btn.addEventListener('click', () => {
                const target = btn.dataset.target;
                document.querySelector(`[data-view="${target}"]`).click();
            });
        });
    }

    function switchView(viewName) {
        Object.values(views).forEach(v => v.classList.add('hidden'));
        if (views[viewName]) {
            views[viewName].classList.remove('hidden');
            if (viewName === 'dashboard') loadDashboard();
        }
    }

    // --- Event Listeners ---
    function setupEventListeners() {
        document.getElementById('btn-refresh').addEventListener('click', loadDashboard);
        
        document.getElementById('btn-submit-analyze').addEventListener('click', submitAnalysis);
        
        sampleSelect.addEventListener('change', async (e) => {
            const sampleId = e.target.value;
            if (!sampleId) return;
            
            try {
                const res = await fetch(`/api/samples/${sampleId}`);
                const data = await res.json();
                jsonInput.value = JSON.stringify(data, null, 2);
            } catch (err) {
                console.error("Failed to load sample", err);
            }
        });
    }

    // --- API Calls & Rendering ---
    
    async function loadSamples() {
        try {
            const res = await fetch('/api/samples');
            const data = await res.json();
            
            data.forEach(sample => {
                const opt = document.createElement('option');
                opt.value = sample.id;
                opt.textContent = sample.name;
                sampleSelect.appendChild(opt);
            });
        } catch (err) {
            console.error("Failed to load samples list", err);
        }
    }

    async function loadDashboard() {
        try {
            // Load alerts
            const alertsRes = await fetch('/api/alerts');
            const alerts = await alertsRes.json();
            renderAlertsTable(alerts);
            
            // Load stats
            const statsRes = await fetch('/api/investigations/stats');
            const stats = await statsRes.json();
            
            const critHigh = (stats.severity_breakdown.critical || 0) + (stats.severity_breakdown.high || 0);
            document.getElementById('stat-critical').textContent = critHigh;
            document.getElementById('stat-latency').textContent = (stats.avg_latency_ms / 1000).toFixed(1);
            
        } catch (err) {
            console.error("Failed to load dashboard data", err);
        }
    }

    function renderAlertsTable(alerts) {
        alertsTbody.innerHTML = '';
        
        if (alerts.length === 0) {
            alertsTbody.innerHTML = '<tr class="empty-state"><td colspan="6">No alerts ingested yet.</td></tr>';
            return;
        }
        
        alerts.forEach(alert => {
            const parsed = typeof alert.normalized_json === 'string' 
                ? JSON.parse(alert.normalized_json) 
                : alert.normalized_json;
                
            const tr = document.createElement('tr');
            const severity = parsed?.severity || 'unknown';
            const date = new Date(alert.created_at * 1000);
            
            // Determine verdict from status or try to fetch it
            let verdictBadge = `<span class="badge" style="background: rgba(255,255,255,0.1)">${alert.status}</span>`;
            if (alert.status === 'completed') {
                verdictBadge = `<span class="badge" style="background: var(--primary-glow); color: var(--primary)">ANALYZED</span>`;
            }
            
            tr.innerHTML = `
                <td><span class="badge ${severity}">${severity}</span></td>
                <td>${verdictBadge}</td>
                <td style="font-weight: 500">${parsed?.title || 'Unknown Alert'}</td>
                <td style="font-family: var(--font-mono); font-size: 0.8rem">${alert.source_format}</td>
                <td style="color: var(--text-muted); font-size: 0.85rem">${date.toLocaleTimeString()}</td>
                <td>
                    ${alert.status === 'completed' 
                        ? `<button class="btn icon-btn view-inv-btn" data-id="${alert.id}">View</button>`
                        : `<span style="font-size:0.8rem; color:var(--text-muted)">Processing...</span>`
                    }
                </td>
            `;
            alertsTbody.appendChild(tr);
        });
        
        // Add listeners to view buttons
        document.querySelectorAll('.view-inv-btn').forEach(btn => {
            btn.addEventListener('click', () => loadInvestigation(btn.dataset.id));
        });
    }

    async function submitAnalysis() {
        const rawJson = jsonInput.value.trim();
        if (!rawJson) {
            alert("Please provide alert JSON data");
            return;
        }
        
        let data;
        try {
            data = JSON.parse(rawJson);
        } catch (e) {
            alert("Invalid JSON format");
            return;
        }
        
        // Switch to investigation view in loading state
        showLoadingState();
        
        try {
            const res = await fetch('/api/alerts/analyze', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ alert_data: data })
            });
            
            const result = await res.json();
            
            if (result.demo_mode) {
                document.getElementById('demo-badge').classList.remove('hidden');
                document.getElementById('ai-status').textContent = 'AI Engine: DEMO (No API Key)';
                document.getElementById('ai-status').style.color = 'var(--sev-high)';
                document.querySelector('.status-dot').style.backgroundColor = 'var(--sev-high)';
                document.querySelector('.status-dot').style.boxShadow = '0 0 8px var(--sev-high)';
            }
            
            if (result.success && result.investigation) {
                renderInvestigation(result.investigation);
            } else {
                alert("Analysis failed: " + (result.error || "Unknown error"));
                switchView('dashboard');
            }
        } catch (err) {
            console.error(err);
            alert("API Error");
            switchView('dashboard');
        }
    }

    async function loadInvestigation(alertId) {
        showLoadingState();
        try {
            const res = await fetch(`/api/investigations/${alertId}`);
            if (!res.ok) throw new Error("Not found");
            const data = await res.json();
            
            // Try to parse if it's a string
            const inv = typeof data.investigation === 'string' ? JSON.parse(data.investigation) : data.investigation;
            renderInvestigation(inv);
        } catch (err) {
            console.error(err);
            alert("Failed to load investigation");
            switchView('dashboard');
        }
    }

    function showLoadingState() {
        switchView('investigation');
        document.getElementById('inv-results').classList.add('hidden');
        document.getElementById('inv-loading').classList.remove('hidden');
        
        // Hide header elements
        document.getElementById('inv-title').textContent = 'Analyzing...';
        document.getElementById('inv-severity-badge').style.opacity = '0';
        document.getElementById('inv-classification').textContent = '';
        
        // Simulate step progression
        const steps = document.querySelectorAll('.loading-steps .step');
        let currentStep = 0;
        
        const interval = setInterval(() => {
            steps.forEach(s => s.classList.remove('active'));
            if (currentStep < steps.length) {
                steps[currentStep].classList.add('active');
                currentStep++;
            } else {
                clearInterval(interval);
            }
        }, 800);
        
        // Store interval ID to clear it when done
        window._loadingInterval = interval;
    }

    function renderInvestigation(inv) {
        if (window._loadingInterval) clearInterval(window._loadingInterval);
        
        document.getElementById('inv-loading').classList.add('hidden');
        document.getElementById('inv-results').classList.remove('hidden');
        
        // Header
        document.getElementById('inv-title').textContent = `Alert Investigation`;
        
        const sevBadge = document.getElementById('inv-severity-badge');
        sevBadge.className = `badge ${inv.severity}`;
        sevBadge.textContent = inv.severity;
        sevBadge.style.opacity = '1';
        
        document.getElementById('inv-classification').textContent = inv.classification || '';
        
        // Confidence
        const confPct = Math.round((inv.confidence || 0) * 100);
        document.getElementById('inv-confidence-fill').style.width = `${confPct}%`;
        
        const confText = document.getElementById('inv-confidence-text');
        confText.textContent = `${confPct}%`;
        confText.style.color = confPct > 80 ? 'var(--sev-low)' : confPct > 50 ? 'var(--sev-medium)' : 'var(--sev-high)';

        // Summary
        const banner = document.getElementById('inv-verdict-banner');
        banner.className = `verdict-banner ${inv.verdict}`;
        const icons = {
            'true_positive': '🚨',
            'suspicious': '⚠️',
            'false_positive': '✅',
            'benign': '✅',
            'inconclusive': '🔍'
        };
        document.querySelector('.verdict-icon').textContent = icons[inv.verdict] || '🔍';
        document.getElementById('inv-verdict-text').textContent = (inv.verdict || 'Unknown').replace('_', ' ').toUpperCase();
        
        document.getElementById('inv-exec-summary').textContent = inv.executive_summary;
        document.getElementById('inv-root-cause').textContent = inv.root_cause_analysis;
        
        // Narrative
        const narrativeEl = document.getElementById('inv-narrative');
        if (inv.attack_narrative) {
            narrativeEl.textContent = inv.attack_narrative;
            narrativeEl.style.display = 'block';
            narrativeEl.previousElementSibling.style.display = 'block'; // heading
        } else {
            narrativeEl.style.display = 'none';
            narrativeEl.previousElementSibling.style.display = 'none';
        }

        // Actions
        const actionsList = document.getElementById('inv-actions-list');
        actionsList.innerHTML = '';
        (inv.recommended_actions || []).forEach(action => {
            const prioColor = action.priority === 'immediate' ? 'var(--sev-critical)' : 
                              action.priority === 'short_term' ? 'var(--sev-high)' : 'var(--text-muted)';
            
            actionsList.innerHTML += `
                <li class="action-item" style="border-left-color: ${prioColor}">
                    <div class="action-header">
                        <span class="action-title">${action.action}</span>
                        ${action.automated ? `<span class="badge info">Automated</span>` : ''}
                    </div>
                    <div class="action-desc">${action.description}</div>
                </li>
            `;
        });

        // Evidence
        const evList = document.getElementById('inv-evidence-list');
        evList.innerHTML = '';
        (inv.evidence || []).forEach(ev => {
            evList.innerHTML += `
                <li class="evidence-item">
                    <div class="evidence-icon">
                        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="9 11 12 14 22 4"></polyline><path d="M21 12v7a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11"></path></svg>
                    </div>
                    <div>
                        <div>${ev.description}</div>
                        <div style="font-size:0.75rem; color:var(--text-muted); margin-top:4px">
                            Source: ${ev.source} &bull; Confidence: ${ev.confidence}
                        </div>
                    </div>
                </li>
            `;
        });

        // MITRE
        const mitreList = document.getElementById('inv-mitre-list');
        mitreList.innerHTML = '';
        (inv.mitre_mapping || []).forEach(m => {
            mitreList.innerHTML += `<div class="mitre-tag" title="${m.tactic}">${m.technique_id}: ${m.technique}</div>`;
        });
        if (mitreList.innerHTML === '') mitreList.innerHTML = '<span style="color:var(--text-muted); font-size:0.85rem">No tactics mapped</span>';

        // Metadata
        document.getElementById('inv-meta-model').textContent = inv.llm_model || 'Unknown';
        document.getElementById('inv-meta-latency').textContent = (inv.analysis_latency_ms / 1000).toFixed(1);
        document.getElementById('inv-meta-tokens').textContent = (inv.token_count || 0).toLocaleString();
        document.getElementById('inv-meta-cost').textContent = (inv.estimated_cost || 0).toFixed(4);
    }

    function setupWebSocket() {
        const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
        const wsUrl = `${protocol}//${window.location.host}/ws`;
        
        try {
            const ws = new WebSocket(wsUrl);
            ws.onmessage = (event) => {
                // If we implemented background broadcast, we'd handle it here
                // e.g., auto-refreshing the dashboard when an alert completes
                console.log("WS message:", event.data);
                loadDashboard(); // simplistic auto-refresh
            };
        } catch (e) {
            console.warn("WebSocket setup failed", e);
        }
    }
});
