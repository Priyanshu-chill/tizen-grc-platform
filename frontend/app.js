// UTSGRCP v3.0 Application Controller
const API_BASE = "";

// App State
let currentView = "dashboard";
let currentDashboardTab = "executive";
let currentAssessment = null;

// Chart Instances
let chartDomainBarInstance = null;
let chartComplianceRadarInstance = null;
let chartRiskCompareInstance = null;
let chartHistoricalTrendsInstance = null;
let chartParetoInstance = null;

// Selections lists
let activeGroups = [];
let activeDevices = [];
let analysts = [
    { id: 1, username: "superadmin", role: "Super Administrator" },
    { id: 3, username: "secadmin", role: "Security Administrator" },
    { id: 6, username: "analyst", role: "Security Analyst" }
];

// DOM Ready
document.addEventListener("DOMContentLoaded", () => {
    // Check Auth
    const token = localStorage.getItem("token");
    if (!token) {
        showLoginScreen();
    } else {
        hideLoginScreen();
        initializePlatform();
    }
});

function showLoginScreen() {
    document.getElementById("loginOverlay").classList.remove("d-none");
    document.getElementById("appContainer").classList.add("d-none");
}

function hideLoginScreen() {
    document.getElementById("loginOverlay").classList.add("d-none");
    document.getElementById("appContainer").classList.remove("d-none");
}

// Login Handler
async function handleLogin(e) {
    e.preventDefault();
    const user = document.getElementById("loginUsername").value;
    const pass = document.getElementById("loginPassword").value;
    const errorDiv = document.getElementById("loginError");
    
    errorDiv.classList.add("d-none");
    
    const formData = new FormData();
    formData.append("username", user);
    formData.append("password", pass);
    
    try {
        const res = await fetch("/api/auth/login", {
            method: "POST",
            body: formData
        });
        
        if (res.ok) {
            const data = await res.json();
            localStorage.setItem("token", data.access_token);
            localStorage.setItem("username", data.username);
            localStorage.setItem("role", data.role);
            
            hideLoginScreen();
            initializePlatform();
        } else {
            const err = await res.json();
            errorDiv.innerText = err.detail || "Authentication failed. Try again.";
            errorDiv.classList.remove("d-none");
        }
    } catch (err) {
        console.error(err);
        errorDiv.innerText = "Error contacting authorization server.";
        errorDiv.classList.remove("d-none");
    }
}

function logout() {
    localStorage.clear();
    showLoginScreen();
}

function getHeaders() {
    return {
        "Authorization": `Bearer ${localStorage.getItem("token")}`
    };
}

// Initialize Application Data
async function initializePlatform() {
    document.getElementById("userDisplay").innerHTML = `<i class="bi bi-person-circle me-1"></i> ${localStorage.getItem("username")} (${localStorage.getItem("role")})`;
    
    // Load dropdown selections
    await fetchDeviceGroups();
    await fetchDevices();
    await fetchAssessmentsForReports();
    await loadControlsLibrary();
    
    // Default View
    switchView("dashboard");
    
    // Fill Analyst lists in Assign workflow drop-down
    const assignSelect = document.getElementById("workflowAssignSelect");
    assignSelect.innerHTML = '<option value="">-- Choose Security Analyst --</option>' +
        analysts.map(a => `<option value="${a.id}">${a.username} (${a.role})</option>`).join("");
}

// Fetch multi-tenant building hierarchies
async function fetchDeviceGroups() {
    try {
        const res = await fetch("/api/device-groups", { headers: getHeaders() });
        if (res.ok) {
            activeGroups = await res.json();
            const select = document.getElementById("deviceGroupSelect");
            select.innerHTML = activeGroups.map(g => `<option value="${g.id}">${g.name} (Building site: ${g.building_id})</option>`).join("");
        }
    } catch (err) {
        console.error("Error fetching device groups:", err);
    }
}

async function fetchDevices() {
    try {
        const res = await fetch("/api/devices", { headers: getHeaders() });
        if (res.ok) {
            activeDevices = await res.json();
            const select = document.getElementById("assessmentDeviceSelect");
            select.innerHTML = activeDevices.map(d => `<option value="${d.id}">${d.name} (${d.model})</option>`).join("");
        }
    } catch (err) {
        console.error("Error fetching devices:", err);
    }
}

async function fetchAssessmentsForReports() {
    try {
        const res = await fetch("/api/assessments", { headers: getHeaders() });
        if (res.ok) {
            const list = await res.json();
            const select = document.getElementById("reportAssessmentSelect");
            select.innerHTML = '<option value="">-- Choose Active Assessment --</option>' + 
                list.map(a => `<option value="${a.id}">${a.device.name} [Posture: ${a.posture_score.toFixed(1)} | Risk: ${a.risk_score.toFixed(1)}]</option>`).join("");
        }
    } catch (err) {
        console.error("Error fetching assessments for reporting dropdown:", err);
    }
}


// --- SPA ROUTING ---
function switchView(viewName) {
    currentView = viewName;
    
    // Sidebar highlights
    document.querySelectorAll(".sidebar .nav-link").forEach(link => {
        link.classList.remove("active");
    });
    
    const activeNav = document.getElementById(`navLink${viewName.charAt(0).toUpperCase() + viewName.slice(1)}`);
    if (activeNav) activeNav.classList.add("active");
    
    // Toggle displays
    document.querySelectorAll(".view-section").forEach(sec => {
        sec.classList.add("d-none");
    });
    document.getElementById(`view-${viewName}`).classList.remove("d-none");
    
    if (viewName !== "assessments") {
        closeWorkbench();
    }
    
    // View triggers
    if (viewName === "dashboard") {
        loadDashboardData();
    } else if (viewName === "devices") {
        loadDevicesTable();
    } else if (viewName === "assessments") {
        loadAssessmentsTable();
    }
}


// --- 6 DASHBOARDS MANAGER ---
function switchDashboardTab(tabName) {
    currentDashboardTab = tabName;
    
    // Pill highlight toggle
    document.querySelectorAll("#dashboardTabs button").forEach(btn => {
        btn.classList.remove("active");
        if (btn.innerText.toLowerCase() === tabName) {
            btn.classList.add("active");
        }
    });
    
    // Content toggle
    document.querySelectorAll(".db-tab-content").forEach(content => {
        content.classList.add("d-none");
    });
    document.getElementById(`db-tab-${tabName}`).classList.remove("d-none");
    
    // Re-draw chart layers if active tab changed
    loadDashboardData();
}

async function loadDashboardData() {
    try {
        const res = await fetch("/api/dashboard/stats", { headers: getHeaders() });
        if (!res.ok) {
            if (res.status === 401) logout();
            return;
        }
        const data = await res.json();
        
        // Bind executive stats widgets
        document.getElementById("statPostureScore").innerText = data.average_posture_score.toFixed(1);
        document.getElementById("statPostureBar").style.width = `${data.average_posture_score}%`;
        
        document.getElementById("statCompliance").innerText = `${data.overall_compliance.toFixed(1)}%`;
        document.getElementById("statComplianceBar").style.width = `${data.overall_compliance}%`;
        
        document.getElementById("statAttackSurface").innerText = data.average_attack_surface.toFixed(1);
        document.getElementById("statAttackSurfaceBar").style.width = `${data.average_attack_surface}%`;
        
        document.getElementById("statRisk").innerText = data.average_risk_score.toFixed(1);
        const rBadge = document.getElementById("statRiskBadge");
        rBadge.innerText = data.average_risk_score <= 20 ? "Low Risk" : data.average_risk_score <= 50 ? "Medium Risk" : data.average_risk_score <= 80 ? "High Risk" : "Critical Risk";
        rBadge.className = `badge mt-2 ${data.average_risk_score <= 20 ? 'badge-pass' : data.average_risk_score <= 50 ? 'badge-partial' : 'badge-fail'}`;
        
        // Execute dynamic bindings based on visible dashboard tab
        if (currentDashboardTab === "executive") {
            document.getElementById("execTotalDevices").innerText = data.total_devices;
            document.getElementById("execCompliantDevices").innerText = data.compliant_devices;
            document.getElementById("execNonCompliantDevices").innerText = data.non_compliant_devices;
            
            // Maturity Rating Calculation
            const matLvl = data.recent_assessments.length > 0 ? Math.max(...data.recent_assessments.map(a => a.maturity_level)) : 1;
            document.getElementById("statMaturityVal").innerText = `Level ${matLvl}`;
            const maturityDescriptions = {
                1: "Level 1: Initial baseline audits active. Security checks incomplete.",
                2: "Level 2: Basic compliance established. Residual risks under tracking.",
                3: "Level 3: Hardened configurations. Active sandboxing enforced.",
                4: "Level 4: Managed security metrics. Evidence logs verified regularly.",
                5: "Level 5: Optimized continuously. Zero posture drift detected."
            };
            document.getElementById("statMaturityDesc").innerText = maturityDescriptions[matLvl] || maturityDescriptions[1];
            
            renderDomainBarChart(data.domain_compliance);
        }
        
        if (currentDashboardTab === "compliance") {
            renderComplianceRadar(data.domain_compliance);
            populatePolicyRegistry();
        }
        
        if (currentDashboardTab === "risk") {
            renderRiskComparison(data.domain_compliance);
            loadActiveExceptions();
        }
        
        if (currentDashboardTab === "analytics") {
            renderParetoChart(data.domain_compliance);
            loadHistoricalTrendsChart();
        }
        
        if (currentDashboardTab === "operations") {
            loadDriftFeed();
            // Pre-run simulator default if device is selected in report select
            runSimulation();
        }
        
        // Always populate recent assessments and top failed controls
        populateRecentAssessmentsTable(data.recent_assessments);
        populateTopFailedList(data.top_failed_controls);
        
    } catch (err) {
        console.error("Dashboard stats loader error:", err);
    }
}

// --- Dynamic Table binders ---
function populateRecentAssessmentsTable(list) {
    const table = document.getElementById("dashboardAssessmentsTable");
    if (list.length === 0) {
        table.innerHTML = `<tr><td colspan="6" class="text-center text-secondary py-3">No assessments run yet.</td></tr>`;
        return;
    }
    table.innerHTML = list.map(a => `
        <tr>
            <td><span class="fw-bold text-white">${a.device.name}</span><br><small class="text-secondary">${a.device.model}</small></td>
            <td><span class="badge bg-dark border border-secondary text-light">Level ${a.maturity_level}</span></td>
            <td><span class="fw-bold text-success">${a.compliance_percentage.toFixed(1)}%</span></td>
            <td><span class="fw-semibold text-danger">${a.risk_score.toFixed(1)}</span></td>
            <td><span class="fw-bold text-glow text-primary">${a.posture_score.toFixed(1)}</span></td>
            <td><small class="text-secondary">${a.assessor ? a.assessor.username : 'System Auto'}</small></td>
        </tr>
    `).join("");
}

function populateTopFailedList(list) {
    const box = document.getElementById("dashboardTopFailedList");
    if (list.length === 0) {
        box.innerHTML = `<div class="text-secondary small py-2 text-center">No failed controls found. All devices are compliant!</div>`;
        return;
    }
    box.innerHTML = list.map(fc => `
        <div class="list-group-item bg-transparent border-secondary-subtle px-0 d-flex justify-content-between align-items-center">
            <div>
                <span class="badge bg-danger-subtle text-danger border border-danger-subtle me-2">${fc.control_id}</span>
                <span class="text-white small">${fc.name}</span>
            </div>
            <span class="badge bg-secondary-subtle text-secondary">${fc.failed_count} device failed</span>
        </div>
    `).join("");
}


// --- 1. EXECUTIVE BAR CHART ---
function renderDomainBarChart(domains) {
    const ctx = document.getElementById("chartDomainBar").getContext("2d");
    if (chartDomainBarInstance) chartDomainBarInstance.destroy();
    
    chartDomainBarInstance = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: domains.map(d => d.domain),
            datasets: [{
                data: domains.map(d => d.compliance_percentage),
                backgroundColor: 'rgba(59, 130, 246, 0.45)',
                borderColor: '#3b82f6',
                borderWidth: 1.5,
                borderRadius: 4
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: { legend: { display: false } },
            scales: {
                x: { grid: { display: false }, ticks: { color: '#94a3b8', font: { size: 9 } } },
                y: { grid: { color: 'rgba(255,255,255,0.05)' }, ticks: { color: '#94a3b8' }, min: 0, max: 100 }
            }
        }
    });
}

// --- 3. COMPLIANCE RADAR CHART ---
function renderComplianceRadar(domains) {
    const ctx = document.getElementById("chartComplianceRadar").getContext("2d");
    if (chartComplianceRadarInstance) chartComplianceRadarInstance.destroy();
    
    chartComplianceRadarInstance = new Chart(ctx, {
        type: 'radar',
        data: {
            labels: domains.map(d => d.domain.split(" ")[0]), // short codes BHS, KOH, etc.
            datasets: [{
                label: 'Compliance Rate %',
                data: domains.map(d => d.compliance_percentage),
                backgroundColor: 'rgba(16, 185, 129, 0.25)',
                borderColor: '#10b981',
                pointBackgroundColor: '#10b981',
                borderWidth: 2
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                r: {
                    grid: { color: 'rgba(255,255,255,0.08)' },
                    angleLines: { color: 'rgba(255,255,255,0.08)' },
                    pointLabels: { color: '#94a3b8' },
                    ticks: { display: false, min: 0, max: 100 }
                }
            }
        }
    });
}

function populatePolicyRegistry() {
    fetch("/api/controls", { headers: getHeaders() })
        .then(res => res.json())
        .then(list => {
            const body = document.getElementById("policyRegistryBody");
            body.innerHTML = list.slice(0, 15).map(c => {
                const guide = JSON.parse(c.remediation_guide || "{}");
                return `
                    <tr>
                        <td><span class="font-monospace text-glow text-primary small">${c.control_id}.json</span></td>
                        <td><span class="badge bg-secondary-subtle text-light small">v3.0.0</span></td>
                        <td><small class="text-secondary">${c.review_frequency_days} Days</small></td>
                        <td><span class="small font-monospace">${c.validation_type}</span></td>
                        <td><span class="small text-secondary">${c.policy_owner}</span></td>
                    </tr>
                `;
            }).join("");
        });
}

// --- 4. RISK INHERENT VS RESIDUAL COMPARISON ---
function renderRiskComparison(domains) {
    const ctx = document.getElementById("chartRiskCompare").getContext("2d");
    if (chartRiskCompareInstance) chartRiskCompareInstance.destroy();
    
    // Mock comparative parameters mapping for visual representation
    const inherentScores = domains.map(d => 100 - (d.compliance_percentage * 0.2));
    const residualScores = domains.map(d => 100 - d.compliance_percentage);
    
    chartRiskCompareInstance = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: domains.map(d => d.domain.split(" ")[0]),
            datasets: [
                {
                    label: 'Inherent Risk',
                    data: inherentScores,
                    backgroundColor: 'rgba(244, 63, 94, 0.4)',
                    borderColor: '#f43f5e',
                    borderWidth: 1
                },
                {
                    label: 'Residual Risk',
                    data: residualScores,
                    backgroundColor: 'rgba(59, 130, 246, 0.5)',
                    borderColor: '#3b82f6',
                    borderWidth: 1
                }
            ]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                x: { ticks: { color: '#94a3b8' } },
                y: { grid: { color: 'rgba(255,255,255,0.05)' }, ticks: { color: '#94a3b8' } }
            }
        }
    });
}

async function loadActiveExceptions() {
    try {
        const res = await fetch("/api/assessments", { headers: getHeaders() });
        if (!res.ok) return;
        const assessments = await res.json();
        
        let exceptions = [];
        for (let a of assessments) {
            const detailRes = await fetch(`/api/assessments/${a.id}`, { headers: getHeaders() });
            if (detailRes.ok) {
                const data = await detailRes.json();
                const active = data.findings.filter(f => f.risk_accepted);
                exceptions = exceptions.concat(active);
            }
        }
        
        const body = document.getElementById("exceptionsRegistryBody");
        if (exceptions.length === 0) {
            body.innerHTML = `<tr><td colspan="4" class="text-center text-secondary py-3">No active exceptions registered.</td></tr>`;
            return;
        }
        
        body.innerHTML = exceptions.map(exc => `
            <tr>
                <td><span class="badge bg-warning-subtle text-warning border border-warning">${exc.control.control_id}</span></td>
                <td><small class="text-white">${exc.risk_exception_reason || 'N/A'}</small></td>
                <td><small class="text-secondary font-monospace">${exc.risk_exception_expiry ? new Date(exc.risk_exception_expiry).toLocaleDateString() : 'Never'}</small></td>
                <td><span class="badge bg-success small">Approved</span></td>
            </tr>
        `).join("");
    } catch(err) {
        console.error(err);
    }
}

// --- 5. ANALYTICS TRAJECTORY AND PARETO ---
async function loadHistoricalTrendsChart() {
    const ctx = document.getElementById("chartHistoricalTrends").getContext("2d");
    if (chartHistoricalTrendsInstance) chartHistoricalTrendsInstance.destroy();
    
    // Fetch device trends (Korea smart signage as reference)
    try {
        const res = await fetch("/api/analytics/1/history", { headers: getHeaders() });
        if (res.ok) {
            const data = await res.json();
            
            const labels = data.map(h => new Date(h.timestamp).toLocaleDateString());
            const complianceData = data.map(h => h.compliance_percentage);
            const riskData = data.map(h => h.risk_score);
            const postureData = data.map(h => h.posture_score);
            
            chartHistoricalTrendsInstance = new Chart(ctx, {
                type: 'line',
                data: {
                    labels: labels.length > 0 ? labels : ['6/24', '6/25', '6/26', '6/27', '6/28', '6/29'],
                    datasets: [
                        {
                            label: 'Posture Score',
                            data: postureData.length > 0 ? postureData : [65, 68, 70, 75, 78, 80],
                            borderColor: '#3b82f6',
                            backgroundColor: 'transparent',
                            tension: 0.2
                        },
                        {
                            label: 'Compliance %',
                            data: complianceData.length > 0 ? complianceData : [72, 75, 76, 80, 84, 88],
                            borderColor: '#10b981',
                            backgroundColor: 'transparent',
                            tension: 0.2
                        },
                        {
                            label: 'Residual Risk %',
                            data: riskData.length > 0 ? riskData : [45, 42, 38, 30, 25, 20],
                            borderColor: '#f43f5e',
                            backgroundColor: 'transparent',
                            tension: 0.2
                        }
                    ]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    scales: {
                        x: { ticks: { color: '#94a3b8' } },
                        y: { grid: { color: 'rgba(255,255,255,0.05)' }, ticks: { color: '#94a3b8' } }
                    }
                }
            });
        }
    } catch (err) {
        console.error(err);
    }
}

function renderParetoChart(domains) {
    const ctx = document.getElementById("chartPareto").getContext("2d");
    if (chartParetoInstance) chartParetoInstance.destroy();
    
    // Sort failed counts in descending order (Pareto rule)
    const sorted = [...domains].sort((a,b) => b.failed_count - a.failed_count);
    
    chartParetoInstance = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: sorted.map(s => s.domain.split(" ")[0]),
            datasets: [{
                label: 'Failure Frequency (Pareto)',
                data: sorted.map(s => s.failed_count),
                backgroundColor: 'rgba(245, 158, 11, 0.45)',
                borderColor: '#f59e0b',
                borderWidth: 1
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                x: { ticks: { color: '#94a3b8' } },
                y: { grid: { color: 'rgba(255,255,255,0.05)' }, ticks: { color: '#94a3b8' } }
            }
        }
    });
}

// --- 6. OPERATIONS DRIFT ALERTS FEED ---
async function loadDriftFeed() {
    try {
        const res = await fetch("/api/notifications", { headers: getHeaders() });
        if (!res.ok) return;
        const alerts = await res.json();
        
        const container = document.getElementById("driftAlertList");
        if (alerts.length === 0) {
            container.innerHTML = `<div class="text-secondary small py-4 text-center"><i class="bi bi-shield-check text-success fs-4 d-block mb-2"></i>No configuration drifts detected in latest scans.</div>`;
            return;
        }
        
        container.innerHTML = alerts.map(a => `
            <div class="list-group-item bg-transparent text-light border-secondary-subtle py-2 px-0 d-flex justify-content-between align-items-start">
                <div>
                    <span class="badge bg-warning text-dark me-2 small">${a.type}</span>
                    <span class="small">${a.message}</span>
                    <div class="text-secondary small mt-1 font-monospace" style="font-size:10px;">${new Date(a.created_at).toLocaleString()}</div>
                </div>
                ${!a.is_read ? `<button class="btn btn-outline-info btn-xs py-0" onclick="markRead(${a.id})">Clear</button>` : ''}
            </div>
        `).join("");
    } catch(err) {
        console.error(err);
    }
}

async function markRead(notifId) {
    try {
        const res = await fetch(`/api/notifications/${notifId}/read`, {
            method: "POST",
            headers: getHeaders()
        });
        if (res.ok) {
            loadDriftFeed();
        }
    } catch (err) {
        console.error(err);
    }
}


// --- COMPLIANCE SIMULATOR DRIVER ---
async function runSimulation() {
    const select = document.getElementById("reportAssessmentSelect");
    const assessmentId = select.value || 1; // Default to Seoul Signage assessment id if empty
    
    const payload = {
        fix_firmware: document.getElementById("sim_firmware").checked,
        fix_secure_boot: document.getElementById("sim_secure_boot").checked,
        fix_usb: document.getElementById("sim_usb").checked,
        fix_bluetooth: document.getElementById("sim_bluetooth").checked
    };
    
    try {
        const res = await fetch(`/api/assessments/${assessmentId}/sim`, {
            method: "POST",
            headers: {
                ...getHeaders(),
                "Content-Type": "application/json"
            },
            body: JSON.stringify(payload)
        });
        
        if (res.ok) {
            const data = await res.json();
            
            document.getElementById("sim_res_compliance").innerText = `${data.current.compliance.toFixed(1)}% -> ${data.predicted.compliance.toFixed(1)}%`;
            document.getElementById("sim_res_compliance_gain").innerText = `+${data.improvements.compliance_gain.toFixed(1)}%`;
            
            document.getElementById("sim_res_risk").innerText = `${data.current.risk.toFixed(1)} -> ${data.predicted.risk.toFixed(1)}`;
            document.getElementById("sim_res_risk_reduction").innerText = `-${data.improvements.risk_reduction.toFixed(1)}`;
            
            document.getElementById("sim_res_posture").innerText = `${data.current.posture.toFixed(1)} -> ${data.predicted.posture.toFixed(1)}`;
            document.getElementById("sim_res_posture_gain").innerText = `+${data.improvements.posture_gain.toFixed(1)}`;
            
            document.getElementById("sim_res_surface").innerText = `${data.current.attack_surface.toFixed(1)} -> ${data.predicted.attack_surface.toFixed(1)}`;
            document.getElementById("sim_res_surface_reduction").innerText = `-${data.improvements.attack_surface_reduction.toFixed(1)}`;
        }
    } catch (err) {
        console.error("Simulation error:", err);
    }
}


// --- DEVICES MANAGER ---
async function loadDevicesTable() {
    try {
        const res = await fetch("/api/devices", { headers: getHeaders() });
        if (!res.ok) return;
        const list = await res.json();
        
        const body = document.getElementById("devicesTableBody");
        if (list.length === 0) {
            body.innerHTML = `<tr><td colspan="8" class="text-center text-secondary py-3">No device assets registered.</td></tr>`;
            return;
        }
        
        body.innerHTML = list.map(d => `
            <tr>
                <td><span class="fw-bold text-white">${d.name}</span></td>
                <td><span class="text-white small">${d.model}</span></td>
                <td><code>${d.serial_number}</code></td>
                <td><span class="badge bg-secondary-subtle text-light">${d.firmware_version}</span></td>
                <td><small class="text-secondary">Group ID: ${d.device_group_id}</small></td>
                <td>
                    <small class="text-white d-block">IP: ${d.ip_address || 'N/A'}</small>
                    <small class="text-secondary">MAC: ${d.mac_address || 'N/A'}</small>
                </td>
                <td><span class="badge ${d.business_criticality === 'HIGH' ? 'bg-danger text-light' : 'bg-secondary text-light'}">${d.business_criticality}</span></td>
                <td>
                    <button class="btn btn-outline-primary btn-sm py-0 px-2" onclick="createAssessmentForDevice(${d.id})">
                        <i class="bi bi-shield-check"></i> Assess
                    </button>
                </td>
            </tr>
        `).join("");
    } catch(err) {
        console.error(err);
    }
}

async function handleRegisterDevice(e) {
    e.preventDefault();
    const payload = {
        name: document.getElementById("deviceName").value,
        model: document.getElementById("deviceModel").value,
        serial_number: document.getElementById("deviceSerial").value,
        firmware_version: document.getElementById("deviceFirmware").value,
        ip_address: document.getElementById("deviceIp").value,
        mac_address: document.getElementById("deviceMac").value,
        device_group_id: parseInt(document.getElementById("deviceGroupSelect").value),
        business_criticality: "MEDIUM",
        installed_applications: "[]",
        certificates: "[]"
    };
    
    try {
        const res = await fetch("/api/devices", {
            method: "POST",
            headers: {
                ...getHeaders(),
                "Content-Type": "application/json"
            },
            body: JSON.stringify(payload)
        });
        
        if (res.ok) {
            bootstrap.Modal.getInstance(document.getElementById("registerDeviceModal")).hide();
            document.getElementById("registerDeviceForm").reset();
            await initializePlatform();
            loadDevicesTable();
        } else {
            alert("Error registering device asset.");
        }
    } catch(err) {
        console.error(err);
    }
}

async function createAssessmentForDevice(deviceId) {
    try {
        const res = await fetch("/api/assessments", {
            method: "POST",
            headers: {
                ...getHeaders(),
                "Content-Type": "application/json"
            },
            body: JSON.stringify({ device_id: deviceId })
        });
        
        if (res.ok) {
            const data = await res.json();
            await initializePlatform();
            switchView("assessments");
            loadAssessmentWorkbench(data.id);
        } else {
            alert("Failed launching compliance assessment.");
        }
    } catch (err) {
        console.error(err);
    }
}


// --- ASSESSMENTS WORKBENCH DRIVER ---
async function loadAssessmentsTable() {
    try {
        const res = await fetch("/api/assessments", { headers: getHeaders() });
        if (!res.ok) return;
        const list = await res.json();
        
        const body = document.getElementById("assessmentsTableBody");
        if (list.length === 0) {
            body.innerHTML = `<tr><td colspan="7" class="text-center text-secondary py-3">No compliance assessments running.</td></tr>`;
            return;
        }
        
        body.innerHTML = list.map(a => `
            <tr>
                <td><span class="fw-bold text-white">${a.device.name}</span><br><small class="text-secondary">${a.device.model}</small></td>
                <td><span class="small text-secondary">${a.assessor ? a.assessor.username : 'System Auto'}</span></td>
                <td><span class="fw-bold text-success">${a.compliance_percentage.toFixed(1)}%</span></td>
                <td><span class="fw-semibold text-danger">${a.risk_score.toFixed(1)}</span></td>
                <td><span class="fw-bold text-glow text-primary">${a.posture_score.toFixed(1)}</span></td>
                <td><span class="badge bg-dark border border-secondary text-light">Level ${a.maturity_level}</span></td>
                <td>
                    <button class="btn btn-outline-info btn-sm py-0 px-2" onclick="loadAssessmentWorkbench(${a.id})">
                        <i class="bi bi-tools"></i> Open Workbench
                    </button>
                </td>
            </tr>
        `).join("");
    } catch(err) {
        console.error(err);
    }
}

async function handleNewAssessment(e) {
    e.preventDefault();
    const payload = {
        device_id: parseInt(document.getElementById("assessmentDeviceSelect").value)
    };
    try {
        const res = await fetch("/api/assessments", {
            method: "POST",
            headers: {
                ...getHeaders(),
                "Content-Type": "application/json"
            },
            body: JSON.stringify(payload)
        });
        
        if (res.ok) {
            const data = await res.json();
            bootstrap.Modal.getInstance(document.getElementById("newAssessmentModal")).hide();
            await initializePlatform();
            loadAssessmentsTable();
            loadAssessmentWorkbench(data.id);
        } else {
            alert("Error launch assessment.");
        }
    } catch (err) {
        console.error(err);
    }
}

async function loadAssessmentWorkbench(assessmentId) {
    try {
        const res = await fetch(`/api/assessments/${assessmentId}`, { headers: getHeaders() });
        if (!res.ok) return;
        currentAssessment = await res.json();
        
        document.getElementById("assessmentWorkbench").classList.remove("d-none");
        document.getElementById("workbenchDeviceMeta").innerHTML = `
            <strong>Device:</strong> ${currentAssessment.device.name} |
            <strong>Compliance:</strong> <span class="text-success fw-bold">${currentAssessment.compliance_percentage.toFixed(1)}%</span> |
            <strong>Posture Score:</strong> <span class="text-primary fw-bold">${currentAssessment.posture_score.toFixed(1)}</span> |
            <strong>Risk Rating:</strong> <span class="text-danger fw-bold">${currentAssessment.risk_score.toFixed(1)}</span>
        `;
        
        const domainSelect = document.getElementById("workbenchDomainFilter");
        const uniqueDomains = [...new Set(currentAssessment.findings.map(f => f.control.domain))];
        domainSelect.innerHTML = '<option value="ALL">All Domains</option>' + 
            uniqueDomains.map(d => `<option value="${d}">${d}</option>`).join("");
            
        renderFindingsTable(currentAssessment.findings);
    } catch(err) {
        console.error(err);
    }
}

function closeWorkbench() {
    document.getElementById("assessmentWorkbench").classList.add("d-none");
    currentAssessment = null;
}

function renderFindingsTable(findings) {
    const body = document.getElementById("workbenchFindingsBody");
    body.innerHTML = findings.map(f => `
        <tr>
            <td><span class="badge bg-secondary-subtle text-white border border-secondary">${f.control.control_id}</span></td>
            <td>
                <span class="fw-bold text-white small d-block">${f.control.name}</span>
                <small class="text-secondary text-truncate d-block" style="max-width:280px;">${f.control.description}</small>
            </td>
            <td><span class="badge bg-dark ${getSeverityBorderClass(f.control.severity)} text-light small">${f.control.severity}</span></td>
            <td><small class="text-secondary font-monospace small">${f.control.validation_type}</small></td>
            <td><span class="small font-monospace">${f.inherent_risk.toFixed(1)}</span></td>
            <td><span class="small font-monospace ${f.risk_accepted ? 'text-success' : 'text-danger'}">${f.residual_risk.toFixed(1)}</span></td>
            <td><span class="badge ${getStatusBadgeClass(f.status)}">${f.status}</span></td>
            <td>
                ${f.evidence_links.length > 0 
                    ? f.evidence_links.map(ev => `<div class="small text-primary"><i class="bi bi-file-earmark-check"></i> ${ev.file_name} <br> <code style="font-size:9px;" class="text-secondary">SHA: ${ev.sha256_hash.slice(0, 10)}...</code></div>`).join("")
                    : '<span class="text-secondary small">No evidence</span>'
                }
            </td>
            <td>
                <button class="btn btn-outline-light btn-xs py-0 px-2" onclick="openEditFindingModal(${f.id}, '${f.control.control_id}', '${f.control.name.replace(/'/g, "\\'")}', '${f.control.description.replace(/'/g, "\\'")}', '${f.status}', '${(f.comments || "").replace(/'/g, "\\'")}', ${f.assigned_to || 'null'}, ${f.risk_accepted})">
                    <i class="bi bi-pencil-square"></i> Review
                </button>
            </td>
        </tr>
    `).join("");
}

function getStatusBadgeClass(status) {
    if (status === "PASS") return "badge-pass";
    if (status === "FAIL") return "badge-fail";
    if (status === "PARTIALLY_COMPLIANT") return "badge-partial";
    return "badge-na";
}

function getSeverityBorderClass(sev) {
    if (sev === "CRITICAL") return "border border-danger text-danger";
    if (sev === "HIGH") return "border border-warning text-warning";
    if (sev === "MEDIUM") return "border border-primary text-primary";
    return "border border-secondary text-secondary";
}

function filterFindings() {
    if (!currentAssessment) return;
    const domainVal = document.getElementById("workbenchDomainFilter").value;
    const statusVal = document.getElementById("workbenchStatusFilter").value;
    
    let filtered = currentAssessment.findings;
    if (domainVal !== "ALL") filtered = filtered.filter(f => f.control.domain === domainVal);
    if (statusVal !== "ALL") filtered = filtered.filter(f => f.status === statusVal);
    
    renderFindingsTable(filtered);
}

async function triggerScan() {
    if (!currentAssessment) return;
    const btn = document.getElementById("btnRunScan");
    btn.disabled = true;
    btn.innerHTML = `<span class="spinner-border spinner-border-sm me-1"></span> Scanning...`;
    
    try {
        const res = await fetch(`/api/assessments/${currentAssessment.id}/scan`, {
            method: "POST",
            headers: getHeaders()
        });
        if (res.ok) {
            await loadAssessmentWorkbench(currentAssessment.id);
            await loadAssessmentsTable();
        }
    } catch(err) {
        console.error(err);
    } finally {
        btn.disabled = false;
        btn.innerHTML = `<i class="bi bi-cpu me-1"></i> Simulate Automated Scan`;
    }
}


// --- REVIEW MODAL WORKFLOW & EXCEPTIONS ---
function openEditFindingModal(findingId, controlId, name, desc, status, comments, assignedTo, riskAccepted) {
    document.getElementById("findingModalId").value = findingId;
    document.getElementById("findingModalControlId").innerText = controlId;
    document.getElementById("findingModalControlName").innerText = name;
    document.getElementById("findingModalControlDesc").innerText = desc;
    document.getElementById("findingStatusSelect").value = status;
    document.getElementById("findingComments").value = comments;
    
    // Workflow Assignee dropdown selection
    document.getElementById("workflowAssignSelect").value = assignedTo || "";
    
    // Exception switch
    document.getElementById("exc_active").checked = riskAccepted;
    
    // Upload list render
    const evidenceList = document.getElementById("uploadedEvidenceList");
    const findingObj = currentAssessment.findings.find(f => f.id === findingId);
    if (findingObj && findingObj.evidence_links.length > 0) {
        evidenceList.innerHTML = findingObj.evidence_links.map(ev => `
            <li class="list-group-item bg-transparent border-secondary px-0 text-secondary small d-flex flex-column">
                <div class="d-flex justify-content-between">
                    <span><i class="bi bi-file-earmark-check text-primary me-1"></i> ${ev.file_name}</span>
                    <span class="small">${new Date(ev.uploaded_at).toLocaleDateString()}</span>
                </div>
                <div style="font-size:9px;" class="font-monospace text-secondary mt-1">SHA-256: ${ev.sha256_hash}</div>
            </li>
        `).join("");
    } else {
        evidenceList.innerHTML = `<li class="list-group-item bg-transparent border-0 px-0 text-secondary small">No evidence files uploaded yet.</li>`;
    }
    
    const modal = new bootstrap.Modal(document.getElementById("editFindingModal"));
    modal.show();
}

async function handleEditFinding(e) {
    e.preventDefault();
    const id = document.getElementById("findingModalId").value;
    const payload = {
        status: document.getElementById("findingStatusSelect").value,
        comments: document.getElementById("findingComments").value
    };
    
    try {
        const res = await fetch(`/api/findings/${id}`, {
            method: "PUT",
            headers: {
                ...getHeaders(),
                "Content-Type": "application/json"
            },
            body: JSON.stringify(payload)
        });
        
        if (res.ok) {
            bootstrap.Modal.getInstance(document.getElementById("editFindingModal")).hide();
            await loadAssessmentWorkbench(currentAssessment.id);
            await loadAssessmentsTable();
        }
    } catch(err) {
        console.error(err);
    }
}

async function assignWorkflow() {
    const id = document.getElementById("findingModalId").value;
    const analystId = document.getElementById("workflowAssignSelect").value;
    if (!analystId) return;
    
    try {
        const res = await fetch(`/api/findings/${id}/assign`, {
            method: "PUT",
            headers: {
                ...getHeaders(),
                "Content-Type": "application/json"
            },
            body: JSON.stringify({ assigned_to: parseInt(analystId) })
        });
        
        if (res.ok) {
            alert("Mitigation task assigned to analyst.");
            bootstrap.Modal.getInstance(document.getElementById("editFindingModal")).hide();
            loadAssessmentWorkbench(currentAssessment.id);
        }
    } catch(err) {
        console.error(err);
    }
}

async function handleExceptionRequest(e) {
    e.preventDefault();
    const id = document.getElementById("findingModalId").value;
    const payload = {
        risk_accepted: document.getElementById("exc_active").checked,
        risk_exception_reason: document.getElementById("exc_reason").value,
        risk_exception_expiry_days: parseInt(document.getElementById("exc_duration").value)
    };
    
    try {
        const res = await fetch(`/api/findings/${id}/exception`, {
            method: "PUT",
            headers: {
                ...getHeaders(),
                "Content-Type": "application/json"
            },
            body: JSON.stringify(payload)
        });
        
        if (res.ok) {
            alert("Risk Exception Waiver configuration saved.");
            bootstrap.Modal.getInstance(document.getElementById("editFindingModal")).hide();
            loadAssessmentWorkbench(currentAssessment.id);
            loadAssessmentsTable();
        }
    } catch(err) {
        console.error(err);
    }
}

async function handleUploadEvidence(e) {
    e.preventDefault();
    const id = document.getElementById("findingModalId").value;
    const fileInput = document.getElementById("evidenceFileInput");
    if (fileInput.files.length === 0) return;
    
    const formData = new FormData();
    formData.append("file", fileInput.files[0]);
    
    try {
        const res = await fetch(`/api/findings/${id}/evidence`, {
            method: "POST",
            headers: getHeaders(),
            body: formData
        });
        
        if (res.ok) {
            alert("Evidence file uploaded and SHA-256 integrity hash verified.");
            bootstrap.Modal.getInstance(document.getElementById("editFindingModal")).hide();
            loadAssessmentWorkbench(currentAssessment.id);
        }
    } catch(err) {
        console.error(err);
    }
}


// --- UTSCF REFERENCE LIBRARY ---
async function loadControlsLibrary() {
    try {
        const res = await fetch("/api/controls", { headers: getHeaders() });
        if (!res.ok) return;
        const list = await res.json();
        
        const domainSelect = document.getElementById("searchDomainFilter");
        const uniqueDomains = [...new Set(list.map(c => c.domain))];
        domainSelect.innerHTML = '<option value="ALL">All Domains</option>' + 
            uniqueDomains.map(d => `<option value="${d}">${d}</option>`).join("");
            
        renderControlsLibraryTable(list);
    } catch(err) {
        console.error(err);
    }
}

function renderControlsLibraryTable(list) {
    const body = document.getElementById("controlsLibraryBody");
    body.innerHTML = list.map(c => `
        <tr>
            <td><span class="badge bg-secondary-subtle text-white border border-secondary">${c.control_id}</span></td>
            <td><small class="text-secondary fw-semibold">${c.domain}</small></td>
            <td><small class="text-secondary">${c.category || 'N/A'}</small></td>
            <td><span class="fw-bold text-white small">${c.name}</span></td>
            <td><span class="badge bg-dark ${getSeverityBorderClass(c.severity)} text-light small">${c.severity}</span></td>
            <td><code class="text-info small" style="font-size:10px;">${c.verification_logic}</code></td>
            <td><span class="small text-secondary">${JSON.parse(c.standards_mapping || "{}").nist_csf_2 || 'N/A'}</span></td>
        </tr>
    `).join("");
}

function filterControlsLibrary() {
    const searchVal = document.getElementById("searchControlInput").value.toLowerCase();
    const domainVal = document.getElementById("searchDomainFilter").value;
    const severityVal = document.getElementById("searchSeverityFilter").value;
    
    fetch("/api/controls", { headers: getHeaders() })
        .then(res => res.json())
        .then(list => {
            let filtered = list;
            if (searchVal) {
                filtered = filtered.filter(c => 
                    c.control_id.toLowerCase().includes(searchVal) ||
                    c.name.toLowerCase().includes(searchVal) ||
                    c.description.toLowerCase().includes(searchVal)
                );
            }
            if (domainVal !== "ALL") filtered = filtered.filter(c => c.domain === domainVal);
            if (severityVal !== "ALL") filtered = filtered.filter(c => c.severity === severityVal);
            
            renderControlsLibraryTable(filtered);
        });
}


// --- REPORTS & RISK EXPORTS ---
async function downloadReport(format) {
    const select = document.getElementById("reportAssessmentSelect");
    const id = select.value;
    if (!id) {
        alert("Please select a target assessment from the dropdown first.");
        return;
    }
    
    const url = `/api/reports/${id}/${format}`;
    try {
        const res = await fetch(url, { headers: getHeaders() });
        if (res.ok) {
            const blob = await res.blob();
            const link = document.createElement("a");
            link.href = URL.createObjectURL(blob);
            link.download = `UTSCF_Assessment_Report_${id}.${format === 'csv' ? 'csv' : 'xls'}`;
            link.click();
        }
    } catch(err) {
        console.error(err);
    }
}

async function downloadRiskRegister() {
    try {
        const res = await fetch("/api/reports/risk-register", { headers: getHeaders() });
        if (res.ok) {
            const blob = await res.blob();
            const link = document.createElement("a");
            link.href = URL.createObjectURL(blob);
            link.download = `UTSCF_Enterprise_Risk_Register.csv`;
            link.click();
        }
    } catch (err) {
        console.error(err);
    }
}

async function fetchRemediationPlan() {
    const select = document.getElementById("reportAssessmentSelect");
    const id = select.value;
    if (!id) {
        alert("Please select an assessment to view its remediation plan.");
        return;
    }
    
    try {
        // Query smart prioritizer endpoint
        const res = await fetch(`/api/recommendations/${id}/prioritized`, { headers: getHeaders() });
        if (res.ok) {
            const data = await res.json();
            
            // Map Immediate
            const immediateBody = document.getElementById("remedImmediateBody");
            if (data.immediate.length === 0) {
                immediateBody.innerHTML = `<tr><td colspan="5" class="text-center text-success py-2">No immediate action required. All critical vectors mitigated.</td></tr>`;
            } else {
                immediateBody.innerHTML = data.immediate.map(act => `
                    <tr>
                        <td><span class="badge bg-danger text-light">${act.control_id}</span><br><small class="text-white">${act.name}</small></td>
                        <td><small class="text-secondary">${act.domain}</small></td>
                        <td><span class="fw-bold text-danger font-monospace">${act.priority_score.toFixed(1)}</span></td>
                        <td><small class="text-light">${act.technical_impact}</small></td>
                        <td><span class="text-info small fw-bold">${act.recommended_fix}</span></td>
                    </tr>
                `).join("");
            }
            
            // Map Short
            const shortBody = document.getElementById("remedShortBody");
            if (data.short_term.length === 0) {
                shortBody.innerHTML = `<tr><td colspan="5" class="text-center text-success py-2">No short-term action required.</td></tr>`;
            } else {
                shortBody.innerHTML = data.short_term.map(act => `
                    <tr>
                        <td><span class="badge bg-warning text-dark">${act.control_id}</span><br><small class="text-white">${act.name}</small></td>
                        <td><small class="text-secondary">${act.domain}</small></td>
                        <td><span class="fw-bold text-warning font-monospace">${act.priority_score.toFixed(1)}</span></td>
                        <td><small class="text-light">${act.technical_impact}</small></td>
                        <td><span class="text-info small fw-bold">${act.recommended_fix}</span></td>
                    </tr>
                `).join("");
            }

            // Map Medium/Long
            const mediumBody = document.getElementById("remedMediumBody");
            const combinedMediumLong = data.medium_term.concat(data.long_term);
            if (combinedMediumLong.length === 0) {
                mediumBody.innerHTML = `<tr><td colspan="5" class="text-center text-success py-2">No medium/long term actions required.</td></tr>`;
            } else {
                mediumBody.innerHTML = combinedMediumLong.map(act => `
                    <tr>
                        <td><span class="badge bg-info text-dark">${act.control_id}</span><br><small class="text-white">${act.name}</small></td>
                        <td><small class="text-secondary">${act.domain}</small></td>
                        <td><span class="fw-bold text-info font-monospace">${act.priority_score.toFixed(1)}</span></td>
                        <td><small class="text-light">${act.technical_impact}</small></td>
                        <td><span class="text-info small fw-bold">${act.recommended_fix}</span></td>
                    </tr>
                `).join("");
            }
            
            document.getElementById("remediationPlanDisplay").classList.remove("d-none");
            document.getElementById("remedDevice").innerText = document.getElementById("reportAssessmentSelect").selectedOptions[0].text.split("[")[0].trim();
        }
    } catch(err) {
        console.error(err);
    }
}
