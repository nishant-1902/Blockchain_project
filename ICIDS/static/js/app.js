/* ========================================
   ICIDS - Intrusion Detection System
   Main Application JavaScript
   ======================================== */

// ========================================
// Global Variables & Configuration
// ========================================

const CONFIG = {
    API_BASE_URL: '/api',
    TOAST_DURATION: 5000,
    REFRESH_INTERVAL: 30000, // 30 seconds
    MAX_CHART_POINTS: 20,
    MAX_ALERT_ROWS: 50
};

// Socket.IO instance
let socket = null;

// Chart instances
let chartsInstance = {
    attacks: null,
    types: null
};

// Application state
const appState = {
    isMonitoring: false,
    currentPage: 1,
    alertFilters: {
        search: '',
        severity: '',
        type: '',
        status: ''
    },
    reportFilters: {
        search: '',
        type: '',
        status: ''
    }
};

// ========================================
// JWT Token Management
// ========================================

/**
 * Store JWT token in localStorage
 * @param {string} token - JWT token from server
 */
function setAuthToken(token) {
    if (token) {
        localStorage.setItem('authToken', token);
    }
}

/**
 * Retrieve JWT token from localStorage
 * @returns {string|null} JWT token or null
 */
function getAuthToken() {
    return localStorage.getItem('authToken');
}

/**
 * Remove JWT token from localStorage
 */
function removeAuthToken() {
    localStorage.removeItem('authToken');
}

/**
 * Add Authorization header to fetch requests
 * @returns {Object} Headers object with Authorization
 */
function getAuthHeaders() {
    const token = getAuthToken();
    return {
        'Content-Type': 'application/json',
        ...(token && { 'Authorization': `Bearer ${token}` })
    };
}

/**
 * Logout user and redirect to login page
 */
function logout() {
    removeAuthToken();
    window.location.href = '/login';
}

// ========================================
// Fetch API Wrapper
// ========================================

/**
 * Wrapper for fetch API with automatic token handling
 * @param {string} endpoint - API endpoint
 * @param {Object} options - Fetch options
 * @returns {Promise} Response promise
 */
async function fetchAPI(endpoint, options = {}) {
    const url = endpoint.startsWith('http') ? endpoint : `${CONFIG.API_BASE_URL}${endpoint}`;
    
    const config = {
        ...options,
        headers: getAuthHeaders()
    };
    
    try {
        const response = await fetch(url, config);
        
        // Check if token expired (401)
        if (response.status === 401) {
            logout();
            return null;
        }
        
        return response;
    } catch (error) {
        console.error('Fetch error:', error);
        showToast('Connection error. Please try again.', 'error');
        return null;
    }
}

// ========================================
// Toast Notification System
// ========================================

/**
 * Show toast notification
 * @param {string} message - Message to display
 * @param {string} type - Notification type: 'info', 'success', 'warning', 'error'
 * @param {number} duration - Duration in milliseconds
 */
function showToast(message, type = 'info', duration = CONFIG.TOAST_DURATION) {
    const toast = document.createElement('div');
    toast.className = `toast toast-${type}`;
    
    let iconClass = 'bi-info-circle';
    switch(type) {
        case 'success':
            iconClass = 'bi-check-circle';
            break;
        case 'warning':
            iconClass = 'bi-exclamation-circle';
            break;
        case 'error':
            iconClass = 'bi-x-circle';
            break;
    }
    
    toast.innerHTML = `
        <div class="toast-icon">
            <i class="bi ${iconClass}"></i>
        </div>
        <div class="toast-content">
            <p class="toast-message">${escapeHTML(message)}</p>
        </div>
    `;
    
    document.body.appendChild(toast);
    
    // Auto-remove after duration
    setTimeout(() => {
        toast.style.animation = 'slideOutRight 0.3s ease forwards';
        setTimeout(() => toast.remove(), 300);
    }, duration);
}

/**
 * Escape HTML to prevent XSS
 * @param {string} text - Text to escape
 * @returns {string} Escaped text
 */
function escapeHTML(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

// ========================================
// Socket.IO Connection & Events
// ========================================

/**
 * Initialize Socket.IO connection
 */
function initializeSocket() {
    socket = io();
    
    socket.on('connect', () => {
        console.log('Connected to server');
        updateSystemStatus('online');
        showToast('Connected to server', 'success');
    });
    
    socket.on('disconnect', () => {
        console.log('Disconnected from server');
        updateSystemStatus('offline');
        showToast('Disconnected from server', 'warning');
    });
    
    // New alert received
    socket.on('new_alert', (alert) => {
        console.log('New alert:', alert);
        handleNewAlert(alert);
    });
    
    // Packet statistics update
    socket.on('packet_stats', (data) => {
        console.log('Packet stats:', data);
        updatePacketStats(data);
    });
    
    // Attack graph data update
    socket.on('attack_graph_data', (data) => {
        console.log('Attack graph data:', data);
        updateCharts(data);
    });
    
    // Dashboard stats update
    socket.on('dashboard_stats', (data) => {
        console.log('Dashboard stats:', data);
        updateDashboardStats(data);
    });
    
    // Error handling
    socket.on('error', (error) => {
        console.error('Socket error:', error);
        showToast('Real-time connection error', 'error');
    });
}

/**
 * Update system status indicator
 * @param {string} status - 'online' or 'offline'
 */
function updateSystemStatus(status) {
    const statusElement = document.getElementById('systemStatus');
    if (statusElement) {
        if (status === 'online') {
            statusElement.textContent = 'Online';
            statusElement.classList.remove('bg-danger');
            statusElement.classList.add('bg-success');
        } else {
            statusElement.textContent = 'Offline';
            statusElement.classList.remove('bg-success');
            statusElement.classList.add('bg-danger');
        }
    }
}

// ========================================
// Alert Management
// ========================================

/**
 * Handle new alert from Socket.IO
 * @param {Object} alert - Alert object
 */
function handleNewAlert(alert) {
    // Add visual pulse effect
    const alertCount = document.getElementById('totalAlerts');
    if (alertCount) {
        const newCount = parseInt(alertCount.textContent) + 1;
        alertCount.textContent = newCount;
        alertCount.parentElement.classList.add('alert-pulse');
        setTimeout(() => {
            alertCount.parentElement.classList.remove('alert-pulse');
        }, 2000);
    }
    
    // Show toast notification
    showToast(`New ${alert.severity} alert: ${alert.type}`, 'warning');
    
    // Reload alerts if on alerts page
    if (window.location.pathname === '/alerts') {
        loadAlerts();
    }
}

/**
 * Load alerts from server
 * @param {number} page - Page number
 */
async function loadAlerts(page = 1) {
    try {
        const params = new URLSearchParams({
            page: page,
            search: appState.alertFilters.search,
            severity: appState.alertFilters.severity,
            type: appState.alertFilters.type,
            status: appState.alertFilters.status
        });
        
        const response = await fetchAPI(`/alerts?${params}`);
        if (!response || !response.ok) throw new Error('Failed to load alerts');
        
        const data = await response.json();
        renderAlertTable(data.alerts || []);
        updateAlertStats(data.stats);
        updatePagination(data.totalPages, page);
        
    } catch (error) {
        console.error('Error loading alerts:', error);
        showToast('Failed to load alerts', 'error');
    }
}

/**
 * Render alert rows in table
 * @param {Array} alerts - Array of alert objects
 */
function renderAlertTable(alerts) {
    const tbody = document.getElementById('alertsTableBody');
    if (!tbody) return;
    
    if (alerts.length === 0) {
        tbody.innerHTML = `
            <tr>
                <td colspan="6" class="text-center p-4">
                    <i class="bi bi-inbox" style="font-size: 2rem; opacity: 0.5;"></i>
                    <p style="margin-top: 1rem;">No alerts found</p>
                </td>
            </tr>
        `;
        return;
    }
    
    tbody.innerHTML = alerts.map(alert => `
        <tr data-alert-id="${alert.id}">
            <td>${formatDateTime(alert.timestamp)}</td>
            <td><strong>${escapeHTML(alert.type)}</strong></td>
            <td>
                <span class="badge badge-${alert.severity.toLowerCase()}">
                    ${alert.severity}
                </span>
            </td>
            <td>${escapeHTML(alert.description || '-')}</td>
            <td>
                <span class="badge badge-${alert.status.toLowerCase()}">
                    ${alert.status}
                </span>
            </td>
            <td>
                <div class="alert-actions" style="display: flex; gap: 0.5rem;">
                    <button class="btn btn-sm btn-icon" title="View Details" onclick="openAlertModal('${alert.id}')">
                        <i class="bi bi-eye"></i>
                    </button>
                    <button class="btn btn-sm btn-icon" title="Delete" onclick="deleteAlert('${alert.id}')">
                        <i class="bi bi-trash"></i>
                    </button>
                </div>
            </td>
        </tr>
    `).join('');
}

/**
 * Update alert statistics
 * @param {Object} stats - Statistics object
 */
function updateAlertStats(stats) {
    if (!stats) return;
    
    document.getElementById('totalAlertCount').textContent = stats.total || '0';
    document.getElementById('criticalCount').textContent = stats.critical || '0';
    document.getElementById('openCount').textContent = stats.open || '0';
    document.getElementById('resolvedCount').textContent = stats.resolved || '0';
}

/**
 * Open alert detail modal
 * @param {string} alertId - Alert ID
 */
async function openAlertModal(alertId) {
    try {
        const response = await fetchAPI(`/alerts/${alertId}`);
        if (!response || !response.ok) throw new Error('Failed to load alert');
        
        const alert = await response.json();
        const modal = document.getElementById('alertModal');
        const body = document.getElementById('alertModalBody');
        
        if (!body) return;
        
        body.innerHTML = `
            <div class="detail-row">
                <span class="detail-label">Type:</span>
                <span class="detail-value"><strong>${escapeHTML(alert.type)}</strong></span>
            </div>
            <div class="detail-row">
                <span class="detail-label">Severity:</span>
                <span class="detail-value">
                    <span class="badge badge-${alert.severity.toLowerCase()}">
                        ${alert.severity}
                    </span>
                </span>
            </div>
            <div class="detail-row">
                <span class="detail-label">Status:</span>
                <span class="detail-value">
                    <span class="badge badge-${alert.status.toLowerCase()}">
                        ${alert.status}
                    </span>
                </span>
            </div>
            <div class="detail-row">
                <span class="detail-label">Timestamp:</span>
                <span class="detail-value">${formatDateTime(alert.timestamp)}</span>
            </div>
            <div class="detail-row">
                <span class="detail-label">Source IP:</span>
                <span class="detail-value">${escapeHTML(alert.sourceIp || '-')}</span>
            </div>
            <div class="detail-row">
                <span class="detail-label">Destination IP:</span>
                <span class="detail-value">${escapeHTML(alert.destIp || '-')}</span>
            </div>
            <div class="detail-row">
                <span class="detail-label">Description:</span>
                <span class="detail-value">${escapeHTML(alert.description || '-')}</span>
            </div>
        `;
        
        modal.classList.add('show');
    } catch (error) {
        console.error('Error opening alert modal:', error);
        showToast('Failed to load alert details', 'error');
    }
}

/**
 * Close alert detail modal
 */
function closeAlertModal() {
    const modal = document.getElementById('alertModal');
    if (modal) {
        modal.classList.remove('show');
    }
}

/**
 * Delete alert
 * @param {string} alertId - Alert ID
 */
async function deleteAlert(alertId) {
    if (!confirm('Are you sure you want to delete this alert?')) return;
    
    try {
        const response = await fetchAPI(`/alerts/${alertId}`, { method: 'DELETE' });
        if (!response || !response.ok) throw new Error('Failed to delete alert');
        
        showToast('Alert deleted successfully', 'success');
        loadAlerts();
    } catch (error) {
        console.error('Error deleting alert:', error);
        showToast('Failed to delete alert', 'error');
    }
}

// ========================================
// Filter & Search
// ========================================

/**
 * Setup alert filters and search
 */
function setupAlertFilters() {
    const searchInput = document.getElementById('searchInput');
    const severityFilter = document.getElementById('severityFilter');
    const typeFilter = document.getElementById('typeFilter');
    const statusFilter = document.getElementById('statusFilter');
    
    if (searchInput) {
        searchInput.addEventListener('input', (e) => {
            appState.alertFilters.search = e.target.value;
            appState.currentPage = 1;
            loadAlerts();
        });
    }
    
    if (severityFilter) {
        severityFilter.addEventListener('change', (e) => {
            appState.alertFilters.severity = e.target.value;
            appState.currentPage = 1;
            loadAlerts();
        });
    }
    
    if (typeFilter) {
        typeFilter.addEventListener('change', (e) => {
            appState.alertFilters.type = e.target.value;
            appState.currentPage = 1;
            loadAlerts();
        });
    }
    
    if (statusFilter) {
        statusFilter.addEventListener('change', (e) => {
            appState.alertFilters.status = e.target.value;
            appState.currentPage = 1;
            loadAlerts();
        });
    }
}

// ========================================
// Dashboard Stats & Charts
// ========================================

/**
 * Update dashboard statistics cards
 * @param {Object} stats - Statistics object
 */
function updateDashboardStats(stats) {
    if (!stats) return;
    
    const updates = {
        'totalAlerts': stats.totalAlerts,
        'activeThreats': stats.activeThreats,
        'packetsCaptured': stats.packetsCaptured,
        'blockedAttacks': stats.blockedAttacks,
        'alertsChange': stats.alertsChangeHour,
        'packetsRate': stats.packetsRate,
        'blockedChange': stats.blockedChangeDay
    };
    
    Object.entries(updates).forEach(([id, value]) => {
        const element = document.getElementById(id);
        if (element && value !== undefined) {
            if (id === 'packetsCaptured') {
                element.textContent = (value || 0).toLocaleString();
            } else if (id === 'packetsRate') {
                element.textContent = `${value || 0} packets/sec`;
            } else {
                element.textContent = value;
            }
        }
    });
}

/**
 * Initialize charts
 */
function initializeCharts() {
    // Check if canvas elements exist
    const attacksCanvas = document.getElementById('attacksChart');
    const typesCanvas = document.getElementById('typesChart');
    
    if (!attacksCanvas || !typesCanvas) return;
    
    const attacksCtx = attacksCanvas.getContext('2d');
    const typesCtx = typesCanvas.getContext('2d');
    
    // Attacks over time - Line Chart
    chartsInstance.attacks = new Chart(attacksCtx, {
        type: 'line',
        data: {
            labels: generateTimeLabels(7),
            datasets: [
                {
                    label: 'Total Attacks',
                    data: [5, 8, 12, 15, 10, 20, 18],
                    borderColor: '#dc2626',
                    backgroundColor: 'rgba(220, 38, 38, 0.1)',
                    borderWidth: 2,
                    fill: true,
                    tension: 0.4,
                    pointRadius: 4,
                    pointHoverRadius: 6,
                    pointBackgroundColor: '#dc2626',
                    pointBorderColor: '#fff',
                    pointBorderWidth: 2
                },
                {
                    label: 'Blocked Attacks',
                    data: [4, 7, 10, 14, 9, 19, 17],
                    borderColor: '#10b981',
                    backgroundColor: 'rgba(16, 185, 129, 0.1)',
                    borderWidth: 2,
                    fill: true,
                    tension: 0.4,
                    pointRadius: 4,
                    pointHoverRadius: 6,
                    pointBackgroundColor: '#10b981',
                    pointBorderColor: '#fff',
                    pointBorderWidth: 2
                }
            ]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    display: true,
                    position: 'top',
                    labels: {
                        usePointStyle: true,
                        padding: 15,
                        font: { size: 12, weight: 600 },
                        color: '#cbd5e1'
                    }
                }
            },
            scales: {
                y: {
                    beginAtZero: true,
                    grid: { color: 'rgba(148, 163, 184, 0.1)' },
                    ticks: { color: '#94a3b8' }
                },
                x: {
                    grid: { display: false },
                    ticks: { color: '#94a3b8' }
                }
            }
        }
    });
    
    // Attack types distribution - Doughnut Chart
    chartsInstance.types = new Chart(typesCtx, {
        type: 'doughnut',
        data: {
            labels: ['DDoS', 'Port Scan', 'Brute Force', 'SQL Injection', 'Malware'],
            datasets: [
                {
                    data: [35, 25, 20, 15, 5],
                    backgroundColor: [
                        '#dc2626',
                        '#f59e0b',
                        '#3b82f6',
                        '#8b5cf6',
                        '#10b981'
                    ],
                    borderColor: '#1e293b',
                    borderWidth: 2
                }
            ]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    display: true,
                    position: 'right',
                    labels: {
                        usePointStyle: true,
                        padding: 15,
                        font: { size: 12 },
                        color: '#cbd5e1'
                    }
                }
            }
        }
    });
}

/**
 * Generate time labels for charts
 * @param {number} days - Number of days
 * @returns {Array} Array of time labels
 */
function generateTimeLabels(days) {
    const labels = [];
    for (let i = days - 1; i >= 0; i--) {
        const date = new Date();
        date.setDate(date.getDate() - i);
        labels.push(date.toLocaleDateString('en-US', { month: 'short', day: 'numeric' }));
    }
    return labels;
}

/**
 * Update charts with new data
 * @param {Object} data - Chart data
 */
function updateCharts(data) {
    if (!chartsInstance.attacks || !chartsInstance.types) return;
    
    if (data.attacks) {
        chartsInstance.attacks.data.datasets[0].data = data.attacks.total;
        chartsInstance.attacks.data.datasets[1].data = data.attacks.blocked;
        chartsInstance.attacks.update();
    }
    
    if (data.types) {
        chartsInstance.types.data.datasets[0].data = Object.values(data.types);
        chartsInstance.types.update();
    }
}

// ========================================
// Packet Statistics
// ========================================

/**
 * Update packet statistics table
 * @param {Array} packets - Array of packet objects
 */
function updatePacketStats(packets) {
    const tbody = document.getElementById('packetTableBody');
    if (!tbody) return;
    
    if (!packets || packets.length === 0) {
        tbody.innerHTML = `
            <tr>
                <td colspan="6" class="text-center p-4">
                    <i class="bi bi-inbox" style="font-size: 2rem; opacity: 0.5;"></i>
                    <p style="margin-top: 1rem;">No packet data available</p>
                </td>
            </tr>
        `;
        return;
    }
    
    tbody.innerHTML = packets.map(packet => `
        <tr>
            <td><strong>${escapeHTML(packet.protocol || '-')}</strong></td>
            <td>${escapeHTML(packet.sourceIp || '-')}</td>
            <td>${escapeHTML(packet.destIp || '-')}</td>
            <td>${packet.port || '-'}</td>
            <td>${packet.count || 0}</td>
            <td>
                <span class="badge badge-${(packet.status || 'active').toLowerCase()}">
                    ${packet.status || 'Active'}
                </span>
            </td>
        </tr>
    `).join('');
}

// ========================================
// Monitoring Controls
// ========================================

/**
 * Setup monitoring buttons
 */
function setupMonitoringButtons() {
    const startBtn = document.getElementById('startMonitoring');
    const stopBtn = document.getElementById('stopMonitoring');
    
    if (startBtn) {
        startBtn.addEventListener('click', startMonitoring);
    }
    
    if (stopBtn) {
        stopBtn.addEventListener('click', stopMonitoring);
    }
}

/**
 * Start monitoring
 */
async function startMonitoring() {
    try {
        const response = await fetchAPI('/monitoring/start', { method: 'POST' });
        if (!response || !response.ok) throw new Error('Failed to start monitoring');
        
        appState.isMonitoring = true;
        showToast('Monitoring started', 'success');
        
        if (socket) {
            socket.emit('monitoring_started');
        }
    } catch (error) {
        console.error('Error starting monitoring:', error);
        showToast('Failed to start monitoring', 'error');
    }
}

/**
 * Stop monitoring
 */
async function stopMonitoring() {
    try {
        const response = await fetchAPI('/monitoring/stop', { method: 'POST' });
        if (!response || !response.ok) throw new Error('Failed to stop monitoring');
        
        appState.isMonitoring = false;
        showToast('Monitoring stopped', 'success');
        
        if (socket) {
            socket.emit('monitoring_stopped');
        }
    } catch (error) {
        console.error('Error stopping monitoring:', error);
        showToast('Failed to stop monitoring', 'error');
    }
}

// ========================================
// Report Management
// ========================================

/**
 * Setup report generation
 */
function setupReportGeneration() {
    const generateBtn = document.getElementById('generateReportBtn');
    const submitBtn = document.getElementById('submitGenerateBtn');
    
    if (generateBtn) {
        generateBtn.addEventListener('click', openGenerateModal);
    }
    
    if (submitBtn) {
        submitBtn.addEventListener('click', submitGenerateReport);
    }
}

/**
 * Open report generation modal
 */
function openGenerateModal() {
    const modal = document.getElementById('generateModal');
    if (modal) {
        modal.classList.add('show');
    }
}

/**
 * Close report generation modal
 */
function closeGenerateModal() {
    const modal = document.getElementById('generateModal');
    if (modal) {
        modal.classList.remove('show');
    }
}

/**
 * Submit report generation
 */
async function submitGenerateReport() {
    const form = document.getElementById('generateReportForm');
    if (!form) return;
    
    if (!form.checkValidity()) {
        form.reportValidity();
        return;
    }
    
    const btn = document.getElementById('submitGenerateBtn');
    if (btn) btn.disabled = true;
    
    try {
        const reportData = {
            name: document.getElementById('reportName').value,
            type: document.getElementById('reportType').value,
            startDate: document.getElementById('startDate').value,
            endDate: document.getElementById('endDate').value,
            sections: {
                alerts: document.getElementById('includeAlerts')?.checked || false,
                network: document.getElementById('includeNetwork')?.checked || false,
                threats: document.getElementById('includeThreats')?.checked || false,
                recommendations: document.getElementById('includeRecommendations')?.checked || false
            },
            format: document.getElementById('exportFormat').value
        };
        
        const response = await fetchAPI('/reports/generate', {
            method: 'POST',
            body: JSON.stringify(reportData)
        });
        
        if (!response || !response.ok) throw new Error('Failed to generate report');
        
        showToast('Report generation started', 'success');
        closeGenerateModal();
        
        // Reload reports list
        if (window.location.pathname === '/reports') {
            loadReports();
        }
    } catch (error) {
        console.error('Error generating report:', error);
        showToast('Failed to generate report', 'error');
    } finally {
        if (btn) btn.disabled = false;
    }
}

/**
 * Load reports from server
 * @param {number} page - Page number
 */
async function loadReports(page = 1) {
    try {
        const params = new URLSearchParams({
            page: page,
            search: appState.reportFilters.search,
            type: appState.reportFilters.type,
            status: appState.reportFilters.status
        });
        
        const response = await fetchAPI(`/reports?${params}`);
        if (!response || !response.ok) throw new Error('Failed to load reports');
        
        const data = await response.json();
        renderReportTable(data.reports || []);
        updatePagination(data.totalPages, page);
    } catch (error) {
        console.error('Error loading reports:', error);
        showToast('Failed to load reports', 'error');
    }
}

/**
 * Render report rows in table
 * @param {Array} reports - Array of report objects
 */
function renderReportTable(reports) {
    const tbody = document.getElementById('reportsTableBody');
    if (!tbody) return;
    
    if (reports.length === 0) {
        tbody.innerHTML = `
            <tr>
                <td colspan="6" class="text-center p-4">
                    <i class="bi bi-inbox" style="font-size: 2rem; opacity: 0.5;"></i>
                    <p style="margin-top: 1rem;">No reports found</p>
                </td>
            </tr>
        `;
        return;
    }
    
    tbody.innerHTML = reports.map(report => `
        <tr>
            <td><strong>${escapeHTML(report.name)}</strong></td>
            <td>
                <span class="badge badge-${report.type.toLowerCase()}">
                    ${report.type}
                </span>
            </td>
            <td>${formatDateTime(report.generatedAt)}</td>
            <td>
                <span class="badge badge-${report.status.toLowerCase()}">
                    ${report.status}
                </span>
            </td>
            <td>${formatFileSize(report.size)}</td>
            <td>
                <div style="display: flex; gap: 0.5rem;">
                    ${report.status === 'Completed' ? `
                        <button class="btn btn-sm btn-icon" title="Download PDF" onclick="downloadReport('${report.id}', 'pdf')">
                            <i class="bi bi-download"></i> PDF
                        </button>
                        <button class="btn btn-sm btn-icon" title="Download CSV" onclick="downloadReport('${report.id}', 'csv')">
                            <i class="bi bi-download"></i> CSV
                        </button>
                    ` : ''}
                    <button class="btn btn-sm btn-icon" title="Delete" onclick="deleteReport('${report.id}')">
                        <i class="bi bi-trash"></i>
                    </button>
                </div>
            </td>
        </tr>
    `).join('');
}

/**
 * Download report
 * @param {string} reportId - Report ID
 * @param {string} format - File format (pdf or csv)
 */
async function downloadReport(reportId, format) {
    try {
        const response = await fetchAPI(`/reports/${reportId}/download?format=${format}`);
        if (!response || !response.ok) throw new Error('Failed to download report');
        
        const blob = await response.blob();
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `report-${reportId}.${format.toLowerCase()}`;
        document.body.appendChild(a);
        a.click();
        window.URL.revokeObjectURL(url);
        document.body.removeChild(a);
        
        showToast(`Report downloaded as ${format.toUpperCase()}`, 'success');
    } catch (error) {
        console.error('Error downloading report:', error);
        showToast('Failed to download report', 'error');
    }
}

/**
 * Delete report
 * @param {string} reportId - Report ID
 */
async function deleteReport(reportId) {
    if (!confirm('Are you sure you want to delete this report?')) return;
    
    try {
        const response = await fetchAPI(`/reports/${reportId}`, { method: 'DELETE' });
        if (!response || !response.ok) throw new Error('Failed to delete report');
        
        showToast('Report deleted successfully', 'success');
        loadReports();
    } catch (error) {
        console.error('Error deleting report:', error);
        showToast('Failed to delete report', 'error');
    }
}

/**
 * Setup report filters
 */
function setupReportFilters() {
    const searchInput = document.getElementById('searchInput');
    const typeFilter = document.getElementById('typeFilter');
    const statusFilter = document.getElementById('statusFilter');
    
    if (searchInput) {
        searchInput.addEventListener('input', (e) => {
            appState.reportFilters.search = e.target.value;
            appState.currentPage = 1;
            loadReports();
        });
    }
    
    if (typeFilter) {
        typeFilter.addEventListener('change', (e) => {
            appState.reportFilters.type = e.target.value;
            appState.currentPage = 1;
            loadReports();
        });
    }
    
    if (statusFilter) {
        statusFilter.addEventListener('change', (e) => {
            appState.reportFilters.status = e.target.value;
            appState.currentPage = 1;
            loadReports();
        });
    }
}

// ========================================
// Pagination
// ========================================

/**
 * Update pagination controls
 * @param {number} totalPages - Total number of pages
 * @param {number} currentPage - Current page number
 */
function updatePagination(totalPages, currentPage) {
    const prevBtn = document.getElementById('prevBtn');
    const nextBtn = document.getElementById('nextBtn');
    const pageInfo = document.getElementById('pageInfo');
    
    if (pageInfo) {
        pageInfo.textContent = `Page ${currentPage} of ${totalPages}`;
    }
    
    if (prevBtn) {
        prevBtn.disabled = currentPage === 1;
        prevBtn.addEventListener('click', () => {
            if (currentPage > 1) {
                if (window.location.pathname === '/alerts') {
                    loadAlerts(currentPage - 1);
                } else if (window.location.pathname === '/reports') {
                    loadReports(currentPage - 1);
                }
            }
        });
    }
    
    if (nextBtn) {
        nextBtn.disabled = currentPage === totalPages;
        nextBtn.addEventListener('click', () => {
            if (currentPage < totalPages) {
                if (window.location.pathname === '/alerts') {
                    loadAlerts(currentPage + 1);
                } else if (window.location.pathname === '/reports') {
                    loadReports(currentPage + 1);
                }
            }
        });
    }
}

// ========================================
// Utility Functions
// ========================================

/**
 * Format date and time
 * @param {string|Date} date - Date to format
 * @returns {string} Formatted date string
 */
function formatDateTime(date) {
    if (!date) return '-';
    const d = new Date(date);
    return d.toLocaleString();
}

/**
 * Format file size
 * @param {number} bytes - File size in bytes
 * @returns {string} Formatted file size
 */
function formatFileSize(bytes) {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

/**
 * Setup modal close handlers
 */
function setupModalHandlers() {
    // Alert modal
    const alertModal = document.getElementById('alertModal');
    if (alertModal) {
        alertModal.addEventListener('click', (e) => {
            if (e.target === alertModal) {
                closeAlertModal();
            }
        });
    }
    
    // Generate report modal
    const generateModal = document.getElementById('generateModal');
    if (generateModal) {
        generateModal.addEventListener('click', (e) => {
            if (e.target === generateModal) {
                closeGenerateModal();
            }
        });
    }
}

/**
 * Auto-refresh dashboard every 30 seconds
 */
function setupAutoRefresh() {
    setInterval(() => {
        if (window.location.pathname === '/dashboard') {
            // Emit refresh event through Socket.IO
            if (socket) {
                socket.emit('request_refresh');
            }
        } else if (window.location.pathname === '/alerts') {
            loadAlerts(appState.currentPage);
        } else if (window.location.pathname === '/reports') {
            loadReports(appState.currentPage);
        }
    }, CONFIG.REFRESH_INTERVAL);
}

// ========================================
// Initialization
// ========================================

/**
 * Initialize application
 */
document.addEventListener('DOMContentLoaded', () => {
    console.log('ICIDS Application Initializing...');
    
    // Initialize Socket.IO
    initializeSocket();
    
    // Setup event listeners
    setupAlertFilters();
    setupMonitoringButtons();
    setupReportGeneration();
    setupReportFilters();
    setupModalHandlers();
    
    // Initialize charts if on dashboard
    if (window.location.pathname === '/dashboard') {
        initializeCharts();
    }
    
    // Load initial data
    if (window.location.pathname === '/alerts') {
        loadAlerts();
    } else if (window.location.pathname === '/reports') {
        loadReports();
    }
    
    // Setup auto-refresh
    setupAutoRefresh();
    
    console.log('ICIDS Application Ready!');
});

// ========================================
// Error Handling
// ========================================

// Global error handler
window.addEventListener('error', (event) => {
    console.error('Global error:', event.error);
    showToast('An unexpected error occurred', 'error');
});

// Unhandled promise rejection handler
window.addEventListener('unhandledrejection', (event) => {
    console.error('Unhandled rejection:', event.reason);
    showToast('An unexpected error occurred', 'error');
});
