/*
 * DDoS Protection System - Dashboard JavaScript
 * Real-time monitoring and visualization
 */

class DDoSDashboard {
    constructor() {
        this.ws = null;
        this.reconnectTimeout = null;
        this.stats = {
            total_packets: 0,
            total_bytes: 0,
            dropped_packets: 0,
            connections: 0
        };
        this.alerts = [];
        this.logs = [];

        this.init();
    }

    init() {
        this.connectWebSocket();
        this.setupEventListeners();
        this.startUpdateLoop();
    }

    connectWebSocket() {
        const host = window.location.hostname || 'localhost';
        const port = 8081;

        this.ws = new WebSocket(`ws://${host}:${port}`);

        this.ws.onopen = () => {
            console.log('WebSocket connected');
            this.updateStatus('connected');
            this.addLog('Connected to DDoS Protection System');
        };

        this.ws.onmessage = (event) => {
            try {
                const data = JSON.parse(event.data);
                this.handleMessage(data);
            } catch (e) {
                console.error('Failed to parse message:', e);
            }
        };

        this.ws.onerror = (error) => {
            console.error('WebSocket error:', error);
            this.addLog('WebSocket error occurred', 'error');
        };

        this.ws.onclose = () => {
            console.log('WebSocket disconnected');
            this.updateStatus('disconnected');
            this.addLog('Disconnected from server, reconnecting...');

            // Reconnect after 5 seconds
            this.reconnectTimeout = setTimeout(() => {
                this.connectWebSocket();
            }, 5000);
        };
    }

    handleMessage(data) {
        if (data.type === 'stats') {
            this.updateStats(data);
        } else if (data.type === 'attack') {
            this.addAlert(data);
        } else if (data.total_packets !== undefined) {
            // Legacy stats format
            this.updateStats(data);
        }
    }

    updateStats(data) {
        this.stats = {
            total_packets: data.total_packets || 0,
            total_bytes: data.total_bytes || 0,
            dropped_packets: data.dropped_packets || 0,
            connections: data.current_connections || 0
        };

        this.renderStats();
    }

    renderStats() {
        document.getElementById('total-packets').textContent =
            this.formatNumber(this.stats.total_packets);

        document.getElementById('total-bytes').textContent =
            this.formatBytes(this.stats.total_bytes);

        document.getElementById('dropped-packets').textContent =
            this.formatNumber(this.stats.dropped_packets);

        document.getElementById('connections').textContent =
            this.formatNumber(this.stats.connections);
    }

    addAlert(data) {
        const alert = {
            type: data.attack_type || 'Unknown',
            source: data.source_ip || 'Unknown',
            timestamp: data.timestamp || Date.now()
        };

        this.alerts.unshift(alert);
        if (this.alerts.length > 50) {
            this.alerts.pop();
        }

        this.renderAlerts();
        this.addLog(`Attack detected: ${alert.type} from ${alert.source}`, 'error');
    }

    renderAlerts() {
        const alertsList = document.getElementById('alerts-list');

        if (this.alerts.length === 0) {
            alertsList.innerHTML = '<p class="no-alerts">No attacks detected</p>';
            return;
        }

        alertsList.innerHTML = this.alerts.map(alert => `
            <div class="alert-item">
                <strong>${this.escapeHtml(alert.type)}</strong>
                <br>
                Source: ${this.escapeHtml(alert.source)}
                <div class="alert-time">${this.formatTime(alert.timestamp)}</div>
            </div>
        `).join('');
    }

    addLog(message, level = 'info') {
        const log = {
            message: message,
            level: level,
            timestamp: Date.now()
        };

        this.logs.unshift(log);
        if (this.logs.length > 100) {
            this.logs.pop();
        }

        this.renderLogs();
    }

    renderLogs() {
        const logOutput = document.getElementById('log-output');

        logOutput.innerHTML = this.logs.map(log => {
            const time = this.formatTime(log.timestamp);
            const level = log.level.toUpperCase().padEnd(5);
            return `<p>[${time}] [${level}] ${this.escapeHtml(log.message)}</p>`;
        }).join('');
    }

    updateStatus(status) {
        const statusEl = document.getElementById('status');
        const statusText = statusEl.querySelector('.status-text');

        if (status === 'connected') {
            statusEl.classList.remove('disconnected');
            statusText.textContent = 'Connected';
        } else {
            statusEl.classList.add('disconnected');
            statusText.textContent = 'Disconnected';
        }
    }

    setupEventListeners() {
        // Handle page visibility changes
        document.addEventListener('visibilitychange', () => {
            if (!document.hidden && this.ws.readyState !== WebSocket.OPEN) {
                this.connectWebSocket();
            }
        });
    }

    startUpdateLoop() {
        // Simulate data if no real connection (for demo)
        if (window.location.hostname === '') {
            setInterval(() => {
                const mockData = {
                    total_packets: this.stats.total_packets + Math.floor(Math.random() * 1000),
                    total_bytes: this.stats.total_bytes + Math.floor(Math.random() * 100000),
                    dropped_packets: this.stats.dropped_packets + Math.floor(Math.random() * 10),
                    current_connections: Math.floor(Math.random() * 1000)
                };

                this.updateStats(mockData);
            }, 2000);
        }
    }

    formatNumber(num) {
        if (num >= 1000000000) {
            return (num / 1000000000).toFixed(2) + 'B';
        } else if (num >= 1000000) {
            return (num / 1000000).toFixed(2) + 'M';
        } else if (num >= 1000) {
            return (num / 1000).toFixed(2) + 'K';
        }
        return num.toString();
    }

    formatBytes(bytes) {
        if (bytes >= 1099511627776) {
            return (bytes / 1099511627776).toFixed(2) + ' TB';
        } else if (bytes >= 1073741824) {
            return (bytes / 1073741824).toFixed(2) + ' GB';
        } else if (bytes >= 1048576) {
            return (bytes / 1048576).toFixed(2) + ' MB';
        } else if (bytes >= 1024) {
            return (bytes / 1024).toFixed(2) + ' KB';
        }
        return bytes + ' B';
    }

    formatTime(timestamp) {
        const date = new Date(timestamp * (timestamp < 10000000000 ? 1000 : 1));
        return date.toLocaleTimeString();
    }

    escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }
}

// Initialize dashboard when page loads
document.addEventListener('DOMContentLoaded', () => {
    new DDoSDashboard();
});
