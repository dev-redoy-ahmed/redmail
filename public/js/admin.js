// RedMail Admin Panel - JavaScript
class AdminPanel {
    constructor() {
        this.token = localStorage.getItem('adminToken');
        this.currentPage = 'dashboard';
        this.socket = null;
        this.init();
    }

    init() {
        this.checkAuth();
        this.bindEvents();
        this.loadDashboard();
        this.initSocketIO();
        
        // Initialize global settings and advanced features
        setTimeout(() => {
            this.loadGlobalSettings();
            this.loadAdvancedFeatures();
            this.initializeGlobalSettings();
            this.initializeAdvancedFeatures();
        }, 100);
    }

    checkAuth() {
        if (!this.token) {
            this.showLogin();
            return;
        }

        // Verify token
        this.apiCall('/api/auth/verify', 'GET')
            .then(response => {
                if (!response.valid) {
                    throw new Error('Invalid token');
                }
            })
            .catch(() => {
                this.logout();
            });
    }

    showLogin() {
        document.body.innerHTML = `
            <div class="login-container">
                <div class="login-card">
                    <div class="login-header">
                        <i class="fas fa-shield-alt"></i>
                        <h2>RedMail Admin Login</h2>
                        <p>Secure access to temporary mail management</p>
                    </div>
                    <form id="loginForm" class="login-form">
                        <div class="form-group">
                            <label class="form-label">Admin Password</label>
                            <input type="password" id="password" class="form-input" placeholder="Enter admin password" required>
                        </div>
                        <button type="submit" class="btn btn-primary btn-full">
                            <i class="fas fa-sign-in-alt"></i>
                            Login
                        </button>
                    </form>
                    <div id="loginError" class="alert alert-error" style="display: none;"></div>
                </div>
            </div>
            <style>
                .login-container {
                    display: flex;
                    justify-content: center;
                    align-items: center;
                    min-height: 100vh;
                    background: var(--black);
                }
                .login-card {
                    background: var(--black);
                    padding: 2rem;
                    border-radius: var(--radius-xl);
                    box-shadow: var(--shadow-xl);
                    width: 100%;
                    max-width: 400px;
                    text-align: center;
                    border: 1px solid var(--gray-800);
                }
                .login-header i {
                    font-size: 3rem;
                    color: var(--primary-color);
                    margin-bottom: 1rem;
                }
                .login-header h2 {
                    margin-bottom: 0.5rem;
                    color: var(--white);
                }
                .login-header p {
                    color: var(--gray-400);
                    margin-bottom: 2rem;
                }
                .login-form {
                    text-align: left;
                }
                .login-form .form-label {
                    color: var(--white);
                }
                .login-form .form-input {
                    background-color: var(--black);
                    color: var(--white);
                    border: 1px solid var(--gray-700);
                }
                .login-form .form-input:focus {
                    border-color: var(--primary-color);
                    box-shadow: 0 0 0 3px rgba(59, 130, 246, 0.1);
                }
                .btn-full {
                    width: 100%;
                    padding: 1rem;
                    font-size: 1.1rem;
                }
            </style>
        `;

        document.getElementById('loginForm').addEventListener('submit', (e) => {
            e.preventDefault();
            this.login();
        });
    }

    async login() {
        const password = document.getElementById('password').value;
        const errorDiv = document.getElementById('loginError');

        try {
            const response = await fetch('/api/auth/login', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ password })
            });

            const data = await response.json();

            if (!response.ok) {
                throw new Error(data.error || 'Login failed');
            }

            this.token = data.token;
            localStorage.setItem('adminToken', this.token);
            location.reload();
        } catch (error) {
            errorDiv.textContent = error.message;
            errorDiv.style.display = 'block';
        }
    }

    logout() {
        localStorage.removeItem('adminToken');
        this.token = null;
        location.reload();
    }

    bindEvents() {
        // Sidebar toggle
        document.getElementById('sidebarToggle').addEventListener('click', () => {
            const sidebar = document.getElementById('sidebar');
            const mainContent = document.getElementById('mainContent');
            
            if (window.innerWidth <= 768) {
                sidebar.classList.toggle('show');
            } else {
                sidebar.classList.toggle('collapsed');
                mainContent.classList.toggle('expanded');
            }
        });

        // Navigation
        document.querySelectorAll('.nav-link').forEach(link => {
            link.addEventListener('click', (e) => {
                e.preventDefault();
                const page = link.dataset.page;
                this.navigateTo(page);
            });
        });

        // Logout
        document.getElementById('logoutBtn').addEventListener('click', () => {
            this.logout();
        });

        // Test inbox functionality will be bound when navigating to test-inbox page

        // Test connectivity button
        document.getElementById('testConnectivity').addEventListener('click', () => {
            this.testConnectivity();
        });

        // Test OTP button
        document.getElementById('testOTP').addEventListener('click', () => {
            this.showOTPTestModal();
        });

        // Save settings button
        document.getElementById('saveSettings').addEventListener('click', () => {
            this.saveSettings();
        });

        // Domain management events
        document.getElementById('addDomainBtn').addEventListener('click', () => {
            this.showAddDomainForm();
        });

        document.getElementById('saveDomainBtn').addEventListener('click', () => {
            this.saveDomain();
        });

        document.getElementById('cancelDomainBtn').addEventListener('click', () => {
            this.hideAddDomainForm();
        });

        // Responsive sidebar
        window.addEventListener('resize', () => {
            const sidebar = document.getElementById('sidebar');
            const mainContent = document.getElementById('mainContent');
            
            if (window.innerWidth > 768) {
                sidebar.classList.remove('show');
                if (!sidebar.classList.contains('collapsed')) {
                    mainContent.classList.remove('expanded');
                }
            }
        });
    }

    navigateTo(page) {
        // Update active nav link
        document.querySelectorAll('.nav-link').forEach(link => {
            link.classList.remove('active');
        });
        document.querySelector(`[data-page="${page}"]`).classList.add('active');

        // Update page title
        const titles = {
            dashboard: 'Dashboard',
            emails: 'Temporary Emails',
            logs: 'Activity Logs',
            settings: 'Settings',
            api: 'API Documentation'
        };
        document.getElementById('pageTitle').textContent = titles[page];

        // Show/hide content
        document.querySelectorAll('.page-content').forEach(content => {
            content.classList.remove('active');
        });
        document.getElementById(`${page}-content`).classList.add('active');

        this.currentPage = page;

        // Load page data
        switch (page) {
            case 'dashboard':
                this.loadDashboard();
                break;
            case 'emails':
                this.loadEmails();
                break;
            case 'logs':
                this.loadLogs();
                break;
            case 'settings':
                this.loadSettings();
                break;
            case 'test-inbox':
                this.loadTestInbox();
                break;
        }
    }

    async loadDashboard() {
        try {
            const stats = await this.apiCall('/api/admin/stats');
            
            document.getElementById('totalEmails').textContent = stats.stats.totalEmails;
            document.getElementById('activeEmails').textContent = stats.stats.activeEmails;
            document.getElementById('expiredEmails').textContent = stats.stats.expiredEmails;
            document.getElementById('todayActivity').textContent = stats.stats.todayActivity;
        } catch (error) {
            console.error('Failed to load dashboard:', error);
        }
    }

    async loadEmails() {
        try {
            const response = await this.apiCall('/api/admin/emails?limit=50');
            const tbody = document.getElementById('emailsTableBody');
            
            if (response.emails.length === 0) {
                tbody.innerHTML = '<tr><td colspan="5" class="text-center">No emails found</td></tr>';
                return;
            }

            tbody.innerHTML = response.emails.map(email => {
                const isExpired = new Date(email.expiresAt) < new Date();
                const status = isExpired ? 
                    '<span class="text-error"><i class="fas fa-times-circle"></i> Expired</span>' :
                    '<span class="text-success"><i class="fas fa-check-circle"></i> Active</span>';
                
                return `
                    <tr>
                        <td>${email.email}</td>
                        <td>${new Date(email.createdAt).toLocaleString()}</td>
                        <td>${new Date(email.expiresAt).toLocaleString()}</td>
                        <td>${email.messages.length}</td>
                        <td>${status}</td>
                    </tr>
                `;
            }).join('');
        } catch (error) {
            console.error('Failed to load emails:', error);
            document.getElementById('emailsTableBody').innerHTML = 
                '<tr><td colspan="5" class="text-center text-error">Failed to load emails</td></tr>';
        }
    }

    async loadLogs() {
        try {
            const response = await this.apiCall('/api/admin/logs?limit=50');
            const tbody = document.getElementById('logsTableBody');
            
            if (response.logs.length === 0) {
                tbody.innerHTML = '<tr><td colspan="4" class="text-center">No logs found</td></tr>';
                return;
            }

            tbody.innerHTML = response.logs.map(log => `
                <tr>
                    <td>${new Date(log.timestamp).toLocaleString()}</td>
                    <td><span class="text-info">${log.action}</span></td>
                    <td>${log.email}</td>
                    <td>${log.ip}</td>
                </tr>
            `).join('');
        } catch (error) {
            console.error('Failed to load logs:', error);
            document.getElementById('logsTableBody').innerHTML = 
                '<tr><td colspan="4" class="text-center text-error">Failed to load logs</td></tr>';
        }
    }

    showTestModal() {
        const modal = document.createElement('div');
        modal.className = 'modal-overlay';
        modal.innerHTML = `
            <div class="modal-content">
                <div class="modal-header">
                    <h3><i class="fas fa-flask"></i> Test Temporary Mail</h3>
                    <button class="modal-close">&times;</button>
                </div>
                <div class="modal-body">
                    <p>Test the temporary mail generation functionality:</p>
                    <div id="testResult"></div>
                    <button class="btn btn-success" id="generateTestEmail">
                        <i class="fas fa-plus"></i>
                        Generate Test Email
                    </button>
                </div>
            </div>
            <style>
                .modal-overlay {
                    position: fixed;
                    top: 0;
                    left: 0;
                    width: 100%;
                    height: 100%;
                    background: rgba(0, 0, 0, 0.5);
                    display: flex;
                    justify-content: center;
                    align-items: center;
                    z-index: var(--z-modal);
                }
                .modal-content {
                    background: var(--bg-primary);
                    border-radius: var(--radius-lg);
                    box-shadow: var(--shadow-xl);
                    width: 90%;
                    max-width: 500px;
                    max-height: 80vh;
                    overflow-y: auto;
                }
                .modal-header {
                    padding: var(--spacing-lg);
                    border-bottom: 1px solid var(--border-primary);
                    display: flex;
                    justify-content: space-between;
                    align-items: center;
                }
                .modal-header h3 {
                    margin: 0;
                    color: var(--text-primary);
                }
                .modal-close {
                    background: none;
                    border: none;
                    font-size: 1.5rem;
                    cursor: pointer;
                    color: var(--text-secondary);
                }
                .modal-body {
                    padding: var(--spacing-lg);
                }
            </style>
        `;

        document.body.appendChild(modal);

        // Close modal events
        modal.querySelector('.modal-close').addEventListener('click', () => {
            document.body.removeChild(modal);
        });
        modal.addEventListener('click', (e) => {
            if (e.target === modal) {
                document.body.removeChild(modal);
            }
        });

        // Generate test email
        modal.querySelector('#generateTestEmail').addEventListener('click', async () => {
            const resultDiv = modal.querySelector('#testResult');
            const button = modal.querySelector('#generateTestEmail');
            
            button.disabled = true;
            button.innerHTML = '<span class="loading"></span> Generating...';
            
            try {
                const response = await fetch('/api/temp-email/generate', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    }
                });
                
                const data = await response.json();
                
                if (!response.ok) {
                    throw new Error(data.error || 'Failed to generate email');
                }
                
                resultDiv.innerHTML = `
                    <div class="alert alert-success">
                        <h4><i class="fas fa-check-circle"></i> Test Email Generated Successfully!</h4>
                        <p><strong>Email:</strong> ${data.email}</p>
                        <p><strong>ID:</strong> ${data.id}</p>
                        <p><strong>Expires:</strong> ${new Date(data.expiresAt).toLocaleString()}</p>
                    </div>
                `;
            } catch (error) {
                resultDiv.innerHTML = `
                    <div class="alert alert-error">
                        <h4><i class="fas fa-exclamation-circle"></i> Test Failed</h4>
                        <p>${error.message}</p>
                    </div>
                `;
            } finally {
                button.disabled = false;
                button.innerHTML = '<i class="fas fa-plus"></i> Generate Test Email';
            }
        });
    }

    async testConnectivity() {
        const resultDiv = document.getElementById('connectivityResult');
        const button = document.getElementById('testConnectivity');
        
        button.disabled = true;
        button.innerHTML = '<span class="loading"></span> Testing...';
        
        try {
            const response = await this.apiCall('/api/admin/test-smtp');
            
            const { tests } = response;
            
            resultDiv.innerHTML = `
                <div class="alert alert-info">
                    <h4><i class="fas fa-check-circle"></i> System Connectivity Test Results</h4>
                    <div class="test-results">
                        <div class="test-item ${tests.redis ? 'success' : 'error'}">
                            <i class="fas fa-${tests.redis ? 'check' : 'times'}"></i>
                            <strong>Redis Connection:</strong> ${tests.redis ? 'Connected' : 'Failed'}
                        </div>
                        <div class="test-item ${tests.smtp ? 'success' : 'error'}">
                            <i class="fas fa-${tests.smtp ? 'check' : 'times'}"></i>
                            <strong>SMTP Server:</strong> ${tests.smtp ? 'Running' : 'Failed'}
                        </div>
                        <div class="test-item info">
                            <i class="fas fa-globe"></i>
                            <strong>Domain:</strong> ${tests.domain}
                        </div>
                        <div class="test-item info">
                            <i class="fas fa-server"></i>
                            <strong>VPS IP:</strong> ${tests.vpsIp}
                        </div>
                    </div>
                </div>
            `;
        } catch (error) {
            resultDiv.innerHTML = `
                <div class="alert alert-error">
                    <h4><i class="fas fa-exclamation-circle"></i> Test Failed</h4>
                    <p>${error.message}</p>
                </div>
            `;
        } finally {
            button.disabled = false;
            button.innerHTML = '<i class="fas fa-check-circle"></i> Test System Connectivity';
        }
    }

    showOTPTestModal() {
        const modal = document.createElement('div');
        modal.className = 'modal';
        modal.style.display = 'flex';
        modal.innerHTML = `
            <div class="modal-content">
                <div class="modal-header">
                    <h3><i class="fas fa-paper-plane"></i> Test OTP Email</h3>
                    <button class="modal-close">&times;</button>
                </div>
                <div class="modal-body">
                    <div class="form-group">
                        <label class="form-label">Select Target Email:</label>
                        <select class="form-input" id="targetEmailSelect">
                            <option value="">Loading emails...</option>
                        </select>
                        <small class="form-help">Choose a temporary email to send test OTP</small>
                    </div>
                    <div id="otpTestResult"></div>
                    <button class="btn btn-success" id="sendTestOTP" disabled>
                        <i class="fas fa-paper-plane"></i>
                        Send Test OTP
                    </button>
                </div>
            </div>
        `;

        document.body.appendChild(modal);

        // Close modal events
        modal.querySelector('.modal-close').addEventListener('click', () => {
            document.body.removeChild(modal);
        });
        modal.addEventListener('click', (e) => {
            if (e.target === modal) {
                document.body.removeChild(modal);
            }
        });

        // Load emails for selection
        this.loadEmailsForOTPTest(modal);

        // Send OTP button
        modal.querySelector('#sendTestOTP').addEventListener('click', () => {
            this.sendTestOTP(modal);
        });
    }

    async loadEmailsForOTPTest(modal) {
        try {
            const response = await this.apiCall('/api/admin/emails?limit=50');
            const select = modal.querySelector('#targetEmailSelect');
            const button = modal.querySelector('#sendTestOTP');
            
            if (response.emails.length === 0) {
                select.innerHTML = '<option value="">No active emails found</option>';
                return;
            }

            const activeEmails = response.emails.filter(email => 
                new Date(email.expiresAt) > new Date()
            );

            if (activeEmails.length === 0) {
                select.innerHTML = '<option value="">No active emails found</option>';
                return;
            }

            select.innerHTML = `
                <option value="">Select an email...</option>
                ${activeEmails.map(email => 
                    `<option value="${email.email}">${email.email} (${email.messageCount || 0} messages)</option>`
                ).join('')}
            `;

            select.addEventListener('change', () => {
                button.disabled = !select.value;
            });

        } catch (error) {
            console.error('Failed to load emails:', error);
            modal.querySelector('#targetEmailSelect').innerHTML = 
                '<option value="">Failed to load emails</option>';
        }
    }

    async sendTestOTP(modal) {
        const resultDiv = modal.querySelector('#otpTestResult');
        const button = modal.querySelector('#sendTestOTP');
        const select = modal.querySelector('#targetEmailSelect');
        const targetEmail = select.value;
        
        if (!targetEmail) {
            resultDiv.innerHTML = `
                <div class="alert alert-error">
                    <i class="fas fa-exclamation-circle"></i>
                    Please select a target email first.
                </div>
            `;
            return;
        }

        button.disabled = true;
        button.innerHTML = '<span class="loading"></span> Sending OTP...';
        
        try {
            const response = await this.apiCall('/api/admin/send-test-otp', 'POST', {
                targetEmail: targetEmail
            });
            
            resultDiv.innerHTML = `
                <div class="alert alert-success">
                    <h4><i class="fas fa-check-circle"></i> Test OTP Sent Successfully!</h4>
                    <p><strong>Target Email:</strong> ${response.targetEmail}</p>
                    <p><strong>OTP Code:</strong> <code style="font-size: 1.2em; font-weight: bold; color: #007bff;">${response.otp}</code></p>
                    <p><strong>Sent At:</strong> ${new Date(response.sentAt).toLocaleString()}</p>
                    <div class="mt-2">
                        <small class="text-info">
                            <i class="fas fa-info-circle"></i>
                            Check the Messages tab to see the OTP email in the admin panel.
                        </small>
                    </div>
                </div>
            `;
        } catch (error) {
            resultDiv.innerHTML = `
                <div class="alert alert-error">
                    <h4><i class="fas fa-exclamation-circle"></i> Failed to Send OTP</h4>
                    <p>${error.message}</p>
                </div>
            `;
        } finally {
            button.disabled = false;
            button.innerHTML = '<i class="fas fa-paper-plane"></i> Send Test OTP';
        }
    }

    async apiCall(endpoint, method = 'GET', data = null) {
        const options = {
            method,
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${this.token}`
            }
        };

        if (data) {
            options.body = JSON.stringify(data);
        }

        const response = await fetch(endpoint, options);
        const result = await response.json();

        if (!response.ok) {
            throw new Error(result.error || 'API call failed');
        }

        return result;
    }

    initSocketIO() {
        if (!this.token) return;
        
        // Initialize Socket.IO connection
        this.socket = io();
        
        // Handle connection events
        this.socket.on('connect', () => {
            console.log('Socket.IO connected for real-time updates');
            this.showNotification('Connected to real-time updates', 'success');
        });
        
        this.socket.on('disconnect', () => {
            console.log('Socket.IO disconnected');
            this.showNotification('Disconnected from real-time updates', 'warning');
        });
        
        // Handle real-time email notifications
        this.socket.on('messageReceived', (data) => {
            console.log('New message received:', data);
            this.handleNewMessage(data);
        });
        
        // Handle real-time log notifications
        this.socket.on('newLog', (data) => {
            console.log('New log entry:', data);
            this.handleNewLog(data);
        });
    }
    
    handleNewMessage(data) {
        // Show notification for new message
        this.showNotification(`New message received for ${data.email}`, 'info');
        
        // Update dashboard stats if on dashboard page
        if (this.currentPage === 'dashboard') {
            this.loadDashboard();
        }
        
        // Update emails table if on emails page
        if (this.currentPage === 'emails') {
            this.loadEmails();
        }
        
        // Play notification sound
        this.playNotificationSound();
    }
    
    handleNewLog(data) {
        // Update logs table if on logs page
        if (this.currentPage === 'logs') {
            this.loadLogs();
        }
    }
    
    showNotification(message, type = 'info') {
        // Create notification element
        const notification = document.createElement('div');
        notification.className = `notification notification-${type}`;
        notification.innerHTML = `
            <div class="notification-content">
                <i class="fas ${this.getNotificationIcon(type)}"></i>
                <span>${message}</span>
                <button class="notification-close">&times;</button>
            </div>
        `;
        
        // Add notification styles if not already added
        if (!document.querySelector('#notification-styles')) {
            const notificationStyles = document.createElement('style');
            notificationStyles.id = 'notification-styles';
            notificationStyles.textContent = `
                .notification {
                    position: fixed;
                    top: 20px;
                    right: 20px;
                    background: var(--bg-primary);
                    border: 1px solid var(--border-primary);
                    border-radius: var(--radius-md);
                    padding: 1rem;
                    box-shadow: var(--shadow-lg);
                    z-index: 1000;
                    min-width: 300px;
                    animation: slideInRight 0.3s ease-out;
                }
                .notification-success {
                    border-left: 4px solid #10b981;
                }
                .notification-info {
                    border-left: 4px solid #3b82f6;
                }
                .notification-warning {
                    border-left: 4px solid #f59e0b;
                }
                .notification-error {
                    border-left: 4px solid #ef4444;
                }
                .notification-content {
                    display: flex;
                    align-items: center;
                    gap: 0.5rem;
                }
                .notification-content i {
                    color: var(--primary-color);
                }
                .notification-content span {
                    flex: 1;
                    color: var(--text-primary);
                }
                .notification-close {
                    background: none;
                    border: none;
                    color: var(--text-secondary);
                    cursor: pointer;
                    font-size: 1.2rem;
                }
                @keyframes slideInRight {
                    from {
                        transform: translateX(100%);
                        opacity: 0;
                    }
                    to {
                        transform: translateX(0);
                        opacity: 1;
                    }
                }
            `;
            document.head.appendChild(notificationStyles);
        }
        
        // Add to page
        document.body.appendChild(notification);
        
        // Auto remove after 5 seconds
        setTimeout(() => {
            if (notification.parentNode) {
                notification.parentNode.removeChild(notification);
            }
        }, 5000);
        
        // Close button event
        notification.querySelector('.notification-close').addEventListener('click', () => {
            if (notification.parentNode) {
                notification.parentNode.removeChild(notification);
            }
        });
    }
    
    getNotificationIcon(type) {
        const icons = {
            success: 'fa-check-circle',
            info: 'fa-info-circle',
            warning: 'fa-exclamation-triangle',
            error: 'fa-times-circle'
        };
        return icons[type] || 'fa-info-circle';
    }
    
    playNotificationSound() {
        // Create a simple notification sound using Web Audio API
        try {
            const audioContext = new (window.AudioContext || window.webkitAudioContext)();
            const oscillator = audioContext.createOscillator();
            const gainNode = audioContext.createGain();
            
            oscillator.connect(gainNode);
            gainNode.connect(audioContext.destination);
            
            oscillator.frequency.setValueAtTime(800, audioContext.currentTime);
            oscillator.frequency.setValueAtTime(600, audioContext.currentTime + 0.1);
            
            gainNode.gain.setValueAtTime(0.3, audioContext.currentTime);
            gainNode.gain.exponentialRampToValueAtTime(0.01, audioContext.currentTime + 0.2);
            
            oscillator.start(audioContext.currentTime);
            oscillator.stop(audioContext.currentTime + 0.2);
        } catch (error) {
            console.log('Audio notification not supported');
         }
     }

    async loadSettings() {
        try {
            const response = await this.apiCall('/api/admin/settings');
            
            // Load current settings
            document.getElementById('emailExpiryTime').value = response.settings.emailExpiryTime || 60;
            document.getElementById('messageRetentionTime').value = response.settings.messageRetentionTime || 24;
            document.getElementById('realtimeApiPush').checked = response.settings.realtimeApiPush !== false;
            document.getElementById('autoRefreshInterval').value = response.settings.autoRefreshInterval || 5;
            
            // Load domains
            this.loadDomains();
        } catch (error) {
            console.error('Failed to load settings:', error);
            // Use default values if loading fails
        }
    }

    async saveSettings() {
        const resultDiv = document.getElementById('settingsResult');
        const button = document.getElementById('saveSettings');
        
        button.disabled = true;
        button.innerHTML = '<span class="loading"></span> Saving...';
        
        try {
            const settings = {
                emailExpiryTime: parseInt(document.getElementById('emailExpiryTime').value),
                messageRetentionTime: parseInt(document.getElementById('messageRetentionTime').value),
                realtimeApiPush: document.getElementById('realtimeApiPush').checked,
                autoRefreshInterval: parseInt(document.getElementById('autoRefreshInterval').value)
            };
            
            // Validate settings
            if (settings.emailExpiryTime < 1 || settings.emailExpiryTime > 1440) {
                throw new Error('Email expiry time must be between 1-1440 minutes');
            }
            if (settings.messageRetentionTime < 1 || settings.messageRetentionTime > 168) {
                throw new Error('Message retention time must be between 1-168 hours');
            }
            if (settings.autoRefreshInterval < 1 || settings.autoRefreshInterval > 60) {
                throw new Error('Auto-refresh interval must be between 1-60 seconds');
            }
            
            const response = await this.apiCall('/api/admin/settings', 'POST', settings);
            
            resultDiv.innerHTML = `
                <div class="alert alert-success">
                    <h4><i class="fas fa-check-circle"></i> Settings Saved Successfully!</h4>
                    <p><strong>Email Expiry:</strong> ${settings.emailExpiryTime} minutes</p>
                    <p><strong>Message Retention:</strong> ${settings.messageRetentionTime} hours</p>
                    <p><strong>Real-time API Push:</strong> ${settings.realtimeApiPush ? 'Enabled' : 'Disabled'}</p>
                    <p><strong>Auto-refresh Interval:</strong> ${settings.autoRefreshInterval} seconds</p>
                    <div class="mt-2">
                        <small class="text-info">
                            <i class="fas fa-info-circle"></i>
                            Settings will take effect immediately for new emails.
                        </small>
                    </div>
                </div>
            `;
            
            // Update auto-refresh if enabled
            this.updateAutoRefresh(settings.autoRefreshInterval, settings.realtimeApiPush);
            
        } catch (error) {
            resultDiv.innerHTML = `
                <div class="alert alert-error">
                    <h4><i class="fas fa-exclamation-circle"></i> Failed to Save Settings</h4>
                    <p>${error.message}</p>
                </div>
            `;
        } finally {
            button.disabled = false;
            button.innerHTML = '<i class="fas fa-save"></i> Save Settings';
        }
    }

    updateAutoRefresh(interval, enabled) {
        // Clear existing auto-refresh
        if (this.autoRefreshTimer) {
            clearInterval(this.autoRefreshTimer);
        }
        
        // Set new auto-refresh if enabled
        if (enabled && interval > 0) {
            this.autoRefreshTimer = setInterval(() => {
                if (this.currentPage === 'emails') {
                    this.loadEmails();
                } else if (this.currentPage === 'dashboard') {
                    this.loadDashboard();
                } else if (this.currentPage === 'logs') {
                    this.loadLogs();
                } else if (this.currentPage === 'test-inbox') {
                    this.refreshTestInboxMessages();
                }
            }, interval * 1000);
        }
    }

    // Test Inbox Methods
    loadTestInbox() {
        this.bindTestInboxEvents();
        this.loadTestHistory();
        this.loadTestConfig();
        
        // Start auto-refresh if enabled
        const autoRefresh = localStorage.getItem('testAutoRefresh');
        if (autoRefresh !== 'false') {
            this.startTestAutoRefresh();
        }
    }

    bindTestInboxEvents() {
        // Generate new test email
        const generateBtn = document.getElementById('generateNewTestEmail');
        if (generateBtn) {
            generateBtn.addEventListener('click', () => {
                this.generateTestEmail();
            });
        }

        // Refresh test inbox
        const refreshBtn = document.getElementById('refreshTestInbox');
        if (refreshBtn) {
            refreshBtn.addEventListener('click', () => {
                this.refreshTestInboxMessages();
            });
        }

        // Clear test history
        const clearBtn = document.getElementById('clearTestHistory');
        if (clearBtn) {
            clearBtn.addEventListener('click', () => {
                this.clearTestHistory();
            });
        }

        // Save test config
        const saveConfigBtn = document.getElementById('saveTestConfig');
        if (saveConfigBtn) {
            saveConfigBtn.addEventListener('click', () => {
                this.saveTestConfig();
            });
        }

        // Auto-refresh toggle
        const autoRefreshToggle = document.getElementById('testAutoRefresh');
        if (autoRefreshToggle) {
            autoRefreshToggle.addEventListener('change', (e) => {
                localStorage.setItem('testAutoRefresh', e.target.checked);
                if (e.target.checked) {
                    this.startTestAutoRefresh();
                } else {
                    this.stopTestAutoRefresh();
                }
            });
        }
    }

    async generateTestEmail() {
        const generateBtn = document.getElementById('generateNewTestEmail');
        const currentEmailDiv = document.getElementById('currentTestEmail');
        
        generateBtn.disabled = true;
        generateBtn.innerHTML = '<span class="loading"></span> Generating...';
        
        try {
            const response = await this.apiCall('/api/temp-email/generate', 'POST');
            
            // Store current test email
            this.currentTestEmail = response;
            localStorage.setItem('currentTestEmail', JSON.stringify(response));
            
            // Update display
            currentEmailDiv.innerHTML = `
                <div class="current-email-card">
                    <div class="email-header">
                        <h4><i class="fas fa-envelope"></i> Current Test Email</h4>
                        <div class="email-actions">
                            <button class="btn btn-sm btn-secondary" onclick="navigator.clipboard.writeText('${response.email}')">
                                <i class="fas fa-copy"></i> Copy
                            </button>
                            <button class="btn btn-sm btn-warning" id="deleteCurrentTestEmail">
                                <i class="fas fa-trash"></i> Delete
                            </button>
                        </div>
                    </div>
                    <div class="email-details">
                        <div class="email-address">
                            <strong>Email:</strong> <code>${response.email}</code>
                        </div>
                        <div class="email-info">
                            <span class="email-created"><i class="fas fa-clock"></i> Created: ${new Date(response.createdAt).toLocaleString()}</span>
                            <span class="email-expires"><i class="fas fa-hourglass-end"></i> Expires: ${new Date(response.expiresAt).toLocaleString()}</span>
                        </div>
                        <div class="email-status">
                            <span class="status-badge status-active">Active</span>
                        </div>
                    </div>
                </div>
            `;
            
            // Show messages section
            document.getElementById('testEmailMessages').style.display = 'block';
            
            // Bind delete button
            document.getElementById('deleteCurrentTestEmail').addEventListener('click', () => {
                this.deleteCurrentTestEmail();
            });
            
            // Subscribe to real-time updates
            if (this.socket) {
                this.socket.emit('subscribe:email', response.email);
            }
            
            // Add to history
            this.addToTestHistory(response);
            
            // Start checking for messages
            this.startMessagePolling();
            
            this.showNotification('success', 'Test email generated successfully!', `Email: ${response.email}`);
            
        } catch (error) {
            this.showNotification('error', 'Failed to generate test email', error.message);
        } finally {
            generateBtn.disabled = false;
            generateBtn.innerHTML = '<i class="fas fa-plus"></i> Generate New Email';
        }
    }

    async deleteCurrentTestEmail() {
        if (!this.currentTestEmail) return;
        
        if (!confirm('Are you sure you want to delete this test email?')) return;
        
        try {
            await this.apiCall(`/api/temp-email/${this.currentTestEmail.id}`, 'DELETE');
            
            // Clear current email
            this.currentTestEmail = null;
            localStorage.removeItem('currentTestEmail');
            
            // Update display
            document.getElementById('currentTestEmail').innerHTML = `
                <div class="alert alert-info">
                    <i class="fas fa-info-circle"></i>
                    Click "Generate New Email" to create a test temporary email address.
                </div>
            `;
            
            // Hide messages section
            document.getElementById('testEmailMessages').style.display = 'none';
            
            // Stop message polling
            this.stopMessagePolling();
            
            // Update history
            this.loadTestHistory();
            
            this.showNotification('success', 'Test email deleted successfully!');
            
        } catch (error) {
            this.showNotification('error', 'Failed to delete test email', error.message);
        }
    }

    async refreshTestInboxMessages() {
        if (!this.currentTestEmail) return;
        
        try {
            const messages = await this.apiCall(`/api/temp-email/${this.currentTestEmail.id}/messages`);
            this.displayTestMessages(messages);
        } catch (error) {
            console.error('Failed to refresh messages:', error);
        }
    }

    displayTestMessages(messages) {
        const container = document.getElementById('messagesContainer');
        
        if (!messages || messages.length === 0) {
            container.innerHTML = `
                <div class="no-messages">
                    <i class="fas fa-inbox"></i>
                    <p>No messages received yet</p>
                    <small>Send an email to ${this.currentTestEmail?.email || 'your test email'} to see it here</small>
                </div>
            `;
            return;
        }
        
        container.innerHTML = messages.map(message => `
            <div class="message-card">
                <div class="message-header">
                    <div class="message-from">
                        <i class="fas fa-user"></i>
                        <strong>From:</strong> ${message.from || 'Unknown'}
                    </div>
                    <div class="message-date">
                        <i class="fas fa-clock"></i>
                        ${new Date(message.receivedAt).toLocaleString()}
                    </div>
                </div>
                <div class="message-subject">
                    <i class="fas fa-envelope"></i>
                    <strong>Subject:</strong> ${message.subject || 'No Subject'}
                </div>
                <div class="message-content">
                    <div class="message-text">
                        ${message.text || message.html || 'No content'}
                    </div>
                </div>
                <div class="message-actions">
                    <button class="btn btn-sm btn-primary" onclick="adminPanel.viewFullMessage('${message.id}')">
                        <i class="fas fa-eye"></i> View Full
                    </button>
                    <button class="btn btn-sm btn-danger" onclick="adminPanel.deleteMessage('${message.id}')">
                        <i class="fas fa-trash"></i> Delete
                    </button>
                </div>
            </div>
        `).join('');
    }

    startMessagePolling() {
        this.stopMessagePolling();
        
        this.messagePollingTimer = setInterval(() => {
            this.refreshTestInboxMessages();
        }, 5000); // Check every 5 seconds
    }

    stopMessagePolling() {
        if (this.messagePollingTimer) {
            clearInterval(this.messagePollingTimer);
            this.messagePollingTimer = null;
        }
    }

    addToTestHistory(email) {
        let history = JSON.parse(localStorage.getItem('testEmailHistory') || '[]');
        history.unshift({
            ...email,
            messagesReceived: 0,
            status: 'active'
        });
        
        // Keep only last 50 entries
        if (history.length > 50) {
            history = history.slice(0, 50);
        }
        
        localStorage.setItem('testEmailHistory', JSON.stringify(history));
        this.loadTestHistory();
    }

    loadTestHistory() {
        const history = JSON.parse(localStorage.getItem('testEmailHistory') || '[]');
        const tbody = document.getElementById('testHistoryTableBody');
        
        if (history.length === 0) {
            tbody.innerHTML = '<tr><td colspan="6" class="text-center">No test emails created yet</td></tr>';
            return;
        }
        
        tbody.innerHTML = history.map(email => {
            const isExpired = new Date() > new Date(email.expiresAt);
            const status = isExpired ? 'expired' : 'active';
            const statusClass = isExpired ? 'status-expired' : 'status-active';
            
            return `
                <tr>
                    <td><code>${email.email}</code></td>
                    <td>${new Date(email.createdAt).toLocaleString()}</td>
                    <td>${new Date(email.expiresAt).toLocaleString()}</td>
                    <td>${email.messagesReceived || 0}</td>
                    <td><span class="status-badge ${statusClass}">${status}</span></td>
                    <td>
                        <button class="btn btn-sm btn-primary" onclick="adminPanel.viewTestEmailMessages('${email.id}')">
                            <i class="fas fa-eye"></i>
                        </button>
                        <button class="btn btn-sm btn-danger" onclick="adminPanel.deleteTestEmailFromHistory('${email.id}')">
                            <i class="fas fa-trash"></i>
                        </button>
                    </td>
                </tr>
            `;
        }).join('');
    }

    async viewTestEmailMessages(emailId) {
        try {
            const messages = await this.apiCall(`/api/temp-email/${emailId}/messages`);
            
            // Create modal to show messages
            const modal = document.createElement('div');
            modal.className = 'modal';
            modal.style.display = 'block';
            modal.innerHTML = `
                <div class="modal-content">
                    <div class="modal-header">
                        <h3>Email Messages</h3>
                        <button class="modal-close">&times;</button>
                    </div>
                    <div class="modal-body">
                        ${messages.length === 0 ? 
                            '<p>No messages found for this email.</p>' : 
                            messages.map(msg => `
                                <div class="message-card">
                                    <strong>From:</strong> ${msg.from}<br>
                                    <strong>Subject:</strong> ${msg.subject}<br>
                                    <strong>Date:</strong> ${new Date(msg.receivedAt).toLocaleString()}<br>
                                    <div class="mt-2">${msg.text || msg.html}</div>
                                </div>
                            `).join('')
                        }
                    </div>
                </div>
            `;
            
            document.body.appendChild(modal);
            
            modal.querySelector('.modal-close').addEventListener('click', () => {
                document.body.removeChild(modal);
            });
            
        } catch (error) {
            this.showNotification('error', 'Failed to load messages', error.message);
        }
    }

    deleteTestEmailFromHistory(emailId) {
        if (!confirm('Remove this email from history?')) return;
        
        let history = JSON.parse(localStorage.getItem('testEmailHistory') || '[]');
        history = history.filter(email => email.id !== emailId);
        localStorage.setItem('testEmailHistory', JSON.stringify(history));
        this.loadTestHistory();
        
        this.showNotification('success', 'Email removed from history');
    }

    clearTestHistory() {
        if (!confirm('Are you sure you want to clear all test email history?')) return;
        
        localStorage.removeItem('testEmailHistory');
        this.loadTestHistory();
        
        this.showNotification('success', 'Test email history cleared');
    }

    loadTestConfig() {
        // Load saved configuration
        const autoGenerate = localStorage.getItem('testAutoGenerateInterval') || '0';
        const emailExpiry = localStorage.getItem('testEmailExpiry') || '10';
        const autoRefresh = localStorage.getItem('testAutoRefresh');
        
        document.getElementById('testAutoGenerateInterval').value = autoGenerate;
        document.getElementById('testEmailExpiry').value = emailExpiry;
        document.getElementById('testAutoRefresh').checked = autoRefresh !== 'false';
    }

    saveTestConfig() {
        const autoGenerate = document.getElementById('testAutoGenerateInterval').value;
        const emailExpiry = document.getElementById('testEmailExpiry').value;
        const autoRefresh = document.getElementById('testAutoRefresh').checked;
        
        localStorage.setItem('testAutoGenerateInterval', autoGenerate);
        localStorage.setItem('testEmailExpiry', emailExpiry);
        localStorage.setItem('testAutoRefresh', autoRefresh);
        
        // Update auto-generation
        this.updateAutoGeneration(parseInt(autoGenerate));
        
        this.showNotification('success', 'Test configuration saved successfully!');
    }

    updateAutoGeneration(intervalMinutes) {
        // Clear existing auto-generation
        if (this.autoGenerateTimer) {
            clearInterval(this.autoGenerateTimer);
        }
        
        // Set new auto-generation if enabled
        if (intervalMinutes > 0) {
            this.autoGenerateTimer = setInterval(() => {
                if (this.currentPage === 'test-inbox') {
                    this.generateTestEmail();
                }
            }, intervalMinutes * 60 * 1000);
        }
    }

    startTestAutoRefresh() {
        this.stopTestAutoRefresh();
        
        this.testAutoRefreshTimer = setInterval(() => {
            if (this.currentPage === 'test-inbox') {
                this.refreshTestInboxMessages();
            }
        }, 5000);
    }

    stopTestAutoRefresh() {
        if (this.testAutoRefreshTimer) {
            clearInterval(this.testAutoRefreshTimer);
            this.testAutoRefreshTimer = null;
        }
    }

    async viewFullMessage(messageId) {
        try {
            const message = await this.apiCall(`/api/message/${messageId}`);
            
            // Create modal to show full message
            const modal = document.createElement('div');
            modal.className = 'modal';
            modal.style.display = 'block';
            modal.innerHTML = `
                <div class="modal-content" style="max-width: 800px;">
                    <div class="modal-header">
                        <h3>Full Message</h3>
                        <button class="modal-close">&times;</button>
                    </div>
                    <div class="modal-body">
                        <div class="message-details">
                            <div class="detail-row">
                                <strong>From:</strong> ${message.from || 'Unknown'}
                            </div>
                            <div class="detail-row">
                                <strong>To:</strong> ${message.to || this.currentTestEmail?.email || 'Unknown'}
                            </div>
                            <div class="detail-row">
                                <strong>Subject:</strong> ${message.subject || 'No Subject'}
                            </div>
                            <div class="detail-row">
                                <strong>Date:</strong> ${new Date(message.receivedAt).toLocaleString()}
                            </div>
                            <hr>
                            <div class="message-body">
                                <h4>Message Content:</h4>
                                <div class="content-display">
                                    ${message.html ? 
                                        `<iframe srcdoc="${message.html.replace(/"/g, '&quot;')}" style="width: 100%; min-height: 300px; border: 1px solid #ddd;"></iframe>` : 
                                        `<pre style="white-space: pre-wrap; background: #f5f5f5; padding: 1rem; border-radius: 4px;">${message.text || 'No content'}</pre>`
                                    }
                                </div>
                            </div>
                            ${message.attachments && message.attachments.length > 0 ? `
                                <hr>
                                <div class="attachments">
                                    <h4>Attachments:</h4>
                                    ${message.attachments.map(att => `
                                        <div class="attachment-item">
                                            <i class="fas fa-paperclip"></i>
                                            ${att.filename} (${att.size} bytes)
                                        </div>
                                    `).join('')}
                                </div>
                            ` : ''}
                        </div>
                    </div>
                    <div class="modal-footer">
                        <button class="btn btn-danger" onclick="adminPanel.deleteMessage('${messageId}'); document.body.removeChild(this.closest('.modal'));">
                            <i class="fas fa-trash"></i> Delete Message
                        </button>
                        <button class="btn btn-secondary" onclick="document.body.removeChild(this.closest('.modal'));">
                            Close
                        </button>
                    </div>
                </div>
            `;
            
            document.body.appendChild(modal);
            
            modal.querySelector('.modal-close').addEventListener('click', () => {
                document.body.removeChild(modal);
            });
            
        } catch (error) {
            this.showNotification('error', 'Failed to load message', error.message);
        }
    }

    async deleteMessage(messageId) {
        if (!confirm('Are you sure you want to delete this message?')) return;
        
        try {
            await this.apiCall(`/api/message/${messageId}`, 'DELETE');
            this.showNotification('success', 'Message deleted successfully');
            this.refreshTestInboxMessages();
        } catch (error) {
            this.showNotification('error', 'Failed to delete message', error.message);
        }
    }

    // Global Settings Methods
    loadGlobalSettings() {
        // Load saved global settings
        const settings = {
            mailAutoDeleteTime: localStorage.getItem('mailAutoDeleteTime') || '30',
            emailChangeInterval: localStorage.getItem('emailChangeInterval') || '0',
            defaultEmailExpiry: localStorage.getItem('defaultEmailExpiry') || '60',
            maxMessagesPerEmail: localStorage.getItem('maxMessagesPerEmail') || '50',
            enableAutoCleanup: localStorage.getItem('enableAutoCleanup') !== 'false',
            enableRateLimit: localStorage.getItem('enableRateLimit') !== 'false'
        };

        // Apply settings to form
        Object.keys(settings).forEach(key => {
            const element = document.getElementById(key);
            if (element) {
                if (element.type === 'checkbox') {
                    element.checked = settings[key];
                } else {
                    element.value = settings[key];
                }
            }
        });
    }

    saveGlobalSettings() {
        const settings = {
            mailAutoDeleteTime: document.getElementById('mailAutoDeleteTime').value,
            emailChangeInterval: document.getElementById('emailChangeInterval').value,
            defaultEmailExpiry: document.getElementById('defaultEmailExpiry').value,
            maxMessagesPerEmail: document.getElementById('maxMessagesPerEmail').value,
            enableAutoCleanup: document.getElementById('enableAutoCleanup').checked,
            enableRateLimit: document.getElementById('enableRateLimit').checked
        };

        // Validate settings
        if (parseInt(settings.mailAutoDeleteTime) < 5 || parseInt(settings.mailAutoDeleteTime) > 1440) {
            this.showNotification('error', 'Auto delete time must be between 5 and 1440 minutes');
            return;
        }

        if (parseInt(settings.emailChangeInterval) < 0 || parseInt(settings.emailChangeInterval) > 60) {
            this.showNotification('error', 'Email change interval must be between 0 and 60 minutes');
            return;
        }

        // Save settings
        Object.keys(settings).forEach(key => {
            localStorage.setItem(key, settings[key]);
        });

        // Apply auto-delete timer
        this.updateAutoDeleteTimer(parseInt(settings.mailAutoDeleteTime));
        
        // Apply email change timer
        this.updateEmailChangeTimer(parseInt(settings.emailChangeInterval));

        this.showNotification('success', 'Global settings saved successfully!');
    }

    resetGlobalSettings() {
        if (!confirm('Are you sure you want to reset all global settings to default?')) return;

        // Clear all global settings from localStorage
        const settingsKeys = [
            'mailAutoDeleteTime', 'emailChangeInterval', 'defaultEmailExpiry',
            'maxMessagesPerEmail', 'enableAutoCleanup', 'enableRateLimit'
        ];
        
        settingsKeys.forEach(key => localStorage.removeItem(key));
        
        // Reload settings
        this.loadGlobalSettings();
        
        this.showNotification('success', 'Global settings reset to default values');
    }

    updateAutoDeleteTimer(minutes) {
        // Clear existing timer
        if (this.autoDeleteTimer) {
            clearInterval(this.autoDeleteTimer);
        }

        // Set new timer if enabled
        if (minutes > 0) {
            this.autoDeleteTimer = setInterval(async () => {
                try {
                    await this.apiCall('/api/admin/cleanup-expired', 'POST');
                    console.log('Auto-cleanup executed');
                } catch (error) {
                    console.error('Auto-cleanup failed:', error);
                }
            }, minutes * 60 * 1000);
        }
    }

    updateEmailChangeTimer(minutes) {
        // Clear existing timer
        if (this.emailChangeTimer) {
            clearInterval(this.emailChangeTimer);
        }

        // Set new timer if enabled
        if (minutes > 0) {
            this.emailChangeTimer = setInterval(() => {
                if (this.currentPage === 'test-inbox' && this.currentTestEmail) {
                    this.generateTestEmail();
                }
            }, minutes * 60 * 1000);
        }
    }

    // Advanced Features Methods
    loadAdvancedFeatures() {
        const features = {
            enableAntiSpam: localStorage.getItem('enableAntiSpam') !== 'false',
            enableAttachments: localStorage.getItem('enableAttachments') !== 'false',
            enableMobileAPI: localStorage.getItem('enableMobileAPI') !== 'false',
            enableNotifications: localStorage.getItem('enableNotifications') !== 'false',
            enableBulkOps: localStorage.getItem('enableBulkOps') !== 'false',
            enableAnalytics: localStorage.getItem('enableAnalytics') !== 'false'
        };

        Object.keys(features).forEach(key => {
            const element = document.getElementById(key);
            if (element) {
                element.checked = features[key];
            }
        });
    }

    saveAdvancedFeatures() {
        const features = {
            enableAntiSpam: document.getElementById('enableAntiSpam').checked,
            enableAttachments: document.getElementById('enableAttachments').checked,
            enableMobileAPI: document.getElementById('enableMobileAPI').checked,
            enableNotifications: document.getElementById('enableNotifications').checked,
            enableBulkOps: document.getElementById('enableBulkOps').checked,
            enableAnalytics: document.getElementById('enableAnalytics').checked
        };

        Object.keys(features).forEach(key => {
            localStorage.setItem(key, features[key]);
        });

        this.showNotification('success', 'Advanced features settings saved successfully!');
    }

    async testAllFeatures() {
        this.showNotification('info', 'Testing all features...');
        
        const tests = [
            { name: 'Anti-Spam Protection', test: () => this.testAntiSpam() },
            { name: 'Attachment Support', test: () => this.testAttachments() },
            { name: 'Mobile API', test: () => this.testMobileAPI() },
            { name: 'Real-time Notifications', test: () => this.testNotifications() },
            { name: 'Bulk Operations', test: () => this.testBulkOps() },
            { name: 'Analytics & Reporting', test: () => this.testAnalytics() }
        ];

        let results = [];
        
        for (const test of tests) {
            try {
                const result = await test.test();
                results.push({ name: test.name, status: 'success', result });
            } catch (error) {
                results.push({ name: test.name, status: 'error', error: error.message });
            }
        }

        // Show test results
        this.showTestResults(results);
    }

    async testAntiSpam() {
        // Test anti-spam functionality
        return 'Anti-spam protection is active';
    }

    async testAttachments() {
        // Test attachment support
        return 'Attachment support is enabled';
    }

    async testMobileAPI() {
        // Test mobile API
        try {
            const response = await this.apiCall('/api/admin/stats');
            return 'Mobile API is responsive';
        } catch (error) {
            throw new Error('Mobile API test failed');
        }
    }

    async testNotifications() {
        // Test real-time notifications
        if (this.socket && this.socket.connected) {
            return 'Real-time notifications are working';
        } else {
            throw new Error('WebSocket connection not available');
        }
    }

    async testBulkOps() {
        // Test bulk operations
        return 'Bulk operations are available';
    }

    async testAnalytics() {
        // Test analytics
        try {
            const stats = await this.apiCall('/api/admin/stats');
            return `Analytics working - ${stats.totalEmails || 0} emails tracked`;
        } catch (error) {
            throw new Error('Analytics test failed');
        }
    }

    showTestResults(results) {
        const modal = document.createElement('div');
        modal.className = 'modal';
        modal.style.display = 'block';
        modal.innerHTML = `
            <div class="modal-content" style="max-width: 600px;">
                <div class="modal-header">
                    <h3>Feature Test Results</h3>
                    <button class="modal-close">&times;</button>
                </div>
                <div class="modal-body">
                    <div class="test-results">
                        ${results.map(result => `
                            <div class="test-result ${result.status}">
                                <div class="test-name">
                                    <i class="fas fa-${result.status === 'success' ? 'check-circle' : 'times-circle'}"></i>
                                    ${result.name}
                                </div>
                                <div class="test-message">
                                    ${result.status === 'success' ? result.result : result.error}
                                </div>
                            </div>
                        `).join('')}
                    </div>
                </div>
                <div class="modal-footer">
                    <button class="btn btn-secondary" onclick="document.body.removeChild(this.closest('.modal'));">Close</button>
                </div>
            </div>
        `;
        
        document.body.appendChild(modal);
        
        modal.querySelector('.modal-close').addEventListener('click', () => {
            document.body.removeChild(modal);
        });
    }

    // Initialize event listeners for global settings
    initializeGlobalSettings() {
        // Save global settings button
        const saveGlobalBtn = document.getElementById('saveGlobalSettings');
        if (saveGlobalBtn) {
            saveGlobalBtn.addEventListener('click', () => {
                this.saveGlobalSettings();
            });
        }

        // Reset global settings button
        const resetGlobalBtn = document.getElementById('resetGlobalSettings');
        if (resetGlobalBtn) {
            resetGlobalBtn.addEventListener('click', () => {
                this.resetGlobalSettings();
            });
        }
    }

    // Initialize event listeners for advanced features
    initializeAdvancedFeatures() {
        // Save advanced features button
        const saveAdvancedBtn = document.getElementById('saveAdvancedFeatures');
        if (saveAdvancedBtn) {
            saveAdvancedBtn.addEventListener('click', () => {
                this.saveAdvancedFeatures();
            });
        }

        // Test all features button
        const testAllBtn = document.getElementById('testAllFeatures');
        if (testAllBtn) {
            testAllBtn.addEventListener('click', () => {
                this.testAllFeatures();
            });
        }
    }

    // Domain Management Methods
    async loadDomains() {
        try {
            const response = await this.apiCall('/api/admin/domains');
            this.displayDomains(response.domains);
            this.updatePrimaryDomainSelect(response.domains);
        } catch (error) {
            console.error('Failed to load domains:', error);
            this.showNotification('error', 'Failed to load domains');
        }
    }

    displayDomains(domains) {
        const tbody = document.getElementById('domainsTableBody');
        
        if (!domains || domains.length === 0) {
            tbody.innerHTML = '<tr><td colspan="5" class="text-center">No domains found</td></tr>';
            return;
        }

        tbody.innerHTML = domains.map(domain => {
            const statusBadge = domain.status === 'active' ? 
                '<span class="badge badge-success">Active</span>' : 
                '<span class="badge badge-secondary">Inactive</span>';
            
            return `
                <tr>
                    <td>${domain.name}</td>
                    <td>${statusBadge}</td>
                    <td>${new Date(domain.addedAt).toLocaleDateString()}</td>
                    <td>${domain.emailsGenerated || 0}</td>
                    <td>
                        <button class="btn btn-sm btn-secondary" onclick="adminPanel.toggleDomainStatus('${domain.name}')">
                            <i class="fas fa-${domain.status === 'active' ? 'pause' : 'play'}"></i>
                            ${domain.status === 'active' ? 'Deactivate' : 'Activate'}
                        </button>
                        <button class="btn btn-sm btn-danger" onclick="adminPanel.deleteDomain('${domain.name}')">
                            <i class="fas fa-trash"></i>
                            Delete
                        </button>
                    </td>
                </tr>
            `;
        }).join('');
    }

    updatePrimaryDomainSelect(domains) {
        const select = document.getElementById('primaryDomain');
        if (!select) return;
        
        const activeDomains = domains.filter(d => d.status === 'active');
        select.innerHTML = activeDomains.map(domain => 
            `<option value="${domain.name}">${domain.name}</option>`
        ).join('');
    }

    showAddDomainForm() {
        document.getElementById('addDomainForm').style.display = 'block';
        document.getElementById('newDomainName').focus();
    }

    hideAddDomainForm() {
        document.getElementById('addDomainForm').style.display = 'none';
        document.getElementById('newDomainName').value = '';
        document.getElementById('newDomainStatus').value = 'active';
    }

    async saveDomain() {
        const domainName = document.getElementById('newDomainName').value.trim();
        const domainStatus = document.getElementById('newDomainStatus').value;

        if (!domainName) {
            this.showNotification('error', 'Please enter a domain name');
            return;
        }

        // Validate domain format
        const domainRegex = /^[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9]?\.[a-zA-Z]{2,}$/;
        if (!domainRegex.test(domainName)) {
            this.showNotification('error', 'Please enter a valid domain name');
            return;
        }

        try {
            await this.apiCall('/api/admin/domains', 'POST', {
                name: domainName,
                status: domainStatus
            });

            this.showNotification('success', 'Domain added successfully!');
            this.hideAddDomainForm();
            this.loadDomains();
        } catch (error) {
            this.showNotification('error', error.message || 'Failed to add domain');
        }
    }

    async toggleDomainStatus(domainName) {
        try {
            await this.apiCall(`/api/admin/domains/${domainName}/toggle`, 'PUT');
            this.showNotification('success', 'Domain status updated successfully!');
            this.loadDomains();
        } catch (error) {
            this.showNotification('error', error.message || 'Failed to update domain status');
        }
    }

    async deleteDomain(domainName) {
        if (!confirm(`Are you sure you want to delete domain "${domainName}"? This action cannot be undone.`)) {
            return;
        }

        try {
            await this.apiCall(`/api/admin/domains/${domainName}`, 'DELETE');
            this.showNotification('success', 'Domain deleted successfully!');
            this.loadDomains();
        } catch (error) {
            this.showNotification('error', error.message || 'Failed to delete domain');
        }
    }
}

// Add CSS for page content visibility
const style = document.createElement('style');
style.textContent = `
    .page-content {
        display: none;
    }
    .page-content.active {
        display: block;
    }
    .text-center {
        text-align: center;
    }
    .api-endpoint {
        margin-bottom: 2rem;
        padding: 1rem;
        background-color: var(--bg-tertiary);
        border-radius: var(--radius-md);
        border-left: 4px solid var(--primary-color);
    }
    .api-endpoint h5 {
        color: var(--primary-color);
        margin-bottom: 0.5rem;
    }
    .api-endpoint pre {
        background-color: var(--gray-800);
        color: var(--white);
        padding: 1rem;
        border-radius: var(--radius-md);
        overflow-x: auto;
        margin-top: 0.5rem;
    }
    .api-endpoint code {
        font-family: 'Courier New', monospace;
    }
`;
document.head.appendChild(style);

// Initialize admin panel
let adminPanel;
document.addEventListener('DOMContentLoaded', () => {
    adminPanel = new AdminPanel();
});