// RedMail Admin Panel - JavaScript
class AdminPanel {
    constructor() {
        this.token = localStorage.getItem('adminToken');
        this.currentPage = 'dashboard';
        this.init();
    }

    init() {
        this.checkAuth();
        this.bindEvents();
        this.loadDashboard();
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

        // Test button
        document.getElementById('testTempMail').addEventListener('click', () => {
            this.showTestModal();
        });

        // Test connectivity button
        document.getElementById('testConnectivity').addEventListener('click', () => {
            this.testConnectivity();
        });

        // Test OTP button
        document.getElementById('testOTP').addEventListener('click', () => {
            this.showOTPTestModal();
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
document.addEventListener('DOMContentLoaded', () => {
    new AdminPanel();
});