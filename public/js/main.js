// RedMail - Main Website JavaScript
class RedMailApp {
    constructor() {
        this.currentEmail = null;
        this.messages = [];
        this.refreshInterval = null;
        this.expiryInterval = null;
        this.socket = null;
        
        this.init();
    }
    
    init() {
        this.bindEvents();
        this.initializeSocket();
        this.generateNewEmail();
        this.startAutoRefresh();
    }
    
    bindEvents() {
        // Email actions
        document.getElementById('copyEmailBtn').addEventListener('click', () => this.copyEmail());
        document.getElementById('refreshEmailBtn').addEventListener('click', () => this.generateNewEmail());
        
        // Inbox actions
        document.getElementById('refreshInboxBtn').addEventListener('click', () => this.refreshInbox());
        document.getElementById('clearInboxBtn').addEventListener('click', () => this.clearInbox());
        
        // Modal actions
        document.getElementById('closeModal').addEventListener('click', () => this.closeModal());
        document.getElementById('closeModalBtn').addEventListener('click', () => this.closeModal());
        document.getElementById('deleteMessageBtn').addEventListener('click', () => this.deleteCurrentMessage());
        
        // Close modal on backdrop click
        document.getElementById('messageModal').addEventListener('click', (e) => {
            if (e.target.id === 'messageModal') {
                this.closeModal();
            }
        });
        
        // Smooth scrolling for navigation links
        document.querySelectorAll('a[href^="#"]').forEach(link => {
            link.addEventListener('click', (e) => {
                const href = link.getAttribute('href');
                if (href.startsWith('#') && href !== '#') {
                    e.preventDefault();
                    const target = document.querySelector(href);
                    if (target) {
                        target.scrollIntoView({ behavior: 'smooth' });
                    }
                }
            });
        });
    }
    
    initializeSocket() {
        try {
            this.socket = io();
            
            this.socket.on('connect', () => {
                console.log('Connected to server');
            });
            
            this.socket.on('newMessage', (data) => {
                if (this.currentEmail && data.emailId === this.currentEmail.id) {
                    this.refreshInbox();
                    this.showNotification('New message received!', 'success');
                }
            });
            
            this.socket.on('disconnect', () => {
                console.log('Disconnected from server');
            });
        } catch (error) {
            console.warn('Socket.IO not available:', error);
        }
    }
    
    async generateNewEmail() {
        try {
            this.showLoading('currentEmail', 'Generating new email...');
            
            const response = await fetch('/api/temp-email/generate', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                }
            });
            
            if (!response.ok) {
                throw new Error('Failed to generate email');
            }
            
            const data = await response.json();
            
            if (data.success) {
                this.currentEmail = data;
                this.displayEmail(data.email);
                this.updateEmailInfo(data);
                this.clearMessages();
                this.refreshInbox();
                this.startExpiryCountdown(data.expiresAt);
                
                // Join socket room for this email
                if (this.socket) {
                    this.socket.emit('joinEmail', data.id);
                }
            } else {
                throw new Error(data.error || 'Failed to generate email');
            }
        } catch (error) {
            console.error('Error generating email:', error);
            this.showError('Failed to generate email. Please try again.');
            document.getElementById('currentEmail').innerHTML = '<span class="error">Error generating email</span>';
        }
    }
    
    displayEmail(email) {
        const emailElement = document.getElementById('currentEmail');
        emailElement.textContent = email;
        emailElement.classList.remove('loading');
    }
    
    updateEmailInfo(data) {
        const expiryElement = document.getElementById('expiryTime');
        const messageCountElement = document.getElementById('messageCount');
        
        if (data.expiresAt) {
            const expiryDate = new Date(data.expiresAt);
            const now = new Date();
            const diffMinutes = Math.max(0, Math.floor((expiryDate - now) / (1000 * 60)));
            expiryElement.textContent = `${diffMinutes} minutes`;
        }
        
        messageCountElement.textContent = '0';
    }
    
    startExpiryCountdown(expiresAt) {
        if (this.expiryInterval) {
            clearInterval(this.expiryInterval);
        }
        
        this.expiryInterval = setInterval(() => {
            const expiryDate = new Date(expiresAt);
            const now = new Date();
            const diffMinutes = Math.max(0, Math.floor((expiryDate - now) / (1000 * 60)));
            
            const expiryElement = document.getElementById('expiryTime');
            expiryElement.textContent = `${diffMinutes} minutes`;
            
            if (diffMinutes <= 0) {
                clearInterval(this.expiryInterval);
                this.showNotification('Email expired! Generating new one...', 'warning');
                setTimeout(() => this.generateNewEmail(), 2000);
            }
        }, 60000); // Update every minute
    }
    
    async copyEmail() {
        if (!this.currentEmail) return;
        
        try {
            await navigator.clipboard.writeText(this.currentEmail.email);
            this.showNotification('Email copied to clipboard!', 'success');
            
            // Visual feedback
            const btn = document.getElementById('copyEmailBtn');
            const originalHTML = btn.innerHTML;
            btn.innerHTML = '<i class="fas fa-check"></i>';
            btn.style.background = 'linear-gradient(135deg, var(--success-color), var(--success-hover))';
            
            setTimeout(() => {
                btn.innerHTML = originalHTML;
                btn.style.background = '';
            }, 2000);
        } catch (error) {
            console.error('Failed to copy email:', error);
            this.showError('Failed to copy email to clipboard');
        }
    }
    
    async refreshInbox() {
        if (!this.currentEmail) return;
        
        try {
            const response = await fetch(`/api/temp-email/${this.currentEmail.id}/messages`);
            
            if (!response.ok) {
                throw new Error('Failed to fetch messages');
            }
            
            const data = await response.json();
            
            if (data.success) {
                this.messages = data.messages || [];
                this.displayMessages();
                this.updateMessageCount();
            } else {
                throw new Error(data.error || 'Failed to fetch messages');
            }
        } catch (error) {
            console.error('Error refreshing inbox:', error);
            this.showError('Failed to refresh inbox');
        }
    }
    
    displayMessages() {
        const container = document.getElementById('messagesContainer');
        
        if (this.messages.length === 0) {
            container.innerHTML = `
                <div class="empty-inbox">
                    <i class="fas fa-inbox"></i>
                    <h3>No messages yet</h3>
                    <p>Send an email to your temporary address to see it here</p>
                </div>
            `;
            return;
        }
        
        const messagesHTML = this.messages.map(message => {
            const date = new Date(message.receivedAt);
            const timeStr = date.toLocaleString();
            
            // Attachment indicator
            const attachmentIcon = message.hasAttachments ? 
                `<i class="fas fa-paperclip" title="${message.attachmentCount} attachment(s)"></i>` : '';
            
            // Expiry countdown
            const expiryCountdown = message.timeRemaining ? 
                `<span class="expiry-countdown" title="Message expires in ${message.timeRemaining}">🕒 ${message.timeRemaining}</span>` : '';
            
            return `
                <div class="message-item ${message.isExpired ? 'expired' : ''}" onclick="app.openMessage('${message.id}')">
                    <div class="message-header">
                        <div class="message-from">
                            ${this.escapeHtml(message.from)}
                            ${attachmentIcon}
                        </div>
                        <div class="message-time">
                            ${timeStr}
                            ${expiryCountdown}
                        </div>
                    </div>
                    <div class="message-subject">${this.escapeHtml(message.subject || 'No Subject')}</div>
                    <div class="message-preview">${this.escapeHtml(this.getMessagePreview(message))}</div>
                </div>
            `;
        }).join('');
        
        container.innerHTML = messagesHTML;
    }
    
    getMessagePreview(message) {
        if (message.text) {
            return message.text.substring(0, 150) + (message.text.length > 150 ? '...' : '');
        }
        if (message.html) {
            const tempDiv = document.createElement('div');
            tempDiv.innerHTML = message.html;
            const text = tempDiv.textContent || tempDiv.innerText || '';
            return text.substring(0, 150) + (text.length > 150 ? '...' : '');
        }
        return 'No content';
    }
    
    updateMessageCount() {
        const messageCountElement = document.getElementById('messageCount');
        messageCountElement.textContent = this.messages.length.toString();
    }
    
    async openMessage(messageId) {
        try {
            const response = await fetch(`/api/message/${messageId}`);
            
            if (!response.ok) {
                throw new Error('Failed to fetch message details');
            }
            
            const data = await response.json();
            
            if (data.success) {
                this.showMessageModal(data.message);
            } else {
                throw new Error(data.error || 'Failed to fetch message details');
            }
        } catch (error) {
            console.error('Error opening message:', error);
            this.showError('Failed to open message');
        }
    }
    
    showMessageModal(message) {
        const modal = document.getElementById('messageModal');
        const modalBody = document.getElementById('modalBody');
        
        const date = new Date(message.receivedAt);
        const timeStr = date.toLocaleString();
        
        let contentHTML = '';
        if (message.html) {
            contentHTML = `
                <div class="message-content">
                    <iframe srcdoc="${this.escapeHtml(message.html)}" style="width: 100%; min-height: 400px; border: 1px solid rgba(255,255,255,0.2); border-radius: 8px;"></iframe>
                </div>
            `;
        } else if (message.text) {
            contentHTML = `
                <div class="message-content">
                    <pre style="white-space: pre-wrap; font-family: inherit; color: var(--gray-300);">${this.escapeHtml(message.text)}</pre>
                </div>
            `;
        } else {
            contentHTML = '<p style="color: var(--gray-400);">No content available</p>';
        }
        
        // Attachments section
        let attachmentsHTML = '';
        if (message.attachments && message.attachments.length > 0) {
            const attachmentsList = message.attachments.map(attachment => {
                const sizeFormatted = this.formatFileSize(attachment.size);
                const isExpired = message.isExpired;
                
                return `
                    <div class="attachment-item ${isExpired ? 'expired' : ''}">
                        <div class="attachment-info">
                            <i class="fas fa-file" style="color: var(--primary-color); margin-right: 8px;"></i>
                            <div class="attachment-details">
                                <div class="attachment-name">${this.escapeHtml(attachment.name)}</div>
                                <div class="attachment-meta">
                                    ${sizeFormatted} • ${attachment.type}
                                    ${attachment.timeRemaining ? ` • 🕒 Expires in ${attachment.timeRemaining}` : ''}
                                </div>
                            </div>
                        </div>
                        <div class="attachment-actions">
                            ${!isExpired ? `
                                <button class="btn-download" onclick="app.downloadAttachment('${attachment.id}', '${this.escapeHtml(attachment.name)}')" title="Download attachment">
                                    <i class="fas fa-download"></i>
                                </button>
                            ` : `
                                <span class="expired-label">Expired</span>
                            `}
                        </div>
                    </div>
                `;
            }).join('');
            
            attachmentsHTML = `
                <div class="attachments-section">
                    <h4 style="color: var(--gray-200); margin-bottom: 1rem; display: flex; align-items: center;">
                        <i class="fas fa-paperclip" style="margin-right: 8px;"></i>
                        Attachments (${message.attachments.length})
                    </h4>
                    <div class="attachments-list">
                        ${attachmentsList}
                    </div>
                </div>
            `;
        }
        
        modalBody.innerHTML = `
            <div class="message-details">
                <div class="detail-row">
                    <strong>From:</strong> ${this.escapeHtml(message.from)}
                </div>
                <div class="detail-row">
                    <strong>To:</strong> ${this.escapeHtml(message.to)}
                </div>
                <div class="detail-row">
                    <strong>Subject:</strong> ${this.escapeHtml(message.subject || 'No Subject')}
                </div>
                <div class="detail-row">
                    <strong>Received:</strong> ${timeStr}
                    ${message.timeRemaining ? ` • 🕒 Expires in ${message.timeRemaining}` : ''}
                </div>
                ${message.hasAttachments ? `
                    <div class="detail-row">
                        <strong>Attachments:</strong> ${message.attachmentCount} file(s)
                    </div>
                ` : ''}
            </div>
            ${attachmentsHTML ? `<hr style="border: none; border-top: 1px solid rgba(255,255,255,0.1); margin: 1.5rem 0;">${attachmentsHTML}` : ''}
            <hr style="border: none; border-top: 1px solid rgba(255,255,255,0.1); margin: 1.5rem 0;">
            ${contentHTML}
        `;
        
        // Store current message ID for deletion
        modal.dataset.messageId = message.id;
        
        modal.classList.add('active');
        document.body.style.overflow = 'hidden';
    }
    
    closeModal() {
        const modal = document.getElementById('messageModal');
        modal.classList.remove('active');
        document.body.style.overflow = '';
        delete modal.dataset.messageId;
    }
    
    async deleteCurrentMessage() {
        const modal = document.getElementById('messageModal');
        const messageId = modal.dataset.messageId;
        
        if (!messageId) return;
        
        if (!confirm('Are you sure you want to delete this message?')) {
            return;
        }
        
        try {
            const response = await fetch(`/api/message/${messageId}`, {
                method: 'DELETE'
            });
            
            if (!response.ok) {
                throw new Error('Failed to delete message');
            }
            
            const data = await response.json();
            
            if (data.success) {
                this.showNotification('Message deleted successfully', 'success');
                this.closeModal();
                this.refreshInbox();
            } else {
                throw new Error(data.error || 'Failed to delete message');
            }
        } catch (error) {
            console.error('Error deleting message:', error);
            this.showError('Failed to delete message');
        }
    }
    
    async clearInbox() {
        if (!this.currentEmail || this.messages.length === 0) return;
        
        if (!confirm('Are you sure you want to delete all messages?')) {
            return;
        }
        
        try {
            const deletePromises = this.messages.map(message => 
                fetch(`/api/message/${message.id}`, { method: 'DELETE' })
            );
            
            await Promise.all(deletePromises);
            
            this.showNotification('All messages deleted successfully', 'success');
            this.refreshInbox();
        } catch (error) {
            console.error('Error clearing inbox:', error);
            this.showError('Failed to clear inbox');
        }
    }
    
    clearMessages() {
        this.messages = [];
        this.displayMessages();
        this.updateMessageCount();
    }
    
    startAutoRefresh() {
        // Refresh inbox every 30 seconds
        this.refreshInterval = setInterval(() => {
            if (this.currentEmail) {
                this.refreshInbox();
            }
        }, 30000);
    }
    
    showLoading(elementId, message) {
        const element = document.getElementById(elementId);
        element.innerHTML = `<span class="loading">${message}</span>`;
    }
    
    showNotification(message, type = 'info') {
        // Create notification element
        const notification = document.createElement('div');
        notification.className = `notification notification-${type}`;
        notification.innerHTML = `
            <i class="fas fa-${this.getNotificationIcon(type)}"></i>
            <span>${message}</span>
            <button class="notification-close" onclick="this.parentElement.remove()">
                <i class="fas fa-times"></i>
            </button>
        `;
        
        // Add styles if not already added
        if (!document.querySelector('#notification-styles')) {
            const styles = document.createElement('style');
            styles.id = 'notification-styles';
            styles.textContent = `
                .notification {
                    position: fixed;
                    top: 100px;
                    right: 20px;
                    background: var(--black);
                    border: 1px solid rgba(255,255,255,0.2);
                    border-radius: 8px;
                    padding: 1rem 1.5rem;
                    color: var(--white);
                    box-shadow: 0 4px 12px rgba(0,0,0,0.3);
                    z-index: 3000;
                    display: flex;
                    align-items: center;
                    gap: 0.5rem;
                    max-width: 400px;
                    animation: slideIn 0.3s ease;
                }
                .notification-success { border-left: 4px solid var(--success-color); }
                .notification-error { border-left: 4px solid var(--error-color); }
                .notification-warning { border-left: 4px solid var(--warning-color); }
                .notification-info { border-left: 4px solid var(--primary-color); }
                .notification-close {
                    background: none;
                    border: none;
                    color: var(--gray-400);
                    cursor: pointer;
                    padding: 0.25rem;
                    margin-left: auto;
                }
                @keyframes slideIn {
                    from { transform: translateX(100%); opacity: 0; }
                    to { transform: translateX(0); opacity: 1; }
                }
            `;
            document.head.appendChild(styles);
        }
        
        document.body.appendChild(notification);
        
        // Auto remove after 5 seconds
        setTimeout(() => {
            if (notification.parentElement) {
                notification.remove();
            }
        }, 5000);
    }
    
    getNotificationIcon(type) {
        const icons = {
            success: 'check-circle',
            error: 'exclamation-circle',
            warning: 'exclamation-triangle',
            info: 'info-circle'
        };
        return icons[type] || 'info-circle';
    }
    
    showError(message) {
        this.showNotification(message, 'error');
    }
    
    escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }
    
    formatFileSize(bytes) {
        if (bytes === 0) return '0 Bytes';
        const k = 1024;
        const sizes = ['Bytes', 'KB', 'MB', 'GB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
    }
    
    getCurrentAttachment(attachmentId) {
        // Find attachment in current messages
        for (const message of this.messages) {
            if (message.attachments) {
                const attachment = message.attachments.find(att => att.id === attachmentId);
                if (attachment) {
                    return attachment;
                }
            }
        }
        return null;
    }
    
    async downloadAttachment(attachmentId, fileName) {
        try {
            this.showNotification('Preparing download...', 'info');
            
            // First get attachment info to get the secure token
            const infoResponse = await fetch(`/api/attachments/${attachmentId}/info`);
            if (!infoResponse.ok) {
                throw new Error('Failed to get attachment information');
            }
            
            const infoData = await infoResponse.json();
            if (!infoData.success) {
                throw new Error(infoData.error || 'Failed to get attachment information');
            }
            
            // Extract token from the attachment data (assuming it's included in the attachment object)
            const attachment = this.getCurrentAttachment(attachmentId);
            if (!attachment || !attachment.downloadUrl) {
                throw new Error('Attachment download URL not available');
            }
            
            const response = await fetch(attachment.downloadUrl, {
                method: 'GET',
                headers: {
                    'Accept': 'application/octet-stream'
                }
            });
            
            if (!response.ok) {
                if (response.status === 404) {
                    throw new Error('Attachment not found or expired');
                } else if (response.status === 410) {
                    throw new Error('Attachment has expired');
                } else {
                    throw new Error('Failed to download attachment');
                }
            }
            
            const blob = await response.blob();
            const url = window.URL.createObjectURL(blob);
            
            // Create download link
            const a = document.createElement('a');
            a.style.display = 'none';
            a.href = url;
            a.download = fileName;
            document.body.appendChild(a);
            a.click();
            
            // Cleanup
            window.URL.revokeObjectURL(url);
            document.body.removeChild(a);
            
            this.showNotification('Download started successfully!', 'success');
            
        } catch (error) {
            console.error('Download error:', error);
            this.showError(`Download failed: ${error.message}`);
        }
    }
    
    destroy() {
        if (this.refreshInterval) {
            clearInterval(this.refreshInterval);
        }
        if (this.expiryInterval) {
            clearInterval(this.expiryInterval);
        }
        if (this.socket) {
            this.socket.disconnect();
        }
    }
}

// Initialize app when DOM is loaded
let app;
document.addEventListener('DOMContentLoaded', () => {
    app = new RedMailApp();
});

// Cleanup on page unload
window.addEventListener('beforeunload', () => {
    if (app) {
        app.destroy();
    }
});

// Add some additional styles for message details
const additionalStyles = document.createElement('style');
additionalStyles.textContent = `
    .message-details {
        background: rgba(255,255,255,0.05);
        border-radius: 8px;
        padding: 1.5rem;
        margin-bottom: 1.5rem;
    }
    .detail-row {
        margin-bottom: 0.75rem;
        color: var(--gray-300);
    }
    .detail-row strong {
        color: var(--white);
        margin-right: 0.5rem;
    }
    .message-content {
        background: rgba(0,0,0,0.3);
        border-radius: 8px;
        padding: 1.5rem;
        border: 1px solid rgba(255,255,255,0.1);
    }
`;
document.head.appendChild(additionalStyles);