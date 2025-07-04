# 🚀 RedMail VPS Deployment Guide

## 📋 Prerequisites

### VPS Information
- **IP Address**: 206.189.94.221
- **Domain**: oplex.online
- **OS**: Ubuntu/Debian (recommended)

## 🌐 DNS Configuration

### Required DNS Records
Add these records to your domain registrar (oplex.online):

```
# A Record
Type: A
Name: @
Value: 206.189.94.221
TTL: 3600

# MX Record
Type: MX
Name: @
Value: oplex.online
Priority: 10
TTL: 3600

# SPF Record
Type: TXT
Name: @
Value: "v=spf1 ip4:206.189.94.221 ~all"
TTL: 3600

# DMARC Record (Optional but recommended)
Type: TXT
Name: _dmarc
Value: "v=DMARC1; p=quarantine; rua=mailto:admin@oplex.online"
TTL: 3600
```

## 🔧 VPS Setup Commands

### 1. Update System
```bash
sudo apt update && sudo apt upgrade -y
```

### 2. Install Node.js
```bash
curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -
sudo apt-get install -y nodejs
```

### 3. Install Redis
```bash
sudo apt install redis-server -y
sudo systemctl enable redis-server
sudo systemctl start redis-server
```

### 4. Install Git
```bash
sudo apt install git -y
```

### 5. Create Application Directory
```bash
sudo mkdir -p /var/www/redmail
sudo chown $USER:$USER /var/www/redmail
cd /var/www/redmail
```

## 📁 Deploy Application

### 1. Upload Files
```bash
# Option 1: Using SCP from local machine
scp -r c:\Users\Redoy\ Ahmed\redmail/* root@206.189.94.221:/var/www/redmail/

# Option 2: Using Git (if you have a repository)
git clone <your-repo-url> .
```

### 2. Install Dependencies
```bash
cd /var/www/redmail
npm install
```

### 3. Configure Environment
```bash
# The .env file is already configured for VPS
# Verify the configuration:
cat .env
```

## 🔥 Firewall Configuration

### Open Required Ports
```bash
# Enable UFW
sudo ufw enable

# Allow SSH
sudo ufw allow 22

# Allow HTTP
sudo ufw allow 80

# Allow HTTPS
sudo ufw allow 443

# Allow SMTP
sudo ufw allow 25

# Allow Application Port
sudo ufw allow 3000

# Check status
sudo ufw status
```

## 🚀 Start Application

### 1. Test Run
```bash
cd /var/www/redmail
node server.js
```

### 2. Production Setup with PM2
```bash
# Install PM2
sudo npm install -g pm2

# Start application
pm2 start server.js --name "redmail"

# Save PM2 configuration
pm2 save

# Setup PM2 startup
pm2 startup
sudo env PATH=$PATH:/usr/bin /usr/lib/node_modules/pm2/bin/pm2 startup systemd -u $USER --hp $HOME
```

## 🌐 Access URLs

After deployment, access your application:

- **Admin Panel**: http://206.189.94.221:3000/admin
- **API Base**: http://206.189.94.221:3000/api
- **Domain Access**: http://oplex.online:3000/admin (after DNS propagation)

## ✅ Verification Steps

### 1. Check Services
```bash
# Check Redis
redis-cli ping

# Check Node.js application
pm2 status

# Check logs
pm2 logs redmail
```

### 2. Test Email Reception
1. Generate a temporary email from admin panel
2. Send test email to: `test@oplex.online`
3. Check if email appears in admin panel

### 3. Test OTP System
1. Go to Admin Panel → Settings
2. Click "Send Test OTP"
3. Select a temporary email
4. Verify OTP delivery

## 🔒 Security Recommendations

### 1. Change Default Password
```bash
# Generate new password hash
node -e "console.log(require('bcryptjs').hashSync('your-new-password', 10))"

# Update .env file
nano .env
# Replace ADMIN_PASSWORD_HASH with new hash
```

### 2. Setup SSL Certificate (Recommended for HTTPS)
```bash
# Run the automated SSL setup script
sudo bash ssl-setup.sh

# Or manual setup:
# Install Certbot and Nginx
sudo apt install certbot python3-certbot-nginx nginx -y

# Get SSL certificate
sudo certbot --nginx -d oplex.online -d www.oplex.online

# Test auto-renewal
sudo certbot renew --dry-run
```

### 3. Configure Reverse Proxy (Optional)
```bash
# Install Nginx
sudo apt install nginx -y

# Configure Nginx for port 80/443 → 3000
# Create /etc/nginx/sites-available/redmail
```

## 🐛 Troubleshooting

### Common Issues

1. **Port 25 Blocked**
   ```bash
   # Test SMTP port
   telnet 206.189.94.221 25
   ```

2. **DNS Not Propagated**
   ```bash
   # Check DNS
   nslookup oplex.online
   dig MX oplex.online
   ```

3. **Redis Connection Failed**
   ```bash
   # Check Redis status
   sudo systemctl status redis-server
   ```

4. **Application Not Starting**
   ```bash
   # Check logs
   pm2 logs redmail
   ```

## 📊 Monitoring

### Check Application Status
```bash
# PM2 monitoring
pm2 monit

# System resources
htop

# Disk usage
df -h

# Memory usage
free -h
```

## 🔄 Updates

### Deploy New Version
```bash
cd /var/www/redmail

# Backup current version
cp -r . ../redmail-backup-$(date +%Y%m%d)

# Update files
# (upload new files or git pull)

# Install new dependencies
npm install

# Restart application
pm2 restart redmail
```

---

## 📞 Support

If you encounter any issues:
1. Check the logs: `pm2 logs redmail`
2. Verify DNS records are properly configured
3. Ensure all ports are open in firewall
4. Test SMTP connectivity

**Your RedMail system is now ready for production use on VPS!** 🎉