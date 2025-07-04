# 🔒 HTTPS Setup Guide for RedMail

## 📋 Overview

This guide will help you secure your RedMail application with HTTPS using SSL/TLS certificates. After following this guide, your admin panel will always use HTTPS.

## 🚀 Quick HTTPS Setup

### Option 1: Automated Setup (Recommended)

```bash
# Upload and run the SSL setup script
scp ssl-setup.sh root@206.189.94.221:/var/www/redmail/
ssh root@206.189.94.221
cd /var/www/redmail
sudo bash ssl-setup.sh
```

### Option 2: Manual Setup

#### Step 1: Install Required Packages
```bash
sudo apt update
sudo apt install nginx certbot python3-certbot-nginx -y
```

#### Step 2: Configure Nginx
```bash
sudo nano /etc/nginx/sites-available/redmail
```

Add this configuration:
```nginx
# HTTP to HTTPS redirect
server {
    listen 80;
    server_name oplex.online www.oplex.online;
    return 301 https://$server_name$request_uri;
}

# HTTPS configuration
server {
    listen 443 ssl http2;
    server_name oplex.online www.oplex.online;

    # SSL Configuration
    ssl_certificate /etc/letsencrypt/live/oplex.online/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/oplex.online/privkey.pem;
    
    # SSL Security Settings
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-RSA-AES256-GCM-SHA512:DHE-RSA-AES256-GCM-SHA512;
    ssl_prefer_server_ciphers off;
    ssl_session_cache shared:SSL:10m;
    
    # Security Headers
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Frame-Options DENY always;
    add_header X-Content-Type-Options nosniff always;
    add_header X-XSS-Protection "1; mode=block" always;
    
    # Proxy to Node.js application
    location / {
        proxy_pass http://localhost:3000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_cache_bypass $http_upgrade;
    }
}
```

#### Step 3: Enable the Site
```bash
sudo ln -s /etc/nginx/sites-available/redmail /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl reload nginx
```

#### Step 4: Get SSL Certificate
```bash
sudo certbot --nginx -d oplex.online -d www.oplex.online
```

#### Step 5: Setup Auto-renewal
```bash
sudo crontab -e
# Add this line:
0 12 * * * /usr/bin/certbot renew --quiet
```

## 🔧 Application Configuration

### Environment Variables
Update your `.env` file:
```env
# Set to production for HTTPS redirect
NODE_ENV=production

# Add HTTPS origins
ALLOWED_ORIGINS=https://oplex.online,https://www.oplex.online,http://localhost:3000
```

### Server Configuration
The application is already configured with:
- ✅ HTTPS redirect middleware (production only)
- ✅ HSTS headers
- ✅ Enhanced security headers
- ✅ WebSocket support over HTTPS

## 🌐 Access URLs After HTTPS Setup

### Primary URLs
- **Admin Panel**: https://oplex.online/admin
- **API Base**: https://oplex.online/api
- **Health Check**: https://oplex.online/api/health

### Automatic Redirects
- http://oplex.online → https://oplex.online
- http://www.oplex.online → https://www.oplex.online
- Any HTTP request → Corresponding HTTPS URL

## 🔒 Security Features Enabled

### SSL/TLS Security
- ✅ **TLS 1.2 & 1.3** - Modern encryption protocols
- ✅ **Strong Ciphers** - Secure cipher suites
- ✅ **Perfect Forward Secrecy** - Enhanced security
- ✅ **Session Caching** - Performance optimization

### HTTP Security Headers
- ✅ **HSTS** - Force HTTPS for 1 year
- ✅ **X-Frame-Options** - Prevent clickjacking
- ✅ **X-Content-Type-Options** - Prevent MIME sniffing
- ✅ **X-XSS-Protection** - XSS attack prevention
- ✅ **CSP** - Content Security Policy

### Application Security
- ✅ **Automatic HTTPS Redirect** - All HTTP → HTTPS
- ✅ **Secure Cookies** - HTTPS-only cookies
- ✅ **WebSocket Security** - WSS support
- ✅ **CORS Protection** - Secure cross-origin requests

## 🧪 Testing HTTPS Setup

### 1. Basic Connectivity Test
```bash
# Test HTTPS connection
curl -I https://oplex.online/api/health

# Test HTTP redirect
curl -I http://oplex.online/admin
```

### 2. SSL Certificate Verification
```bash
# Check certificate details
openssl s_client -connect oplex.online:443 -servername oplex.online

# Check certificate expiry
echo | openssl s_client -connect oplex.online:443 2>/dev/null | openssl x509 -noout -dates
```

### 3. Security Headers Test
```bash
# Check security headers
curl -I https://oplex.online/admin
```

### 4. Online SSL Tests
- **SSL Labs**: https://www.ssllabs.com/ssltest/
- **Security Headers**: https://securityheaders.com/

## 🔄 Certificate Management

### Check Certificate Status
```bash
sudo certbot certificates
```

### Manual Renewal
```bash
sudo certbot renew
sudo systemctl reload nginx
```

### Test Auto-renewal
```bash
sudo certbot renew --dry-run
```

## 🐛 Troubleshooting

### Common Issues

#### 1. Certificate Not Found
```bash
# Check if certificate exists
sudo ls -la /etc/letsencrypt/live/oplex.online/

# Re-run certbot if missing
sudo certbot --nginx -d oplex.online -d www.oplex.online
```

#### 2. Nginx Configuration Error
```bash
# Test nginx configuration
sudo nginx -t

# Check nginx logs
sudo tail -f /var/log/nginx/error.log
```

#### 3. Port 80/443 Not Accessible
```bash
# Check firewall
sudo ufw status
sudo ufw allow 80
sudo ufw allow 443

# Check if ports are in use
sudo netstat -tlnp | grep :80
sudo netstat -tlnp | grep :443
```

#### 4. DNS Issues
```bash
# Check DNS resolution
nslookup oplex.online
dig oplex.online

# Check from external source
curl -I http://oplex.online
```

### Application Issues

#### 1. HTTPS Redirect Loop
- Check `NODE_ENV=production` in `.env`
- Verify nginx proxy headers
- Check `X-Forwarded-Proto` header

#### 2. WebSocket Connection Issues
- Ensure WSS is working: `wss://oplex.online`
- Check nginx WebSocket configuration
- Verify Socket.IO HTTPS compatibility

#### 3. Mixed Content Warnings
- All resources should use HTTPS
- Check browser console for mixed content
- Update any hardcoded HTTP URLs

## 📊 Monitoring HTTPS

### Certificate Expiry Monitoring
```bash
# Add to crontab for monitoring
0 0 * * * /usr/bin/certbot renew --quiet && /bin/systemctl reload nginx
```

### Log Monitoring
```bash
# Monitor nginx access logs
sudo tail -f /var/log/nginx/access.log

# Monitor SSL errors
sudo tail -f /var/log/nginx/error.log

# Monitor application logs
pm2 logs redmail
```

## 🎯 Best Practices

### Security
1. **Always use HTTPS** in production
2. **Enable HSTS** with long max-age
3. **Use strong ciphers** only
4. **Monitor certificate expiry**
5. **Test SSL configuration** regularly

### Performance
1. **Enable HTTP/2** for better performance
2. **Use session caching** for SSL
3. **Optimize cipher selection**
4. **Enable compression** where appropriate

### Maintenance
1. **Automate certificate renewal**
2. **Monitor SSL health** regularly
3. **Keep nginx updated**
4. **Test backup procedures**

---

## 🎉 Completion Checklist

After following this guide, verify:

- [ ] HTTPS is working: https://oplex.online/admin
- [ ] HTTP redirects to HTTPS automatically
- [ ] SSL certificate is valid and trusted
- [ ] Security headers are present
- [ ] WebSocket connections work over WSS
- [ ] Auto-renewal is configured
- [ ] Firewall allows ports 80 and 443
- [ ] DNS points to correct IP
- [ ] Application logs show no SSL errors

**Your RedMail admin panel now always uses HTTPS! 🔒✨**