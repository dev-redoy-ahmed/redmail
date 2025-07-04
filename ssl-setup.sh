#!/bin/bash

# 🔒 SSL Certificate Setup Script for RedMail
# This script sets up SSL certificate using Let's Encrypt

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
DOMAIN="oplex.online"
EMAIL="admin@oplex.online"
APP_DIR="/var/www/redmail"
NGINX_CONFIG="/etc/nginx/sites-available/redmail"
NGINX_ENABLED="/etc/nginx/sites-enabled/redmail"

echo -e "${BLUE}🔒 Setting up SSL Certificate for RedMail${NC}"
echo -e "${BLUE}Domain: ${DOMAIN}${NC}"
echo ""

# Function to print status
print_status() {
    echo -e "${GREEN}✅ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

print_error() {
    echo -e "${RED}❌ $1${NC}"
}

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    print_error "This script must be run as root"
    exit 1
fi

# Install Nginx
echo -e "${BLUE}📦 Installing Nginx...${NC}"
apt update
apt install nginx -y
systemctl enable nginx
print_status "Nginx installed"

# Install Certbot
echo -e "${BLUE}📦 Installing Certbot...${NC}"
apt install certbot python3-certbot-nginx -y
print_status "Certbot installed"

# Create Nginx configuration
echo -e "${BLUE}🔧 Creating Nginx configuration...${NC}"
cat > $NGINX_CONFIG << EOF
# HTTP to HTTPS redirect
server {
    listen 80;
    server_name ${DOMAIN} www.${DOMAIN};
    return 301 https://\$server_name\$request_uri;
}

# HTTPS configuration
server {
    listen 443 ssl http2;
    server_name ${DOMAIN} www.${DOMAIN};

    # SSL Configuration (will be updated by certbot)
    ssl_certificate /etc/letsencrypt/live/${DOMAIN}/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/${DOMAIN}/privkey.pem;
    
    # SSL Security Settings
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-RSA-AES256-GCM-SHA512:DHE-RSA-AES256-GCM-SHA512:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 10m;
    
    # Security Headers
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Frame-Options DENY always;
    add_header X-Content-Type-Options nosniff always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    
    # Proxy to Node.js application
    location / {
        proxy_pass http://167.99.70.90:3000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_cache_bypass \$http_upgrade;
        
        # WebSocket support for Socket.IO
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
    }
    
    # Static files caching
    location ~* \.(js|css|png|jpg|jpeg|gif|ico|svg)\$ {
        proxy_pass http://167.99.70.90:3000;
        expires 1y;
        add_header Cache-Control "public, immutable";
    }
}
EOF

print_status "Nginx configuration created"

# Enable the site
ln -sf $NGINX_CONFIG $NGINX_ENABLED
nginx -t
systemctl reload nginx
print_status "Nginx configuration enabled"

# Stop application temporarily
echo -e "${BLUE}⏸️  Stopping application temporarily...${NC}"
pm2 stop redmail || true
print_status "Application stopped"

# Get SSL certificate
echo -e "${BLUE}🔒 Obtaining SSL certificate...${NC}"
certbot --nginx -d $DOMAIN -d www.$DOMAIN --non-interactive --agree-tos --email $EMAIL

if [ $? -eq 0 ]; then
    print_status "SSL certificate obtained successfully"
else
    print_error "Failed to obtain SSL certificate"
    exit 1
fi

# Start application
echo -e "${BLUE}▶️  Starting application...${NC}"
pm2 start redmail || pm2 restart redmail
print_status "Application started"

# Test SSL
echo -e "${BLUE}🔍 Testing SSL configuration...${NC}"
sleep 5
if curl -s https://$DOMAIN > /dev/null; then
    print_status "HTTPS is working correctly"
else
    print_warning "HTTPS test failed, but certificate might still be valid"
fi

# Setup auto-renewal
echo -e "${BLUE}🔄 Setting up auto-renewal...${NC}"
(crontab -l 2>/dev/null; echo "0 12 * * * /usr/bin/certbot renew --quiet") | crontab -
print_status "Auto-renewal configured"

echo ""
echo -e "${GREEN}🎉 SSL setup completed successfully!${NC}"
echo ""
echo -e "${BLUE}🌐 Your site is now available at:${NC}"
echo -e "  HTTPS: https://${DOMAIN}/admin"
echo -e "  HTTPS: https://www.${DOMAIN}/admin"
echo ""
echo -e "${BLUE}🔒 Security Features Enabled:${NC}"
echo -e "  ✅ SSL/TLS encryption"
echo -e "  ✅ HTTP to HTTPS redirect"
echo -e "  ✅ Security headers"
echo -e "  ✅ Auto-renewal setup"
echo ""
echo -e "${BLUE}📋 Certificate Information:${NC}"
certbot certificates
echo ""
echo -e "${GREEN}✅ RedMail is now secured with HTTPS!${NC}"