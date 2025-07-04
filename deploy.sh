#!/bin/bash

# 🚀 RedMail VPS Deployment Script
# Usage: bash deploy.sh

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
VPS_IP="167.99.70.90"
DOMAIN="oplex.online"
APP_DIR="/var/www/redmail"
APP_NAME="redmail"

echo -e "${BLUE}🚀 Starting RedMail VPS Deployment${NC}"
echo -e "${BLUE}VPS IP: ${VPS_IP}${NC}"
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
if [ "$EUID" -eq 0 ]; then
    print_warning "Running as root. Some commands will be adjusted."
    SUDO=""
else
    SUDO="sudo"
fi

# Update system
echo -e "${BLUE}📦 Updating system packages...${NC}"
$SUDO apt update && $SUDO apt upgrade -y
print_status "System updated"

# Install Node.js
echo -e "${BLUE}📦 Installing Node.js...${NC}"
if ! command -v node &> /dev/null; then
    curl -fsSL https://deb.nodesource.com/setup_18.x | $SUDO -E bash -
    $SUDO apt-get install -y nodejs
    print_status "Node.js installed"
else
    print_status "Node.js already installed ($(node --version))"
fi

# Install Redis
echo -e "${BLUE}📦 Installing Redis...${NC}"
if ! command -v redis-server &> /dev/null; then
    $SUDO apt install redis-server -y
    $SUDO systemctl enable redis-server
    $SUDO systemctl start redis-server
    print_status "Redis installed and started"
else
    print_status "Redis already installed"
    $SUDO systemctl start redis-server || true
fi

# Install Git
echo -e "${BLUE}📦 Installing Git...${NC}"
if ! command -v git &> /dev/null; then
    $SUDO apt install git -y
    print_status "Git installed"
else
    print_status "Git already installed"
fi

# Install PM2
echo -e "${BLUE}📦 Installing PM2...${NC}"
if ! command -v pm2 &> /dev/null; then
    $SUDO npm install -g pm2
    print_status "PM2 installed"
else
    print_status "PM2 already installed"
fi

# Create application directory
echo -e "${BLUE}📁 Setting up application directory...${NC}"
$SUDO mkdir -p $APP_DIR
$SUDO chown $USER:$USER $APP_DIR
print_status "Application directory created"

# Copy application files (assuming script is run from project directory)
echo -e "${BLUE}📁 Copying application files...${NC}"
cp -r ./* $APP_DIR/
cd $APP_DIR
print_status "Application files copied"

# Install dependencies
echo -e "${BLUE}📦 Installing application dependencies...${NC}"
npm install
print_status "Dependencies installed"

# Configure firewall
echo -e "${BLUE}🔥 Configuring firewall...${NC}"
if command -v ufw &> /dev/null; then
    $SUDO ufw --force enable
    $SUDO ufw allow 22    # SSH
    $SUDO ufw allow 80    # HTTP
    $SUDO ufw allow 443   # HTTPS
    $SUDO ufw allow 25    # SMTP
    $SUDO ufw allow 3000  # Application
    print_status "Firewall configured"
else
    print_warning "UFW not available, please configure firewall manually"
fi

# Stop existing PM2 process if running
echo -e "${BLUE}🔄 Managing PM2 processes...${NC}"
pm2 delete $APP_NAME 2>/dev/null || true
print_status "Cleaned up existing processes"

# Start application with PM2
echo -e "${BLUE}🚀 Starting application...${NC}"
pm2 start server.js --name $APP_NAME
pm2 save
print_status "Application started with PM2"

# Setup PM2 startup
echo -e "${BLUE}🔄 Setting up PM2 startup...${NC}"
pm2 startup systemd -u $USER --hp $HOME | grep "sudo" | bash || true
print_status "PM2 startup configured"

# Test Redis connection
echo -e "${BLUE}🔍 Testing Redis connection...${NC}"
if redis-cli ping | grep -q "PONG"; then
    print_status "Redis connection successful"
else
    print_error "Redis connection failed"
fi

# Test application
echo -e "${BLUE}🔍 Testing application...${NC}"
sleep 5  # Wait for app to start
if curl -s http://167.99.70.90:3000/api/health > /dev/null 2>&1; then
    print_status "Application is responding"
else
    print_warning "Application health check failed (this might be normal if no health endpoint exists)"
fi

# Display status
echo ""
echo -e "${GREEN}🎉 Deployment completed successfully!${NC}"
echo ""
echo -e "${BLUE}📊 Application Status:${NC}"
pm2 status
echo ""
echo -e "${BLUE}🌐 Access URLs:${NC}"
echo -e "  Admin Panel: http://${VPS_IP}:3000/admin"
echo -e "  API Base: http://${VPS_IP}:3000/api"
echo -e "  Domain Access: http://${DOMAIN}:3000/admin (after DNS propagation)"
echo ""
echo -e "${BLUE}📋 Next Steps:${NC}"
echo -e "  1. Configure DNS records for ${DOMAIN}"
echo -e "  2. Test email reception"
echo -e "  3. Change default admin password"
echo -e "  4. Setup SSL certificate for HTTPS"
echo ""
echo -e "${BLUE}🔒 Setup HTTPS (Recommended):${NC}"
echo -e "  Run: bash ssl-setup.sh"
echo -e "  Guide: HTTPS_SETUP_GUIDE.md"
echo ""
echo -e "${BLUE}🔍 Useful Commands:${NC}"
echo -e "  Check logs: pm2 logs ${APP_NAME}"
echo -e "  Restart app: pm2 restart ${APP_NAME}"
echo -e "  Stop app: pm2 stop ${APP_NAME}"
echo -e "  Monitor: pm2 monit"
echo -e "  Setup HTTPS: bash ssl-setup.sh"
echo ""
echo -e "${GREEN}✅ RedMail is now running on your VPS!${NC}"
echo -e "${YELLOW}🔒 Don't forget to setup HTTPS for secure admin panel access!${NC}"