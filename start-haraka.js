#!/usr/bin/env node

// RedMail Haraka Startup Script
const path = require('path');
const fs = require('fs');
const { spawn } = require('child_process');

// Configuration
const CONFIG = {
  EMAIL_DOMAIN: process.env.EMAIL_DOMAIN || 'redmail.dev',
  SMTP_PORT: process.env.SMTP_PORT || 25,
  SMTP_HOST: process.env.SMTP_HOST || '0.0.0.0'
};

// Set up Haraka configuration
const setupHarakaConfig = () => {
  const configDir = path.join(__dirname, 'config');
  
  // Ensure config directory exists
  if (!fs.existsSync(configDir)) {
    fs.mkdirSync(configDir, { recursive: true });
  }
  
  // Update SMTP configuration
  const smtpConfig = `[main]
port=${CONFIG.SMTP_PORT}
host=${CONFIG.SMTP_HOST}
listen=*:${CONFIG.SMTP_PORT}

[logging]
level=INFO

[plugins]
queue/discard
rcpt_to.in_host_list
redmail_handler
log.syslog
`;
  
  fs.writeFileSync(path.join(configDir, 'smtp.ini'), smtpConfig);
  
  // Update host list
  const hostList = `# Accepted domains for RedMail\n${CONFIG.EMAIL_DOMAIN}\n`;
  fs.writeFileSync(path.join(configDir, 'host_list'), hostList);
  
  console.log(`📬 Haraka configuration updated for domain: ${CONFIG.EMAIL_DOMAIN}`);
  console.log(`📬 SMTP server will listen on ${CONFIG.SMTP_HOST}:${CONFIG.SMTP_PORT}`);
};

// Start Haraka
const startHaraka = () => {
  const configPath = path.join(__dirname, 'config');
  
  // Set environment variables
  process.env.HARAKA_CONFIG = configPath;
  process.env.EMAIL_DOMAIN = CONFIG.EMAIL_DOMAIN;
  
  console.log(`📬 Starting Haraka SMTP server...`);
  console.log(`📬 Config directory: ${configPath}`);
  
  // Start Haraka process
  const haraka = spawn('node', [
    require.resolve('haraka'),
    '-c', configPath
  ], {
    stdio: 'inherit',
    env: process.env
  });
  
  haraka.on('error', (error) => {
    console.error('📬 Failed to start Haraka:', error);
    process.exit(1);
  });
  
  haraka.on('exit', (code) => {
    console.log(`📬 Haraka exited with code ${code}`);
    process.exit(code);
  });
  
  // Handle graceful shutdown
  process.on('SIGINT', () => {
    console.log('📬 Shutting down Haraka...');
    haraka.kill('SIGINT');
  });
  
  process.on('SIGTERM', () => {
    console.log('📬 Shutting down Haraka...');
    haraka.kill('SIGTERM');
  });
};

// Main execution
if (require.main === module) {
  setupHarakaConfig();
  startHaraka();
}

module.exports = {
  setupHarakaConfig,
  startHaraka,
  CONFIG
};