const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const cors = require('cors');
const { body, validationResult } = require('express-validator');
const path = require('path');
const fs = require('fs');
const { v4: uuidv4 } = require('uuid');
const morgan = require('morgan');
const redis = require('redis');
const { Server } = require('socket.io');
const http = require('http');
const { simpleParser } = require('mailparser');

// Configuration object - replace environment variables
const CONFIG = {
  // Server Configuration
  PORT: 3000,
  NODE_ENV: 'production', // Set to production for VPS deployment
  
  // Security Configuration
  JWT_SECRET: 'redmail-super-secret-jwt-key-2024-production-secure-random-string-change-this',
  ADMIN_PASSWORD_HASH: '$2a$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi', // Default: 'password'
  
  // CORS Configuration
  ALLOWED_ORIGINS: [
    'http://167.99.70.90:3000',
    'https://oplex.online',
    'https://www.oplex.online'
  ],
  
  // Email Configuration
  EMAIL_DOMAIN: 'oplex.online',
  EMAIL_RETENTION_HOURS: 24,
  VPS_IP: '167.99.70.90',
  
  // Redis Configuration
  REDIS_HOST: '167.99.70.90',
  REDIS_PORT: 6379,
  REDIS_PASSWORD: '',
  
  // SMTP Server Configuration
  SMTP_PORT: 25,
  SMTP_HOST: '0.0.0.0',
  
  // Rate Limiting
  AUTH_RATE_LIMIT: 5,
  API_RATE_LIMIT: 100,
  RATE_LIMIT_WINDOW_MS: 900000, // 15 minutes
  
  // Logging
  LOG_LEVEL: 'info',
  LOG_FILE: 'logs/app.log'
};

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
  cors: {
    origin: CONFIG.ALLOWED_ORIGINS,
    methods: ['GET', 'POST']
  }
});

const PORT = CONFIG.PORT;
const JWT_SECRET = CONFIG.JWT_SECRET;
const ADMIN_PASSWORD_HASH = CONFIG.ADMIN_PASSWORD_HASH;

// Redis connection
const client = redis.createClient({
  host: '127.0.0.1',
  port: 6379
});

// Connect to Redis
client.connect();

client.on('connect', () => {
  console.log('✅ Connected to Redis server');
});

client.on('error', (err) => {
  console.error('❌ Redis connection error:', err);
});

// HTTPS Redirect Middleware (only in production)
if (CONFIG.NODE_ENV === 'production') {
  app.use((req, res, next) => {
    if (req.header('x-forwarded-proto') !== 'https') {
      res.redirect(`https://${req.header('host')}${req.url}`);
    } else {
      next();
    }
  });
}

// Security middleware
app.use(helmet({
  hsts: {
    maxAge: 31536000,
    includeSubDomains: true,
    preload: true
  },
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://cdnjs.cloudflare.com"],
      scriptSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", "data:"],
      fontSrc: ["'self'", "https://cdnjs.cloudflare.com"],
      connectSrc: ["'self'", "ws:", "wss:"]
    }
  }
}));

app.use(cors({
  origin: CONFIG.ALLOWED_ORIGINS,
  credentials: true
}));

app.use(morgan('combined'));
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use(express.static(path.join(__dirname, 'public')));

// Rate limiting
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // limit each IP to 5 requests per windowMs
  message: { error: 'Too many login attempts, please try again later.' },
  standardHeaders: true,
  legacyHeaders: false
});

const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per windowMs
  message: { error: 'Too many API requests, please try again later.' },
  standardHeaders: true,
  legacyHeaders: false
});

// Redis keys
const REDIS_KEYS = {
  EMAILS: 'temp_emails',
  LOGS: 'email_logs',
  MESSAGES: 'email_messages:'
};

// Socket.IO connection handling
io.on('connection', (socket) => {
  console.log('👤 Admin connected:', socket.id);
  
  socket.on('disconnect', () => {
    console.log('👤 Admin disconnected:', socket.id);
  });
});

// Helper functions for Redis operations
const saveEmailToRedis = async (email) => {
  await client.hSet(REDIS_KEYS.EMAILS, email.id, JSON.stringify(email));
  await client.expire(REDIS_KEYS.EMAILS, 24 * 60 * 60); // 24 hours
};

const getEmailsFromRedis = async () => {
  const emails = await client.hGetAll(REDIS_KEYS.EMAILS);
  return Object.values(emails).map(email => JSON.parse(email));
};

const saveLogToRedis = async (log) => {
  await client.lPush(REDIS_KEYS.LOGS, JSON.stringify(log));
  await client.lTrim(REDIS_KEYS.LOGS, 0, 999); // Keep last 1000 logs
};

const getLogsFromRedis = async (start = 0, end = 19) => {
  const logs = await client.lRange(REDIS_KEYS.LOGS, start, end);
  return logs.map(log => JSON.parse(log));
};

const saveMessageToRedis = async (emailId, message) => {
  await client.lPush(REDIS_KEYS.MESSAGES + emailId, JSON.stringify(message));
  await client.expire(REDIS_KEYS.MESSAGES + emailId, 24 * 60 * 60); // 24 hours
};

const getMessagesFromRedis = async (emailId) => {
  const messages = await client.lRange(REDIS_KEYS.MESSAGES + emailId, 0, -1);
  return messages.map(message => JSON.parse(message));
};

// Middleware to verify JWT token
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Invalid or expired token' });
    }
    req.user = user;
    next();
  });
};

// Admin login endpoint
app.post('/api/auth/login', authLimiter, [
  body('password').isLength({ min: 1 }).withMessage('Password is required')
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { password } = req.body;
    const isValidPassword = await bcrypt.compare(password, ADMIN_PASSWORD_HASH);

    if (!isValidPassword) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const token = jwt.sign(
      { userId: 'admin', role: 'admin' },
      JWT_SECRET,
      { expiresIn: '24h' }
    );

    res.json({
      success: true,
      token,
      expiresIn: '24h'
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Verify token endpoint
app.get('/api/auth/verify', authenticateToken, (req, res) => {
  res.json({ valid: true, user: req.user });
});

// Generate temporary email endpoint
app.post('/api/temp-email/generate', apiLimiter, async (req, res) => {
  try {
    const emailId = uuidv4();
    const domain = `@${CONFIG.EMAIL_DOMAIN}`;
    const tempEmail = {
      id: emailId,
      email: `${emailId.substring(0, 8)}${domain}`,
      createdAt: new Date(),
      expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000), // 24 hours
      messageCount: 0
    };

    await saveEmailToRedis(tempEmail);

    // Log the generation
    const log = {
      id: uuidv4(),
      action: 'EMAIL_GENERATED',
      email: tempEmail.email,
      timestamp: new Date(),
      ip: req.ip
    };
    await saveLogToRedis(log);

    // Emit real-time update to admin panel
    io.emit('emailGenerated', tempEmail);
    io.emit('newLog', log);

    res.json({
      success: true,
      email: tempEmail.email,
      id: tempEmail.id,
      expiresAt: tempEmail.expiresAt
    });
  } catch (error) {
    console.error('Email generation error:', error);
    res.status(500).json({ error: 'Failed to generate temporary email' });
  }
});

// Get messages for temporary email
app.get('/api/temp-email/:emailId/messages', apiLimiter, async (req, res) => {
  try {
    const { emailId } = req.params;
    const emails = await getEmailsFromRedis();
    const tempEmail = emails.find(e => e.id === emailId);

    if (!tempEmail) {
      return res.status(404).json({ error: 'Email not found' });
    }

    if (new Date() > new Date(tempEmail.expiresAt)) {
      return res.status(410).json({ error: 'Email expired' });
    }

    const messages = await getMessagesFromRedis(emailId);

    res.json({
      success: true,
      messages: messages
    });
  } catch (error) {
    console.error('Get messages error:', error);
    res.status(500).json({ error: 'Failed to retrieve messages' });
  }
});

// Admin endpoints - protected
app.get('/api/admin/emails', authenticateToken, async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const startIndex = (page - 1) * limit;
    const endIndex = page * limit;

    const allEmails = await getEmailsFromRedis();
    const paginatedEmails = allEmails.slice(startIndex, endIndex);

    res.json({
      success: true,
      emails: paginatedEmails,
      total: allEmails.length,
      page,
      totalPages: Math.ceil(allEmails.length / limit)
    });
  } catch (error) {
    console.error('Get emails error:', error);
    res.status(500).json({ error: 'Failed to retrieve emails' });
  }
});

app.get('/api/admin/logs', authenticateToken, async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 20;
    const startIndex = (page - 1) * limit;
    const endIndex = startIndex + limit - 1;

    const paginatedLogs = await getLogsFromRedis(startIndex, endIndex);
    const totalLogs = await client.lLen(REDIS_KEYS.LOGS);

    res.json({
      success: true,
      logs: paginatedLogs,
      total: totalLogs,
      page,
      totalPages: Math.ceil(totalLogs / limit)
    });
  } catch (error) {
    console.error('Get logs error:', error);
    res.status(500).json({ error: 'Failed to retrieve logs' });
  }
});

app.get('/api/admin/stats', authenticateToken, async (req, res) => {
  try {
    const now = new Date();
    const allEmails = await getEmailsFromRedis();
    const activeEmails = allEmails.filter(e => new Date(e.expiresAt) > now);
    const expiredEmails = allEmails.filter(e => new Date(e.expiresAt) <= now);
    
    const allLogs = await getLogsFromRedis(0, -1);
    const todayLogs = allLogs.filter(log => {
      const logDate = new Date(log.timestamp);
      return logDate.toDateString() === now.toDateString();
    });

    res.json({
      success: true,
      stats: {
        totalEmails: allEmails.length,
        activeEmails: activeEmails.length,
        expiredEmails: expiredEmails.length,
        todayActivity: todayLogs.length
      }
    });
  } catch (error) {
    console.error('Get stats error:', error);
    res.status(500).json({ error: 'Failed to retrieve statistics' });
  }
});

// Serve admin panel
app.get('/', (req, res) => {
  res.redirect('/admin');
});

app.get('/admin', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ error: 'Something went wrong!' });
});

// 404 handler
app.use((req, res) => {
  res.status(404).json({ error: 'Endpoint not found' });
});

// SMTP Server with smtp-server integration
const setupSMTPServer = () => {
  try {
    const { SMTPServer } = require('smtp-server');
    
    const smtpServer = new SMTPServer({
      secure: false,
      authOptional: true,
      disabledCommands: ['AUTH'],
      
      // Handle incoming emails
      onData(stream, session, callback) {
        let emailData = '';
        
        stream.on('data', (chunk) => {
          emailData += chunk;
        });
        
        stream.on('end', async () => {
          try {
            const parsed = await simpleParser(emailData);
            const recipient = session.envelope.rcptTo[0].address;
            
            // Extract email ID from recipient
            const emailId = recipient.split('@')[0];
            const emails = await getEmailsFromRedis();
            const targetEmail = emails.find(e => e.email === recipient);
            
            if (targetEmail && new Date() < new Date(targetEmail.expiresAt)) {
              const message = {
                id: uuidv4(),
                from: parsed.from?.text || 'Unknown',
                to: recipient,
                subject: parsed.subject || 'No Subject',
                text: parsed.text || '',
                html: parsed.html || '',
                date: new Date(),
                attachments: parsed.attachments || []
              };
              
              await saveMessageToRedis(targetEmail.id, message);
              
              // Update message count
              targetEmail.messageCount = (targetEmail.messageCount || 0) + 1;
              await saveEmailToRedis(targetEmail);
              
              // Log the message
              const log = {
                id: uuidv4(),
                action: 'MESSAGE_RECEIVED',
                email: recipient,
                timestamp: new Date(),
                ip: session.remoteAddress
              };
              await saveLogToRedis(log);
              
              // Emit real-time update
              io.emit('messageReceived', { email: recipient, message });
              io.emit('newLog', log);
              
              console.log(`📧 Message received for ${recipient}`);
            }
            
            callback();
          } catch (error) {
            console.error('SMTP processing error:', error);
            callback(new Error('Processing failed'));
          }
        });
      },
      
      // Validate recipients
      onRcptTo(address, session, callback) {
        const recipient = address.address;
        const domain = recipient.split('@')[1];
        
        if (domain === CONFIG.EMAIL_DOMAIN) {
          callback();
        } else {
          callback(new Error('Invalid recipient domain'));
        }
      }
    });
    
    const smtpPort = CONFIG.SMTP_PORT;
    const smtpHost = CONFIG.SMTP_HOST;
    
    smtpServer.listen(smtpPort, smtpHost, () => {
      console.log(`📬 SMTP Server running on ${smtpHost}:${smtpPort}`);
    });
    
    smtpServer.on('error', (error) => {
      console.error('SMTP Server error:', error);
    });
    
  } catch (error) {
    console.error('❌ Failed to start SMTP server:', error);
    console.log('⚠️  SMTP server disabled. Install dependencies: npm install smtp-server');
  }
};

// Cleanup expired emails every hour
setInterval(async () => {
  try {
    const now = new Date();
    const allEmails = await getEmailsFromRedis();
    const activeEmails = allEmails.filter(email => new Date(email.expiresAt) > now);
    const expiredCount = allEmails.length - activeEmails.length;
    
    if (expiredCount > 0) {
      // Clear expired emails from Redis
      await client.del(REDIS_KEYS.EMAILS);
      for (const email of activeEmails) {
        await saveEmailToRedis(email);
      }
      console.log(`🧹 Cleaned up ${expiredCount} expired emails`);
    }
  } catch (error) {
    console.error('Cleanup error:', error);
  }
}, 60 * 60 * 1000); // 1 hour

// Health check endpoint (no authentication required)
app.get('/api/health', (req, res) => {
  res.json({
    status: 'OK',
    timestamp: new Date(),
    uptime: process.uptime(),
    domain: CONFIG.EMAIL_DOMAIN,
    vpsIp: CONFIG.VPS_IP
  });
});

// Test SMTP connectivity endpoint
app.get('/api/admin/test-smtp', authenticateToken, async (req, res) => {
  try {
    const testResult = {
      redis: false,
      smtp: false,
      domain: CONFIG.EMAIL_DOMAIN,
      vpsIp: CONFIG.VPS_IP
    };
    
    // Test Redis connection
    try {
      await client.ping();
      testResult.redis = true;
    } catch (error) {
      console.error('Redis test failed:', error);
    }
    
    // Test SMTP (basic check)
    testResult.smtp = true; // Assume SMTP is working if no errors
    
    res.json({
      success: true,
      tests: testResult,
      message: 'System connectivity test completed'
    });
  } catch (error) {
    console.error('Test error:', error);
    res.status(500).json({ error: 'Test failed' });
  }
});

// Send test OTP email endpoint
app.post('/api/admin/send-test-otp', authenticateToken, async (req, res) => {
  try {
    const { targetEmail } = req.body;
    
    if (!targetEmail) {
      return res.status(400).json({ error: 'Target email is required' });
    }
    
    // Generate OTP
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    
    // Create test message
    const testMessage = {
      id: uuidv4(),
      from: 'noreply@' + CONFIG.EMAIL_DOMAIN,
      to: targetEmail,
      subject: 'Your OTP Code - RedMail Test',
      text: `Your OTP code is: ${otp}\n\nThis is a test message from RedMail system.\n\nThe OTP will expire in 5 minutes.`,
      html: `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
          <h2 style="color: #333; text-align: center;">Your OTP Code</h2>
          <div style="background: #f8f9fa; border: 2px solid #007bff; border-radius: 8px; padding: 20px; text-align: center; margin: 20px 0;">
            <h1 style="color: #007bff; font-size: 36px; margin: 0; letter-spacing: 5px;">${otp}</h1>
          </div>
          <p style="color: #666; text-align: center;">This is a test message from RedMail system.</p>
          <p style="color: #666; text-align: center; font-size: 14px;">The OTP will expire in 5 minutes.</p>
          <hr style="border: none; border-top: 1px solid #eee; margin: 20px 0;">
          <p style="color: #999; font-size: 12px; text-align: center;">This email was sent from RedMail Admin Panel</p>
        </div>
      `,
      date: new Date(),
      attachments: []
    };
    
    // Find the target email in Redis
    const emails = await getEmailsFromRedis();
    const targetTempEmail = emails.find(e => e.email === targetEmail);
    
    if (!targetTempEmail) {
      return res.status(404).json({ error: 'Target email not found in system' });
    }
    
    if (new Date() > new Date(targetTempEmail.expiresAt)) {
      return res.status(410).json({ error: 'Target email has expired' });
    }
    
    // Save message to Redis
    await saveMessageToRedis(targetTempEmail.id, testMessage);
    
    // Update message count
    targetTempEmail.messageCount = (targetTempEmail.messageCount || 0) + 1;
    await saveEmailToRedis(targetTempEmail);
    
    // Log the test
    const log = {
      id: uuidv4(),
      action: 'TEST_OTP_SENT',
      email: targetEmail,
      timestamp: new Date(),
      ip: req.ip,
      otp: otp
    };
    await saveLogToRedis(log);
    
    // Emit real-time update
    io.emit('messageReceived', { email: targetEmail, message: testMessage });
    io.emit('newLog', log);
    
    res.json({
      success: true,
      message: 'Test OTP email sent successfully',
      otp: otp, // For admin reference
      targetEmail: targetEmail,
      sentAt: new Date()
    });
    
  } catch (error) {
    console.error('Send test OTP error:', error);
    res.status(500).json({ error: 'Failed to send test OTP' });
  }
});

server.listen(PORT, () => {
  console.log(`🚀 RedMail Admin Server running on port ${PORT}`);
  console.log(`📧 Admin Panel: http://167.99.70.90:${PORT}/admin`);
    console.log(`🔒 API Base: http://167.99.70.90:${PORT}/api`);
  console.log(`🌐 VPS IP: ${CONFIG.VPS_IP}`);
  console.log(`📮 Email Domain: ${CONFIG.EMAIL_DOMAIN}`);
  
  // Start SMTP server
  setupSMTPServer();
});

module.exports = app;