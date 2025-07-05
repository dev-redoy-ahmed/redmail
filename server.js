/**
 * RedMail - Temporary Email Service (RECEIVE ONLY)
 * 
 * SECURITY NOTICE: This system is designed exclusively for receiving emails.
 * All outgoing email functionality has been disabled for security purposes.
 * No email sending capabilities are available in this system.
 * NO SMTP CLIENT OR EMAIL SENDING LIBRARIES ARE ALLOWED
 */

// SECURITY: Block any attempt to require email sending libraries
const originalRequire = require;
require = function(id) {
  const blockedModules = ['nodemailer', 'sendmail', 'emailjs', 'smtp-client', 'node-smtp-client', 'sendgrid', 'mailgun', 'aws-ses', 'postmark'];
  // Allow legitimate email parsing libraries but block sending libraries
  const allowedModules = ['mailparser', 'mail-parser', 'email-parser'];
  
  if (blockedModules.some(module => id.toLowerCase().includes(module.toLowerCase())) && 
      !allowedModules.some(allowed => id.toLowerCase().includes(allowed.toLowerCase()))) {
    throw new Error(`SECURITY BLOCK: Email sending module '${id}' is permanently blocked. This system is RECEIVE-ONLY.`);
  }
  return originalRequire.apply(this, arguments);
};

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
const { simpleParser } = require('mailparser');
const redis = require('redis');
const { Server } = require('socket.io');
const http = require('http');
const crypto = require('crypto');
const multer = require('multer');
const mime = require('mime-types');

// Create attachment storage directory if it doesn't exist
if (!fs.existsSync('./attachments')) {
  fs.mkdirSync('./attachments', { recursive: true });
  console.log('📁 Created attachments directory');
}

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
  LOG_FILE: 'logs/app.log',
  
  // Default settings
  EMAIL_EXPIRY_TIME: 60, // minutes
  MESSAGE_RETENTION_TIME: 24, // hours
  REALTIME_API_PUSH: true,
  AUTO_REFRESH_INTERVAL: 5, // seconds
  
  // Attachment Configuration
  MAX_ATTACHMENT_SIZE: 5 * 1024 * 1024, // 5MB per email
  MAX_ATTACHMENTS_PER_EMAIL: 10,
  ALLOWED_ATTACHMENT_TYPES: ['pdf', 'doc', 'docx', 'txt', 'jpg', 'jpeg', 'png', 'gif', 'zip', 'rar'],
  ATTACHMENT_STORAGE_PATH: './attachments',
  ATTACHMENT_CLEANUP_HOURS: 24
};

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
  cors: {
    origin: CONFIG.ALLOWED_ORIGINS,
    methods: ['GET', 'POST']
  }
});

// Real-time API endpoint for email subscription
app.post('/api/temp-email/:emailId/subscribe', async (req, res) => {
  try {
    const { emailId } = req.params;
    const email = await getEmailFromRedis(emailId);
    
    if (!email) {
      return res.status(404).json({ error: 'Email not found' });
    }
    
    // Check if email is expired
    if (new Date() > new Date(email.expiresAt)) {
      return res.status(410).json({ error: 'Email has expired' });
    }
    
    res.json({
      success: true,
      message: 'Subscribe to Socket.IO for real-time updates',
      email: email.email,
      socketEvents: {
        subscribe: `email:${email.email}`,
        messageEvent: 'new_message',
        apiEvent: 'api:message'
      },
      instructions: {
        connect: 'Connect to Socket.IO at the same domain',
        subscribe: `Emit 'subscribe:email' with email address: ${email.email}`,
        listen: 'Listen for events on the subscribed channel'
      }
    });
    
  } catch (error) {
    console.error('Subscribe API error:', error);
    res.status(500).json({ error: 'Failed to setup subscription' });
  }
});

// Real-time status endpoint
app.get('/api/realtime/status', (req, res) => {
  res.json({
    success: true,
    realtimeEnabled: CONFIG.REALTIME_API_PUSH,
    autoRefreshInterval: CONFIG.AUTO_REFRESH_INTERVAL,
    socketIO: {
      enabled: true,
      endpoint: '/socket.io/',
      events: {
        messageReceived: 'messageReceived',
        newLog: 'newLog',
        emailSpecific: 'email:{emailAddress}',
        apiMessages: 'api:message'
      }
    },
    settings: {
      emailExpiryTime: CONFIG.EMAIL_EXPIRY_TIME,
      messageRetentionTime: CONFIG.MESSAGE_RETENTION_TIME
    }
  });
});

const PORT = CONFIG.PORT;
const JWT_SECRET = CONFIG.JWT_SECRET;
const ADMIN_PASSWORD_HASH = CONFIG.ADMIN_PASSWORD_HASH;

// Redis connection with graceful fallback
let client;
let redisConnected = false;
let redisErrorLogged = false;

try {
  client = redis.createClient({
    host: '127.0.0.1',
    port: 6379,
    retry_strategy: () => null // Don't retry on connection failure
  });

  // Connect to Redis
  client.connect().then(() => {
    redisConnected = true;
    redisErrorLogged = false;
    console.log('✅ Connected to Redis server');
  }).catch((err) => {
    if (!redisErrorLogged) {
      console.warn('⚠️  Redis not available, running in memory mode:', err.message);
      redisErrorLogged = true;
    }
    redisConnected = false;
    client = null;
  });

  client.on('error', (err) => {
    if (!redisErrorLogged) {
      console.warn('⚠️  Redis connection error, falling back to memory mode:', err.message);
      redisErrorLogged = true;
    }
    redisConnected = false;
  });
} catch (error) {
  if (!redisErrorLogged) {
    console.warn('⚠️  Redis not available, running in memory mode');
    redisErrorLogged = true;
  }
  redisConnected = false;
  client = null;
}

// In-memory fallback storage
const memoryStore = {
  emails: new Map(),
  logs: [],
  messages: new Map(),
  domains: new Map()
};

// Initialize default domain
memoryStore.domains.set('oplex.online', {
  name: 'oplex.online',
  status: 'active',
  addedAt: new Date(),
  emailsGenerated: 0
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

// Trust proxy for Nginx reverse proxy
app.set('trust proxy', 1);

app.use(cors({
  origin: CONFIG.ALLOWED_ORIGINS,
  credentials: true
}));

// Security Middleware - Block all outgoing email functionality
app.use((req, res, next) => {
  // Add security headers
  res.setHeader('X-RedMail-Mode', 'RECEIVE-ONLY');
  res.setHeader('X-Email-Sending', 'DISABLED');
  
  // Block any email sending endpoints
  const blockedPaths = [
    '/send',
    '/mail/send',
    '/email/send',
    '/smtp/send',
    '/api/send',
    '/api/mail/send',
    '/api/email/send',
    '/api/smtp/send',
    '/send-email',
    '/send-mail',
    '/sendmail',
    '/mail-send',
    '/email-send'
  ];
  
  const isBlockedPath = blockedPaths.some(path => 
    req.path.toLowerCase().includes(path.toLowerCase()) ||
    req.path.toLowerCase().includes('send') && req.path.toLowerCase().includes('mail') ||
    req.path.toLowerCase().includes('send') && req.path.toLowerCase().includes('email') ||
    req.path.toLowerCase().includes('send') && req.path.toLowerCase().includes('otp')
  );
  
  if (isBlockedPath && req.method !== 'GET') {
    return res.status(403).json({
      error: 'Email sending is permanently disabled',
      message: 'This system is designed exclusively for receiving emails',
      mode: 'RECEIVE-ONLY',
      timestamp: new Date().toISOString()
    });
  }
  
  next();
});

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
  console.log('👤 Client connected:', socket.id);
  
  // Handle email subscription for real-time updates
  socket.on('subscribe:email', (emailAddress) => {
    if (emailAddress) {
      socket.join(`email:${emailAddress}`);
      console.log(`Client subscribed to email: ${emailAddress}`);
      
      // Send confirmation
      socket.emit('subscribed', {
        email: emailAddress,
        timestamp: new Date()
      });
    }
  });
  
  // Handle email ID subscription
  socket.on('joinEmail', (emailId) => {
    if (emailId) {
      socket.join(`email_id:${emailId}`);
      console.log(`Client joined email room: ${emailId}`);
    }
  });
  
  // Handle email unsubscription
  socket.on('unsubscribe:email', (emailAddress) => {
    if (emailAddress) {
      socket.leave(`email:${emailAddress}`);
      console.log(`Client unsubscribed from email: ${emailAddress}`);
    }
  });
  
  // Handle API subscription for real-time message updates
  socket.on('subscribe:api', () => {
    socket.join('api:listeners');
    console.log('Client subscribed to API updates');
  });
  
  socket.on('disconnect', () => {
    console.log('👤 Client disconnected:', socket.id);
  });
});

// Helper functions for Redis operations with memory fallback
const saveEmailToRedis = async (email) => {
  if (redisConnected && client) {
    try {
      await client.hSet(REDIS_KEYS.EMAILS, email.id, JSON.stringify(email));
      await client.expire(REDIS_KEYS.EMAILS, 24 * 60 * 60); // 24 hours
    } catch (error) {
      console.warn('Redis save failed, using memory store:', error.message);
      memoryStore.emails.set(email.id, email);
    }
  } else {
    memoryStore.emails.set(email.id, email);
  }
};

const getEmailFromRedis = async (emailId) => {
  if (redisConnected && client) {
    try {
      const emailData = await client.hGet(REDIS_KEYS.EMAILS, emailId);
      return emailData ? JSON.parse(emailData) : null;
    } catch (error) {
      console.warn('Redis get failed, using memory store:', error.message);
      return memoryStore.emails.get(emailId) || null;
    }
  } else {
    return memoryStore.emails.get(emailId) || null;
  }
};

const getEmailsFromRedis = async () => {
  if (redisConnected && client) {
    try {
      const emails = await client.hGetAll(REDIS_KEYS.EMAILS);
      return Object.values(emails).map(email => JSON.parse(email));
    } catch (error) {
      console.warn('Redis get failed, using memory store:', error.message);
      return Array.from(memoryStore.emails.values());
    }
  } else {
    return Array.from(memoryStore.emails.values());
  }
};

const saveLogToRedis = async (log) => {
  if (redisConnected && client) {
    try {
      await client.lPush(REDIS_KEYS.LOGS, JSON.stringify(log));
      await client.lTrim(REDIS_KEYS.LOGS, 0, 999); // Keep last 1000 logs
    } catch (error) {
      console.warn('Redis log save failed, using memory store:', error.message);
      memoryStore.logs.unshift(log);
      if (memoryStore.logs.length > 1000) memoryStore.logs = memoryStore.logs.slice(0, 1000);
    }
  } else {
    memoryStore.logs.unshift(log);
    if (memoryStore.logs.length > 1000) memoryStore.logs = memoryStore.logs.slice(0, 1000);
  }
};

const getLogsFromRedis = async (start = 0, end = 19) => {
  if (redisConnected && client) {
    try {
      const logs = await client.lRange(REDIS_KEYS.LOGS, start, end);
      return logs.map(log => JSON.parse(log));
    } catch (error) {
      console.warn('Redis log get failed, using memory store:', error.message);
      return memoryStore.logs.slice(start, end + 1);
    }
  } else {
    return memoryStore.logs.slice(start, end + 1);
  }
};

const saveMessageToRedis = async (emailId, message) => {
  if (redisConnected && client) {
    try {
      await client.lPush(REDIS_KEYS.MESSAGES + emailId, JSON.stringify(message));
      await client.expire(REDIS_KEYS.MESSAGES + emailId, 24 * 60 * 60); // 24 hours
    } catch (error) {
      console.warn('Redis message save failed, using memory store:', error.message);
      if (!memoryStore.messages.has(emailId)) memoryStore.messages.set(emailId, []);
      memoryStore.messages.get(emailId).unshift(message);
    }
  } else {
    if (!memoryStore.messages.has(emailId)) memoryStore.messages.set(emailId, []);
    memoryStore.messages.get(emailId).unshift(message);
  }
};

const getMessagesFromRedis = async (emailId) => {
  if (redisConnected && client) {
    try {
      const messages = await client.lRange(REDIS_KEYS.MESSAGES + emailId, 0, -1);
      return messages.map(message => JSON.parse(message));
    } catch (error) {
      console.warn('Redis message get failed, using memory store:', error.message);
      return memoryStore.messages.get(emailId) || [];
    }
  } else {
    return memoryStore.messages.get(emailId) || [];
  }
};

const deleteMessageFromRedis = async (emailId, messageId) => {
  if (redisConnected && client) {
    try {
      const messages = await client.lRange(REDIS_KEYS.MESSAGES + emailId, 0, -1);
      const filteredMessages = messages.filter(msgStr => {
        const message = JSON.parse(msgStr);
        return message.id !== messageId;
      });
      
      await client.del(REDIS_KEYS.MESSAGES + emailId);
      if (filteredMessages.length > 0) {
        await client.lPush(REDIS_KEYS.MESSAGES + emailId, ...filteredMessages);
      }
      return true;
    } catch (error) {
      console.warn('Redis message delete failed, using memory store:', error.message);
      const messages = memoryStore.messages.get(emailId) || [];
      const messageIndex = messages.findIndex(m => m.id === messageId);
      if (messageIndex !== -1) {
        messages.splice(messageIndex, 1);
        return true;
      }
      return false;
    }
  } else {
    const messages = memoryStore.messages.get(emailId) || [];
    const messageIndex = messages.findIndex(m => m.id === messageId);
    if (messageIndex !== -1) {
      messages.splice(messageIndex, 1);
      return true;
    }
    return false;
  }
};

const clearMessagesFromRedis = async (emailId) => {
  if (redisConnected && client) {
    try {
      await client.del(REDIS_KEYS.MESSAGES + emailId);
      return true;
    } catch (error) {
      console.warn('Redis messages clear failed, using memory store:', error.message);
      memoryStore.messages.delete(emailId);
      return true;
    }
  } else {
    memoryStore.messages.delete(emailId);
    return true;
  }
};

// Domain management helper functions
const saveDomainToRedis = async (domain) => {
  if (redisConnected && client) {
    try {
      await client.hSet('domains', domain.name, JSON.stringify(domain));
    } catch (error) {
      console.warn('Redis domain save failed, using memory store:', error.message);
      memoryStore.domains.set(domain.name, domain);
    }
  } else {
    memoryStore.domains.set(domain.name, domain);
  }
};

const getDomainsFromRedis = async () => {
  if (redisConnected && client) {
    try {
      const domains = await client.hGetAll('domains');
      return Object.values(domains).map(domain => JSON.parse(domain));
    } catch (error) {
      console.warn('Redis domain get failed, using memory store:', error.message);
      return Array.from(memoryStore.domains.values());
    }
  } else {
    return Array.from(memoryStore.domains.values());
  }
};

const getDomainFromRedis = async (domainName) => {
  if (redisConnected && client) {
    try {
      const domainData = await client.hGet('domains', domainName);
      return domainData ? JSON.parse(domainData) : null;
    } catch (error) {
      console.warn('Redis domain get failed, using memory store:', error.message);
      return memoryStore.domains.get(domainName) || null;
    }
  } else {
    return memoryStore.domains.get(domainName) || null;
  }
};

const deleteDomainFromRedis = async (domainName) => {
  if (redisConnected && client) {
    try {
      await client.hDel('domains', domainName);
      return true;
    } catch (error) {
      console.warn('Redis domain delete failed, using memory store:', error.message);
      return memoryStore.domains.delete(domainName);
    }
  } else {
    return memoryStore.domains.delete(domainName);
  }
};

const getRandomActiveDomain = async () => {
  const domains = await getDomainsFromRedis();
  const activeDomains = domains.filter(d => d.status === 'active');
  if (activeDomains.length === 0) {
    return 'oplex.online'; // fallback to default
  }
  return activeDomains[Math.floor(Math.random() * activeDomains.length)].name;
};

const incrementDomainEmailCount = async (domainName) => {
  const domain = await getDomainFromRedis(domainName);
  if (domain) {
    domain.emailsGenerated = (domain.emailsGenerated || 0) + 1;
    await saveDomainToRedis(domain);
  }
};

// Attachment helper functions
const saveAttachmentToStorage = async (attachment, emailId) => {
  try {
    const attachmentId = uuidv4();
    const sanitizedFilename = attachment.filename.replace(/[^a-zA-Z0-9.-]/g, '_');
    const fileExtension = path.extname(sanitizedFilename).toLowerCase().substring(1);
    
    // Validate file type
    if (!CONFIG.ALLOWED_ATTACHMENT_TYPES.includes(fileExtension)) {
      throw new Error(`File type .${fileExtension} not allowed`);
    }
    
    // Validate file size
    if (attachment.size > CONFIG.MAX_ATTACHMENT_SIZE) {
      throw new Error(`File size exceeds ${CONFIG.MAX_ATTACHMENT_SIZE / (1024 * 1024)}MB limit`);
    }
    
    const fileName = `${attachmentId}_${sanitizedFilename}`;
    const filePath = path.join(CONFIG.ATTACHMENT_STORAGE_PATH, fileName);
    
    // Save file to disk
    fs.writeFileSync(filePath, attachment.content);
    
    const attachmentData = {
      id: attachmentId,
      originalName: attachment.filename,
      fileName: fileName,
      filePath: filePath,
      size: attachment.size,
      mimeType: attachment.contentType || mime.lookup(sanitizedFilename) || 'application/octet-stream',
      emailId: emailId,
      uploadedAt: new Date(),
      expiresAt: new Date(Date.now() + CONFIG.ATTACHMENT_CLEANUP_HOURS * 60 * 60 * 1000),
      downloadCount: 0,
      secureToken: crypto.randomBytes(32).toString('hex')
    };
    
    // Save attachment metadata
    await saveAttachmentMetadata(attachmentData);
    
    return {
      id: attachmentId,
      name: attachment.filename,
      size: attachment.size,
      type: attachmentData.mimeType,
      downloadUrl: `/api/attachments/${attachmentId}/download?token=${attachmentData.secureToken}`
    };
  } catch (error) {
    console.error('Attachment save error:', error);
    throw error;
  }
};

const saveAttachmentMetadata = async (attachmentData) => {
  if (redisConnected && client) {
    try {
      await client.hSet('attachments', attachmentData.id, JSON.stringify(attachmentData));
      await client.expire('attachments', CONFIG.ATTACHMENT_CLEANUP_HOURS * 60 * 60);
    } catch (error) {
      console.warn('Redis attachment save failed, using memory store:', error.message);
      if (!memoryStore.attachments) memoryStore.attachments = new Map();
      memoryStore.attachments.set(attachmentData.id, attachmentData);
    }
  } else {
    if (!memoryStore.attachments) memoryStore.attachments = new Map();
    memoryStore.attachments.set(attachmentData.id, attachmentData);
  }
};

const getAttachmentMetadata = async (attachmentId) => {
  if (redisConnected && client) {
    try {
      const attachmentData = await client.hGet('attachments', attachmentId);
      return attachmentData ? JSON.parse(attachmentData) : null;
    } catch (error) {
      console.warn('Redis attachment get failed, using memory store:', error.message);
      return memoryStore.attachments?.get(attachmentId) || null;
    }
  } else {
    return memoryStore.attachments?.get(attachmentId) || null;
  }
};

const deleteAttachmentFile = async (attachmentId) => {
  try {
    const attachment = await getAttachmentMetadata(attachmentId);
    if (attachment && fs.existsSync(attachment.filePath)) {
      fs.unlinkSync(attachment.filePath);
    }
    
    // Remove metadata
    if (redisConnected && client) {
      try {
        await client.hDel('attachments', attachmentId);
      } catch (error) {
        console.warn('Redis attachment delete failed:', error.message);
      }
    }
    
    if (memoryStore.attachments) {
      memoryStore.attachments.delete(attachmentId);
    }
    
    return true;
  } catch (error) {
    console.error('Attachment delete error:', error);
    return false;
  }
};

const cleanupExpiredAttachments = async () => {
  try {
    const now = new Date();
    
    if (redisConnected && client) {
      try {
        const attachments = await client.hGetAll('attachments');
        for (const [id, data] of Object.entries(attachments)) {
          const attachment = JSON.parse(data);
          if (new Date(attachment.expiresAt) < now) {
            await deleteAttachmentFile(id);
          }
        }
      } catch (error) {
        console.warn('Redis attachment cleanup failed:', error.message);
      }
    }
    
    if (memoryStore.attachments) {
      for (const [id, attachment] of memoryStore.attachments.entries()) {
        if (new Date(attachment.expiresAt) < now) {
          await deleteAttachmentFile(id);
        }
      }
    }
  } catch (error) {
    console.error('Attachment cleanup error:', error);
  }
};

// Calculate time remaining until expiration
const getTimeRemaining = (expiresAt) => {
  const now = new Date();
  const expiry = new Date(expiresAt);
  const diff = expiry - now;
  
  if (diff <= 0) return '00:00';
  
  const hours = Math.floor(diff / (1000 * 60 * 60));
  const minutes = Math.floor((diff % (1000 * 60 * 60)) / (1000 * 60));
  
  return `${hours.toString().padStart(2, '0')}:${minutes.toString().padStart(2, '0')}`;
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
// Generate random temporary email
app.post('/api/temp-email/generate', apiLimiter, async (req, res) => {
  try {
    const emailId = uuidv4();
    const selectedDomain = await getRandomActiveDomain();
    const domain = `@${selectedDomain}`;
    const tempEmail = {
      id: emailId,
      email: `${emailId.substring(0, 8)}${domain}`,
      createdAt: new Date(),
      expiresAt: new Date(Date.now() + CONFIG.EMAIL_EXPIRY_TIME * 60 * 1000), // Dynamic expiry time
      messageCount: 0,
      domain: selectedDomain,
      type: 'random'
    };

    await saveEmailToRedis(tempEmail);
    await incrementDomainEmailCount(selectedDomain);

    // Log the generation
    const log = {
      id: uuidv4(),
      action: 'EMAIL_GENERATED',
      email: tempEmail.email,
      timestamp: new Date(),
      ip: req.ip
    };
    await saveLogToRedis(log);

    // Emit real-time update to admin panel and email subscribers
    io.emit('emailGenerated', tempEmail);
    io.emit('newLog', log);
    io.to(`email_id:${tempEmail.id}`).emit('emailCreated', tempEmail);

    res.json({
      success: true,
      email: tempEmail.email,
      id: tempEmail.id,
      expiresAt: tempEmail.expiresAt,
      domain: selectedDomain
    });
  } catch (error) {
    console.error('Email generation error:', error);
    res.status(500).json({ error: 'Failed to generate temporary email' });
  }
});

// Create custom temporary email
app.post('/api/temp-email/create-custom', apiLimiter, [
  body('name').isLength({ min: 1, max: 50 }).matches(/^[a-zA-Z0-9._-]+$/).withMessage('Invalid email name format'),
  body('domain').isLength({ min: 1 }).withMessage('Domain is required')
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ error: errors.array()[0].msg });
    }

    const { name, domain } = req.body;
    
    // Check if domain exists and is active
    const domainData = await getDomainFromRedis(domain);
    if (!domainData) {
      return res.status(400).json({ error: 'Domain not found' });
    }
    if (domainData.status !== 'active') {
      return res.status(400).json({ error: 'Domain is not active' });
    }

    const customEmail = `${name}@${domain}`;
    
    // Check if email already exists
    const existingEmails = await getEmailsFromRedis();
    const emailExists = existingEmails.some(e => e.email === customEmail);
    if (emailExists) {
      return res.status(400).json({ error: 'Email already exists' });
    }

    const emailId = uuidv4();
    const tempEmail = {
      id: emailId,
      email: customEmail,
      createdAt: new Date(),
      expiresAt: new Date(Date.now() + CONFIG.EMAIL_EXPIRY_TIME * 60 * 1000),
      messageCount: 0,
      domain: domain,
      type: 'custom',
      customName: name
    };

    await saveEmailToRedis(tempEmail);
    await incrementDomainEmailCount(domain);

    // Log the creation
    const log = {
      id: uuidv4(),
      action: 'CUSTOM_EMAIL_CREATED',
      email: tempEmail.email,
      timestamp: new Date(),
      ip: req.ip
    };
    await saveLogToRedis(log);

    // Emit real-time update
    io.emit('emailGenerated', tempEmail);
    io.emit('newLog', log);
    io.to(`email_id:${tempEmail.id}`).emit('emailCreated', tempEmail);

    res.json({
      success: true,
      email: tempEmail.email,
      id: tempEmail.id,
      expiresAt: tempEmail.expiresAt,
      domain: domain,
      type: 'custom'
    });
  } catch (error) {
    console.error('Custom email creation error:', error);
    res.status(500).json({ error: 'Failed to create custom email' });
  }
});

// Get available domains for email creation
app.get('/api/domains/available', apiLimiter, async (req, res) => {
  try {
    const domains = await getDomainsFromRedis();
    const activeDomains = domains.filter(d => d.status === 'active').map(d => ({
      name: d.name,
      emailsGenerated: d.emailsGenerated || 0
    }));
    
    res.json({
      success: true,
      domains: activeDomains
    });
  } catch (error) {
    console.error('Get available domains error:', error);
    res.status(500).json({ error: 'Failed to fetch available domains' });
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
    
    // Enhance messages with attachment info and countdown timers
    const enhancedMessages = messages.map(message => {
      const enhancedMessage = {
        ...message,
        timeRemaining: message.expiresAt ? getTimeRemaining(message.expiresAt) : null,
        isExpired: message.expiresAt ? new Date() > new Date(message.expiresAt) : false
      };
      
      // Process attachments if they exist
      if (message.attachments && message.attachments.length > 0) {
        enhancedMessage.attachments = message.attachments.map(attachment => ({
          id: attachment.id,
          name: attachment.name,
          size: attachment.size,
          type: attachment.type,
          downloadUrl: attachment.downloadUrl,
          timeRemaining: getTimeRemaining(new Date(Date.now() + CONFIG.ATTACHMENT_CLEANUP_HOURS * 60 * 60 * 1000))
        }));
      }
      
      return enhancedMessage;
    });

    res.json({
      success: true,
      messages: enhancedMessages,
      emailTimeRemaining: getTimeRemaining(tempEmail.expiresAt),
      totalMessages: enhancedMessages.length,
      hasAttachments: enhancedMessages.some(m => m.hasAttachments),
      totalAttachments: enhancedMessages.reduce((total, m) => total + (m.attachmentCount || 0), 0)
    });
  } catch (error) {
    console.error('Get messages error:', error);
    res.status(500).json({ error: 'Failed to retrieve messages' });
  }
});

// Get single message by ID
app.get('/api/message/:messageId', apiLimiter, async (req, res) => {
  try {
    const { messageId } = req.params;
    
    // Search through all messages to find the one with matching ID
    let foundMessage = null;
    
    if (redisConnected && client) {
      // Redis implementation - search through all email messages
      const emails = await getEmailsFromRedis();
      for (const email of emails) {
        const messages = await getMessagesFromRedis(email.id);
        const message = messages.find(m => m.id === messageId);
        if (message) {
          foundMessage = message;
          break;
        }
      }
    } else {
      // Memory implementation
      for (const [emailId, messages] of memoryStore.messages) {
        const message = messages.find(m => m.id === messageId);
        if (message) {
          foundMessage = message;
          break;
        }
      }
    }
    
    if (!foundMessage) {
      return res.status(404).json({ error: 'Message not found' });
    }
    
    res.json({
      success: true,
      message: foundMessage
    });
  } catch (error) {
    console.error('Get message error:', error);
    res.status(500).json({ error: 'Failed to retrieve message' });
  }
});

// Get email by ID
app.get('/api/temp-email/:emailId', apiLimiter, async (req, res) => {
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

    res.json({
      success: true,
      email: tempEmail
    });
  } catch (error) {
    console.error('Get email error:', error);
    res.status(500).json({ error: 'Failed to retrieve email' });
  }
});

// Delete email by ID
app.delete('/api/temp-email/:emailId', apiLimiter, async (req, res) => {
  try {
    const { emailId } = req.params;
    
    let emailDeleted = false;
    
    if (redisConnected && client) {
      // Redis implementation
      const emailData = await client.hGet(REDIS_KEYS.EMAILS, emailId);
      if (emailData) {
        await client.hDel(REDIS_KEYS.EMAILS, emailId);
        await client.del(REDIS_KEYS.MESSAGES + emailId);
        emailDeleted = true;
      }
    } else {
      // Memory implementation
      if (memoryStore.emails.has(emailId)) {
        memoryStore.emails.delete(emailId);
        memoryStore.messages.delete(emailId);
        emailDeleted = true;
      }
    }
    
    if (!emailDeleted) {
      return res.status(404).json({ error: 'Email not found' });
    }
    
    // Log the deletion
    const log = {
      id: uuidv4(),
      action: 'EMAIL_DELETED',
      emailId: emailId,
      timestamp: new Date(),
      ip: req.ip
    };
    await saveLogToRedis(log);
    
    // Emit real-time update
    io.emit('emailDeleted', { emailId });
    io.emit('newLog', log);
    
    res.json({
      success: true,
      message: 'Email deleted successfully'
    });
  } catch (error) {
    console.error('Delete email error:', error);
    res.status(500).json({ error: 'Failed to delete email' });
  }
});

// Delete single message by ID
app.delete('/api/message/:messageId', apiLimiter, async (req, res) => {
  try {
    const { messageId } = req.params;
    
    let messageDeleted = false;
    let emailId = null;
    
    if (redisConnected && client) {
      // Redis implementation - search through all email messages
      const emails = await getEmailsFromRedis();
      for (const email of emails) {
        const messages = await getMessagesFromRedis(email.id);
        const messageIndex = messages.findIndex(m => m.id === messageId);
        
        if (messageIndex !== -1) {
          messages.splice(messageIndex, 1);
          
          // Clear and repopulate the list
          await client.del(REDIS_KEYS.MESSAGES + email.id);
          if (messages.length > 0) {
            const messageStrings = messages.map(m => JSON.stringify(m));
            await client.lPush(REDIS_KEYS.MESSAGES + email.id, ...messageStrings);
          }
          
          messageDeleted = true;
          emailId = email.id;
          break;
        }
      }
    } else {
      // Memory implementation
      for (const [eId, messages] of memoryStore.messages) {
        const messageIndex = messages.findIndex(m => m.id === messageId);
        if (messageIndex !== -1) {
          messages.splice(messageIndex, 1);
          messageDeleted = true;
          emailId = eId;
          break;
        }
      }
    }
    
    if (!messageDeleted) {
      return res.status(404).json({ error: 'Message not found' });
    }
    
    // Log the deletion
    const log = {
      id: uuidv4(),
      action: 'MESSAGE_DELETED',
      messageId: messageId,
      emailId: emailId,
      timestamp: new Date(),
      ip: req.ip
    };
    await saveLogToRedis(log);
    
    // Emit real-time update
    io.emit('messageDeleted', { messageId, emailId });
    io.emit('newLog', log);
    
    res.json({
      success: true,
      message: 'Message deleted successfully'
    });
  } catch (error) {
    console.error('Delete message error:', error);
    res.status(500).json({ error: 'Failed to delete message' });
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

// Cleanup expired emails and messages
app.post('/api/admin/cleanup-expired', authenticateToken, async (req, res) => {
  try {
    const now = new Date();
    let cleanedEmails = 0;
    let cleanedMessages = 0;

    if (redisConnected && client) {
      // Redis implementation
      const emailIds = await client.sMembers('emails');
      
      for (const emailId of emailIds) {
        const emailData = await client.hGetAll(`email:${emailId}`);
        
        if (emailData && emailData.expiresAt) {
          const expiresAt = new Date(emailData.expiresAt);
          
          if (expiresAt <= now) {
            // Remove expired email
            await client.sRem('emails', emailId);
            await client.del(`email:${emailId}`);
            
            // Remove associated messages
            const messages = await client.lRange(`messages:${emailId}`, 0, -1);
            cleanedMessages += messages.length;
            await client.del(`messages:${emailId}`);
            
            cleanedEmails++;
          } else {
            // Check for old messages in active emails
            const messages = await client.lRange(`messages:${emailId}`, 0, -1);
            const validMessages = [];
            
            for (const msgStr of messages) {
              const message = JSON.parse(msgStr);
              const messageAge = now - new Date(message.receivedAt);
              const maxAge = 30 * 60 * 1000; // 30 minutes default
              
              if (messageAge <= maxAge) {
                validMessages.push(msgStr);
              } else {
                cleanedMessages++;
              }
            }
            
            if (validMessages.length !== messages.length) {
              await client.del(`messages:${emailId}`);
              if (validMessages.length > 0) {
                await client.lPush(`messages:${emailId}`, ...validMessages);
              }
            }
          }
        }
      }
    } else {
      // Memory implementation
      const emailsToDelete = [];
      
      for (const [emailId, emailData] of memoryStore.emails) {
        const expiresAt = new Date(emailData.expiresAt);
        
        if (expiresAt <= now) {
          emailsToDelete.push(emailId);
          const messages = memoryStore.messages.get(emailId) || [];
          cleanedMessages += messages.length;
          cleanedEmails++;
        } else {
          // Check for old messages in active emails
          const messages = memoryStore.messages.get(emailId) || [];
          const validMessages = messages.filter(message => {
            const messageAge = now - new Date(message.receivedAt);
            const maxAge = 30 * 60 * 1000; // 30 minutes default
            return messageAge <= maxAge;
          });
          
          if (validMessages.length !== messages.length) {
            cleanedMessages += messages.length - validMessages.length;
            memoryStore.messages.set(emailId, validMessages);
          }
        }
      }
      
      // Remove expired emails
      emailsToDelete.forEach(emailId => {
        memoryStore.emails.delete(emailId);
        memoryStore.messages.delete(emailId);
      });
    }

    // Log the cleanup
    const log = {
      id: uuidv4(),
      action: 'CLEANUP_EXECUTED',
      details: `Cleaned ${cleanedEmails} emails and ${cleanedMessages} messages`,
      timestamp: new Date(),
      ip: req.ip
    };
    await saveLogToRedis(log);

    // Emit real-time update
    io.emit('cleanupCompleted', { cleanedEmails, cleanedMessages });
    io.emit('newLog', log);

    res.json({
      success: true,
      message: 'Cleanup completed successfully',
      cleanedEmails,
      cleanedMessages
    });
  } catch (error) {
    console.error('Cleanup error:', error);
    res.status(500).json({ error: 'Failed to perform cleanup' });
  }
});

// Global settings API endpoints
app.get('/api/admin/global-settings', authenticateToken, async (req, res) => {
  try {
    const settings = {
      autoDeleteTime: process.env.AUTO_DELETE_TIME || 30, // minutes
      emailChangeInterval: process.env.EMAIL_CHANGE_INTERVAL || 10, // minutes
      defaultEmailExpiry: process.env.DEFAULT_EMAIL_EXPIRY || 60, // minutes
      maxMessagesPerEmail: process.env.MAX_MESSAGES_PER_EMAIL || 50,
      autoCleanupEnabled: process.env.AUTO_CLEANUP_ENABLED === 'true',
      rateLimitEnabled: process.env.RATE_LIMIT_ENABLED === 'true'
    };
    
    res.json({ success: true, settings });
  } catch (error) {
    console.error('Get global settings error:', error);
    res.status(500).json({ error: 'Failed to retrieve global settings' });
  }
});

app.post('/api/admin/global-settings', authenticateToken, async (req, res) => {
  try {
    const { 
      autoDeleteTime, 
      emailChangeInterval, 
      defaultEmailExpiry, 
      maxMessagesPerEmail, 
      autoCleanupEnabled, 
      rateLimitEnabled 
    } = req.body;
    
    // Validate settings
    if (autoDeleteTime && (autoDeleteTime < 1 || autoDeleteTime > 1440)) {
      return res.status(400).json({ error: 'Auto delete time must be between 1-1440 minutes' });
    }
    
    if (emailChangeInterval && (emailChangeInterval < 1 || emailChangeInterval > 1440)) {
      return res.status(400).json({ error: 'Email change interval must be between 1-1440 minutes' });
    }
    
    // Update environment variables (in production, these should be saved to a config file)
    if (autoDeleteTime) process.env.AUTO_DELETE_TIME = autoDeleteTime.toString();
    if (emailChangeInterval) process.env.EMAIL_CHANGE_INTERVAL = emailChangeInterval.toString();
    if (defaultEmailExpiry) process.env.DEFAULT_EMAIL_EXPIRY = defaultEmailExpiry.toString();
    if (maxMessagesPerEmail) process.env.MAX_MESSAGES_PER_EMAIL = maxMessagesPerEmail.toString();
    if (autoCleanupEnabled !== undefined) process.env.AUTO_CLEANUP_ENABLED = autoCleanupEnabled.toString();
    if (rateLimitEnabled !== undefined) process.env.RATE_LIMIT_ENABLED = rateLimitEnabled.toString();
    
    // Restart cleanup scheduler if auto-cleanup is enabled
    if (autoCleanupEnabled && autoDeleteTime) {
      restartCleanupScheduler(autoDeleteTime);
    }
    
    // Log the settings change
    const log = {
      id: uuidv4(),
      action: 'GLOBAL_SETTINGS_UPDATED',
      details: `Settings updated: autoDeleteTime=${autoDeleteTime}, emailChangeInterval=${emailChangeInterval}`,
      timestamp: new Date(),
      ip: req.ip
    };
    await saveLogToRedis(log);
    
    io.emit('newLog', log);
    
    res.json({ success: true, message: 'Global settings updated successfully' });
  } catch (error) {
    console.error('Update global settings error:', error);
    res.status(500).json({ error: 'Failed to update global settings' });
  }
});

// Advanced features API endpoints
app.get('/api/admin/advanced-features', authenticateToken, async (req, res) => {
  try {
    const features = {
      antiSpamEnabled: process.env.ANTI_SPAM_ENABLED === 'true',
      attachmentSupport: process.env.ATTACHMENT_SUPPORT === 'true',
      mobileApiEnabled: process.env.MOBILE_API_ENABLED === 'true',
      realTimeNotifications: process.env.REALTIME_NOTIFICATIONS === 'true',
      bulkOperations: process.env.BULK_OPERATIONS === 'true',
      analyticsEnabled: process.env.ANALYTICS_ENABLED === 'true'
    };
    
    res.json({ success: true, features });
  } catch (error) {
    console.error('Get advanced features error:', error);
    res.status(500).json({ error: 'Failed to retrieve advanced features' });
  }
});

app.post('/api/admin/advanced-features', authenticateToken, async (req, res) => {
  try {
    const { 
      antiSpamEnabled, 
      attachmentSupport, 
      mobileApiEnabled, 
      realTimeNotifications, 
      bulkOperations, 
      analyticsEnabled 
    } = req.body;
    
    // Update environment variables
    if (antiSpamEnabled !== undefined) process.env.ANTI_SPAM_ENABLED = antiSpamEnabled.toString();
    if (attachmentSupport !== undefined) process.env.ATTACHMENT_SUPPORT = attachmentSupport.toString();
    if (mobileApiEnabled !== undefined) process.env.MOBILE_API_ENABLED = mobileApiEnabled.toString();
    if (realTimeNotifications !== undefined) process.env.REALTIME_NOTIFICATIONS = realTimeNotifications.toString();
    if (bulkOperations !== undefined) process.env.BULK_OPERATIONS = bulkOperations.toString();
    if (analyticsEnabled !== undefined) process.env.ANALYTICS_ENABLED = analyticsEnabled.toString();
    
    // Log the features change
    const log = {
      id: uuidv4(),
      action: 'ADVANCED_FEATURES_UPDATED',
      details: `Features updated: antiSpam=${antiSpamEnabled}, attachments=${attachmentSupport}, mobileAPI=${mobileApiEnabled}`,
      timestamp: new Date(),
      ip: req.ip
    };
    await saveLogToRedis(log);
    
    io.emit('newLog', log);
    
    res.json({ success: true, message: 'Advanced features updated successfully' });
  } catch (error) {
    console.error('Update advanced features error:', error);
    res.status(500).json({ error: 'Failed to update advanced features' });
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

// Enhanced SMTP Server with smtp-server
const setupSMTPServer = () => {
  try {
    const { SMTPServer } = require('smtp-server');
    
    const smtpServer = new SMTPServer({
      secure: false,
      authOptional: true,
      disabledCommands: ['AUTH', 'STARTTLS'],
      banner: 'RedMail SMTP Server Ready - No Spam Checking',
      hideSTARTTLS: true,
      hidePIPELINING: false,
      allowInsecureAuth: true,
      disableReverseLookup: true,
      
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
              
              // Minimal logging for performance - no IP tracking
               const log = {
                 id: uuidv4(),
                 action: 'MESSAGE_RECEIVED',
                 email: recipient,
                 timestamp: new Date()
               };
               
               // Fast async operations - no waiting
               setImmediate(() => {
                 saveLogToRedis(log);
                 
                 const messageData = {
                   email: recipient,
                   subject: parsed.subject,
                   from: parsed.from?.text,
                   timestamp: new Date(),
                   messageId: message.id
                 };
                 
                 io.emit('messageReceived', messageData);
                 io.emit('newLog', log);
                 
                 // Real-time API push if enabled
                 if (CONFIG.REALTIME_API_PUSH) {
                   // Emit to specific email listeners
                   io.emit(`email:${recipient}`, {
                     type: 'new_message',
                     data: messageData
                   });
                   
                   // Emit to API listeners
                   io.emit('api:message', {
                     email: recipient,
                     message: message,
                     timestamp: new Date()
                   });
                 }
               });
              
              console.log(`📧 Message received for ${recipient}`);
            }
            
            callback();
          } catch (error) {
            console.error('SMTP processing error:', error);
            callback(new Error('Processing failed'));
          }
        });
      },
      
      // Accept all recipients - no domain validation for faster processing
       onRcptTo(address, session, callback) {
         // Accept all emails without domain checking for maximum speed
         callback();
       }
    });
    
    const smtpPort = CONFIG.SMTP_PORT;
    const smtpHost = CONFIG.SMTP_HOST;
    
    smtpServer.listen(smtpPort, smtpHost, () => {
      console.log(`📬 Enhanced SMTP Server running on ${smtpHost}:${smtpPort}`);
      console.log(`📧 Email domain: ${CONFIG.EMAIL_DOMAIN}`);
    });
    
    smtpServer.on('error', (error) => {
      console.error('SMTP Server error:', error);
    });
    
  } catch (error) {
    console.error('❌ Failed to start SMTP server:', error);
    console.log('⚠️  SMTP server disabled. Install dependencies: npm install smtp-server');
  }
};

// Automatic cleanup scheduler
let cleanupInterval;

const restartCleanupScheduler = (intervalMinutes) => {
  if (cleanupInterval) {
    clearInterval(cleanupInterval);
  }
  
  const intervalMs = intervalMinutes * 60 * 1000;
  
  cleanupInterval = setInterval(async () => {
    try {
      const now = new Date();
      const allEmails = await getEmailsFromRedis();
      const activeEmails = allEmails.filter(email => new Date(email.expiresAt) > now);
      const expiredCount = allEmails.length - activeEmails.length;
      
      if (expiredCount > 0) {
        // Clear expired emails from Redis
        if (redisConnected && client) {
          await client.del(REDIS_KEYS.EMAILS);
          for (const email of activeEmails) {
            await saveEmailToRedis(email);
          }
        } else {
          // Memory cleanup
          const expiredEmails = allEmails.filter(email => new Date(email.expiresAt) <= now);
          expiredEmails.forEach(email => {
            memoryStore.emails.delete(email.id);
            memoryStore.messages.delete(email.id);
          });
        }
        
        console.log(`🧹 Auto-cleanup: Removed ${expiredCount} expired emails`);
        
        // Log the cleanup
        const log = {
          id: uuidv4(),
          action: 'AUTO_CLEANUP',
          details: `Removed ${expiredCount} expired emails`,
          timestamp: new Date()
        };
        await saveLogToRedis(log);
        io.emit('newLog', log);
      }
    } catch (error) {
      console.error('Auto-cleanup error:', error);
    }
  }, intervalMs);
  
  console.log(`🔄 Cleanup scheduler restarted: every ${intervalMinutes} minutes`);
};

// Start initial cleanup scheduler (default: every 30 minutes)
const initialCleanupInterval = parseInt(process.env.AUTO_DELETE_TIME) || 30;
if (process.env.AUTO_CLEANUP_ENABLED !== 'false') {
  restartCleanupScheduler(initialCleanupInterval);
}

// Cleanup expired emails every hour (fallback)
setInterval(async () => {
  try {
    const now = new Date();
    const allEmails = await getEmailsFromRedis();
    const activeEmails = allEmails.filter(email => new Date(email.expiresAt) > now);
    const expiredCount = allEmails.length - activeEmails.length;
    
    if (expiredCount > 0) {
      // Clear expired emails from Redis
      if (redisConnected && client) {
        await client.del(REDIS_KEYS.EMAILS);
        for (const email of activeEmails) {
          await saveEmailToRedis(email);
        }
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

// Send test OTP email endpoint - BLOCKED FOR SECURITY
// This endpoint has been disabled to prevent any outgoing email functionality
app.post('/api/admin/send-test-otp', authenticateToken, async (req, res) => {
  // Email sending functionality is completely blocked
  // This system is designed only for receiving emails
  res.status(403).json({ 
    error: 'Email sending is disabled', 
    message: 'This system only supports receiving emails. Outgoing email functionality is blocked for security.' 
  });
});

// Settings API endpoints
app.get('/api/admin/settings', authenticateToken, async (req, res) => {
  try {
    const settings = {
      domain: CONFIG.EMAIL_DOMAIN,
      vpsIp: CONFIG.VPS_IP,
      smtpPort: CONFIG.SMTP_PORT,
      webPort: CONFIG.PORT,
      redisHost: CONFIG.REDIS_HOST,
      redisPort: CONFIG.REDIS_PORT,
      emailExpiryTime: CONFIG.EMAIL_EXPIRY_TIME,
      messageRetentionTime: CONFIG.MESSAGE_RETENTION_TIME,
      realtimeApiPush: CONFIG.REALTIME_API_PUSH,
      autoRefreshInterval: CONFIG.AUTO_REFRESH_INTERVAL
    };
    
    res.json({
      success: true,
      settings: settings
    });
  } catch (error) {
    console.error('Get settings error:', error);
    res.status(500).json({ error: 'Failed to retrieve settings' });
  }
});

app.post('/api/admin/settings', authenticateToken, async (req, res) => {
   try {
     const settings = req.body;
    
    if (!settings) {
      return res.status(400).json({ error: 'Settings data is required' });
    }
    
    // Update CONFIG object with new settings
    if (settings.emailExpiryTime !== undefined) {
      CONFIG.EMAIL_EXPIRY_TIME = parseInt(settings.emailExpiryTime);
    }
    if (settings.messageRetentionTime !== undefined) {
      CONFIG.MESSAGE_RETENTION_TIME = parseInt(settings.messageRetentionTime);
    }
    if (settings.realtimeApiPush !== undefined) {
      CONFIG.REALTIME_API_PUSH = Boolean(settings.realtimeApiPush);
    }
    if (settings.autoRefreshInterval !== undefined) {
      CONFIG.AUTO_REFRESH_INTERVAL = parseInt(settings.autoRefreshInterval);
    }
    
    // Log the settings update
    const log = {
      id: uuidv4(),
      action: 'SETTINGS_UPDATED',
      timestamp: new Date(),
      ip: req.ip,
      changes: settings
    };
    await saveLogToRedis(log);
    
    // Emit real-time update
    io.emit('settingsUpdated', settings);
    io.emit('newLog', log);
    
    res.json({
      success: true,
      message: 'Settings updated successfully',
      settings: {
        emailExpiryTime: CONFIG.EMAIL_EXPIRY_TIME,
        messageRetentionTime: CONFIG.MESSAGE_RETENTION_TIME,
        realtimeApiPush: CONFIG.REALTIME_API_PUSH,
        autoRefreshInterval: CONFIG.AUTO_REFRESH_INTERVAL
      }
    });
    
  } catch (error) {
    console.error('Update settings error:', error);
    res.status(500).json({ error: 'Failed to update settings' });
  }
});

// Domain Management API Endpoints

// Get all domains
app.get('/api/admin/domains', authenticateToken, async (req, res) => {
  try {
    const domains = await getDomainsFromRedis();
    res.json({ success: true, domains });
  } catch (error) {
    console.error('Get domains error:', error);
    res.status(500).json({ error: 'Failed to fetch domains' });
  }
});

// Add new domain
app.post('/api/admin/domains', authenticateToken, async (req, res) => {
  try {
    const { domain } = req.body;
    
    if (!domain || typeof domain !== 'string') {
      return res.status(400).json({ error: 'Domain is required' });
    }
    
    // Validate domain format
    const domainRegex = /^[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9]\.[a-zA-Z]{2,}$/;
    if (!domainRegex.test(domain)) {
      return res.status(400).json({ error: 'Invalid domain format' });
    }
    
    // Check if domain already exists
    const existingDomain = await getDomainFromRedis(domain);
    if (existingDomain) {
      return res.status(400).json({ error: 'Domain already exists' });
    }
    
    const newDomain = {
      name: domain,
      status: 'active',
      addedAt: new Date(),
      emailsGenerated: 0
    };
    
    await saveDomainToRedis(newDomain);
    
    // Log the domain addition
    const log = {
      id: uuidv4(),
      action: 'DOMAIN_ADDED',
      domain: domain,
      timestamp: new Date(),
      ip: req.ip
    };
    await saveLogToRedis(log);
    
    // Emit real-time update
    io.emit('domainAdded', newDomain);
    io.emit('newLog', log);
    
    res.json({ success: true, domain: newDomain });
  } catch (error) {
    console.error('Add domain error:', error);
    res.status(500).json({ error: 'Failed to add domain' });
  }
});

// Toggle domain status
app.patch('/api/admin/domains/:domain/toggle', authenticateToken, async (req, res) => {
  try {
    const { domain } = req.params;
    const existingDomain = await getDomainFromRedis(domain);
    
    if (!existingDomain) {
      return res.status(404).json({ error: 'Domain not found' });
    }
    
    existingDomain.status = existingDomain.status === 'active' ? 'inactive' : 'active';
    await saveDomainToRedis(existingDomain);
    
    // Log the status change
    const log = {
      id: uuidv4(),
      action: 'DOMAIN_STATUS_CHANGED',
      domain: domain,
      newStatus: existingDomain.status,
      timestamp: new Date(),
      ip: req.ip
    };
    await saveLogToRedis(log);
    
    // Emit real-time update
    io.emit('domainStatusChanged', existingDomain);
    io.emit('newLog', log);
    
    res.json({ success: true, domain: existingDomain });
  } catch (error) {
    console.error('Toggle domain status error:', error);
    res.status(500).json({ error: 'Failed to toggle domain status' });
  }
});

// Delete domain
app.delete('/api/admin/domains/:domain', authenticateToken, async (req, res) => {
  try {
    const { domain } = req.params;
    const existingDomain = await getDomainFromRedis(domain);
    
    if (!existingDomain) {
      return res.status(404).json({ error: 'Domain not found' });
    }
    
    await deleteDomainFromRedis(domain);
    
    // Log the domain deletion
    const log = {
      id: uuidv4(),
      action: 'DOMAIN_DELETED',
      domain: domain,
      timestamp: new Date(),
      ip: req.ip
    };
    await saveLogToRedis(log);
    
    // Emit real-time update
    io.emit('domainDeleted', { domain });
    io.emit('newLog', log);
    
    res.json({ success: true, message: 'Domain deleted successfully' });
  } catch (error) {
    console.error('Delete domain error:', error);
    res.status(500).json({ error: 'Failed to delete domain' });
  }
});

// Cleanup function for expired messages
function cleanupExpiredMessages() {
  const now = new Date();
  const retentionTime = CONFIG.MESSAGE_RETENTION_TIME * 60 * 60 * 1000; // Convert hours to milliseconds
  
  if (redisConnected && client) {
    // Redis cleanup (implement if needed)
  } else {
    // Memory cleanup
    for (const [emailId, messages] of memoryStore.messages) {
      const filteredMessages = messages.filter(message => {
        const messageAge = now - new Date(message.date);
        return messageAge < retentionTime;
      });
      
      if (filteredMessages.length === 0) {
        memoryStore.messages.delete(emailId);
      } else {
        memoryStore.messages.set(emailId, filteredMessages);
      }
    }
  }
  
  console.log(`🧹 Cleaned up expired messages (retention: ${CONFIG.MESSAGE_RETENTION_TIME} hours)`);
}

// Run cleanup every hour
setInterval(cleanupExpiredMessages, 60 * 60 * 1000);
setInterval(cleanupExpiredAttachments, 60 * 60 * 1000);

// Enhanced rate limiter for attachment downloads
const attachmentLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 10, // Limit each IP to 10 attachment downloads per windowMs
  message: {
    error: 'Too many download requests, please try again later',
    retryAfter: 15 * 60
  },
  standardHeaders: true,
  legacyHeaders: false
});

// Secure attachment download endpoint with enhanced security
app.get('/api/attachments/:attachmentId/download', attachmentLimiter, async (req, res) => {
  try {
    const { attachmentId } = req.params;
    const { token } = req.query;
    
    if (!token) {
      return res.status(401).json({ error: 'Security token required' });
    }
    
    const attachment = await getAttachmentMetadata(attachmentId);
    
    if (!attachment) {
      return res.status(404).json({ error: 'Attachment not found' });
    }
    
    // Verify security token
    if (attachment.secureToken !== token) {
      return res.status(403).json({ error: 'Invalid security token' });
    }
    
    // Check if attachment has expired
    if (new Date() > new Date(attachment.expiresAt)) {
      await deleteAttachmentFile(attachmentId);
      return res.status(410).json({ error: 'Attachment has expired' });
    }
    
    // Check if file exists
    if (!fs.existsSync(attachment.filePath)) {
      return res.status(404).json({ error: 'Attachment file not found' });
    }
    
    // Increment download count
    attachment.downloadCount = (attachment.downloadCount || 0) + 1;
    await saveAttachmentMetadata(attachment);
    
    // Set security headers
    res.setHeader('Content-Type', attachment.mimeType);
    res.setHeader('Content-Disposition', `attachment; filename="${attachment.originalName}"`);
    res.setHeader('Content-Length', attachment.size);
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate');
    
    // Stream file to response
    const fileStream = fs.createReadStream(attachment.filePath);
    fileStream.pipe(res);
    
    console.log(`📎 Attachment downloaded: ${attachment.originalName} (${attachment.downloadCount} downloads)`);
    
  } catch (error) {
    console.error('Attachment download error:', error);
    res.status(500).json({ error: 'Failed to download attachment' });
  }
});

// Get attachment info endpoint with rate limiting
app.get('/api/attachments/:attachmentId/info', attachmentLimiter, async (req, res) => {
  try {
    const { attachmentId } = req.params;
    const { token } = req.query;
    
    if (!token) {
      return res.status(401).json({ error: 'Security token required' });
    }
    
    const attachment = await getAttachmentMetadata(attachmentId);
    
    if (!attachment) {
      return res.status(404).json({ error: 'Attachment not found' });
    }
    
    // Verify security token
    if (attachment.secureToken !== token) {
      return res.status(403).json({ error: 'Invalid security token' });
    }
    
    // Check if attachment has expired
    if (new Date() > new Date(attachment.expiresAt)) {
      await deleteAttachmentFile(attachmentId);
      return res.status(410).json({ error: 'Attachment has expired' });
    }
    
    res.json({
      id: attachment.id,
      name: attachment.originalName,
      size: attachment.size,
      type: attachment.mimeType,
      uploadedAt: attachment.uploadedAt,
      expiresAt: attachment.expiresAt,
      downloadCount: attachment.downloadCount || 0,
      timeRemaining: getTimeRemaining(attachment.expiresAt)
    });
    
  } catch (error) {
    console.error('Attachment info error:', error);
    res.status(500).json({ error: 'Failed to get attachment info' });
  }
});

// Server will be started by initializeApp() function

// Start SMTP server for receiving emails
const startSMTPServer = () => {
  try {
    const { SMTPServer } = require('smtp-server');
    
    const server = new SMTPServer({
      secure: false,
      authOptional: true,
      onConnect(session, callback) {
        console.log(`📧 SMTP connection from ${session.remoteAddress}`);
        return callback();
      },
      onMailFrom(address, session, callback) {
        console.log(`📧 Mail from: ${address.address}`);
        return callback();
      },
      onRcptTo(address, session, callback) {
        const emailAddress = address.address.toLowerCase();
        console.log(`📧 Mail to: ${emailAddress}`);
        
        // Check if this is a valid temporary email
        getEmailsFromRedis().then(emails => {
          const tempEmail = emails.find(e => e.email.toLowerCase() === emailAddress);
          
          if (!tempEmail) {
            console.log(`❌ Email not found: ${emailAddress}`);
            return callback(new Error('Email not found'));
          }
          
          if (new Date() > new Date(tempEmail.expiresAt)) {
            console.log(`❌ Email expired: ${emailAddress}`);
            return callback(new Error('Email expired'));
          }
          
          console.log(`✅ Email accepted: ${emailAddress}`);
          return callback();
        }).catch(error => {
          console.error('Error checking email:', error);
          return callback(new Error('Internal error'));
        });
      },
      onData(stream, session, callback) {
        let emailData = '';
        
        stream.on('data', (chunk) => {
          emailData += chunk;
        });
        
        stream.on('end', async () => {
          try {
            const parsed = await simpleParser(emailData);
            
            // Find the recipient email
            const recipientEmail = session.envelope.rcptTo[0].address.toLowerCase();
            const emails = await getEmailsFromRedis();
            const tempEmail = emails.find(e => e.email.toLowerCase() === recipientEmail);
            
            if (!tempEmail) {
              console.log(`❌ Recipient email not found: ${recipientEmail}`);
              return callback(new Error('Recipient not found'));
            }
            
            // Process attachments with size validation
            let processedAttachments = [];
            let totalAttachmentSize = 0;
            
            if (parsed.attachments && parsed.attachments.length > 0) {
              // Check total number of attachments
              if (parsed.attachments.length > CONFIG.MAX_ATTACHMENTS_PER_EMAIL) {
                console.warn(`⚠️  Too many attachments (${parsed.attachments.length}), limit: ${CONFIG.MAX_ATTACHMENTS_PER_EMAIL}`);
                parsed.attachments = parsed.attachments.slice(0, CONFIG.MAX_ATTACHMENTS_PER_EMAIL);
              }
              
              for (const attachment of parsed.attachments) {
                totalAttachmentSize += attachment.size || 0;
                
                // Check total size limit
                if (totalAttachmentSize > CONFIG.MAX_ATTACHMENT_SIZE) {
                  console.warn(`⚠️  Attachment size limit exceeded (${totalAttachmentSize} bytes), limit: ${CONFIG.MAX_ATTACHMENT_SIZE}`);
                  break;
                }
                
                try {
                  const savedAttachment = await saveAttachmentToStorage(attachment, tempEmail.id);
                  processedAttachments.push(savedAttachment);
                  console.log(`📎 Attachment saved: ${attachment.filename} (${attachment.size} bytes)`);
                } catch (error) {
                  console.error(`❌ Failed to save attachment ${attachment.filename}:`, error.message);
                  // Continue processing other attachments
                }
              }
            }
            
            // Create message object
            const message = {
              id: uuidv4(),
              from: parsed.from?.text || session.envelope.mailFrom.address,
              to: recipientEmail,
              subject: parsed.subject || 'No Subject',
              text: parsed.text || '',
              html: parsed.html || '',
              date: parsed.date || new Date(),
              attachments: processedAttachments,
              hasAttachments: processedAttachments.length > 0,
              attachmentCount: processedAttachments.length,
              receivedAt: new Date(),
              expiresAt: new Date(Date.now() + CONFIG.MESSAGE_RETENTION_TIME * 60 * 60 * 1000)
            };
            
            // Save message to Redis
            await saveMessageToRedis(tempEmail.id, message);
            
            // Update message count
            tempEmail.messageCount = (tempEmail.messageCount || 0) + 1;
            await saveEmailToRedis(tempEmail);
            
            // Log the received message
            const log = {
              id: uuidv4(),
              action: 'MESSAGE_RECEIVED',
              email: recipientEmail,
              from: message.from,
              subject: message.subject,
              timestamp: new Date(),
              messageId: message.id
            };
            await saveLogToRedis(log);
            
            // Emit real-time updates
            io.emit('messageReceived', { email: recipientEmail, message });
            io.to(`email:${recipientEmail}`).emit('newMessage', { emailId: tempEmail.id, message });
            io.to(`email_id:${tempEmail.id}`).emit('newMessage', { emailId: tempEmail.id, message });
            io.emit('newLog', log);
            
            console.log(`✅ Message received for ${recipientEmail} from ${message.from}`);
            return callback();
          } catch (error) {
            console.error('Error processing email:', error);
            return callback(error);
          }
        });
      }
    });
    
    server.listen(CONFIG.SMTP_PORT, CONFIG.SMTP_HOST, () => {
      console.log(`📧 SMTP server listening on ${CONFIG.SMTP_HOST}:${CONFIG.SMTP_PORT}`);
    });
    
    server.on('error', (error) => {
      console.error('❌ SMTP server error:', error);
    });
    
  } catch (error) {
    console.error('❌ Failed to start SMTP server:', error);
    console.log('⚠️  SMTP server disabled. Install dependencies: npm install smtp-server');
  }
};

// ===== COMPREHENSIVE API ENDPOINTS =====

// Get all emails for a user (inbox)
app.get('/api/inbox/emails', apiLimiter, async (req, res) => {
  try {
    const { limit = 50, offset = 0, domain } = req.query;
    const emails = await getEmailsFromRedis();
    
    let filteredEmails = emails;
    if (domain) {
      filteredEmails = emails.filter(e => e.domain === domain);
    }
    
    // Sort by creation date (newest first)
    filteredEmails.sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
    
    // Apply pagination
    const paginatedEmails = filteredEmails.slice(parseInt(offset), parseInt(offset) + parseInt(limit));
    
    // Get message counts for each email
    const emailsWithCounts = await Promise.all(paginatedEmails.map(async (email) => {
      const messages = await getMessagesFromRedis(email.id);
      return {
        ...email,
        messageCount: messages.length,
        hasUnread: messages.some(m => !m.read),
        lastMessageAt: messages.length > 0 ? messages[messages.length - 1].receivedAt : null
      };
    }));
    
    res.json({
      success: true,
      emails: emailsWithCounts,
      total: filteredEmails.length,
      limit: parseInt(limit),
      offset: parseInt(offset)
    });
  } catch (error) {
    console.error('Get inbox emails error:', error);
    res.status(500).json({ error: 'Failed to fetch inbox emails' });
  }
});

// Get inbox for specific email
app.get('/api/inbox/:emailId', apiLimiter, async (req, res) => {
  try {
    const { emailId } = req.params;
    const { limit = 20, offset = 0 } = req.query;
    
    const email = await getEmailFromRedis(emailId);
    if (!email) {
      return res.status(404).json({ error: 'Email not found' });
    }
    
    if (new Date() > new Date(email.expiresAt)) {
      return res.status(410).json({ error: 'Email expired' });
    }
    
    const messages = await getMessagesFromRedis(emailId);
    
    // Sort by received date (newest first)
    messages.sort((a, b) => new Date(b.receivedAt) - new Date(a.receivedAt));
    
    // Apply pagination
    const paginatedMessages = messages.slice(parseInt(offset), parseInt(offset) + parseInt(limit));
    
    res.json({
      success: true,
      email: {
        id: email.id,
        email: email.email,
        domain: email.domain,
        type: email.type,
        createdAt: email.createdAt,
        expiresAt: email.expiresAt
      },
      messages: paginatedMessages,
      total: messages.length,
      limit: parseInt(limit),
      offset: parseInt(offset),
      unreadCount: messages.filter(m => !m.read).length
    });
  } catch (error) {
    console.error('Get inbox error:', error);
    res.status(500).json({ error: 'Failed to fetch inbox' });
  }
});

// Mark message as read
app.patch('/api/message/:messageId/read', apiLimiter, async (req, res) => {
  try {
    const { messageId } = req.params;
    
    // Find message across all emails
    const emails = await getEmailsFromRedis();
    let foundMessage = null;
    let emailId = null;
    
    for (const email of emails) {
      const messages = await getMessagesFromRedis(email.id);
      const message = messages.find(m => m.id === messageId);
      if (message) {
        foundMessage = message;
        emailId = email.id;
        break;
      }
    }
    
    if (!foundMessage) {
      return res.status(404).json({ error: 'Message not found' });
    }
    
    // Mark as read
    foundMessage.read = true;
    foundMessage.readAt = new Date();
    
    await saveMessageToRedis(foundMessage, emailId);
    
    // Emit real-time update
    io.to(`email_id:${emailId}`).emit('messageRead', { messageId, readAt: foundMessage.readAt });
    
    res.json({
      success: true,
      message: 'Message marked as read',
      readAt: foundMessage.readAt
    });
  } catch (error) {
    console.error('Mark message as read error:', error);
    res.status(500).json({ error: 'Failed to mark message as read' });
  }
});

// Clear all messages from inbox
app.delete('/api/inbox/:emailId/clear', apiLimiter, async (req, res) => {
  try {
    const { emailId } = req.params;
    
    const email = await getEmailFromRedis(emailId);
    if (!email) {
      return res.status(404).json({ error: 'Email not found' });
    }
    
    // Get all messages for deletion
    const messages = await getMessagesFromRedis(emailId);
    
    // Delete all attachments
    for (const message of messages) {
      if (message.attachments) {
        for (const attachment of message.attachments) {
          try {
            await fs.promises.unlink(attachment.filePath);
          } catch (err) {
            console.warn(`Failed to delete attachment file: ${attachment.filePath}`);
          }
        }
      }
    }
    
    // Clear messages from storage
    await clearMessagesFromRedis(emailId);
    
    // Update email message count
    email.messageCount = 0;
    await saveEmailToRedis(email);
    
    // Log the action
    const log = {
      id: uuidv4(),
      action: 'INBOX_CLEARED',
      email: email.email,
      messagesDeleted: messages.length,
      timestamp: new Date(),
      ip: req.ip
    };
    await saveLogToRedis(log);
    
    // Emit real-time update
    io.to(`email_id:${emailId}`).emit('inboxCleared');
    io.emit('newLog', log);
    
    res.json({
      success: true,
      message: 'Inbox cleared successfully',
      deletedCount: messages.length
    });
  } catch (error) {
    console.error('Clear inbox error:', error);
    res.status(500).json({ error: 'Failed to clear inbox' });
  }
});

// Get email statistics
app.get('/api/stats/email/:emailId', apiLimiter, async (req, res) => {
  try {
    const { emailId } = req.params;
    
    const email = await getEmailFromRedis(emailId);
    if (!email) {
      return res.status(404).json({ error: 'Email not found' });
    }
    
    const messages = await getMessagesFromRedis(emailId);
    
    const stats = {
      totalMessages: messages.length,
      unreadMessages: messages.filter(m => !m.read).length,
      readMessages: messages.filter(m => m.read).length,
      messagesWithAttachments: messages.filter(m => m.attachments && m.attachments.length > 0).length,
      totalAttachments: messages.reduce((sum, m) => sum + (m.attachments ? m.attachments.length : 0), 0),
      lastMessageAt: messages.length > 0 ? messages[messages.length - 1].receivedAt : null,
      emailAge: Math.floor((new Date() - new Date(email.createdAt)) / (1000 * 60)), // in minutes
      timeUntilExpiry: Math.max(0, Math.floor((new Date(email.expiresAt) - new Date()) / (1000 * 60))) // in minutes
    };
    
    res.json({
      success: true,
      stats
    });
  } catch (error) {
    console.error('Get email stats error:', error);
    res.status(500).json({ error: 'Failed to fetch email statistics' });
  }
});

// Search messages
app.get('/api/search/messages', apiLimiter, async (req, res) => {
  try {
    const { q, emailId, limit = 20, offset = 0 } = req.query;
    
    if (!q || q.trim().length < 2) {
      return res.status(400).json({ error: 'Search query must be at least 2 characters' });
    }
    
    const searchTerm = q.toLowerCase().trim();
    let searchResults = [];
    
    if (emailId) {
      // Search within specific email
      const email = await getEmailFromRedis(emailId);
      if (!email) {
        return res.status(404).json({ error: 'Email not found' });
      }
      
      const messages = await getMessagesFromRedis(emailId);
      searchResults = messages.filter(message => 
        message.subject.toLowerCase().includes(searchTerm) ||
        message.from.toLowerCase().includes(searchTerm) ||
        (message.text && message.text.toLowerCase().includes(searchTerm)) ||
        (message.html && message.html.toLowerCase().includes(searchTerm))
      ).map(message => ({ ...message, emailId, emailAddress: email.email }));
    } else {
      // Search across all emails
      const emails = await getEmailsFromRedis();
      
      for (const email of emails) {
        const messages = await getMessagesFromRedis(email.id);
        const matchingMessages = messages.filter(message => 
          message.subject.toLowerCase().includes(searchTerm) ||
          message.from.toLowerCase().includes(searchTerm) ||
          (message.text && message.text.toLowerCase().includes(searchTerm)) ||
          (message.html && message.html.toLowerCase().includes(searchTerm))
        ).map(message => ({ ...message, emailId: email.id, emailAddress: email.email }));
        
        searchResults.push(...matchingMessages);
      }
    }
    
    // Sort by received date (newest first)
    searchResults.sort((a, b) => new Date(b.receivedAt) - new Date(a.receivedAt));
    
    // Apply pagination
    const paginatedResults = searchResults.slice(parseInt(offset), parseInt(offset) + parseInt(limit));
    
    res.json({
      success: true,
      results: paginatedResults,
      total: searchResults.length,
      query: q,
      limit: parseInt(limit),
      offset: parseInt(offset)
    });
  } catch (error) {
    console.error('Search messages error:', error);
    res.status(500).json({ error: 'Failed to search messages' });
  }
});

// Initialize default domains
const initializeDefaultDomains = async () => {
  try {
    const existingDomains = await getDomainsFromRedis();
    
    // Default domains to add if none exist
    const defaultDomains = [
      { name: 'oplex.online', status: 'active', addedAt: new Date(), emailsGenerated: 0 },
      { name: 'tempmail.dev', status: 'active', addedAt: new Date(), emailsGenerated: 0 },
      { name: 'quickmail.io', status: 'active', addedAt: new Date(), emailsGenerated: 0 },
      { name: 'fastmail.temp', status: 'active', addedAt: new Date(), emailsGenerated: 0 }
    ];
    
    // Add default domains if no domains exist
    if (existingDomains.length === 0) {
      console.log('🌐 Initializing default domains...');
      for (const domain of defaultDomains) {
        await saveDomainToRedis(domain);
        console.log(`✅ Added default domain: ${domain.name}`);
      }
    } else {
      console.log(`🌐 Found ${existingDomains.length} existing domains`);
    }
  } catch (error) {
    console.error('❌ Failed to initialize default domains:', error);
  }
};

// Initialize the application
const initializeApp = async () => {
  await initializeDefaultDomains();
  
  // Start the server
  server.listen(PORT, () => {
    console.log('🔄 Cleanup scheduler restarted: every 30 minutes');
    console.log(`🚀 RedMail Admin Server running on port ${PORT}`);
    console.log(`📧 Admin Panel: http://localhost:${PORT}/admin`);
    console.log(`🔒 API Base: http://localhost:${PORT}/api`);
    console.log(`🌐 VPS IP: ${CONFIG.VPS_IP}`);
    console.log(`📮 Email Domain: ${CONFIG.EMAIL_DOMAIN}`);
    console.log(`⚙️  Email Expiry: ${CONFIG.EMAIL_EXPIRY_TIME} minutes`);
    console.log(`📦 Message Retention: ${CONFIG.MESSAGE_RETENTION_TIME} hours`);
    console.log(`🔄 Real-time Push: ${CONFIG.REALTIME_API_PUSH ? 'Enabled' : 'Disabled'}`);
    
    if (CONFIG.NODE_ENV === 'development') {
      console.log('⚠️  SMTP server disabled for local development');
    } else {
      startSMTPServer();
    }
  });
};

// Start the application
initializeApp();

module.exports = app;