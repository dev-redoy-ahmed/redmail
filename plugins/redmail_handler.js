// RedMail Haraka Plugin
const { simpleParser } = require('mailparser');
const { v4: uuidv4 } = require('uuid');
const Redis = require('redis');
const constants = require('haraka-constants');

let redisClient;
let io;

// Initialize Redis connection
const initRedis = async () => {
  if (!redisClient) {
    redisClient = Redis.createClient({
      socket: {
        host: '127.0.0.1',
        port: 6379
      },
      retry_strategy: (options) => {
        if (options.error && options.error.code === 'ECONNREFUSED') {
          return new Error('Redis server is not running');
        }
        if (options.total_retry_time > 1000 * 60 * 60) {
          return new Error('Retry time exhausted');
        }
        if (options.attempt > 10) {
          return undefined;
        }
        return Math.min(options.attempt * 100, 3000);
      }
    });
    
    await redisClient.connect();
  }
  return redisClient;
};

// Redis keys
const REDIS_KEYS = {
  EMAILS: 'redmail:emails',
  MESSAGES: 'redmail:messages:',
  LOGS: 'redmail:logs'
};

// Helper functions
const getEmailsFromRedis = async () => {
  try {
    const client = await initRedis();
    const emailsData = await client.get(REDIS_KEYS.EMAILS);
    return emailsData ? JSON.parse(emailsData) : [];
  } catch (error) {
    console.error('Redis get emails error:', error);
    return [];
  }
};

const saveEmailToRedis = async (email) => {
  try {
    const client = await initRedis();
    const emails = await getEmailsFromRedis();
    const index = emails.findIndex(e => e.id === email.id);
    
    if (index !== -1) {
      emails[index] = email;
    } else {
      emails.push(email);
    }
    
    await client.set(REDIS_KEYS.EMAILS, JSON.stringify(emails));
  } catch (error) {
    console.error('Redis save email error:', error);
  }
};

const saveMessageToRedis = async (emailId, message) => {
  try {
    const client = await initRedis();
    const key = REDIS_KEYS.MESSAGES + emailId;
    const messages = await client.get(key);
    const messageList = messages ? JSON.parse(messages) : [];
    
    messageList.push(message);
    await client.set(key, JSON.stringify(messageList));
  } catch (error) {
    console.error('Redis save message error:', error);
  }
};

const saveLogToRedis = async (log) => {
  try {
    const client = await initRedis();
    const logs = await client.get(REDIS_KEYS.LOGS);
    const logList = logs ? JSON.parse(logs) : [];
    
    logList.unshift(log);
    
    // Keep only last 1000 logs
    if (logList.length > 1000) {
      logList.splice(1000);
    }
    
    await client.set(REDIS_KEYS.LOGS, JSON.stringify(logList));
  } catch (error) {
    console.error('Redis save log error:', error);
  }
};

// Set Socket.IO instance
const setSocketIO = (socketIO) => {
  io = socketIO;
};

// Haraka plugin exports
exports.register = function () {
  this.loginfo('RedMail Handler Plugin loaded');
};

exports.hook_rcpt = async function (next, connection, params) {
  const recipient = params[0].address();
  const domain = recipient.split('@')[1];
  
  // Check if domain matches our email domain
  const EMAIL_DOMAIN = process.env.EMAIL_DOMAIN || 'redmail.dev';
  
  if (domain === EMAIL_DOMAIN) {
    // Check if email exists in Redis
    const emails = await getEmailsFromRedis();
    const targetEmail = emails.find(e => e.email === recipient);
    
    if (targetEmail && new Date() < new Date(targetEmail.expiresAt)) {
      return next(constants.ok);
    } else {
      return next(constants.deny, 'Recipient not found or expired');
    }
  } else {
    return next(constants.deny, 'Invalid recipient domain');
  }
};

exports.hook_data_post = async function (next, connection) {
  try {
    const emailData = connection.transaction.message_stream.get_data();
    const parsed = await simpleParser(emailData);
    const recipients = connection.transaction.rcpt_to;
    
    for (const rcpt of recipients) {
      const recipient = rcpt.address();
      const emailId = recipient.split('@')[0];
      
      // Get target email from Redis
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
          ip: connection.remote.ip
        };
        await saveLogToRedis(log);
        
        // Emit real-time update if Socket.IO is available
        if (io) {
          io.emit('messageReceived', { email: recipient, message });
          io.emit('newLog', log);
        }
        
        this.loginfo(`Message received for ${recipient}`);
      }
    }
    
    return next(constants.ok);
  } catch (error) {
    this.logerror('Error processing email:', error);
    return next(constants.denysoft, 'Temporary processing error');
  }
};

// Export helper functions for external use
module.exports = {
  setSocketIO,
  initRedis,
  getEmailsFromRedis,
  saveEmailToRedis,
  saveMessageToRedis,
  saveLogToRedis
};