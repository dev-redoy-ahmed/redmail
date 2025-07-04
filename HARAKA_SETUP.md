# RedMail Haraka Integration

This document explains the Haraka SMTP server integration for RedMail, which provides better performance and scalability compared to the previous smtp-server implementation.

## What is Haraka?

Haraka is a high-performance, plugin-oriented SMTP server written in Node.js. It's designed to handle large volumes of email efficiently and is highly configurable.

## Benefits of Using Haraka

- **Better Performance**: Haraka is optimized for high-throughput email processing
- **Plugin Architecture**: Modular design allows for easy customization
- **Production Ready**: Battle-tested in production environments
- **Better Resource Management**: More efficient memory and CPU usage
- **Advanced Features**: Built-in support for various SMTP extensions

## Installation

1. Install Haraka dependency:
```bash
npm install haraka
```

2. The RedMail project includes pre-configured Haraka setup:
   - `config/` - Haraka configuration directory
   - `plugins/redmail_handler.js` - Custom plugin for RedMail integration
   - `start-haraka.js` - Startup script for Haraka

## Configuration Files

### `config/smtp.ini`
Main SMTP server configuration:
```ini
[main]
port=25
host=0.0.0.0
listen=*:25

[logging]
level=INFO

[plugins]
queue/discard
rcpt_to.in_host_list
redmail_handler
log.syslog
```

### `config/plugins`
Defines which plugins to load:
```
queue/discard
rcpt_to.in_host_list
redmail_handler
log.syslog
```

### `config/host_list`
Accepted domains (automatically updated with your EMAIL_DOMAIN):
```
redmail.dev
```

## Custom Plugin: redmail_handler.js

The `plugins/redmail_handler.js` file contains the custom Haraka plugin that:
- Validates recipients against Redis database
- Processes incoming emails
- Stores messages in Redis
- Emits real-time updates via Socket.IO
- Logs email activities

## Usage

### Automatic Startup
When you start the RedMail server with `npm start`, Haraka will automatically start as a child process.

### Manual Startup
You can also start Haraka manually:
```bash
node start-haraka.js
```

### Environment Variables
- `EMAIL_DOMAIN`: Your email domain (default: redmail.dev)
- `SMTP_PORT`: SMTP server port (default: 25)
- `SMTP_HOST`: SMTP server host (default: 0.0.0.0)

## Monitoring

Haraka logs are integrated with the main RedMail application. You'll see Haraka-specific logs prefixed with `📬 Haraka:`.

## Troubleshooting

### Port 25 Permission Issues
On Linux/Unix systems, port 25 requires root privileges. You can:
1. Run as root (not recommended for production)
2. Use a different port and configure port forwarding
3. Use authbind or similar tools

### Redis Connection Issues
Ensure Redis is running and accessible at `127.0.0.1:6379`.

### Plugin Loading Issues
Check that all required dependencies are installed:
```bash
npm install haraka mailparser uuid redis haraka-constants
```

## Performance Tuning

For high-volume email processing, you can adjust:
- `delivery_concurrency` in smtp.ini
- Redis connection pool settings
- System-level TCP settings

## Migration from smtp-server

The migration from smtp-server to Haraka is seamless:
- All existing functionality is preserved
- Redis integration remains the same
- Socket.IO real-time updates continue to work
- Admin panel functionality is unaffected

## Security Considerations

- Haraka runs as a separate process for better isolation
- Input validation is handled by the custom plugin
- Rate limiting can be added via Haraka plugins
- TLS/SSL support can be configured in smtp.ini

## Support

For Haraka-specific issues, refer to:
- [Haraka Documentation](https://haraka.github.io/)
- [Haraka GitHub Repository](https://github.com/haraka/Haraka)

For RedMail integration issues, check the logs and ensure all dependencies are properly installed.