# 📧 RedMail - Temporary Email Service

A modern, real-time temporary email service with admin panel built using Node.js, Express, Socket.IO, and Redis. Perfect for VPS deployment with full SMTP server capabilities.

## ✨ Features

- 🔥 **Real-time Updates**: Live email reception using Socket.IO
- 📧 **Temporary Email Generation**: Create disposable email addresses
- 🎛️ **Admin Panel**: Comprehensive dashboard for management
- 🔒 **Secure Authentication**: JWT-based admin authentication
- 📊 **Analytics**: Email statistics and usage tracking
- 🗃️ **Redis Storage**: Fast and efficient data storage
- 📱 **Responsive Design**: Works on all devices
- 🌐 **Haraka SMTP Server**: High-performance email reception (Port 25)
- 🚀 **VPS Ready**: Production-ready deployment scripts
- 🧪 **OTP Testing**: Built-in OTP email testing system
- 🚀 **Enhanced Performance**: Haraka provides better throughput and resource management
- 🔧 **Plugin Architecture**: Modular SMTP server with custom plugins

## 🚀 Quick Start (Local Development)

### Prerequisites

- Node.js (v14 or higher)
- Redis server
- npm or yarn

### Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd redmail
```

2. Install dependencies:
```bash
npm install
```

3. Start Redis server:
```bash
redis-server
```

4. Start the application:
```bash
node server.js
```

5. Access the admin panel:
```
http://167.99.70.90:3000/admin
```

Default login: `admin` / `password`

## 🌐 VPS Deployment

### Current Configuration
- **VPS IP**: 167.99.70.90
- **Domain**: oplex.online
- **SMTP Port**: 25
- **Web Port**: 3000

### Quick VPS Deployment

1. **Upload files to VPS**:
   ```bash
   # On Windows
   upload-to-vps.bat
   
   # On Linux/Mac
   scp -r ./* root@167.99.70.90:/var/www/redmail/
   ```

2. **Run deployment script**:
   ```bash
   ssh root@167.99.70.90
   cd /var/www/redmail
   bash deploy.sh
   ```

3. **Access your live application**:
   - Admin Panel: http://167.99.70.90:3000/admin
   - After DNS: http://oplex.online:3000/admin

### DNS Configuration Required

Add these DNS records to your domain registrar:

```
# A Record
Type: A
Name: @
Value: 167.99.70.90

# MX Record
Type: MX
Name: @
Value: oplex.online
Priority: 10

# SPF Record
Type: TXT
Name: @
Value: "v=spf1 ip4:167.99.70.90 ~all"
```

## 📋 Configuration

### Built-in Configuration

All configuration is now hardcoded in the `CONFIG` object in `server.js` for easy GitHub deployment:

```javascript
const CONFIG = {
  // Server Configuration
  PORT: 3000,
  NODE_ENV: 'production',
  
  // Email Configuration
  EMAIL_DOMAIN: 'oplex.online',
  VPS_IP: '167.99.70.90',
  
  // Redis Configuration
  REDIS_HOST: '167.99.70.90',
  REDIS_PORT: 6379,
  
  // SMTP Configuration
  SMTP_PORT: 25,
  SMTP_HOST: '0.0.0.0',
  
  // Security
  JWT_SECRET: 'redmail-super-secret-jwt-key-2024-production-secure-random-string-change-this',
  ADMIN_PASSWORD_HASH: '$2a$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi' // Default: 'password'
};
```

**Note**: No `.env` file needed! All configuration is embedded in the code for seamless GitHub → VPS deployment.

## 🔌 API Endpoints

### Public Endpoints

- `GET /api/health` - Health check
- `POST /api/auth/login` - Admin login
- `GET /api/emails/generate` - Generate temporary email
- `GET /api/emails/:id/messages` - Get messages for email

### Admin Endpoints (Requires Authentication)

- `GET /api/admin/emails` - List all emails
- `GET /api/admin/logs` - Get system logs
- `GET /api/admin/stats` - Get statistics
- `DELETE /api/admin/emails/:id` - Delete email
- `GET /api/admin/test-smtp` - Test SMTP connectivity
- `POST /api/admin/send-test-otp` - Send test OTP email

## 🧪 Testing OTP System

1. Generate a temporary email from admin panel
2. Go to Settings → Send Test OTP
3. Select the temporary email
4. Check the OTP delivery in real-time

## 📁 Project Structure

```
redmail/
├── server.js                 # Main server file (with built-in CONFIG)
├── package.json             # Dependencies
├── deploy.sh                # VPS deployment script
├── upload-to-vps.bat        # Windows upload script
├── ssl-setup.sh             # HTTPS setup script
├── VPS_DEPLOYMENT_GUIDE.md  # Detailed deployment guide
├── HTTPS_SETUP_GUIDE.md     # HTTPS setup guide
├── public/
│   ├── admin.html          # Admin panel
│   ├── css/
│   │   ├── admin.css       # Admin panel styles
│   │   └── colors.css      # Color scheme
│   └── js/
│       └── admin.js        # Admin panel JavaScript
└── README.md               # This file
```

## 🛠️ Technologies Used

- **Backend**: Node.js, Express.js
- **Real-time**: Socket.IO
- **Database**: Redis
- **Authentication**: JWT, bcryptjs
- **Email**: haraka, mailparser
- **Frontend**: Vanilla JavaScript, CSS3
- **Deployment**: PM2, Ubuntu/Debian

## 🔒 Security Features

- JWT-based authentication
- bcrypt password hashing
- Rate limiting
- CORS protection
- Input validation
- Secure headers

## 📊 Monitoring

- Real-time email reception
- System logs and analytics
- PM2 process monitoring
- Redis connection status
- SMTP server health checks



## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## 📄 License

MIT License

## 🆘 Support

For deployment issues, check:
1. `VPS_DEPLOYMENT_GUIDE.md` for detailed instructions
2. PM2 logs: `pm2 logs redmail`
3. System logs for SMTP issues
4. DNS propagation status

---

**Ready for production deployment on VPS with full email capabilities!** 🚀