@echo off
REM 🚀 RedMail VPS Upload Script for Windows
REM This script uploads files to VPS using SCP

setlocal enabledelayedexpansion

REM Configuration
set VPS_IP=206.189.94.221
set VPS_USER=root
set LOCAL_PATH=%~dp0
set REMOTE_PATH=/var/www/redmail

echo.
echo ========================================
echo 🚀 RedMail VPS Upload Script
echo ========================================
echo VPS IP: %VPS_IP%
echo Local Path: %LOCAL_PATH%
echo Remote Path: %REMOTE_PATH%
echo.

REM Check if SCP is available
scp >nul 2>&1
if %errorlevel% neq 0 (
    echo ❌ SCP not found. Please install OpenSSH or use WSL.
    echo.
    echo Options:
    echo 1. Install OpenSSH: Settings ^> Apps ^> Optional Features ^> OpenSSH Client
    echo 2. Use WSL: wsl --install
    echo 3. Use PuTTY PSCP: https://www.putty.org/
    pause
    exit /b 1
)

echo ✅ SCP found, proceeding with upload...
echo.

REM Create remote directory
echo 📁 Creating remote directory...
ssh %VPS_USER%@%VPS_IP% "mkdir -p %REMOTE_PATH%"
if %errorlevel% neq 0 (
    echo ❌ Failed to create remote directory
    pause
    exit /b 1
)
echo ✅ Remote directory created

REM Upload files
echo 📤 Uploading files to VPS...
echo This may take a few minutes...
echo.

REM Upload main files
scp "%LOCAL_PATH%server.js" %VPS_USER%@%VPS_IP%:%REMOTE_PATH%/
scp "%LOCAL_PATH%package.json" %VPS_USER%@%VPS_IP%:%REMOTE_PATH%/
scp "%LOCAL_PATH%package-lock.json" %VPS_USER%@%VPS_IP%:%REMOTE_PATH%/
scp "%LOCAL_PATH%README.md" %VPS_USER%@%VPS_IP%:%REMOTE_PATH%/
scp "%LOCAL_PATH%deploy.sh" %VPS_USER%@%VPS_IP%:%REMOTE_PATH%/
scp "%LOCAL_PATH%ssl-setup.sh" %VPS_USER%@%VPS_IP%:%REMOTE_PATH%/
scp "%LOCAL_PATH%VPS_DEPLOYMENT_GUIDE.md" %VPS_USER%@%VPS_IP%:%REMOTE_PATH%/
scp "%LOCAL_PATH%HTTPS_SETUP_GUIDE.md" %VPS_USER%@%VPS_IP%:%REMOTE_PATH%/

REM Upload public directory
echo 📁 Uploading public directory...
scp -r "%LOCAL_PATH%public" %VPS_USER%@%VPS_IP%:%REMOTE_PATH%/

if %errorlevel% neq 0 (
    echo ❌ Upload failed
    pause
    exit /b 1
)

echo ✅ Files uploaded successfully!
echo.

REM Make scripts executable
echo 🔧 Making scripts executable...
ssh %VPS_USER%@%VPS_IP% "chmod +x %REMOTE_PATH%/deploy.sh"
ssh %VPS_USER%@%VPS_IP% "chmod +x %REMOTE_PATH%/ssl-setup.sh"
echo ✅ Scripts are now executable
echo.

echo ========================================
echo 🎉 Upload completed successfully!
echo ========================================
echo.
echo 📋 Next Steps:
echo 1. Connect to your VPS: ssh %VPS_USER%@%VPS_IP%
echo 2. Navigate to app directory: cd %REMOTE_PATH%
echo 3. Run deployment script: bash deploy.sh
echo 4. Setup HTTPS (recommended): bash ssl-setup.sh
echo.
echo 🌐 After deployment, access your app at:
echo    HTTP: http://%VPS_IP%:3000/admin
echo    HTTPS: https://oplex.online/admin (after SSL setup)
echo.
echo 📖 For detailed instructions:
echo    VPS_DEPLOYMENT_GUIDE.md
echo    HTTPS_SETUP_GUIDE.md
echo.

REM Ask if user wants to connect to VPS
set /p connect="Do you want to connect to VPS now? (y/n): "
if /i "%connect%"=="y" (
    echo.
    echo 🔗 Connecting to VPS...
    echo Run: cd %REMOTE_PATH% && bash deploy.sh
    echo.
    ssh %VPS_USER%@%VPS_IP%
)

echo.
echo ✅ Script completed!
pause