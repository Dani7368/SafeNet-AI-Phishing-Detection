@echo off
title SafeNet AI — Starting...
echo.
echo  ===================================
echo   SafeNet AI Phishing Detection
echo  ===================================
echo.

python --version >nul 2>&1
if errorlevel 1 (
    echo  [ERROR] Python not found. Please install Python 3.11+ from python.org
    echo          Make sure to check "Add Python to PATH" during installation.
    pause
    exit /b 1
)

echo  [1/2] Installing dependencies...
pip install -r requirements.txt --quiet

echo  [2/2] Starting SafeNet AI server...
echo.
echo  Dashboard:  http://localhost:5000
echo  Press Ctrl+C to stop.
echo.

start "" http://localhost:5000
python app.py
pause
