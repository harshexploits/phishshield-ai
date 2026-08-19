@echo off
REM PhishShield AI Setup Script for Windows

echo 🛡️  Setting up PhishShield AI...
echo.

REM Check if Python is installed
python --version >nul 2>&1
if errorlevel 1 (
    echo ❌ Python is not installed. Please install Python 3.8 or higher from python.org
    pause
    exit /b 1
)

REM Show Python version
python -c "import sys; print(f'✅ Python version: {sys.version_info.major}.{sys.version_info.minor}')"
echo.

REM Install required packages
echo 📦 Installing required packages...
pip install -r requirements.txt

if errorlevel 1 (
    echo ❌ Failed to install packages. Please check your internet connection.
    pause
    exit /b 1
)

echo ✅ Packages installed successfully!
echo.

REM Check for API key
if exist .env (
    findstr "your-api-key-here" .env >nul
    if not errorlevel 1 (
        echo ⚠️  Please add your Gemini API key to the .env file!
        echo    Get your free API key from: https://makersuite.google.com/app/apikey
        echo.
        echo    Edit .env and replace 'your-api-key-here' with your actual key.
        echo.
    ) else (
        echo ✅ API key found in .env
    )
) else (
    echo ❌ .env file not found. Please create one with your API key.
)

echo.
echo 🚀 Setup complete! To run the app:
echo    cd phishshield-ai
echo    streamlit run app.py
echo.
echo    Then open http://localhost:8501 in your browser.
echo.
echo 📖 For more information, check README.md
echo.
echo 🛡️  Happy phishing detection!
pause
