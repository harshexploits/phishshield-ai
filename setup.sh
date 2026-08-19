#!/bin/bash

# PhishShield AI Setup Script
echo "🛡️  Setting up PhishShield AI..."
echo ""

# Check if Python is installed
if ! command -v python3 &> /dev/null; then
    echo "❌ Python3 is not installed. Please install Python 3.8 or higher from python.org"
    exit 1
fi

# Check Python version
python_version=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
echo "✅ Python version: $python_version"

# Install required packages
echo ""
echo "📦 Installing required packages..."
pip3 install -r requirements.txt

if [ $? -ne 0 ]; then
    echo "❌ Failed to install packages. Please check your internet connection."
    exit 1
fi

echo "✅ Packages installed successfully!"
echo ""

# Check for API key
if [ -f .env ]; then
    if grep -q "your-api-key-here" .env; then
        echo "⚠️  Please add your Gemini API key to the .env file!"
        echo "   Get your free API key from: https://makersuite.google.com/app/apikey"
        echo ""
        echo "   Edit .env and replace 'your-api-key-here' with your actual key."
        echo ""
    else
        echo "✅ API key found in .env"
    fi
else
    echo "❌ .env file not found. Please create one with your API key."
fi

echo ""
echo "🚀 Setup complete! To run the app:"
echo "   cd phishshield-ai"
echo "   streamlit run app.py"
echo ""
echo "   Then open http://localhost:8501 in your browser."
echo ""
echo "📖 For more information, check README.md"
echo ""
echo "🛡️  Happy phishing detection!"
