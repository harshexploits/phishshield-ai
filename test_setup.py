#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PhishShield AI - Setup Verification Script
Run this to check if everything is configured correctly.
"""

import sys
import os

# Handle Windows console encoding
if sys.platform == 'win32':
    import codecs
    sys.stdout = codecs.getwriter('utf-8')(sys.stdout.buffer, 'strict')
    sys.stderr = codecs.getwriter('utf-8')(sys.stderr.buffer, 'strict')

print("PhishShield AI - Setup Verification")
print("=" * 50)
print()

# Check Python version
print("1. Checking Python version...")
python_version = sys.version_info
print(f"   [OK] Python {python_version.major}.{python_version.minor}.{python_version.micro}")

if python_version < (3, 8):
    print("   [ERROR] Python 3.8 or higher is required!")
    print("   Please update Python from python.org")
    sys.exit(1)
else:
    print("   [OK] Python version is compatible")
print()

# Check required packages
print("2. Checking required packages...")
required_packages = [
    'streamlit',
    'google.genai',
    'dotenv',
    'requests'
]

missing_packages = []
for package in required_packages:
    try:
        if package == 'dotenv':
            __import__('dotenv')
        elif package == 'google.genai':
            import google.genai
        else:
            __import__(package)
        print(f"   [OK] {package} - installed")
    except ImportError:
        print(f"   [ERROR] {package} - NOT INSTALLED")
        missing_packages.append(package)

if missing_packages:
    print()
    print(f"   Missing packages: {', '.join(missing_packages)}")
    print("   Run: pip install -r requirements.txt")
    print()
else:
    print()
    print("   [OK] All packages are installed")
print()

# Check .env file
print("3. Checking .env file...")
if os.path.exists('.env'):
    print("   [OK] .env file exists")
    
    # Check if API key is configured
    with open('.env', 'r') as f:
        content = f.read()
        if 'your-api-key-here' in content:
            print("   [WARN] API key not configured!")
            print("   Please edit .env and add your Gemini API key")
            print("   Get it from: https://makersuite.google.com/app/apikey")
        elif 'GEMINI_API_KEY=' in content and len(content.split('GEMINI_API_KEY=')[1].strip()) > 10:
            print("   [OK] API key appears to be configured")
        else:
            print("   [WARN] API key might be missing or invalid")
else:
    print("   [ERROR] .env file not found!")
    print("   Please create .env file with your API key")
print()

# Check project files
print("4. Checking project files...")
required_files = [
    'app.py',
    'requirements.txt',
    'README.md',
    'GETTING_STARTED.md',
    '.gitignore'
]

for file in required_files:
    if os.path.exists(file):
        print(f"   [OK] {file}")
    else:
        print(f"   [ERROR] {file} - MISSING!")
print()

# Summary
print("=" * 50)
print("SETUP SUMMARY")
print("=" * 50)
print()

if not missing_packages and os.path.exists('.env') and 'your-api-key-here' not in content:
    print("SETUP COMPLETE!")
    print()
    print("You're ready to run PhishShield AI!")
    print()
    print("To start the app:")
    print("  streamlit run app.py")
    print()
    print("Then open: http://localhost:8501")
    print()
    print("Check these files for more info:")
    print("  • GETTING_STARTED.md - Quick start guide")
    print("  • README.md - Full documentation")
    print("  • examples.md - Test cases")
    print()
else:
    print("[WARN] SETUP INCOMPLETE")
    print()
    print("Please fix the issues above and run this script again.")
    print()
    print("Common fixes:")
    print("  • Install packages: pip install -r requirements.txt")
    print("  • Get API key: https://makersuite.google.com/app/apikey")
    print("  • Edit .env file with your API key")
print()

print("Stay safe online!")
