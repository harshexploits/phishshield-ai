# 🚀 PhishShield AI - Quick Start Guide

## 📋 What You Have

Your PhishShield AI project is now set up with:

```
phishshield-ai/
├── .env                    # API key configuration (edit this!)
├── .gitignore              # Git ignore rules
├── README.md               # Full documentation
├── app.py                  # Main application (Streamlit + Gemini AI)
├── examples.md             # Test cases and examples
├── requirements.txt        # Python dependencies
├── setup.bat               # Windows setup script
└── setup.sh                # Linux/Mac setup script
```

## 🎯 3 Steps to Get Started

### Step 1: Install Dependencies

**Windows:**
```bash
cd phishshield-ai
setup.bat
```

**Linux/Mac:**
```bash
cd phishshield-ai
chmod +x setup.sh
./setup.sh
```

**Manual installation:**
```bash
cd phishshield-ai
pip install -r requirements.txt
```

### Step 2: Add Your API Key

1. **Get a free Gemini API key:**
   - Go to: https://makersuite.google.com/app/apikey
   - Sign in with your Google account
   - Click "Create API Key"
   - Copy the key

2. **Edit the `.env` file:**
   - Open `.env` in any text editor
   - Replace `your-api-key-here` with your actual key
   - Save the file

   Example:
   ```
   GEMINI_API_KEY=AIzaSyC...your-actual-key-here
   ```

### Step 3: Run the App

```bash
streamlit run app.py
```

**Then open:** http://localhost:8501 in your browser

## 🧪 Test It Out

Once the app is running:

1. **Click "Example: Suspicious URL"** - Test with `https://paypal-verify-account.xyz/confirm`
2. **Click "Analyze for Threats"** - See the AI analysis
3. **Try other examples** from the `examples.md` file
4. **Paste your own suspicious URLs or emails** to test

## 📊 What You'll See

- **✅ Safe** - Green box, high confidence
- **⚠️ Suspicious** - Yellow box, moderate confidence  
- **🚨 Malicious** - Red box, high confidence
- **🚩 Red Flags** - Specific indicators the AI found
- **💡 Recommendation** - What you should do next

## 🔧 Troubleshooting

### "API key not found"
- Make sure you edited the `.env` file
- Check there are no extra spaces around the key
- Verify the key is correct by testing it in Google AI Studio

### "Module not found"
- Run: `pip install -r requirements.txt`
- Or install manually: `pip install streamlit google-generativeai python-dotenv requests`

### "Port already in use"
- Streamlit uses port 8501 by default
- Close other apps using that port, or run: `streamlit run app.py --server.port 8502`

### App won't start
- Check Python version: `python --version` (need 3.8+)
- Check if all packages are installed: `pip list`

## 🎉 What's Next?

Once you have it working:

1. **Share with friends** - Get feedback on the interface
2. **Test with real suspicious emails** from your spam folder
3. **Deploy online** (see README.md for options)
4. **Add VirusTotal integration** for enhanced accuracy
5. **Build a browser extension** (Version 2 roadmap)

## 💡 Pro Tips

- **Test edge cases** - Try URLs with IP addresses, encoded characters
- **Check confidence scores** - Lower scores might need manual review
- **Verify red flags** - Make sure they're relevant to the input
- **Read the explanations** - They should be clear for non-technical users

## 🆘 Need Help?

- Check the **README.md** for detailed documentation
- Review **examples.md** for test cases
- Look at **app.py** comments for code explanations
- Google the error message - most issues have solutions online

---

**🛡️ You're ready to start phishing detection!**

**Command to run:**
```bash
cd phishshield-ai
streamlit run app.py
```

**Then open:** http://localhost:8501

**Happy testing! 🚀**
