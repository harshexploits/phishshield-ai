# 🛡️ PhishShield AI

**AI-powered cybersecurity assistant for detecting phishing and online scams.**

## 🚀 Features

- **URL Analysis**: Paste any suspicious URL and get instant analysis
- **Email Analysis**: Paste email content to detect phishing attempts
- **AI-Powered Detection**: Uses Google Gemini AI for accurate threat detection
- **Clear Verdicts**: Safe, Suspicious, or Malicious ratings with confidence scores
- **Red Flags**: Specific indicators highlighted for transparency
- **User-Friendly**: Plain English explanations for non-technical users

## 📋 Prerequisites

- Python 3.8 or higher
- Google Gemini API key (free tier available)

## 🛠️ Installation

1. **Clone or download this repository**

2. **Navigate to the project folder:**
   ```bash
   cd phishshield-ai
   ```

3. **Install required packages:**
   ```bash
   pip install -r requirements.txt
   ```

4. **Set up your API key:**
   - Get a free Gemini API key from [Google AI Studio](https://makersuite.google.com/app/apikey)
   - Open `.env` file and replace `your-api-key-here` with your actual API key

## 🎯 Usage

1. **Run the application:**
   ```bash
   streamlit run app.py
   ```

2. **Open your browser** and go to `http://localhost:8501`

3. **Test with examples:**
   - Click "Example: Suspicious URL" to test a phishing URL
   - Click "Example: Phishing Email" to test a phishing email
   - Click "Example: Safe URL" to test a legitimate site

4. **Paste any URL or email content** and click "Analyze for Threats"

## 🔍 What It Detects

- Urgent language ("Your account will be suspended!")
- Suspicious links (misspelled domains, unusual subdomains)
- Requests for personal information (passwords, credit cards, OTP)
- Impersonation of trusted organizations
- Grammar and spelling mistakes
- Unusual sender email addresses

## 📊 Example Results

**Suspicious URL Test:**
- Input: `https://paypal-verify-account.xyz/confirm`
- Verdict: Malicious
- Red Flags: Misspelled domain, urgent language, requests for credentials

**Safe URL Test:**
- Input: `https://www.google.com`
- Verdict: Safe
- Confidence: 95%

## 🛡️ Security Tips

1. **Check before clicking** - Hover over links to see the actual URL
2. **Never share OTP** - Legitimate companies never ask for OTP via email/SMS
3. **Verify sender** - Check email addresses carefully for fake but similar addresses
4. **When in doubt, don't click** - If something feels off, it probably is

## 🚀 Deployment Options

### Option 1: Streamlit Cloud (Easiest, Free)
1. Push code to GitHub
2. Go to [share.streamlit.io](https://share.streamlit.io)
3. Click "New App" → Select your repo → Deploy

### Option 2: Render (Free)
1. Create `requirements.txt` (already included)
2. Go to [render.com](https://render.com) → "New Web Service"
3. Connect GitHub repo → Deploy

### Option 3: Hugging Face Spaces (Free)
1. Go to [huggingface.co/spaces](https://huggingface.co/spaces)
2. Click "New Space" → Select "Streamlit"
3. Upload files and deploy

## 📈 Future Enhancements

- Browser extension (Chrome/Firefox)
- WhatsApp bot integration
- Email plugin for Gmail/Outlook
- Deepfake image/video detection
- Enterprise dashboard for businesses
- VirusTotal integration for enhanced accuracy

## 🤝 Contributing

Feel free to submit issues, fork the repository, and create pull requests for any improvements.

## 📝 License

This project is open source and available for personal and educational use.

## 🙏 Acknowledgments

- Built with Streamlit for the web interface
- Powered by Google Gemini AI for intelligent analysis
- Designed with ❤️ for cybersecurity awareness

---

**⚡ Quick Start:** Just run `pip install -r requirements.txt` then `streamlit run app.py` and you're ready to go!
