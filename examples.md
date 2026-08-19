# 🧪 PhishShield AI - Test Cases & Examples

## 🟢 Safe URLs

### Example 1: Google
```
https://www.google.com
```
**Expected Verdict:** Safe ✅
**Why:** Legitimate domain, no suspicious indicators

### Example 2: Amazon
```
https://www.amazon.com
```
**Expected Verdict:** Safe ✅
**Why:** Official Amazon domain, HTTPS secured

### Example 3: GitHub
```
https://github.com
```
**Expected Verdict:** Safe ✅
**Why:** Legitimate developer platform

---

## 🟡 Suspicious URLs

### Example 4: PayPal Lookalike
```
https://paypal-verify-account.xyz/confirm
```
**Expected Verdict:** Suspicious ⚠️ or Malicious 🚨
**Why:** Misspelled domain (.xyz TTP), verification scam pattern

### Example 5: Bank Impersonation
```
https://secure-banking-login.ru/auth
```
**Expected Verdict:** Malicious 🚨
**Why:** Suspicious domain (.ru), impersonates banking

### Example 6: Amazon Phishing
```
https://amazon.com.secure-update.com/login
```
**Expected Verdict:** Malicious 🚨
**Why:** Fake subdomain, tries to look like Amazon

---

## 🔴 Malicious Emails

### Example 7: Classic Phishing Email
```
Dear Valued Customer,

Your account has been compromised! 
Click here immediately to verify your identity:
https://bank-secure-verify.xyz/update

You must act within 24 hours or your account will be permanently suspended.

DO NOT ignore this message!

Best regards,
The Security Team
```
**Expected Verdict:** Malicious 🚨
**Why:** Urgency tactics, suspicious link, threat of account suspension

### Example 8: Tech Support Scam
```
URGENT: Your computer is infected with malware!

Our Microsoft support team detected suspicious activity on your device.

Please call us immediately at 1-800-FAKE-NUM or click the link below to remove the threat:

https://microsoft-support.scam-site.com/clean

Failure to act within 1 hour will result in permanent data loss.

Microsoft Security Team
```
**Expected Verdict:** Malicious 🚨
**Why:** Fake Microsoft support, fear tactics, suspicious link

### Example 9: Prize Scam
```
Congratulations! You've won $1,000,000!

You have been randomly selected as our grand prize winner!

To claim your prize, please provide:
- Full name
- Bank account details
- Credit card number

Reply to this email immediately with your information.

Regards,
International Lottery Commission
```
**Expected Verdict:** Malicious 🚨
**Why:** Classic prize scam, requests sensitive financial information

---

## 🟢 Safe Emails

### Example 10: Normal Business Email
```
Hi Sarah,

Just wanted to follow up on our meeting yesterday. 

The project timeline looks good, and I'll send the updated proposal by Friday.

Let me know if you have any questions.

Best,
John
```
**Expected Verdict:** Safe ✅
**Why:** Normal business communication, no suspicious elements

### Example 11: Friend Message
```
Hey! Want to grab lunch tomorrow around noon?

There's a new pizza place on Main Street I've been wanting to try.

Let me know if that works for you!
```
**Expected Verdict:** Safe ✅
**Why:** Casual personal message, no threats or requests

---

## 🔍 Mixed Content (Test AI Judgment)

### Example 12: Neutral Link
```
Check out this article about cybersecurity: https://www.wired.com/story/phishing-attacks-2024/
```
**Expected Verdict:** Safe ✅
**Why:** Legitimate news source, informative content

### Example 13: Suspicious but Not Malicious
```
Hey, check out this deal: https://free-iphone-giveaway.com/prize
```
**Expected Verdict:** Suspicious ⚠️
**Why:** Too-good-to-be-true offer, suspicious domain, but not necessarily harmful

---

## 💡 Tips for Testing

1. **Test with real suspicious emails** from your spam folder
2. **Try variations** of known phishing patterns
3. **Test edge cases** like URLs with IP addresses
4. **Check confidence scores** - lower confidence might indicate ambiguous cases
5. **Verify red flags** - make sure the AI identifies the right indicators

## 🎯 What to Look For in Results

- **Verdict accuracy** - Does it match your intuition?
- **Confidence score** - Higher = more certain
- **Red flags** - Are they relevant and specific?
- **Explanation** - Is it clear and understandable?
- **Recommendation** - Is it actionable and safe?

---

**Happy Testing! 🛡️**
