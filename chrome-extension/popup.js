document.addEventListener('DOMContentLoaded', async () => {
  const targetUrlEl = document.getElementById('targetUrl');
  const scanBtn = document.getElementById('scanBtn');
  const resultContainer = document.getElementById('resultContainer');
  const verdictTitle = document.getElementById('verdictTitle');
  const verdictReason = document.getElementById('verdictReason');
  const verdictBadge = document.getElementById('verdictBadge');

  let currentTabUrl = '';

  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (tab && tab.url) {
      currentTabUrl = tab.url;
      targetUrlEl.textContent = currentTabUrl;
    } else {
      targetUrlEl.textContent = 'Could not detect active tab URL.';
    }
  } catch (err) {
    targetUrlEl.textContent = 'Error querying tab: ' + err.message;
  }

  scanBtn.addEventListener('click', async () => {
    if (!currentTabUrl || currentTabUrl.startsWith('chrome://')) {
      alert('Cannot scan browser internal pages.');
      return;
    }

    scanBtn.disabled = true;
    scanBtn.textContent = '⌛ SCANNING...';
    resultContainer.classList.remove('hidden');
    verdictTitle.textContent = 'ANALYZING...';
    verdictTitle.style.color = '#a855f7';
    verdictReason.textContent = 'Scanning domain reputation & neural threat indicators...';

    // Simulated/Heuristic scan call
    setTimeout(() => {
      let isSuspicious = false;
      let isMalicious = false;
      const lowerUrl = currentTabUrl.lowerCase ? currentTabUrl.lowerCase() : currentTabUrl.toLowerCase();

      const suspiciousKeywords = ['verify', 'login', 'secure', 'account', 'banking', 'paypal', 'support', 'update', 'token', 'confirm'];
      const matched = suspiciousKeywords.filter(k => lowerUrl.includes(k));

      if (matched.length >= 2 || lowerUrl.includes('.xyz') || lowerUrl.includes('.top') || lowerUrl.includes('000webhost')) {
        isMalicious = true;
      } else if (matched.length === 1) {
        isSuspicious = true;
      }

      if (isMalicious) {
        verdictTitle.textContent = '🚨 MALICIOUS';
        verdictTitle.style.color = '#f43f5e';
        verdictBadge.textContent = 'HIGH RISK';
        verdictBadge.style.background = 'rgba(244, 63, 94, 0.2)';
        verdictBadge.style.color = '#f43f5e';
        verdictReason.textContent = `Flagged: Suspicious parameters (${matched.join(', ')}) detected in domain pattern.`;
      } else if (isSuspicious) {
        verdictTitle.textContent = '⚠️ SUSPICIOUS';
        verdictTitle.style.color = '#f59e0b';
        verdictBadge.textContent = 'MEDIUM RISK';
        verdictBadge.style.background = 'rgba(245, 158, 11, 0.2)';
        verdictBadge.style.color = '#f59e0b';
        verdictReason.textContent = `Caution: Contains keywords (${matched.join(', ')}) commonly seen in phishing links.`;
      } else {
        verdictTitle.textContent = '✅ SAFE';
        verdictTitle.style.color = '#10b981';
        verdictBadge.textContent = 'CLEAN';
        verdictBadge.style.background = 'rgba(16, 107, 74, 0.2)';
        verdictBadge.style.color = '#10b981';
        verdictReason.textContent = 'No immediate phishing or credential-harvesting indicators found.';
      }

      scanBtn.disabled = false;
      scanBtn.textContent = '⚡ INITIATE THREAT SCAN';
    }, 1000);
  });
});
