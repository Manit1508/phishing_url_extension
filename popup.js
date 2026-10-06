document.getElementById('current-tab-btn').addEventListener('click', () => {
    chrome.tabs.query({active: true, currentWindow: true}, (tabs) => {
      document.getElementById('url-input').value = tabs[0].url;
    });
  });
  
  document.getElementById('scan-btn').addEventListener('click', async () => {
    const url = document.getElementById('url-input').value;
    if (!url) return;
  
    const resultDiv = document.getElementById('result');
    const verdictTitle = document.getElementById('verdict');
    const reasonsList = document.getElementById('reasons');
    
    resultDiv.classList.remove('hidden');
    verdictTitle.textContent = "Scanning...";
    verdictTitle.className = "";
    reasonsList.innerHTML = "";
  
    // Mock logic: This simulates your future Machine Learning backend
    setTimeout(() => {
      const isSuspicious = url.length > 50 || url.includes("192.") || url.includes("-");
      
      if (isSuspicious) {
        verdictTitle.textContent = "⚠️ Suspicious Link";
        verdictTitle.className = "danger";
        reasonsList.innerHTML = `
          <li>High character length or special characters</li>
          <li>Potential IP address routing</li>
        `;
      } else {
        verdictTitle.textContent = "✅ Safe Link";
        verdictTitle.className = "safe";
        reasonsList.innerHTML = "<li>No standard phishing indicators found</li>";
      }
    }, 800);
  });