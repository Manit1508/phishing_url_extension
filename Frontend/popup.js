const API_URL = "http://127.0.0.1:8000/predict";

document.getElementById('current-tab-btn').addEventListener('click', () => {
  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    if (tabs && tabs[0] && tabs[0].url) {
      document.getElementById('url-input').value = tabs[0].url;
    }
  });
});

document.getElementById('scan-btn').addEventListener('click', async () => {
  let targetUrl = document.getElementById('url-input').value.trim();
  if (!targetUrl) return;

  // Ensure standard protocol prefix if omitted
  if (!targetUrl.startsWith("http://") && !targetUrl.startsWith("https://")) {
    targetUrl = "https://" + targetUrl;
  }

  const resultDiv = document.getElementById('result');
  const verdictTitle = document.getElementById('verdict');
  const probText = document.getElementById('probability');
  const reasonsList = document.getElementById('reasons');

  resultDiv.classList.remove('hidden');
  verdictTitle.textContent = "Analyzing with ML model...";
  verdictTitle.className = "";
  probText.textContent = "";
  reasonsList.innerHTML = "";

  try {
    const response = await fetch(API_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url: targetUrl })
    });

    if (!response.ok) throw new Error("Inference API error");

    const data = await response.json();
    const isPhishing = data.is_phishing;

    if (isPhishing) {
      verdictTitle.textContent = "⚠️ Suspicious / Phishing";
      verdictTitle.className = "danger";
    } else {
      verdictTitle.textContent = "✅ Legitimate Link";
      verdictTitle.className = "safe";
    }

    probText.textContent = `Phishing Probability: ${(data.probability * 100).toFixed(1)}%`;

    reasonsList.innerHTML = "";
    data.explanations.forEach(reason => {
      const li = document.createElement("li");
      li.textContent = reason;
      reasonsList.appendChild(li);
    });

  } catch (err) {
    verdictTitle.textContent = "❌ Server Offline";
    verdictTitle.className = "danger";
    probText.textContent = "Run: uvicorn main:app --reload in your backend folder.";
  }
});