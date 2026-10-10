document.addEventListener("DOMContentLoaded", () => {
  const urlInput = document.getElementById("urlInput");
  const scanBtn = document.getElementById("scanBtn");
  const currentTabBtn = document.getElementById("currentTabBtn");
  const resultDiv = document.getElementById("result");

  // Populate input with the active browser tab URL
  currentTabBtn.addEventListener("click", () => {
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      if (tabs && tabs[0] && tabs[0].url) {
        urlInput.value = tabs[0].url;
      }
    });
  });

  // Handle URL scanning
  scanBtn.addEventListener("click", () => {
    const rawUrl = urlInput.value.trim();

    if (!rawUrl) {
      showError("Please enter or capture a URL first.");
      return;
    }

    renderLoading();

    fetch("http://127.0.0.1:8000/predict", {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify({ url: rawUrl })
    })
      .then((res) => {
        if (!res.ok) {
          throw new Error(`Server returned HTTP ${res.status}`);
        }
        return res.json();
      })
      .then((data) => {
        renderResults(data);
      })
      .catch((err) => {
        showError("Could not reach backend API. Ensure Uvicorn is running on port 8000.");
        console.error("Scan error:", err);
      });
  });

  function renderLoading() {
    resultDiv.style.display = "block";
    resultDiv.innerHTML = `<p style="color: #5f6368; font-weight: 500;">Analyzing URL features...</p>`;
  }

  function showError(message) {
    resultDiv.style.display = "block";
    resultDiv.innerHTML = `<p style="color: #d93025; font-weight: 500;">${message}</p>`;
  }

  function renderResults(data) {
    resultDiv.style.display = "block";

    const isPhishing = Boolean(data.is_phishing);
    const probPercent = (data.probability * 100).toFixed(1);

    const statusBadge = isPhishing
      ? `<h3 style="color: #d93025; margin: 0 0 8px 0; font-size: 16px;">⚠️ Suspicious / Phishing</h3>`
      : `<h3 style="color: #188038; margin: 0 0 8px 0; font-size: 16px;">✅ Legitimate Link</h3>`;

    let html = `
      ${statusBadge}
      <p style="margin: 0 0 10px 0; font-size: 13px; color: #5f6368;">
        Phishing Probability: <strong>${probPercent}%</strong>
      </p>
    `;

    // Render Red Flags (Malicious indicators)
    if (data.red_flags && data.red_flags.length > 0) {
      html += `
        <p style="font-weight: 600; font-size: 13px; color: #d93025; margin: 8px 0 4px 0;">Red Flags:</p>
        <ul style="margin: 0 0 8px 0; padding-left: 18px; font-size: 12px; color: #d93025; line-height: 1.4;">
      `;
      data.red_flags.forEach((flag) => {
        html += `<li>${flag}</li>`;
      });
      html += `</ul>`;
    }

    // Render Green Flags (Legitimate indicators)
    if (data.green_flags && data.green_flags.length > 0) {
      html += `
        <p style="font-weight: 600; font-size: 13px; color: #188038; margin: 8px 0 4px 0;">Green Flags:</p>
        <ul style="margin: 0 0 8px 0; padding-left: 18px; font-size: 12px; color: #188038; line-height: 1.4;">
      `;
      data.green_flags.forEach((flag) => {
        html += `<li>${flag}</li>`;
      });
      html += `</ul>`;
    }

    resultDiv.innerHTML = html;
  }
});