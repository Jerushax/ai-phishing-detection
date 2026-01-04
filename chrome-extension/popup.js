chrome.tabs.query({ active: true, currentWindow: true }, function (tabs) {
  let currentUrl = tabs[0].url;

  fetch("http://127.0.0.1:8000/scan-url", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ url: currentUrl })
  })
  .then(res => res.json())
  .then(data => {
    let statusDiv = document.getElementById("status");

    if (data.prediction === "Phishing") {
      statusDiv.className = "phishing";
      statusDiv.innerText = "🚨 PHISHING DETECTED";
    }
    else if (data.prediction === "Suspicious") {
      statusDiv.className = "suspicious";
      statusDiv.innerText = "⚠️ SUSPICIOUS WEBSITE";
    }
    else {
      statusDiv.className = "safe";
      statusDiv.innerText = "✅ SAFE WEBSITE";
    }
  })
  .catch(err => {
    document.getElementById("status").innerText = "❌ Server Error";
  });
});
