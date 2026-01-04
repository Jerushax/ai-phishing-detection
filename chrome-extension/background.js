chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === "complete" && tab.url.startsWith("http")) {
    fetch("http://127.0.0.1:8000/scan-url", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url: tab.url })
    })
    .then(res => res.json())
    .then(data => {
      if (data.prediction === "Phishing" || data.prediction === "Suspicious") {
        chrome.scripting.executeScript({
          target: { tabId: tabId },
          func: (prediction) => {
            if (!document.getElementById("phish-warning")) {
              let banner = document.createElement("div");
              banner.id = "phish-warning";
              banner.innerText = prediction === "Phishing"
                ? "🚨 WARNING: THIS WEBSITE IS PHISHING!"
                : "⚠️ WARNING: THIS WEBSITE IS SUSPICIOUS!";
              
              banner.style.position = "fixed";
              banner.style.top = "0";
              banner.style.left = "0";
              banner.style.width = "100%";
              banner.style.padding = "15px";
              banner.style.backgroundColor = prediction === "Phishing" ? "red" : "orange";
              banner.style.color = "white";
              banner.style.fontSize = "18px";
              banner.style.fontWeight = "bold";
              banner.style.textAlign = "center";
              banner.style.zIndex = "999999";
              
              document.body.appendChild(banner);
            }
          },
          args: [data.prediction]
        });
      }
    })
    .catch(err => console.error("Scan failed:", err));
  }
});
