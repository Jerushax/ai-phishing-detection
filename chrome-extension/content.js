if (!document.getElementById("phish-warning")) {
  let warning = document.createElement("div");
  warning.id = "phish-warning";

  warning.innerHTML = `
    ⚠️ WARNING: THIS WEBSITE IS DETECTED AS PHISHING ⚠️
  `;

  warning.style.position = "fixed";
  warning.style.top = "0";
  warning.style.left = "0";
  warning.style.width = "100%";
  warning.style.padding = "15px";
  warning.style.backgroundColor = "red";
  warning.style.color = "white";
  warning.style.fontSize = "18px";
  warning.style.fontWeight = "bold";
  warning.style.textAlign = "center";
  warning.style.zIndex = "999999";

  document.body.appendChild(warning);
}
