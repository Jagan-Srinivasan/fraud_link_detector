function checkURL() {
  const url = document.getElementById("urlInput").value.trim();

  if (!url) {
    document.getElementById("result").innerText = "❌ Please enter a valid URL.";
    return;
  }

  fetch('/check', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ url: url })
  })
  .then(res => res.json())
  .then(data => {
    // Show all results
    document.getElementById("basicCheck").innerText = "🛡️ Basic Check: " + data.basic_check;
    document.getElementById("vtCheck").innerText = "🔍 VirusTotal Check: " + data.vt_check;
    
    if (data.gsb_check) {
      // Add Safe Browsing result only if available
      let gsbPara = document.getElementById("gsbCheck");
      if (!gsbPara) {
        gsbPara = document.createElement("p");
        gsbPara.id = "gsbCheck";
        gsbPara.style.margin = "5px 0";
        document.getElementById("resultBox").insertBefore(gsbPara, document.getElementById("explanation"));
      }
      gsbPara.innerText = "🧠 Google Safe Browsing: " + data.gsb_check;
    }

    // Explanation message
    const explanation =
      (data.vt_check.includes("Clean") && data.basic_check.includes("❌"))
        ? "⚠️ VirusTotal shows clean, but basic analysis found it suspicious."
        : (data.vt_check === "🔄 Not available")
          ? "⚠️ VirusTotal check is not active."
          : "⚠️ VirusTotal check is based on scan data.";

    document.getElementById("explanation").innerText = explanation;

    document.getElementById("resultBox").style.display = "block";
  })
  .catch(() => {
    document.getElementById("result").innerText = "⚠️ Error checking the link.";
  });
}
