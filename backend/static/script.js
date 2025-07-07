function checkURL() {
  const url = document.getElementById("urlInput").value.trim(); // ⬅️ Add .trim()

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
    document.getElementById("basicCheck").innerText = "🛡️ Basic Check: " + data.basic_check;
    document.getElementById("vtCheck").innerText = "🔍 VirusTotal Check: " + data.vt_check;
    document.getElementById("explanation").innerText =
      "⚠️ VirusTotal check is " + (data.vt_check === "🔄 Not available" ? "not active." : "based on scan data.");
    document.getElementById("resultBox").style.display = "block";
  })
  .catch(() => {
    document.getElementById("result").innerText = "⚠️ Error checking the link.";
  });
}

