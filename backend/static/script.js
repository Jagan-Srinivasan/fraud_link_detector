function checkURL() {
  const url = document.getElementById("urlInput").value.trim();

  if (!url) {
    document.getElementById("result").innerHTML = "❗ Please enter a URL.";
    return;
  }

  fetch('/check', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ url: url })
  })
  .then(res => res.json())
  .then(data => {
    document.getElementById("result").innerHTML = `
      <p><strong>🛡️ Basic Check:</strong> ${data.basic_check}</p>
      <p><strong>🔍 VirusTotal Check:</strong> ${data.vt_check}</p>
    `;
  })
  .catch(() => {
    document.getElementById("result").innerText = "⚠️ Error checking the link. Try again later.";
  });
}
