function checkURL() {
  const url = document.getElementById("urlInput").value;
  fetch('/check', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ url: url })
  })
  .then(res => res.json())
  .then(data => {
    document.getElementById("result").innerText = data.result;
  })
  .catch(() => {
    document.getElementById("result").innerText = "Error checking the link.";
  });
}

