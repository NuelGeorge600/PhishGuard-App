document.getElementById('urlForm').addEventListener('submit', async function(e) {
  e.preventDefault();
  const url = document.getElementById('urlInput').value;
  const resultDiv = document.getElementById('result');
  resultDiv.textContent = 'Checking...';

  try {
    const response = await fetch(`/api/check-url?url=${encodeURIComponent(url)}`);
    const data = await response.json();

    if (data.virustotal) {
      resultDiv.textContent = `✅ VirusTotal: ${data.virustotal}`;
    } else {
      resultDiv.textContent = `⚠️ ${data.message || 'Check complete.'}`;
    }
  } catch (err) {
    resultDiv.textContent = 'An error occurred while checking the URL.';
  }
});
