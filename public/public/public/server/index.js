const express = require('express');
const fetch = require('node-fetch');
const path = require('path');
const dotenv = require('dotenv');
const cors = require('cors');

dotenv.config();

const app = express();
app.use(cors());
app.use(express.static(path.join(__dirname, '../public')));

const VIRUSTOTAL_API_KEY = process.env.VIRUSTOTAL_API_KEY;

app.get('/api/check-url', async (req, res) => {
  const { url } = req.query;

  if (!url) {
    return res.status(400).json({ message: 'No URL provided.' });
  }

  if (!VIRUSTOTAL_API_KEY) {
    return res.json({ message: 'Client-side check only. No API key.' });
  }

  try {
    const scanRes = await fetch('https://www.virustotal.com/api/v3/urls', {
      method: 'POST',
      headers: {
        'x-apikey': VIRUSTOTAL_API_KEY,
        'content-type': 'application/x-www-form-urlencoded'
      },
      body: `url=${encodeURIComponent(url)}`
    });

    const scanData = await scanRes.json();
    const analysisId = scanData.data.id;

    const analysisRes = await fetch(`https://www.virustotal.com/api/v3/analyses/${analysisId}`, {
      headers: { 'x-apikey': VIRUSTOTAL_API_KEY }
    });

    const analysisData = await analysisRes.json();
    const stats = analysisData.data.attributes.stats;

    const resultText = `${stats.harmless} harmless / ${stats.malicious} malicious / ${stats.suspicious} suspicious`;
    res.json({ virustotal: resultText });
  } catch (error) {
    res.json({ message: 'VirusTotal check failed. Client-side only.' });
  }
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
