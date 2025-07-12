const express = require('express');
const cors = require('cors');
const axios = require('axios');
require('dotenv').config();

const app = express();
app.use(cors());
app.use(express.json());

const API_KEY = process.env.VIRUSTOTAL_API_KEY;

app.post('/check-url', async (req, res) => {
  const { url } = req.body;
  try {
    const response = await axios.post(
      'https://www.virustotal.com/api/v3/urls',
      new URLSearchParams({ url }),
      {
        headers: {
          'x-apikey': API_KEY,
          'Content-Type': 'application/x-www-form-urlencoded',
        },
      }
    );

    const analysisId = response.data.data.id;

    const result = await axios.get(
      `https://www.virustotal.com/api/v3/analyses/${analysisId}`,
      {
        headers: {
          'x-apikey': API_KEY,
        },
      }
    );

    res.json(result.data);
  } catch (error) {
    res.status(500).json({ error: 'Failed to scan URL' });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
