
# PhishGuard 🛡️

A JavaScript web app that helps users identify fake or suspicious URLs using client-side validation and the VirusTotal API.

## Features

- Real-time phishing detection
- Client-side URL validation
- VirusTotal API integration
- Modern responsive UI
- Secure Node.js backend

## Stack

- **Frontend:** HTML, CSS, JavaScript
- **Backend:** Node.js, Express.js
- **External API:** VirusTotal

## How It Works

1. User enters a URL
2. Client performs immediate validation checks
3. Backend submits URL to VirusTotal (if API key configured)
4. Results are displayed with threat analysis

## Setup

1. Install dependencies:
   ```bash
   npm install
   ```

2. Configure VirusTotal API key in `server/.env`:
   ```
   VIRUSTOTAL_API_KEY=your_api_key_here
   ```

3. Start the server:
   ```bash
   npm start
   ```

## Client-Side Validation

The app performs several security checks:

- Protocol validation (http/https)
- IP address detection
- Suspicious character detection
- Phishing keyword detection
- Subdomain spoofing detection
- URL shortener detection

## Deployment

Deploy on Replit by clicking the Run button. The app will be available on your Repl's URL.

---

**Author:** Built with ❤️ on Replit by Emmanuel Obele Ngeyai as a learning project in cybersecurity and AI.
