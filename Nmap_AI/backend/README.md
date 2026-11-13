# NetScan AI Backend

A powerful Node.js backend API for network scanning with AI-powered analysis using Nmap and Google's Gemini AI.

## 🚀 Features

- **Network Scanning**: Perform basic, aggressive, and passive Nmap scans
- **AI Analysis**: Get intelligent summaries of scan results using Gemini AI
- **PDF Reports**: Generate professional PDF reports with scan results and AI insights
- **Rate Limiting**: Built-in protection against abuse
- **Security**: Input validation, XSS protection, and secure CORS configuration
- **Health Monitoring**: Built-in health check endpoint

## 📋 Prerequisites

- Node.js (v14 or higher)
- Nmap installed on your system
- Google Gemini API key

## 🛠️ Installation

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd backend
   ```

2. **Install dependencies**
   ```bash
   npm install
   ```

3. **Environment Setup**
   Create a `.env` file in the root directory:
   ```env
   PORT=3001
   NODE_ENV=development
   FRONTEND_URL=http://localhost:3000
   GEMINI_API_KEY=your_gemini_api_key_here
   ```

4. **Install Nmap**
   - **Windows**: Download from https://nmap.org/download.html
   - **macOS**: `brew install nmap`
   - **Linux**: `sudo apt-get install nmap` or `sudo yum install nmap`

## 🚀 Running the Application

### Development Mode
```bash
npm run dev
```

### Production Mode
```bash
npm start
```

The server will start on `http://localhost:3001` (or your configured PORT).

## 📚 API Endpoints

### Health Check
```
GET /health
```
Returns server status and timestamp.

### Network Scanning
```
POST /api/scan
```
**Body:**
```json
{
  "target": "example.com",
  "scanType": "basic"
}
```

**Scan Types:**
- `basic`: top 100 ports with a quick version check (`-F -sV --version-light -T4`)
- `aggressive`: versions, OS detection, default scripts (`-A -T4`)
- `passive`: stealth SYN scan, no versions (`-sS -T3 -Pn`, needs root)

**Returns** the normal nmap text in `scanOutput`, plus `hosts` (parsed from nmap's XML output:
address, hostnames, and for each port the state, service, product, version and CPEs) and `stats`.

### Threat intel lookup
```
POST /api/intel/enrich
```
**Body:** `{ "hosts": [ ...the hosts list from /api/scan... ] }`

For every open port with a known product version it looks up:
- **NVD** (CVE list and CVSS score)
- **CISA KEV** (is this CVE being exploited in the wild right now?)
- **FIRST EPSS** (chance the CVE gets exploited in the next 30 days)
- **Shodan InternetDB** for public IPs (ports and CVEs Shodan already sees). Private IPs are never sent.

CVEs are ranked: known-exploited first, then by EPSS, then by CVSS. Results are cached for a day.
Without `NVD_API_KEY` only 5 product versions are checked per scan (NVD allows 5 requests per
30 seconds without a key), so a lookup can take about 30 seconds. A free key raises this to 20.
If a source is down you get a warning, not an error.

### AI Summary
```
POST /api/ai-summary
```
**Body:**
```json
{
  "scanOutput": "nmap scan results...",
  "target": "example.com",
  "intel": { "hosts": [] }
}
```
`intel` is optional. When given, the real CVE facts are added to the prompt so the AI does not
have to guess version vulnerabilities.

### PDF Report Generation
```
POST /api/report
```
**Body:**
```json
{
  "target": "example.com",
  "scanOutput": "nmap scan results...",
  "aiSummary": "AI analysis...",
  "intel": { "hosts": [] }
}
```
`intel` is optional and adds a "Known vulnerabilities" table to the PDF.

## 🔧 Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `PORT` | Server port | `3001` |
| `NODE_ENV` | Environment mode | `development` |
| `FRONTEND_URL` | Frontend URL for CORS | `http://localhost:3000` |
| `GEMINI_API_KEY` | Google Gemini API key | Required |
| `GEMINI_MODEL` | Gemini model name | `gemini-flash-latest` |
| `ML_API_URL` | Where the Python ML API runs | `http://localhost:5000` |
| `NVD_API_KEY` | Free NVD key, makes CVE lookups faster | (none) |
| `INTEL_ENABLED` | Set to `false` to turn off all outside lookups | `true` |

### Rate Limiting

- **Window**: 15 minutes
- **Limit**: 10 requests per IP per window, counted separately for scan, AI summary, report and intel
- **Scope**: scan, AI summary, report and intel endpoints

### Tests
```bash
npm test
```

## 🛡️ Security Features

- **Input Validation**: Comprehensive validation for all inputs
- **XSS Protection**: HTML sanitization in report generation
- **Rate Limiting**: Protection against abuse
- **CORS Configuration**: Secure cross-origin resource sharing
- **Private Network Protection**: Prevents scanning private networks in production
- **Error Handling**: Secure error messages without sensitive information

## 📊 Monitoring

### Health Check
Monitor your application health:
```bash
curl http://localhost:3001/health
```

### Logs
The application logs important events:
- Scan start/completion
- Error details
- Rate limit violations
- PDF generation status

## 🚨 Error Handling

The API returns structured error responses:

```json
{
  "error": "Error description",
  "details": "Additional error details",
  "timestamp": "2024-01-01T00:00:00.000Z"
}
```

Common HTTP status codes:
- `400`: Bad Request (invalid input)
- `403`: Forbidden (private network scan in production)
- `429`: Too Many Requests (rate limit exceeded)
- `500`: Internal Server Error

## 🔍 Development

### Project Structure
```
backend/
├── controllers/          # Route handlers
│   ├── scanController.js
│   ├── reportController.js
│   └── summaryController.js
├── routes/              # API routes
│   ├── scanRoutes.js
│   ├── reportRoutes.js
│   └── summaryRoutes.js
├── utils/               # Utility functions
│   ├── validator.js
│   ├── buildReportHtml.js
│   └── rateLimiter.js
├── app.js               # Express app configuration
├── server.js            # Server startup
└── package.json         # Dependencies
```

### Adding New Features

1. **New Controller**: Create in `controllers/`
2. **New Route**: Add to `routes/` and mount in `app.js`
3. **New Utility**: Add to `utils/` and import where needed

## 🐛 Troubleshooting

### Common Issues

1. **Nmap not found**
   - Ensure Nmap is installed and in your PATH
   - Test with: `nmap --version`

2. **Gemini API errors**
   - Verify your API key is correct
   - Check API quota and billing

3. **Puppeteer issues**
   - Ensure sufficient memory for PDF generation
   - Check system dependencies

4. **Rate limiting**
   - Wait for the rate limit window to reset
   - Adjust limits in `utils/rateLimiter.js`

## 📝 License

MIT License - see LICENSE file for details.

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## 📞 Support

For issues and questions:
1. Check the troubleshooting section
2. Search existing GitHub issues
3. Create a new issue with detailed information
