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
- `basic`: Fast scan with common ports
- `aggressive`: Comprehensive scan with service detection
- `passive`: Stealth scan with SYN packets

### AI Summary
```
POST /api/ai-summary
```
**Body:**
```json
{
  "scanOutput": "nmap scan results..."
}
```

### PDF Report Generation
```
POST /api/report
```
**Body:**
```json
{
  "target": "example.com",
  "scanOutput": "nmap scan results...",
  "aiSummary": "AI analysis..."
}
```

## 🔧 Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `PORT` | Server port | `3001` |
| `NODE_ENV` | Environment mode | `development` |
| `FRONTEND_URL` | Frontend URL for CORS | `http://localhost:3000` |
| `GEMINI_API_KEY` | Google Gemini API key | Required |

### Rate Limiting

- **Window**: 15 minutes
- **Limit**: 10 requests per IP per window
- **Scope**: Applied to all API endpoints

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
