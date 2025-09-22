# NetScan AI - Frontend-Backend Integration Guide

## 🚀 Quick Start

### Prerequisites
- Node.js (v18 or higher)
- Nmap installed on your system
- Google Gemini API key

### Environment Setup

1. **Backend Environment Variables**
   Create `backend/.env`:
   ```
   GEMINI_API_KEY=your_gemini_api_key_here
   NODE_ENV=development
   PORT=3001
   ```

2. **Frontend Environment Variables**
   Create `frontend/NMAP_AI_Scanner/.env`:
   ```
   VITE_API_URL=http://localhost:3001
   VITE_NODE_ENV=development
   ```

### Installation & Startup

1. **Install Dependencies**
   ```bash
   # Backend
   cd backend
   npm install
   
   # Frontend
   cd frontend/NMAP_AI_Scanner
   npm install
   ```

2. **Start Development Servers**
   
   **Option 1: Use the batch script (Windows)**
   ```bash
   ./start-dev.bat
   ```
   
   **Option 2: Manual startup**
   ```bash
   # Terminal 1 - Backend
   cd backend
   npm start
   
   # Terminal 2 - Frontend
   cd frontend/NMAP_AI_Scanner
   npm run dev
   ```

## 🔧 Integration Features

### React Context Implementation
- **ScanContext**: Centralized state management for scan operations
- **useScanAPI**: Custom hook for API interactions
- **State Management**: Comprehensive state handling for scans, AI analysis, and downloads

### API Integration
- **CORS Configuration**: Proper cross-origin setup
- **Proxy Setup**: Vite proxy for development
- **Error Handling**: Comprehensive error management
- **Loading States**: Visual feedback for all operations

### Data Flow
1. **Scan Request** → Backend API → Nmap execution → Results
2. **AI Analysis** → Gemini AI → Security insights → Frontend display
3. **Report Generation** → Puppeteer PDF → Download

## 🛠️ Key Components

### Context Structure
```javascript
// State
{
  scanId, target, scanType, scanOutput, timestamp,
  aiSummary, isAnalyzing,
  isScanning, isDownloading,
  scanError, aiError, downloadError
}

// Actions
startScan, generateAISummary, downloadReport,
resetScan, resetAI, resetAll
```

### API Endpoints
- `POST /api/scan` - Execute Nmap scan
- `POST /api/ai-summary` - Generate AI analysis
- `POST /api/report` - Generate PDF report

## 🐛 Troubleshooting

### Common Issues

1. **CORS Errors**
   - Ensure backend is running on port 3001
   - Check Vite proxy configuration

2. **API Connection Issues**
   - Verify `VITE_API_URL` environment variable
   - Check backend server status

3. **Nmap Not Found**
   - Install Nmap on your system
   - Add Nmap to your PATH

4. **Gemini API Errors**
   - Verify `GEMINI_API_KEY` in backend/.env
   - Check API quota and permissions

### Development Tips

1. **Backend Logs**: Check console for scan execution details
2. **Frontend DevTools**: Use React DevTools for state inspection
3. **Network Tab**: Monitor API requests and responses
4. **Error Boundaries**: Check error display components

## 📁 File Structure

```
frontend/NMAP_AI_Scanner/src/
├── context/
│   └── ScanContext.jsx          # React context for state management
├── hooks/
│   └── useScanAPI.js            # Custom hook for API calls
├── components/                  # UI components
├── pages/
│   └── Home.jsx                # Main page with context integration
└── utils/
    └── api.js                  # API configuration and calls
```

## 🔄 State Flow

1. **User Input** → ScanForm → Context Action
2. **Context Action** → API Call → Backend Processing
3. **Backend Response** → Context Update → UI Update
4. **AI Analysis** → Gemini API → Context Update
5. **Download** → PDF Generation → File Download

## ✅ Integration Checklist

- [x] React Context implementation
- [x] API endpoint configuration
- [x] CORS and proxy setup
- [x] Error handling and loading states
- [x] Component integration
- [x] State management
- [x] File download functionality
- [x] Development environment setup
