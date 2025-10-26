require('dotenv').config();
const { GoogleGenerativeAI } = require('@google/generative-ai');

// Initialize Gemini AI
const genAI = new GoogleGenerativeAI(process.env.GEMINI_API_KEY);

/**
 * Generate AI-powered security analysis from Nmap scan output
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 */
exports.getSummary = async (req, res) => {
  try {
    const { scanOutput, target } = req.body;
    const apiKey = process.env.GEMINI_API_KEY;

    // Input validation
    if (!scanOutput || typeof scanOutput !== 'string') {
      return res.status(400).json({ 
        error: 'Invalid scan output. Must be a non-empty string.',
        received: typeof scanOutput
      });
    }

    if (!apiKey || apiKey === 'your_gemini_api_key_here') {
      return res.status(500).json({ 
        error: 'Missing or invalid Gemini API key. Please configure GEMINI_API_KEY in environment variables.',
        details: 'Create a .env file in the backend directory with: GEMINI_API_KEY=your_actual_api_key',
        help: 'Get your API key from: https://makersuite.google.com/app/apikey'
      });
    }

    // Validate scan output length
    if (scanOutput.trim().length < 10) {
      return res.status(400).json({ 
        error: 'Scan output too short. Please provide a valid Nmap scan result.' 
      });
    }

    console.log(`Generating AI analysis for target: ${target || 'Unknown'}`);

    // Use Gemini SDK for better error handling and consistency
    const model = genAI.getGenerativeModel({ model: 'gemini-1.5-flash' });

    const systemPrompt = `You are a professional cybersecurity analyst with expertise in network security and vulnerability assessment. 

Your task is to analyze Nmap scan results and provide a comprehensive security report with the following structure:

## SECURITY ANALYSIS REPORT

### 🎯 EXECUTIVE SUMMARY
- Brief overview of the scan results
- Overall security posture assessment
- Key findings summary

### 🔍 DETAILED FINDINGS
For each open port/service found:
- **Port/Service**: [Port number and service name]
- **Risk Level**: HIGH/MEDIUM/LOW
- **Vulnerability**: [Specific security concerns]
- **Impact**: [Potential business impact]
- **Evidence**: [Relevant scan data]

### ⚠️ CRITICAL ISSUES
List any high-risk findings that require immediate attention

### 🛡️ RECOMMENDATIONS
Prioritized remediation steps:
1. **Immediate Actions** (Critical)
2. **Short-term Actions** (High Priority)
3. **Long-term Actions** (Medium Priority)

### 📊 RISK ASSESSMENT
- Overall risk score (1-10)
- Compliance considerations
- Business impact assessment

### 🔧 TECHNICAL DETAILS
- Service versions and potential vulnerabilities
- Network topology insights
- Security best practices recommendations

Format the response in clear, professional language suitable for both technical and executive audiences.`;

    const userPrompt = `Analyze the following Nmap scan results and provide a comprehensive security analysis:

**Target**: ${target || 'Unknown'}
**Scan Output**:
\`\`\`
${scanOutput}
\`\`\`

Please provide a detailed security analysis following the structure outlined above.`;

    console.log('Sending request to Gemini API...');
    const result = await model.generateContent({
      contents: [
        {
          role: 'user',
          parts: [{ text: userPrompt }]
        }
      ],
      systemInstruction: {
        parts: [{ text: systemPrompt }]
      }
    });

    console.log('Received response from Gemini API');
    const summary = result?.response?.text?.();

    if (!summary || summary.trim().length < 50) {
      console.error('Empty or insufficient response from AI model:', summary);
      throw new Error('Empty or insufficient response from AI model');
    }

    console.log('AI analysis generated successfully');
    
    return res.json({ 
      success: true,
      summary: summary.trim(),
      target: target || 'Unknown',
      timestamp: new Date().toISOString(),
      analysisLength: summary.length
    });

  } catch (error) {
    console.error('Error generating AI summary:', error);
    
    // Handle specific error types
    if (error.message.includes('API key') || error.message.includes('API_KEY')) {
      return res.status(500).json({ 
        error: 'Invalid or missing API key',
        details: 'Please check your GEMINI_API_KEY environment variable',
        help: 'Get your API key from: https://makersuite.google.com/app/apikey'
      });
    }
    
    if (error.message.includes('quota') || error.message.includes('QUOTA_EXCEEDED')) {
      return res.status(429).json({ 
        error: 'API quota exceeded',
        details: 'Please try again later or check your API usage limits',
        help: 'Check your Gemini API usage at: https://makersuite.google.com/app/apikey'
      });
    }

    if (error.message.includes('PERMISSION_DENIED')) {
      return res.status(403).json({ 
        error: 'Permission denied',
        details: 'Your API key does not have permission to access Gemini API',
        help: 'Check your API key permissions at: https://makersuite.google.com/app/apikey'
      });
    }

    if (error.message.includes('network') || error.message.includes('timeout')) {
      return res.status(503).json({ 
        error: 'Network error',
        details: 'Unable to connect to Gemini API. Please check your internet connection.',
        help: 'Try again in a few moments'
      });
    }

    return res.status(500).json({ 
      error: 'Failed to generate AI summary', 
      details: process.env.NODE_ENV === 'development' ? error.message : 'Internal server error',
      timestamp: new Date().toISOString(),
      help: 'Check the backend logs for more details'
    });
  }
};
