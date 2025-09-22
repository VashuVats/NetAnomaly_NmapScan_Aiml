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

    if (!apiKey) {
      return res.status(500).json({ 
        error: 'Missing Gemini API key. Please configure GEMINI_API_KEY in environment variables.' 
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

    const summary = result?.response?.text?.();

    if (!summary || summary.trim().length < 50) {
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
    if (error.message.includes('API key')) {
      return res.status(500).json({ 
        error: 'Invalid or missing API key',
        details: 'Please check your GEMINI_API_KEY environment variable'
      });
    }
    
    if (error.message.includes('quota')) {
      return res.status(429).json({ 
        error: 'API quota exceeded',
        details: 'Please try again later or check your API usage limits'
      });
    }

    return res.status(500).json({ 
      error: 'Failed to generate AI summary', 
      details: process.env.NODE_ENV === 'development' ? error.message : 'Internal server error',
      timestamp: new Date().toISOString()
    });
  }
};
