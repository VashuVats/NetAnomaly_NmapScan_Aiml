const puppeteer = require('puppeteer');
const { buildReportHtml } = require('../utils/buildReportHtml');

exports.generateReport = async (req, res) => {
  const { target, scanOutput, aiSummary } = req.body;

  // Input validation
  if (!scanOutput || !aiSummary) {
    return res.status(400).json({ 
      error: 'Missing required fields.',
      required: ['scanOutput', 'aiSummary'],
      received: Object.keys(req.body)
    });
  }

  // Validate data types and content
  if (typeof scanOutput !== 'string' || typeof aiSummary !== 'string') {
    return res.status(400).json({ 
      error: 'Invalid data types. scanOutput and aiSummary must be strings.' 
    });
  }

  // Sanitize target for filename
  const sanitizedTarget = target ? target.replace(/[^a-zA-Z0-9.-]/g, '_') : 'unknown';
  const htmlContent = buildReportHtml(target, scanOutput, aiSummary);

  let browser;
  try {
    console.log('Launching Puppeteer for PDF generation...');
    browser = await puppeteer.launch({ 
      headless: true, 
      args: [
        '--no-sandbox',
        '--disable-setuid-sandbox',
        '--disable-dev-shm-usage',
        '--disable-accelerated-2d-canvas',
        '--no-first-run',
        '--no-zygote',
        '--disable-gpu'
      ]
    });
    
    const page = await browser.newPage();
    
    // Set viewport for consistent rendering
    await page.setViewport({ width: 1200, height: 800 });
    
    await page.setContent(htmlContent, { waitUntil: 'networkidle0' });
    
    const pdfBuffer = await page.pdf({ 
      format: 'A4', 
      printBackground: true,
      margin: {
        top: '20mm',
        right: '20mm',
        bottom: '20mm',
        left: '20mm'
      }
    });

    await browser.close();
    browser = null;

    console.log('PDF generated successfully');
    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition', `attachment; filename=Nmap-Report-${sanitizedTarget}-${Date.now()}.pdf`);
    res.setHeader('Content-Length', pdfBuffer.length);
    
    return res.send(pdfBuffer);
  } catch (err) {
    console.error('Puppeteer error:', err);
    
    // Ensure browser is closed on error
    if (browser) {
      try {
        await browser.close();
      } catch (closeErr) {
        console.error('Error closing browser:', closeErr);
      }
    }
    
    return res.status(500).json({ 
      error: 'Failed to generate PDF report', 
      details: err.message,
      timestamp: new Date().toISOString()
    });
  }
};
