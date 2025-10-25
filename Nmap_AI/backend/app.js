const express = require("express");
const cors = require("cors");

const scanRoutes = require("./routes/scanRoutes");
const summaryRoutes = require("./routes/summaryRoutes");
const reportRoutes = require("./routes/reportRoutes");
const analysisRoutes = require("./routes/analysisRoutes");

const app = express();

const corsOptions = {
  origin: process.env.NODE_ENV === 'production' 
    ? [process.env.FRONTEND_URL || 'http://localhost:3000'] 
    : '*',
  credentials: true
};
app.use(cors(corsOptions));

app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

app.get('/health', (req, res) => {
  res.json({ status: 'OK', timestamp: new Date().toISOString() });
});

app.use("/api/scan", scanRoutes);
app.use("/api/ai-summary", summaryRoutes);
app.use("/api/report", reportRoutes);
app.use("/api/analysis", analysisRoutes);

app.use((req, res) => {
  res.status(404).json({ error: 'Route not found' });
});

app.use((err, req, res, next) => {
  console.error('Global error handler:', err);
  res.status(500).json({ 
    error: 'Internal server error',
    message: process.env.NODE_ENV === 'development' ? err.message : 'Something went wrong'
  });
});


module.exports = app;
