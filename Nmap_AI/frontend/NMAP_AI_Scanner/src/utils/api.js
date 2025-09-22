// API base URL configuration
const API_BASE_URL = import.meta.env.VITE_API_URL || 'http://localhost:3001';

export async function apiStartScan({ target, scanType }) {
  // POST /api/scan -> { scanOutput, target, scanType, timestamp }
  const res = await fetch(`${API_BASE_URL}/api/scan`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ target, scanType }),
  });
  
  if (!res.ok) {
    const errorData = await res.json().catch(() => ({}));
    throw new Error(errorData.error || `Scan failed: ${res.status} ${res.statusText}`);
  }
  
  const data = await res.json();
  return {
    scanId: Date.now().toString(), // Generate client-side ID
    scanOutput: data.scanOutput,
    target: data.target,
    scanType: data.scanType,
    timestamp: data.timestamp
  };
}

export async function apiGenerateAISummary({ scanOutput, target }) {
  // POST /api/ai-summary -> { success, summary, target, timestamp, analysisLength }
  const res = await fetch(`${API_BASE_URL}/api/ai-summary`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ scanOutput, target }),
  });
  
  if (!res.ok) {
    const errorData = await res.json().catch(() => ({}));
    throw new Error(errorData.error || `AI summary failed: ${res.status} ${res.statusText}`);
  }
  
  const data = await res.json();
  return {
    summary: data.summary,
    target: data.target,
    timestamp: data.timestamp,
    analysisLength: data.analysisLength
  };
}

export async function apiDownloadReport({ target, scanOutput, aiSummary }) {
  // POST /api/report -> returns PDF blob
  const res = await fetch(`${API_BASE_URL}/api/report`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ target, scanOutput, aiSummary }),
  });
  
  if (!res.ok) {
    const errorData = await res.json().catch(() => ({}));
    throw new Error(errorData.error || `Report download failed: ${res.status} ${res.statusText}`);
  }
  
  const blob = await res.blob();
  return blob;
}
