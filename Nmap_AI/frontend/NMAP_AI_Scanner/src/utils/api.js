// In development Vite proxies /api to the backend (see vite.config.js), so the default is ''.
export const API_BASE_URL = import.meta.env.VITE_API_URL || '';

async function request(path, { method = 'GET', body, asBlob = false } = {}) {
  let res;
  try {
    res = await fetch(`${API_BASE_URL}${path}`, {
      method,
      headers: body ? { 'Content-Type': 'application/json' } : undefined,
      body: body ? JSON.stringify(body) : undefined,
    });
  } catch {
    throw new Error('Cannot reach the backend. Check that it is running (npm start in Nmap_AI/backend).');
  }
  if (!res.ok) {
    const data = await res.json().catch(() => ({}));
    const parts = [data.error, data.details, data.help].filter(Boolean);
    throw new Error(parts.length ? parts.join('. ') : `Request failed (${res.status})`);
  }
  return asBlob ? res.blob() : res.json();
}

export const apiStartScan = ({ target, scanType }) =>
  request('/api/scan', { method: 'POST', body: { target, scanType } });

export const apiEnrich = ({ hosts }) =>
  request('/api/intel/enrich', { method: 'POST', body: { hosts } });

export const apiGenerateAISummary = ({ scanOutput, target, intel }) =>
  request('/api/ai-summary', { method: 'POST', body: { scanOutput, target, intel } });

export const apiDownloadReport = ({ target, scanOutput, aiSummary, intel }) =>
  request('/api/report', { method: 'POST', body: { target, scanOutput, aiSummary, intel }, asBlob: true });

// Traffic analysis (proxied by the backend to the Python ML API)
export const apiStartCapture = ({ duration, networkInterface }) =>
  request('/api/analysis/start-tcpdump', { method: 'POST', body: { duration, interface: networkInterface } });
export const apiStopCapture = () => request('/api/analysis/stop-tcpdump', { method: 'POST' });
export const apiRunZeek = ({ pcapFile }) =>
  request('/api/analysis/score', { method: 'POST', body: { pcap_file: pcapFile } });
export const apiPredict = ({ connLog }) =>
  request('/api/analysis/predict', { method: 'POST', body: { conn_log: connLog } });
export const apiMlHealth = () => request('/api/analysis/health');

export async function downloadBlob(blob, filename) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

export async function apiDownloadResult(filename) {
  const name = String(filename).split(/[\\/]/).pop();
  const blob = await request(`/api/analysis/download/${encodeURIComponent(name)}`, { asBlob: true });
  await downloadBlob(blob, name);
}
