import React, { createContext, useContext, useMemo, useReducer } from 'react';

const initialState = {
  // scan
  target: '',
  scanType: 'basic',
  scanOutput: '',
  hosts: [],
  stats: null,
  timestamp: null,
  isScanning: false,
  scanError: null,
  // threat intel (CVE lookups)
  intel: null,
  isEnriching: false,
  intelError: null,
  // AI summary
  aiSummary: '',
  isAnalyzing: false,
  aiError: null,
  // PDF
  isDownloading: false,
  downloadError: null,
};

function reducer(state, { type, payload }) {
  switch (type) {
    case 'START_SCAN':
      return { ...initialState, isScanning: true, target: payload.target, scanType: payload.scanType };
    case 'SCAN_SUCCESS':
      return { ...state, isScanning: false, scanOutput: payload.scanOutput, hosts: payload.hosts || [],
        stats: payload.stats || null, timestamp: payload.timestamp };
    case 'SCAN_ERROR':
      // keep scanOutput empty so the AI is never asked to analyse an error message
      return { ...state, isScanning: false, scanError: payload };
    case 'START_ENRICH':
      return { ...state, isEnriching: true, intelError: null };
    case 'ENRICH_SUCCESS':
      return { ...state, isEnriching: false, intel: payload };
    case 'ENRICH_ERROR':
      return { ...state, isEnriching: false, intelError: payload };
    case 'START_AI':
      return { ...state, isAnalyzing: true, aiError: null };
    case 'AI_SUCCESS':
      return { ...state, isAnalyzing: false, aiSummary: payload };
    case 'AI_ERROR':
      return { ...state, isAnalyzing: false, aiError: payload };
    case 'START_DOWNLOAD':
      return { ...state, isDownloading: true, downloadError: null };
    case 'DOWNLOAD_SUCCESS':
      return { ...state, isDownloading: false };
    case 'DOWNLOAD_ERROR':
      return { ...state, isDownloading: false, downloadError: payload };
    case 'RESET_ALL':
      return initialState;
    default:
      return state;
  }
}

const ScanContext = createContext(null);

export function ScanProvider({ children }) {
  const [state, dispatch] = useReducer(reducer, initialState);
  const actions = useMemo(() => {
    const make = (type) => (payload) => dispatch({ type, payload });
    return {
      startScan: (target, scanType) => dispatch({ type: 'START_SCAN', payload: { target, scanType } }),
      scanSuccess: make('SCAN_SUCCESS'),
      scanError: make('SCAN_ERROR'),
      startEnrich: make('START_ENRICH'),
      enrichSuccess: make('ENRICH_SUCCESS'),
      enrichError: make('ENRICH_ERROR'),
      startAIAnalysis: make('START_AI'),
      aiAnalysisSuccess: make('AI_SUCCESS'),
      aiAnalysisError: make('AI_ERROR'),
      startDownload: make('START_DOWNLOAD'),
      downloadSuccess: make('DOWNLOAD_SUCCESS'),
      downloadError: make('DOWNLOAD_ERROR'),
      resetAll: make('RESET_ALL'),
    };
  }, []);
  return <ScanContext.Provider value={{ state, actions }}>{children}</ScanContext.Provider>;
}

// eslint-disable-next-line react-refresh/only-export-components
export function useScan() {
  const context = useContext(ScanContext);
  if (!context) throw new Error('useScan must be used within a ScanProvider');
  return context;
}
