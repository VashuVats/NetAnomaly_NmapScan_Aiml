import React, { createContext, useContext, useReducer } from 'react';

// Initial state
const initialState = {
  // Scan data
  scanId: null,
  target: '',
  scanType: 'basic',
  scanOutput: '',
  timestamp: null,
  
  // AI Analysis
  aiSummary: '',
  isAnalyzing: false,
  
  // Loading states
  isScanning: false,
  isDownloading: false,
  
  // Error states
  scanError: null,
  aiError: null,
  downloadError: null,
};

// Action types
const ActionTypes = {
  // Scan actions
  START_SCAN: 'START_SCAN',
  SCAN_SUCCESS: 'SCAN_SUCCESS',
  SCAN_ERROR: 'SCAN_ERROR',
  
  // AI actions
  START_AI_ANALYSIS: 'START_AI_ANALYSIS',
  AI_ANALYSIS_SUCCESS: 'AI_ANALYSIS_SUCCESS',
  AI_ANALYSIS_ERROR: 'AI_ANALYSIS_ERROR',
  
  // Download actions
  START_DOWNLOAD: 'START_DOWNLOAD',
  DOWNLOAD_SUCCESS: 'DOWNLOAD_SUCCESS',
  DOWNLOAD_ERROR: 'DOWNLOAD_ERROR',
  
  // Reset actions
  RESET_SCAN: 'RESET_SCAN',
  RESET_AI: 'RESET_AI',
  RESET_ALL: 'RESET_ALL',
};

// Reducer
function scanReducer(state, action) {
  switch (action.type) {
    case ActionTypes.START_SCAN:
      return {
        ...state,
        isScanning: true,
        scanError: null,
        scanOutput: '',
        aiSummary: '',
        target: action.payload.target,
        scanType: action.payload.scanType,
      };
      
    case ActionTypes.SCAN_SUCCESS:
      return {
        ...state,
        isScanning: false,
        scanId: action.payload.scanId || Date.now().toString(),
        scanOutput: action.payload.scanOutput,
        timestamp: action.payload.timestamp,
        scanError: null,
      };
      
    case ActionTypes.SCAN_ERROR:
      return {
        ...state,
        isScanning: false,
        scanError: action.payload.error,
        scanOutput: `Scan failed: ${action.payload.error}`,
      };
      
    case ActionTypes.START_AI_ANALYSIS:
      return {
        ...state,
        isAnalyzing: true,
        aiError: null,
      };
      
    case ActionTypes.AI_ANALYSIS_SUCCESS:
      return {
        ...state,
        isAnalyzing: false,
        aiSummary: action.payload.summary,
        aiError: null,
      };
      
    case ActionTypes.AI_ANALYSIS_ERROR:
      return {
        ...state,
        isAnalyzing: false,
        aiError: action.payload.error,
        aiSummary: `AI analysis failed: ${action.payload.error}`,
      };
      
    case ActionTypes.START_DOWNLOAD:
      return {
        ...state,
        isDownloading: true,
        downloadError: null,
      };
      
    case ActionTypes.DOWNLOAD_SUCCESS:
      return {
        ...state,
        isDownloading: false,
        downloadError: null,
      };
      
    case ActionTypes.DOWNLOAD_ERROR:
      return {
        ...state,
        isDownloading: false,
        downloadError: action.payload.error,
      };
      
    case ActionTypes.RESET_SCAN:
      return {
        ...state,
        scanId: null,
        scanOutput: '',
        scanError: null,
        timestamp: null,
      };
      
    case ActionTypes.RESET_AI:
      return {
        ...state,
        aiSummary: '',
        aiError: null,
        isAnalyzing: false,
      };
      
    case ActionTypes.RESET_ALL:
      return {
        ...initialState,
      };
      
    default:
      return state;
  }
}

// Create context
const ScanContext = createContext();

// Provider component
export function ScanProvider({ children }) {
  const [state, dispatch] = useReducer(scanReducer, initialState);
  
  // Action creators
  const actions = {
    startScan: (target, scanType) => {
      dispatch({
        type: ActionTypes.START_SCAN,
        payload: { target, scanType }
      });
    },
    
    scanSuccess: (data) => {
      dispatch({
        type: ActionTypes.SCAN_SUCCESS,
        payload: data
      });
    },
    
    scanError: (error) => {
      dispatch({
        type: ActionTypes.SCAN_ERROR,
        payload: { error }
      });
    },
    
    startAIAnalysis: () => {
      dispatch({ type: ActionTypes.START_AI_ANALYSIS });
    },
    
    aiAnalysisSuccess: (summary) => {
      dispatch({
        type: ActionTypes.AI_ANALYSIS_SUCCESS,
        payload: { summary }
      });
    },
    
    aiAnalysisError: (error) => {
      dispatch({
        type: ActionTypes.AI_ANALYSIS_ERROR,
        payload: { error }
      });
    },
    
    startDownload: () => {
      dispatch({ type: ActionTypes.START_DOWNLOAD });
    },
    
    downloadSuccess: () => {
      dispatch({ type: ActionTypes.DOWNLOAD_SUCCESS });
    },
    
    downloadError: (error) => {
      dispatch({
        type: ActionTypes.DOWNLOAD_ERROR,
        payload: { error }
      });
    },
    
    resetScan: () => {
      dispatch({ type: ActionTypes.RESET_SCAN });
    },
    
    resetAI: () => {
      dispatch({ type: ActionTypes.RESET_AI });
    },
    
    resetAll: () => {
      dispatch({ type: ActionTypes.RESET_ALL });
    },
  };
  
  return (
    <ScanContext.Provider value={{ state, actions }}>
      {children}
    </ScanContext.Provider>
  );
}

// Custom hook to use the context
export function useScan() {
  const context = useContext(ScanContext);
  if (!context) {
    throw new Error('useScan must be used within a ScanProvider');
  }
  return context;
}

export { ActionTypes };
