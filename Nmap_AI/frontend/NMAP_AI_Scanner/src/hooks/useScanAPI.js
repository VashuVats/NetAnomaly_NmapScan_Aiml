import { useCallback } from 'react';
import { useScan } from '../context/ScanContext';
import { apiStartScan, apiGenerateAISummary, apiDownloadReport } from '../utils/api';

export function useScanAPI() {
  const { state, actions } = useScan();

  const startScan = useCallback(async (target, scanType) => {
    try {
      actions.startScan(target, scanType);
      const result = await apiStartScan({ target, scanType });
      actions.scanSuccess(result);
    } catch (error) {
      console.error('Scan failed:', error);
      actions.scanError(error.message);
    }
  }, [actions]);

  const generateAISummary = useCallback(async () => {
    if (!state.scanOutput) return;
    
    try {
      actions.startAIAnalysis();
      const result = await apiGenerateAISummary({ 
        scanOutput: state.scanOutput, 
        target: state.target 
      });
      actions.aiAnalysisSuccess(result.summary);
    } catch (error) {
      console.error('AI analysis failed:', error);
      actions.aiAnalysisError(error.message);
    }
  }, [state.scanOutput, state.target, actions]);

  const downloadReport = useCallback(async () => {
    if (!state.scanOutput || !state.aiSummary) return;
    
    try {
      actions.startDownload();
      const blob = await apiDownloadReport({
        target: state.target,
        scanOutput: state.scanOutput,
        aiSummary: state.aiSummary
      });
      
      // Create download link
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `nmap-report-${state.target}-${Date.now()}.pdf`;
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(url);
      
      actions.downloadSuccess();
    } catch (error) {
      console.error('Download failed:', error);
      actions.downloadError(error.message);
    }
  }, [state.scanOutput, state.aiSummary, state.target, actions]);

  const resetScan = useCallback(() => {
    actions.resetScan();
  }, [actions]);

  const resetAI = useCallback(() => {
    actions.resetAI();
  }, [actions]);

  const resetAll = useCallback(() => {
    actions.resetAll();
  }, [actions]);

  return {
    // State
    state,
    
    // Actions
    startScan,
    generateAISummary,
    downloadReport,
    resetScan,
    resetAI,
    resetAll,
    
    // Computed values
    canGenerateAI: !!state.scanOutput && !state.isAnalyzing,
    canDownload: !!state.scanOutput && !!state.aiSummary && !state.isDownloading,
    hasErrors: !!(state.scanError || state.aiError || state.downloadError),
  };
}
