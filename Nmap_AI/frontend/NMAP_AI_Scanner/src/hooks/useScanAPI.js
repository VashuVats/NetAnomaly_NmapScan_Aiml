import { useCallback } from 'react';
import { useScan } from '../context/ScanContext';
import { apiDownloadReport, apiEnrich, apiGenerateAISummary, apiStartScan, downloadBlob } from '../utils/api';

export function useScanAPI() {
  const { state, actions } = useScan();

  const lookUpVulnerabilities = useCallback(async (hosts) => {
    if (!hosts || !hosts.length) return;
    actions.startEnrich();
    try {
      actions.enrichSuccess(await apiEnrich({ hosts }));
    } catch (error) {
      actions.enrichError(error.message);
    }
  }, [actions]);

  const startScan = useCallback(async (target, scanType) => {
    actions.startScan(target, scanType);
    let result;
    try {
      result = await apiStartScan({ target, scanType });
      actions.scanSuccess(result);
    } catch (error) {
      actions.scanError(error.message);
      return;
    }
    // CVE lookups start on their own once the scan is done
    const hasVersions = (result.hosts || []).some((h) => h.ports.some((p) => p.state === 'open' && p.cpes.length));
    if (hasVersions) lookUpVulnerabilities(result.hosts);
  }, [actions, lookUpVulnerabilities]);

  const generateAISummary = useCallback(async () => {
    if (!state.scanOutput) return;
    actions.startAIAnalysis();
    try {
      const data = await apiGenerateAISummary({ scanOutput: state.scanOutput, target: state.target, intel: state.intel });
      actions.aiAnalysisSuccess(data.summary);
    } catch (error) {
      actions.aiAnalysisError(error.message);
    }
  }, [state.scanOutput, state.target, state.intel, actions]);

  const downloadReport = useCallback(async () => {
    if (!state.scanOutput || !state.aiSummary) return;
    actions.startDownload();
    try {
      const blob = await apiDownloadReport({ target: state.target, scanOutput: state.scanOutput,
        aiSummary: state.aiSummary, intel: state.intel });
      const safe = state.target.replace(/[^a-zA-Z0-9.-]/g, '_');
      await downloadBlob(blob, `netscan-report-${safe}-${Date.now()}.pdf`);
      actions.downloadSuccess();
    } catch (error) {
      actions.downloadError(error.message);
    }
  }, [state.scanOutput, state.aiSummary, state.target, state.intel, actions]);

  return {
    state,
    startScan,
    lookUpVulnerabilities,
    generateAISummary,
    downloadReport,
    canGenerateAI: !!state.scanOutput && !state.isAnalyzing,
    canDownload: !!state.scanOutput && !!state.aiSummary && !state.isDownloading,
  };
}
