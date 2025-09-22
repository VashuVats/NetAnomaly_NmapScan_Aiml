import React from 'react';
import Header from '../components/Header';
import ScanForm from '../components/ScanForm';
import ResultPanel from '../components/ResultPanel';
import AISummary from '../components/AISummary';
import DownloadButton from '../components/DownloadButton';
import { useScanAPI } from '../hooks/useScanAPI';

export default function Home() {
    const {
        state,
        startScan,
        generateAISummary,
        downloadReport,
        canGenerateAI,
        canDownload,
        hasErrors
    } = useScanAPI();

    async function onStartScan({ target, scanType }) {
        await startScan(target, scanType);
    }

    async function onGenerateAI() {
        await generateAISummary();
    }

    async function onDownload() {
        await downloadReport();
    }

    return (
        <div className="min-h-screen bg-gray-900 text-gray-200 font-sans p-4 sm:p-6 md:p-8">
            <div className="max-w-7xl mx-auto">
                <Header />
                <ScanForm onStartScan={onStartScan} isLoading={state.isScanning} />

                {/* Error Display */}
                {hasErrors && (
                    <div className="mt-4 p-4 bg-red-900/20 border border-red-500/50 rounded-lg">
                        {state.scanError && (
                            <p className="text-red-400">Scan Error: {state.scanError}</p>
                        )}
                        {state.aiError && (
                            <p className="text-red-400">AI Analysis Error: {state.aiError}</p>
                        )}
                        {state.downloadError && (
                            <p className="text-red-400">Download Error: {state.downloadError}</p>
                        )}
                    </div>
                )}

                {state.scanOutput && (
                    <div className="mt-8 grid grid-cols-1 lg:grid-cols-2 gap-8">
                        <div className="flex flex-col">
                            <ResultPanel scanOutput={state.scanOutput} />
                        </div>
                        <div className="flex flex-col">
                            <AISummary 
                                aiSummary={state.aiSummary} 
                                onGenerate={onGenerateAI} 
                                isSummarizing={state.isAnalyzing}
                                canGenerate={canGenerateAI}
                            />
                        </div>
                    </div>
                )}
                
                {state.aiSummary && (
                    <div className="mt-8 flex justify-center">
                        <DownloadButton 
                            onClick={onDownload} 
                            isDownloading={state.isDownloading}
                            canDownload={canDownload}
                        />
                    </div>
                )}
            </div>
        </div>
    );
}

