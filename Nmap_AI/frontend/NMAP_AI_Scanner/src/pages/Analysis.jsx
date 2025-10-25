import React, { useState, useEffect } from 'react';
import Header from '../components/Header';

export default function Analysis() {
    const [duration, setDuration] = useState(30);
    const [networkInterface, setNetworkInterface] = useState('eth0');
    const [isCapturing, setIsCapturing] = useState(false);
    const [capturedFile, setCapturedFile] = useState(null);
    const [isScoring, setIsScoring] = useState(false);
    const [scoredFile, setScoredFile] = useState(null);
    const [isAnalyzing, setIsAnalyzing] = useState(false);
    const [analysisResults, setAnalysisResults] = useState(null);
    const [error, setError] = useState(null);
    const [progress, setProgress] = useState('');

    const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:3001';

    const startCapture = async () => {
        try {
            setError(null);
            setProgress('Starting tcpdump...');
            setIsCapturing(true);

            const response = await fetch(`${API_URL}/api/analysis/start-tcpdump`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ duration, interface: networkInterface })
            });

            const data = await response.json();

            if (data.success) {
                setCapturedFile(data.pcap_file);
                setProgress(`Capturing traffic for ${duration} seconds...`);
                
                // Wait for the capture to complete
                setTimeout(() => {
                    setIsCapturing(false);
                    setProgress('Capture completed!');
                }, duration * 1000);
            } else {
                throw new Error(data.error || 'Failed to start capture');
            }
        } catch (err) {
            setError(err.message);
            setIsCapturing(false);
            setProgress('');
        }
    };

    const stopCapture = async () => {
        try {
            const response = await fetch(`${API_URL}/api/analysis/stop-tcpdump`, {
                method: 'POST'
            });

            const data = await response.json();
            if (data.success) {
                setIsCapturing(false);
                setProgress('Capture stopped');
            }
        } catch (err) {
            setError(err.message);
        }
    };

    const scoreTraffic = async () => {
        if (!capturedFile) {
            setError('No captured file available');
            return;
        }

        try {
            setError(null);
            setIsScoring(true);
            setProgress('Running scorer.py on captured data...');

            const response = await fetch(`${API_URL}/api/analysis/score`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ pcap_file: capturedFile })
            });

            const data = await response.json();

            if (data.success) {
                setScoredFile(data.output_file);
                setProgress('Scoring completed!');
            } else {
                throw new Error(data.error || 'Scoring failed');
            }
        } catch (err) {
            setError(err.message);
        } finally {
            setIsScoring(false);
        }
    };

    const runMLAnalysis = async () => {
        if (!scoredFile) {
            setError('No scored file available');
            return;
        }

        try {
            setError(null);
            setIsAnalyzing(true);
            setProgress('Running ML model analysis...');

            const response = await fetch(`${API_URL}/api/analysis/predict`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ csv_file: scoredFile })
            });

            const data = await response.json();

            if (data.success) {
                setAnalysisResults(data.summary);
                setProgress('Analysis completed!');
            } else {
                throw new Error(data.error || 'Analysis failed');
            }
        } catch (err) {
            setError(err.message);
        } finally {
            setIsAnalyzing(false);
        }
    };

    const downloadFile = async (filename) => {
        try {
            const response = await fetch(`${API_URL}/api/analysis/download/${filename}`);
            const blob = await response.blob();
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = filename;
            document.body.appendChild(a);
            a.click();
            window.URL.revokeObjectURL(url);
            document.body.removeChild(a);
        } catch (err) {
            setError('Download failed: ' + err.message);
        }
    };

    return (
        <div className="min-h-screen bg-gray-900 text-gray-200 font-sans p-4 sm:p-6 md:p-8">
            <div className="max-w-7xl mx-auto">
                <Header />
                
                <div className="mt-8">
                    <h2 className="text-3xl font-bold mb-2">Network Traffic Analysis</h2>
                    <p className="text-gray-400 mb-8">Capture, score, and analyze network traffic using ML</p>
                </div>

                {/* Error Display */}
                {error && (
                    <div className="mt-4 p-4 bg-red-900/20 border border-red-500/50 rounded-lg mb-6">
                        <p className="text-red-400">{error}</p>
                    </div>
                )}

                {/* Progress Indicator */}
                {progress && (
                    <div className="mt-4 p-4 bg-blue-900/20 border border-blue-500/50 rounded-lg mb-6">
                        <p className="text-blue-400">{progress}</p>
                    </div>
                )}

                {/* Step 1: Capture Traffic */}
                <div className="bg-gray-800 rounded-lg p-6 mb-6">
                    <h3 className="text-xl font-bold mb-4 flex items-center">
                        <span className="bg-blue-600 text-white rounded-full w-8 h-8 flex items-center justify-center mr-3">1</span>
                        Capture Network Traffic
                    </h3>
                    
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-4">
                        <div>
                            <label className="block text-sm font-medium mb-2">Duration (seconds)</label>
                            <input
                                type="number"
                                value={duration}
                                onChange={(e) => setDuration(parseInt(e.target.value))}
                                className="w-full px-4 py-2 bg-gray-700 rounded-lg text-white"
                                min="10"
                                max="300"
                                disabled={isCapturing}
                            />
                        </div>
                        
                        <div>
                            <label className="block text-sm font-medium mb-2">Network Interface</label>
                            <input
                                type="text"
                                value={networkInterface}
                                onChange={(e) => setNetworkInterface(e.target.value)}
                                className="w-full px-4 py-2 bg-gray-700 rounded-lg text-white"
                                disabled={isCapturing}
                            />
                        </div>
                    </div>

                    {!isCapturing ? (
                        <button
                            onClick={startCapture}
                            className="px-6 py-2 bg-blue-600 hover:bg-blue-700 rounded-lg font-medium transition"
                            disabled={isCapturing}
                        >
                            Start Capture
                        </button>
                    ) : (
                        <button
                            onClick={stopCapture}
                            className="px-6 py-2 bg-red-600 hover:bg-red-700 rounded-lg font-medium transition"
                        >
                            Stop Capture
                        </button>
                    )}

                    {capturedFile && (
                        <div className="mt-4 p-3 bg-green-900/20 rounded-lg">
                            <p className="text-green-400">✓ File captured: {capturedFile.split('/').pop()}</p>
                        </div>
                    )}
                </div>

                {/* Step 2: Score Traffic */}
                {capturedFile && (
                    <div className="bg-gray-800 rounded-lg p-6 mb-6">
                        <h3 className="text-xl font-bold mb-4 flex items-center">
                            <span className="bg-purple-600 text-white rounded-full w-8 h-8 flex items-center justify-center mr-3">2</span>
                            Score Captured Traffic
                        </h3>
                        
                        <p className="text-gray-400 mb-4">
                            Run the scorer.py script to analyze the captured traffic and extract features.
                        </p>

                        <button
                            onClick={scoreTraffic}
                            className="px-6 py-2 bg-purple-600 hover:bg-purple-700 rounded-lg font-medium transition"
                            disabled={isScoring || isCapturing}
                        >
                            {isScoring ? 'Scoring...' : 'Run Scorer'}
                        </button>

                        {scoredFile && (
                            <div className="mt-4 p-3 bg-green-900/20 rounded-lg">
                                <p className="text-green-400">✓ File scored: {scoredFile.split('/').pop()}</p>
                                <button
                                    onClick={() => downloadFile(scoredFile.split('/').pop())}
                                    className="mt-2 px-4 py-2 bg-gray-700 hover:bg-gray-600 rounded-lg text-sm"
                                >
                                    Download CSV
                                </button>
                            </div>
                        )}
                    </div>
                )}

                {/* Step 3: ML Analysis */}
                {scoredFile && (
                    <div className="bg-gray-800 rounded-lg p-6 mb-6">
                        <h3 className="text-xl font-bold mb-4 flex items-center">
                            <span className="bg-green-600 text-white rounded-full w-8 h-8 flex items-center justify-center mr-3">3</span>
                            Run ML Model Analysis
                        </h3>
                        
                        <p className="text-gray-400 mb-4">
                            Use the trained anomaly detection model to identify attacks and anomalies.
                        </p>

                        <button
                            onClick={runMLAnalysis}
                            className="px-6 py-2 bg-green-600 hover:bg-green-700 rounded-lg font-medium transition"
                            disabled={isAnalyzing}
                        >
                            {isAnalyzing ? 'Analyzing...' : 'Run ML Model'}
                        </button>

                        {analysisResults && (
                            <div className="mt-6 p-4 bg-gray-900 rounded-lg">
                                <h4 className="text-lg font-bold mb-3">Analysis Results</h4>
                                <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-4">
                                    <div className="bg-gray-800 p-3 rounded-lg">
                                        <p className="text-gray-400 text-sm">Total Records</p>
                                        <p className="text-2xl font-bold">{analysisResults.total_records}</p>
                                    </div>
                                    <div className="bg-gray-800 p-3 rounded-lg">
                                        <p className="text-gray-400 text-sm">Normal</p>
                                        <p className="text-2xl font-bold text-green-400">{analysisResults.normal}</p>
                                    </div>
                                    <div className="bg-gray-800 p-3 rounded-lg">
                                        <p className="text-gray-400 text-sm">Attacks</p>
                                        <p className="text-2xl font-bold text-red-400">{analysisResults.attacks}</p>
                                    </div>
                                    <div className="bg-gray-800 p-3 rounded-lg">
                                        <p className="text-gray-400 text-sm">High Confidence Alerts</p>
                                        <p className="text-2xl font-bold text-yellow-400">{analysisResults.high_confidence_alerts}</p>
                                    </div>
                                </div>

                                {Object.keys(analysisResults.attack_breakdown).length > 0 && (
                                    <div className="mt-4">
                                        <h5 className="font-bold mb-2">Attack Breakdown:</h5>
                                        <div className="grid grid-cols-2 md:grid-cols-3 gap-2">
                                            {Object.entries(analysisResults.attack_breakdown).map(([type, count]) => (
                                                <div key={type} className="bg-red-900/20 p-2 rounded">
                                                    <span className="text-red-400 font-medium">{type}:</span> {count}
                                                </div>
                                            ))}
                                        </div>
                                    </div>
                                )}
                            </div>
                        )}
                    </div>
                )}

                {/* Navigation */}
                <div className="mt-8 flex gap-4">
                    <a href="/" className="px-6 py-2 bg-gray-700 hover:bg-gray-600 rounded-lg">
                        ← Back to Scanner
                    </a>
                </div>
            </div>
        </div>
    );
}
