import React, { useState, useEffect, useRef } from 'react';
import Header from '../components/Header';

export default function Analysis() {
    const [duration, setDuration] = useState(30);
    const [networkInterface, setNetworkInterface] = useState('eth0');
    const [isCapturing, setIsCapturing] = useState(false);
    const [capturedFile, setCapturedFile] = useState(null);

    // changed: keep both full server path and display filename
    const [scoredFileFull, setScoredFileFull] = useState(null); // full path returned by backend
    const [scoredFile, setScoredFile] = useState(null); // basename for UI / download

    const [isScoring, setIsScoring] = useState(false);
    const [isAnalyzing, setIsAnalyzing] = useState(false);
    const [analysisResults, setAnalysisResults] = useState(null);
    const [error, setError] = useState(null);
    const [progress, setProgress] = useState('');
    const [showThreatModal, setShowThreatModal] = useState(false);
    const [threatInfo, setThreatInfo] = useState(null);
    const captureTimerRef = useRef(null);

    const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:3001';

    // Cleanup timer on unmount
    useEffect(() => {
        return () => {
            if (captureTimerRef.current) {
                clearTimeout(captureTimerRef.current);
            }
        };
    }, []);

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
                captureTimerRef.current = setTimeout(() => {
                    setIsCapturing(false);
                    setProgress('Capture completed!');
                    captureTimerRef.current = null;
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
            // Clear the timer if it exists
            if (captureTimerRef.current) {
                clearTimeout(captureTimerRef.current);
                captureTimerRef.current = null;
            }

            const response = await fetch(`${API_URL}/api/analysis/stop-tcpdump`, {
                method: 'POST'
            });

            const data = await response.json();
            if (data.success) {
                setIsCapturing(false);
                setProgress('Capture stopped by user');
            }
        } catch (err) {
            setError(err.message);
            setIsCapturing(false);
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
                // backend may return conn_log (full path) or output_file
                const full = data.conn_log || data.output_file || data.conn || null;
                const display = full ? full.split('/').pop() : (data.output_file ? data.output_file.split('/').pop() : null);

                setScoredFileFull(full);
                setScoredFile(display);

                // also support older responses where conn log moved to results path
                setProgress('Scoring completed!');
            } else {
                // helpful backend message may be in data.error or data.stderr
                const msg = data.error || data.stderr || JSON.stringify(data);
                throw new Error(msg);
            }
        } catch (err) {
            setError(err.message);
        } finally {
            setIsScoring(false);
        }
    };

    const runMLAnalysis = async () => {
        // frontend must send full server path (conn_log) to backend
        if (!scoredFileFull && !scoredFile) {
            setError('No scored file available');
            return;
        }

        try {
            setError(null);
            setIsAnalyzing(true);
            setProgress('Running ML model analysis...');

            // prefer full path if available
            const body = { conn_log: scoredFileFull || scoredFile };

            const response = await fetch(`${API_URL}/api/analysis/predict`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(body)
            });

            const data = await response.json();

            if (response.ok && data) {
                // store entire response so UI can show details (output_csv, scorer_stdout, etc.)
                setAnalysisResults(data);
                // also set scoredFileFull to output csv for download convenience
                if (data.output_csv) {
                    setScoredFileFull(data.output_csv);
                    setScoredFile(String(data.output_csv).split('/').pop());
                }
                setProgress('Analysis completed!');
            } else {
                const msg = (data && (data.error || data.stderr || data.message)) || 'Analysis failed';
                throw new Error(msg);
            }
        } catch (err) {
            setError(err.message);
        } finally {
            setIsAnalyzing(false);
        }
    };

    const downloadFile = async (filename) => {
        try {
            // backend download endpoint expects filename within RESULTS_DIR
            // ensure we pass basename only
            const name = filename.split('/').pop();
            const response = await fetch(`${API_URL}/api/analysis/download/${encodeURIComponent(name)}`);
            if (!response.ok) throw new Error('Download failed');
            const blob = await response.blob();
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = name;
            document.body.appendChild(a);
            a.click();
            window.URL.revokeObjectURL(url);
            document.body.removeChild(a);
        } catch (err) {
            setError('Download failed: ' + err.message);
        }
    };

    // When analysisResults updates, derive threat status and optionally show modal
    useEffect(() => {
        if (!analysisResults) return;

        const high = Number(analysisResults.high_confidence_alerts ?? analysisResults.high_conf_attacks ?? 0);
        const attacks = Number(analysisResults.attacks ?? analysisResults.total_attacks ?? analysisResults.pred_count ?? 0);
        const records = Number(analysisResults.total_records ?? analysisResults.n_records ?? 0);

        let level = 'no-data';
        if (records === 0) level = 'no-data';
        else if (high > 0) level = 'high';
        else if (attacks > 0) level = 'medium';
        else level = 'safe';

        const info = {
            level,
            high,
            attacks,
            records
        };
        setThreatInfo(info);

        // Show modal for medium/high
        if (level === 'high' || level === 'medium') {
            setShowThreatModal(true);
        } else {
            setShowThreatModal(false);
        }
    }, [analysisResults]);

    const closeModal = () => setShowThreatModal(false);

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
                                <p className="text-green-400">✓ File scored: {scoredFile}</p>
                                <button
                                    onClick={() => downloadFile(scoredFile)}
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

                                {/* Summary cards (if provided) */}
                                <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-4">
                                    <div className="bg-gray-800 p-3 rounded-lg">
                                        <p className="text-gray-400 text-sm">Total Records</p>
                                        <p className="text-2xl font-bold">{analysisResults.total_records ?? analysisResults.n_records ?? analysisResults.pred_count ?? '-'}</p>
                                    </div>
                                    <div className="bg-gray-800 p-3 rounded-lg">
                                        <p className="text-gray-400 text-sm">Normal</p>
                                        <p className="text-2xl font-bold text-green-400">{analysisResults.normal ?? '-'}</p>
                                    </div>
                                    <div className="bg-gray-800 p-3 rounded-lg">
                                        <p className="text-gray-400 text-sm">Attacks</p>
                                        <p className="text-2xl font-bold text-red-400">{analysisResults.attacks ?? '-'}</p>
                                    </div>
                                    <div className="bg-gray-800 p-3 rounded-lg">
                                        <p className="text-gray-400 text-sm">High Confidence Alerts</p>
                                        <p className="text-2xl font-bold text-yellow-400">{analysisResults.high_confidence_alerts ?? '-'}</p>
                                    </div>
                                </div>

                                {/* Attack breakdown if present */}
                                {analysisResults.attack_breakdown && Object.keys(analysisResults.attack_breakdown).length > 0 && (
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

                                {/* Download / raw output area */}
                                <div className="mt-4 flex flex-col md:flex-row md:items-center md:justify-between gap-3">
                                    <div className="flex items-center gap-3">
                                        {analysisResults.output_csv && (
                                            <button
                                                onClick={() => downloadFile(analysisResults.output_csv)}
                                                className="px-4 py-2 bg-indigo-600 hover:bg-indigo-700 rounded-lg text-white"
                                            >
                                                Download Predictions CSV
                                            </button>
                                        )}

                                        {/* Also allow downloading the conn log if backend returned it */}
                                        {analysisResults.zeek_conn && (
                                            <button
                                                onClick={() => downloadFile(analysisResults.zeek_conn)}
                                                className="px-4 py-2 bg-gray-700 hover:bg-gray-600 rounded-lg text-white"
                                            >
                                                Download conn log
                                            </button>
                                        )}
                                    </div>

                                    {/* Show short scorer output / warnings */}
                                    <div className="text-sm text-gray-400">
                                        {analysisResults.warning && <div className="text-yellow-300">Warning: {analysisResults.warning}</div>}
                                        {analysisResults.model_error && <div className="text-red-400">Model: {analysisResults.model_error}</div>}
                                        {analysisResults.scorer_stdout && <div>Scorer: {String(analysisResults.scorer_stdout).slice(0, 200)}{String(analysisResults.scorer_stdout).length > 200 ? '...' : ''}</div>}
                                    </div>
                                </div>
                            </div>
                        )}
                    </div>
                )}

                {/* Inline threat banner under Analysis area */}
                {analysisResults && threatInfo && (
                    <div className="mt-4">
                        {threatInfo.level === 'high' && (
                            <div className="p-4 rounded-lg bg-red-800 text-white">
                                <strong>Under Attack:</strong> {threatInfo.high} high-confidence alerts detected — check predictions and take action.
                            </div>
                        )}
                        {threatInfo.level === 'medium' && (
                            <div className="p-4 rounded-lg bg-yellow-700 text-gray-900">
                                <strong>Possible Attack:</strong> {threatInfo.attacks} suspicious events detected. Review results.
                            </div>
                        )}
                        {threatInfo.level === 'safe' && (
                            <div className="p-4 rounded-lg bg-green-800 text-white">
                                <strong>No worries:</strong> No attacks detected in this analysis.
                            </div>
                        )}
                        {threatInfo.level === 'no-data' && (
                            <div className="p-4 rounded-lg bg-gray-700 text-gray-300">
                                <strong>No data:</strong> No records found in predictions.
                            </div>
                        )}
                    </div>
                )}

                {/* Modal popup (appears for medium/high) */}
                {showThreatModal && threatInfo && (
                    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black bg-opacity-60">
                        <div className="bg-gray-800 rounded-lg max-w-lg w-full p-6">
                            <h3 className={`text-xl font-bold mb-2 ${threatInfo.level === 'high' ? 'text-red-400' : 'text-yellow-300'}`}>
                                {threatInfo.level === 'high' ? 'High-confidence attack detected' : 'Suspicious activity detected'}
                            </h3>
                            <p className="text-sm text-gray-300 mb-4">
                                Records analyzed: {threatInfo.records} — Suspicious events: {threatInfo.attacks} — High confidence: {threatInfo.high}
                            </p>

                            <div className="flex gap-3">
                                {analysisResults && analysisResults.output_csv && (
                                    <button
                                        onClick={() => downloadFile(analysisResults.output_csv)}
                                        className="px-4 py-2 bg-indigo-600 hover:bg-indigo-700 rounded text-white"
                                    >
                                        Download Predictions CSV
                                    </button>
                                )}
                                {analysisResults && analysisResults.zeek_conn && (
                                    <button
                                        onClick={() => downloadFile(analysisResults.zeek_conn)}
                                        className="px-4 py-2 bg-gray-700 hover:bg-gray-600 rounded text-white"
                                    >
                                        Download conn log
                                    </button>
                                )}
                                <button onClick={closeModal} className="ml-auto px-4 py-2 bg-gray-600 hover:bg-gray-500 rounded text-white">
                                    Close
                                </button>
                            </div>
                        </div>
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
