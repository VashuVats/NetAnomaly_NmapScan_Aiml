import React, { useState } from 'react';
import { LoaderDots } from './LoaderDots';


export default function ScanForm({ onStartScan, isLoading = false }) {
    const [target, setTarget] = useState('');
    const [scanType, setScanType] = useState('basic');
    const [error, setError] = useState('');


    async function submit(e) {
        e && e.preventDefault();
        setError('');
        if (!target.trim()) return setError('Please enter target');
        
        // Basic validation for IP/domain
        const targetValue = target.trim();
        const isValidTarget = /^[a-zA-Z0-9.-]+$/.test(targetValue) && targetValue.length > 0;
        if (!isValidTarget) return setError('Please enter a valid IP address or domain name');
        
        // call parent handler which will call API
        try {
            await onStartScan({ target: targetValue, scanType });
        } catch (err) {
            console.error(err);
            setError(err.message || 'Scan failed');
        }
    }


    return (
        <form onSubmit={submit} className="bg-gray-800 p-6 rounded-xl shadow-2xl border border-gray-700">
            <div className="flex flex-col sm:flex-row items-center gap-4">
                <input value={target} onChange={e => setTarget(e.target.value)} placeholder="e.g., scanme.nmap.org or 192.168.1.1" className="w-full px-4 py-3 bg-gray-700 text-white rounded-lg border border-gray-600" />
                <select value={scanType} onChange={e => setScanType(e.target.value)} className="w-full sm:w-auto px-4 py-3 bg-gray-700 text-white rounded-lg border border-gray-600">
                    <option value="basic">Basic Scan (-sV)</option>
                    <option value="aggressive">Aggressive Scan (-A)</option>
                    <option value="passive">Passive Scan (-sS -T4)</option>
                    <option value="vuln">Vuln Scan (--script vuln)</option>
                </select>
                <button type="submit" disabled={isLoading} className="w-full sm:w-auto bg-blue-600 hover:bg-blue-700 disabled:bg-blue-800 text-white font-bold py-3 px-6 rounded-lg flex items-center justify-center gap-2">
                    {isLoading ? <LoaderDots /> : <>Scan</>}
                </button>
            </div>
            {error && <p className="text-red-400 mt-4 text-center">{error}</p>}
        </form>
    );
}

