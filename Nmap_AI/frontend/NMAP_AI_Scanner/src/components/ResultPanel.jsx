import React from 'react';


export default function ResultPanel({ scanOutput }) {
    return (
        <div className="bg-gray-800 p-6 rounded-xl shadow-lg border border-gray-700">
            <h2 className="text-2xl font-semibold mb-4 text-white">Nmap Scan Output</h2>
            <pre className="bg-black text-sm text-green-400 rounded-lg p-4 overflow-x-auto h-96"><code>{scanOutput}</code></pre>
        </div>
    );
}