import React from 'react';
import { ScanIcon } from './Icons';


export default function Header() {
    const path = window.location.pathname;
    
    return (
        <header className="mb-8">
            <div className="text-center mb-4">
                <h1 className="text-4xl sm:text-5xl font-bold text-white flex items-center justify-center gap-3">
                    <ScanIcon className="w-10 h-10 text-blue-400" />
                    NetScan AI
                </h1>
                <p className="text-gray-400 mt-2">Advanced Network Security Analysis</p>
            </div>
            
            <nav className="flex justify-center gap-4">
                <a 
                    href="/" 
                    className={`px-4 py-2 rounded-lg transition ${path === '/' ? 'bg-blue-600 text-white' : 'bg-gray-800 text-gray-300 hover:bg-gray-700'}`}
                >
                    Nmap Scanner
                </a>
                <a 
                    href="/analysis" 
                    className={`px-4 py-2 rounded-lg transition ${path === '/analysis' ? 'bg-blue-600 text-white' : 'bg-gray-800 text-gray-300 hover:bg-gray-700'}`}
                >
                    ML Analysis
                </a>
            </nav>
        </header>
    );
}