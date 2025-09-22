import React from 'react';
import { ScanIcon } from './Icons';


export default function Header() {
    return (
        <header className="text-center mb-8">
            <h1 className="text-4xl sm:text-5xl font-bold text-white flex items-center justify-center gap-3">
                <ScanIcon className="w-10 h-10 text-blue-400" />
                Nmap Scanner AI Assistant
            </h1>
            <p className="text-gray-400 mt-2">Enter a target and let AI analyze the results for you.</p>
        </header>
    );
}