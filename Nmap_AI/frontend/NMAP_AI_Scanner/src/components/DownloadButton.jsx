import React from 'react';
import { DownloadIcon } from './Icons';


export default function DownloadButton({ onClick, isDownloading = false, canDownload = true }) {
    return (
        <button 
            onClick={onClick} 
            disabled={!canDownload || isDownloading} 
            className="bg-green-600 hover:bg-green-700 disabled:bg-green-800 text-white font-bold py-3 px-8 rounded-lg flex items-center justify-center gap-2 transition duration-200"
        >
            <DownloadIcon className="w-5 h-5" />
            <span>{isDownloading ? 'Generating PDF...' : 'Download Report'}</span>
        </button>
    );
}