import React from 'react';
import { BrainCircuitIcon } from './Icons';


export default function AISummary({ aiSummary, onGenerate, isSummarizing, canGenerate = true }) {
    return (
        <div className="bg-gray-800 p-6 rounded-xl shadow-lg border border-gray-700">
            <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center mb-4">
                <h2 className="text-2xl font-semibold text-white">GenAI Analysis</h2>
                {!aiSummary && (
                    <button 
                        onClick={onGenerate} 
                        disabled={isSummarizing || !canGenerate} 
                        className="mt-2 sm:mt-0 bg-indigo-600 hover:bg-indigo-700 disabled:bg-indigo-800 text-white font-bold py-2 px-4 rounded-lg flex items-center gap-2"
                    >
                        <BrainCircuitIcon className="w-5 h-5" />
                        <span>{isSummarizing ? 'Analyzing...' : 'Analyze'}</span>
                    </button>
                )}
            </div>


            {isSummarizing && !aiSummary && (
                <div className="flex items-center justify-center h-80">
                    <div className="text-center">
                        <BrainCircuitIcon className="w-12 h-12 text-indigo-400 mx-auto animate-pulse" />
                        <p className="mt-4 text-gray-400">AI is analyzing the scan results...</p>
                    </div>
                </div>
            )}


            {aiSummary && (
                <div className="prose prose-invert prose-sm max-w-none h-96 overflow-y-auto" dangerouslySetInnerHTML={{ __html: aiSummary }}></div>
            )}


            {!aiSummary && !isSummarizing && (
                <p className="text-gray-400">Run a scan and click Analyze to generate an AI summary.</p>
            )}
        </div>
    );
}

