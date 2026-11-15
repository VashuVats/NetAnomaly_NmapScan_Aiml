import React from 'react';
import { DownloadIcon } from './Icons';
import { Button } from './ui';

export default function DownloadButton({ onClick, isDownloading = false, canDownload = true }) {
  return (
    <Button variant="secondary" onClick={onClick} disabled={!canDownload || isDownloading} title={canDownload ? '' : 'Write the AI analysis first'}>
      <DownloadIcon className="h-4 w-4" />
      {isDownloading ? 'Making PDF' : 'Download PDF report'}
    </Button>
  );
}
