import React, { useMemo } from 'react';
import { marked } from 'marked';
import DOMPurify from 'dompurify';
import { Button, Panel, Spinner } from './ui';

export default function AISummary({ aiSummary, onGenerate, isSummarizing, canGenerate, hasIntel, error }) {
  const html = useMemo(
    () => (aiSummary ? DOMPurify.sanitize(marked.parse(aiSummary), { USE_PROFILES: { html: true } }) : ''),
    [aiSummary],
  );
  return (
    <Panel
      title="AI analysis"
      actions={
        <Button variant={aiSummary ? 'secondary' : 'primary'} onClick={onGenerate} disabled={isSummarizing || !canGenerate}>
          {aiSummary ? 'Write again' : 'Write analysis'}
        </Button>
      }
    >
      {isSummarizing && <Spinner label="Gemini is reading the scan results" />}
      {error && !isSummarizing && <p className="text-sm text-critical">{error}</p>}
      {!aiSummary && !isSummarizing && !error && (
        <p className="text-sm text-muted">
          Gemini writes a plain-language risk report from the scan
          {hasIntel ? ', using the CVE facts found above.' : '. Wait for the vulnerability check to finish for a more accurate report.'}
        </p>
      )}
      {aiSummary && !isSummarizing && <div className="md max-h-[32rem] overflow-y-auto pr-1" dangerouslySetInnerHTML={{ __html: html }} />}
    </Panel>
  );
}
