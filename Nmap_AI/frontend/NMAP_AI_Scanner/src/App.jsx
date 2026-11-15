import React from 'react';
import { ScanProvider } from './context/ScanContext';
import { ThemeProvider } from './theme/ThemeContext';
import { useRoute } from './hooks/useRoute';
import AppShell from './components/AppShell';
import Home from './pages/Home';
import Analysis from './pages/Analysis';

function Pages() {
  const page = useRoute();
  return (
    <AppShell page={page}>
      {/* Both pages stay mounted so switching tabs keeps their results */}
      <div hidden={page !== 'scan'}><Home /></div>
      <div hidden={page !== 'traffic'}><Analysis /></div>
    </AppShell>
  );
}

export default function App() {
  return (
    <ThemeProvider>
      <ScanProvider>
        <Pages />
      </ScanProvider>
    </ThemeProvider>
  );
}
