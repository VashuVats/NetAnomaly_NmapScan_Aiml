import React from 'react'
import { ScanProvider } from './context/ScanContext'
import Home from './pages/Home'
import Analysis from './pages/Analysis'
import './App.css'

function App() {
  // Simple routing based on URL
  const path = window.location.pathname;
  
  if (path === '/analysis') {
    return (
      <ScanProvider>
        <Analysis />
      </ScanProvider>
    );
  }
  
  return (
    <ScanProvider>
      <Home />
    </ScanProvider>
  );
}

export default App
