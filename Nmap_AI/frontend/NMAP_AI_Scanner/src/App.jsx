import React from 'react'
import { ScanProvider } from './context/ScanContext'
import Home from './pages/Home'
import './App.css'

function App() {
  return (
    <ScanProvider>
      <Home />
    </ScanProvider>
  )
}

export default App
