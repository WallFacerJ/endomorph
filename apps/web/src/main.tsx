import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import './index.css'
import App from './App.tsx'
import { DetectionLabPage } from './DetectionLabPage.tsx'

// The detection lab has its own front door at `?lab`, so a detection engineer
// can reach the rule scorer without playing an investigation first, while the
// default experience stays investigation-first.
const isLab = new URLSearchParams(
  window.location.search,
).has('lab')

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    {isLab ? <DetectionLabPage /> : <App />}
  </StrictMode>,
)
