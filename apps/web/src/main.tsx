import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import './index.css'
import App from './App.tsx'
import { DetectionLabPage } from './DetectionLabPage.tsx'
import { LandingPage } from './LandingPage.tsx'

// Three front doors, decided by the URL:
//   ?lab            -> the Detection Lab (score a rule against ground truth)
//   any param       -> the investigation app (?scenario, ?mode, or a bare ?app)
//   no params at all -> the landing page, the ten-second explanation of what
//                       Endomorph is, with doors into the other two.
// Keying the app on "any param present" means every existing deep link
// (?scenario=..., ?mode=...) still lands in the app unchanged.
const params = new URLSearchParams(
  window.location.search,
)

const page = params.has('lab')
  ? <DetectionLabPage />
  : [...params.keys()].length > 0
    ? <App />
    : <LandingPage />

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    {page}
  </StrictMode>,
)
