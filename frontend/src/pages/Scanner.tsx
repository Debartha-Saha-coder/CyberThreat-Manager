import React, { useState, useRef } from 'react'
import { useNavigate } from 'react-router-dom'
import { Search, Shield, AlertCircle, CheckCircle, Loader2, Globe } from 'lucide-react'
import { motion, AnimatePresence } from 'framer-motion'
import { scanService } from '../services'
import type { ScanListItem } from '../types'
import { RiskBadge } from '../components/RiskBadge'

type Phase = 'idle' | 'submitting' | 'polling' | 'done' | 'error'

const ENGINE_LABELS = [
  { key: 'threat_engine_ran',    label: 'Threat Intelligence',       color: '#ef4444' },
  { key: 'web_engine_ran',       label: 'Web Security Assessment',    color: '#3b82f6' },
  { key: 'cert_engine_ran',      label: 'Certificate Analysis',       color: '#7c3aed' },
  { key: 'community_engine_ran', label: 'Community Intelligence',     color: '#10b981' },
]

export default function Scanner() {
  const navigate = useNavigate()
  const [url, setUrl] = useState('')
  const [phase, setPhase] = useState<Phase>('idle')
  const [errorMsg, setErrorMsg] = useState('')
  const [scan, setScan] = useState<ScanListItem | null>(null)
  const inputRef = useRef<HTMLInputElement>(null)

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!url.trim()) return
    setPhase('submitting')
    setErrorMsg('')
    setScan(null)

    try {
      const resp = await scanService.submit(url.trim())
      const scanId = resp.data.scan_id
      setPhase('polling')

      await scanService.pollUntilComplete(scanId, (s) => setScan(s))
      const finalResp = await scanService.get(scanId)
      setScan(finalResp.data)
      setPhase('done')
    } catch (err: unknown) {
      const msg = (err as { response?: { data?: { detail?: string } } })?.response?.data?.detail || 'Scan failed. Please try again.'
      setErrorMsg(msg)
      setPhase('error')
    }
  }

  const handleViewReport = () => {
    if (scan) navigate(`/scan/${scan.id}`)
  }

  return (
    <div className="max-w-2xl mx-auto space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-white">Website Scanner</h1>
        <p className="text-gray-400 text-sm mt-1">
          Submit a URL for multi-engine threat analysis. All four engines run independently.
        </p>
      </div>

      {/* Input form */}
      <div className="card p-6">
        <form onSubmit={handleSubmit} className="space-y-4">
          <label className="block text-sm font-medium text-gray-300">Target URL</label>
          <div className="flex gap-3">
            <div className="relative flex-1">
              <Globe size={16} className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-500" />
              <input
                ref={inputRef}
                type="text"
                className="input-field pl-9"
                placeholder="https://example.com/path"
                value={url}
                onChange={(e) => setUrl(e.target.value)}
                disabled={phase === 'submitting' || phase === 'polling'}
              />
            </div>
            <button
              type="submit"
              className="btn-primary"
              disabled={phase === 'submitting' || phase === 'polling' || !url.trim()}
            >
              {phase === 'submitting' || phase === 'polling' ? (
                <><Loader2 size={16} className="animate-spin" /> Scanning…</>
              ) : (
                <><Search size={16} /> Scan</>
              )}
            </button>
          </div>
          <p className="text-xs text-gray-500">
            Only HTTP/HTTPS URLs are accepted. Private IP addresses and cloud metadata endpoints are blocked.
          </p>
        </form>
      </div>

      {/* Error state */}
      <AnimatePresence>
        {phase === 'error' && (
          <motion.div
            initial={{ opacity: 0, y: -8 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0 }}
            className="card p-4 flex items-start gap-3 border-red-800 bg-red-900/10"
          >
            <AlertCircle size={18} className="text-red-400 mt-0.5 flex-shrink-0" />
            <p className="text-red-400 text-sm">{errorMsg}</p>
          </motion.div>
        )}
      </AnimatePresence>

      {/* Progress */}
      <AnimatePresence>
        {(phase === 'polling' || phase === 'done') && scan && (
          <motion.div
            initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }}
            className="card p-5 space-y-4"
          >
            <div className="flex items-center justify-between">
              <h2 className="text-sm font-semibold text-gray-300">Engine Progress</h2>
              <span className={`text-xs px-2 py-0.5 rounded-full ${
                scan.status === 'completed' ? 'bg-green-900/40 text-green-400' :
                scan.status === 'running'   ? 'bg-blue-900/40 text-blue-400' :
                scan.status === 'failed'    ? 'bg-red-900/40 text-red-400' :
                'bg-gray-800 text-gray-400'
              } capitalize`}>{scan.status}</span>
            </div>

            {ENGINE_LABELS.map(({ key, label, color }) => {
              const ran = (scan as unknown as Record<string, boolean>)[key]
              const running = scan.status === 'running' || scan.status === 'pending'
              return (
                <div key={key} className="flex items-center gap-3">
                  <div className="w-5 h-5 flex-shrink-0">
                    {ran ? (
                      <CheckCircle size={18} className="text-green-400" />
                    ) : running ? (
                      <Loader2 size={18} className="animate-spin text-blue-400" />
                    ) : (
                      <div className="w-4 h-4 rounded-full border border-gray-700" />
                    )}
                  </div>
                  <span className="text-sm text-gray-300 flex-1">{label}</span>
                  <div className="w-2 h-2 rounded-full" style={{ backgroundColor: ran ? color : '#374151' }} />
                </div>
              )
            })}

            {phase === 'done' && scan.risk_classification && (
              <div className="pt-2 border-t border-gray-800 flex items-center justify-between">
                <RiskBadge classification={scan.risk_classification} score={scan.overall_risk_score} size="lg" />
                <button onClick={handleViewReport} className="btn-primary text-sm py-2">
                  View Full Report →
                </button>
              </div>
            )}
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  )
}
