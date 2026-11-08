import React, { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { Users, Plus, ThumbsUp, ThumbsDown, ChevronRight } from 'lucide-react'
import { motion } from 'framer-motion'
import { communityService, authService } from '../services'
import type { CommunityReport } from '../types'

const CATEGORIES = [
  'phishing', 'malware', 'spam', 'scam', 'fake_brand',
  'fake_recruitment', 'fraudulent_payment', 'impersonation', 'ransomware',
  'credential_harvesting', 'other',
]

const STATUS_COLORS: Record<string, string> = {
  pending: 'text-gray-400',
  under_review: 'text-blue-400',
  verified: 'text-green-400',
  rejected: 'text-red-400',
  duplicate: 'text-gray-500',
}

export default function Community() {
  const [reports, setReports] = useState<CommunityReport[]>([])
  const [loading, setLoading] = useState(true)
  const [showForm, setShowForm] = useState(false)
  const [form, setForm] = useState({ url: '', category: 'phishing', title: '', description: '' })
  const [submitting, setSubmitting] = useState(false)
  const [submitMsg, setSubmitMsg] = useState('')
  const user = authService.currentUser()

  const loadReports = () => {
    communityService.list().then((r) => setReports(r.data)).finally(() => setLoading(false))
  }

  useEffect(() => { loadReports() }, [])

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!user) { setSubmitMsg('Please log in to submit reports.'); return }
    setSubmitting(true)
    setSubmitMsg('')
    try {
      await communityService.submit(form)
      setSubmitMsg('Report submitted successfully. It will be reviewed by an analyst.')
      setForm({ url: '', category: 'phishing', title: '', description: '' })
      setShowForm(false)
      loadReports()
    } catch (err: unknown) {
      const detail = (err as { response?: { data?: { detail?: string } } })?.response?.data?.detail
      setSubmitMsg(detail || 'Submission failed.')
    } finally {
      setSubmitting(false)
    }
  }

  const handleVote = async (id: number, vote_type: 'support' | 'dispute') => {
    if (!user) return alert('Please log in to vote.')
    try {
      await communityService.vote(id, vote_type)
      loadReports()
    } catch { /* handled */ }
  }

  return (
    <div className="max-w-3xl space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">Community Intelligence</h1>
          <p className="text-gray-400 text-sm mt-1">Community-reported threats, reviewed by analysts before verification.</p>
        </div>
        <button onClick={() => setShowForm((s) => !s)} className="btn-primary text-sm py-2">
          <Plus size={15} />Report Threat
        </button>
      </div>

      {/* Submit form */}
      {showForm && (
        <motion.div initial={{ opacity: 0, y: -8 }} animate={{ opacity: 1, y: 0 }} className="card p-5">
          <h2 className="text-sm font-semibold text-gray-300 mb-4">Submit a Report</h2>
          <form onSubmit={handleSubmit} className="space-y-3">
            <input className="input-field" placeholder="https://suspicious-site.com" value={form.url}
              onChange={(e) => setForm((f) => ({ ...f, url: e.target.value }))} required />
            <select className="input-field" value={form.category}
              onChange={(e) => setForm((f) => ({ ...f, category: e.target.value }))}>
              {CATEGORIES.map((c) => <option key={c} value={c}>{c.replace('_', ' ')}</option>)}
            </select>
            <input className="input-field" placeholder="Short title describing the threat" value={form.title}
              onChange={(e) => setForm((f) => ({ ...f, title: e.target.value }))} required minLength={5} />
            <textarea className="input-field" rows={3} placeholder="Describe the threat and how you identified it (minimum 20 characters)"
              value={form.description} onChange={(e) => setForm((f) => ({ ...f, description: e.target.value }))} required minLength={20} />
            {submitMsg && <p className="text-sm text-blue-400">{submitMsg}</p>}
            <div className="flex gap-3">
              <button type="submit" className="btn-primary text-sm py-2" disabled={submitting}>
                {submitting ? 'Submitting…' : 'Submit Report'}
              </button>
              <button type="button" onClick={() => setShowForm(false)} className="btn-secondary text-sm py-2">
                Cancel
              </button>
            </div>
          </form>
        </motion.div>
      )}

      {/* Reports list */}
      <div className="card divide-y divide-gray-800">
        {loading ? (
          <div className="p-8 text-center"><div className="w-6 h-6 border-2 border-blue-500 border-t-transparent rounded-full animate-spin mx-auto" /></div>
        ) : reports.length === 0 ? (
          <div className="p-8 text-center text-gray-500 text-sm">No community reports yet. Be the first to submit one.</div>
        ) : reports.map((r) => (
          <div key={r.id} className="p-4 hover:bg-navy-700 transition-colors">
            <div className="flex items-start justify-between gap-3">
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2 flex-wrap">
                  <span className="text-xs bg-navy-900 text-gray-300 px-2 py-0.5 rounded">{r.category.replace('_', ' ')}</span>
                  <span className={`text-xs capitalize ${STATUS_COLORS[r.status] || 'text-gray-400'}`}>{r.status.replace('_', ' ')}</span>
                </div>
                <p className="text-sm font-medium text-gray-200 mt-1.5">{r.title}</p>
                <p className="text-xs font-mono text-gray-500 truncate mt-0.5">{r.domain}</p>
              </div>
              <Link to={`/reports/${r.id}`} className="text-gray-500 hover:text-blue-400 transition-colors flex-shrink-0">
                <ChevronRight size={16} />
              </Link>
            </div>
            <div className="flex items-center gap-4 mt-3">
              <button onClick={() => handleVote(r.id, 'support')} className="flex items-center gap-1.5 text-xs text-gray-500 hover:text-green-400 transition-colors">
                <ThumbsUp size={13} />{r.support_count}
              </button>
              <button onClick={() => handleVote(r.id, 'dispute')} className="flex items-center gap-1.5 text-xs text-gray-500 hover:text-red-400 transition-colors">
                <ThumbsDown size={13} />{r.dispute_count}
              </button>
              <span className="text-xs text-gray-600">{new Date(r.created_at).toLocaleDateString()}</span>
            </div>
          </div>
        ))}
      </div>
    </div>
  )
}
