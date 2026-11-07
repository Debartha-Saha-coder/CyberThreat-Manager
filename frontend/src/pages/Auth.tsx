import React, { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { ShieldAlert, Loader2, AlertCircle } from 'lucide-react'
import { authService } from '../services'

type Mode = 'login' | 'register'

export default function Auth() {
  const navigate = useNavigate()
  const [mode, setMode] = useState<Mode>('login')
  const [form, setForm] = useState({ email: '', username: '', password: '' })
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setLoading(true)
    setError('')

    try {
      if (mode === 'login') {
        await authService.login(form.email, form.password)
      } else {
        await authService.register(form.email, form.username, form.password)
        await authService.login(form.email, form.password)
      }
      navigate('/')
    } catch (err: unknown) {
      const detail = (err as { response?: { data?: { detail?: string } } })?.response?.data?.detail
      setError(detail || 'Authentication failed.')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="min-h-screen bg-navy-900 flex items-center justify-center p-4">
      <div className="w-full max-w-sm space-y-6">
        {/* Logo */}
        <div className="text-center">
          <div className="w-14 h-14 rounded-2xl bg-blue-600 flex items-center justify-center mx-auto mb-4">
            <ShieldAlert size={28} className="text-white" />
          </div>
          <h1 className="text-2xl font-bold text-white">Hackmetrix</h1>
          <p className="text-gray-400 text-sm mt-1">Cyber Threat Intelligence Platform</p>
        </div>

        {/* Card */}
        <div className="card p-6 space-y-4">
          <div className="flex bg-navy-900 rounded-lg p-1">
            {(['login', 'register'] as Mode[]).map((m) => (
              <button key={m} onClick={() => setMode(m)} className={`flex-1 py-2 rounded-md text-sm font-medium transition-colors capitalize ${mode === m ? 'bg-blue-600 text-white' : 'text-gray-400 hover:text-gray-200'}`}>
                {m}
              </button>
            ))}
          </div>

          <form onSubmit={handleSubmit} className="space-y-3">
            <input
              type="email"
              className="input-field"
              placeholder="Email address"
              value={form.email}
              onChange={(e) => setForm((f) => ({ ...f, email: e.target.value }))}
              required
            />
            {mode === 'register' && (
              <input
                type="text"
                className="input-field"
                placeholder="Username"
                value={form.username}
                onChange={(e) => setForm((f) => ({ ...f, username: e.target.value }))}
                required
                minLength={3}
              />
            )}
            <input
              type="password"
              className="input-field"
              placeholder="Password"
              value={form.password}
              onChange={(e) => setForm((f) => ({ ...f, password: e.target.value }))}
              required
              minLength={8}
            />

            {error && (
              <div className="flex items-center gap-2 text-red-400 text-sm">
                <AlertCircle size={14} />
                {error}
              </div>
            )}

            <button type="submit" className="btn-primary w-full justify-center" disabled={loading}>
              {loading ? <><Loader2 size={16} className="animate-spin" />Processing…</> : mode === 'login' ? 'Sign In' : 'Create Account'}
            </button>
          </form>
        </div>
      </div>
    </div>
  )
}
