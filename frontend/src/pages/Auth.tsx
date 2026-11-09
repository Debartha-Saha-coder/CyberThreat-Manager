import React, { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { ShieldAlert, Loader2, AlertCircle } from 'lucide-react'
import { authService } from '../services'
import { BrandMark } from '../components/BrandMark'

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
    <main className="auth-shell">
      <section className="auth-brand-panel" aria-label="THREXIS">
        <div className="auth-brand-lockup">
          <BrandMark className="auth-brand-mark" />
          <div>
            <p className="auth-wordmark">THRE<span className="brand-accent">X</span>IS</p>
            <p className="auth-tagline">See the threat. Understand the risk.</p>
          </div>
        </div>

        <div className="auth-brand-message">
          <p className="auth-kicker">Threat intelligence / 01</p>
          <h2>See the threat.<br />Understand the risk.</h2>
          <p className="auth-principles">Identify <span>·</span> Analyze <span>·</span> Understand <span>·</span> Protect</p>
        </div>

        <div className="auth-brand-footer">
          <span><span className="status-dot" /> Intelligence for a safer digital world</span>
          <span>THREXIS / 01</span>
        </div>
      </section>

      <section className="auth-form-panel">
        <div className="auth-form-card">
          <p className="auth-eyebrow">Secure access</p>
          <h1 className="auth-title">{mode === 'login' ? 'Welcome back' : 'Create your account'}</h1>
          <p className="auth-intro">{mode === 'login' ? 'Sign in to your intelligence workspace.' : 'Set up an account to continue.'}</p>

          <div className="auth-tabs" role="tablist" aria-label="Account access">
            {(['login', 'register'] as Mode[]).map((m) => (
              <button
                key={m}
                type="button"
                role="tab"
                aria-selected={mode === m}
                onClick={() => setMode(m)}
                className={mode === m ? 'auth-tab active' : 'auth-tab'}
              >
                {m === 'login' ? 'Sign in' : 'Create account'}
              </button>
            ))}
          </div>

          <form onSubmit={handleSubmit} className="auth-form">
            <label className="auth-field">
              <span>Email address</span>
              <input
                type="email"
                className="input-field"
                autoComplete="email"
                value={form.email}
                onChange={(e) => setForm((f) => ({ ...f, email: e.target.value }))}
                required
              />
            </label>
            {mode === 'register' && (
              <label className="auth-field">
                <span>Username</span>
                <input
                  type="text"
                  className="input-field"
                  autoComplete="username"
                  value={form.username}
                  onChange={(e) => setForm((f) => ({ ...f, username: e.target.value }))}
                  required
                  minLength={3}
                />
              </label>
            )}
            <label className="auth-field">
              <span>Password</span>
              <input
                type="password"
                className="input-field"
                autoComplete={mode === 'login' ? 'current-password' : 'new-password'}
                value={form.password}
                onChange={(e) => setForm((f) => ({ ...f, password: e.target.value }))}
                required
                minLength={8}
              />
            </label>

            {error && (
              <div className="auth-error" role="alert">
                <AlertCircle size={15} />
                {error}
              </div>
            )}

            <button type="submit" className="btn-primary auth-submit" disabled={loading}>
              {loading ? <><Loader2 size={16} className="animate-spin" />Processing…</> : mode === 'login' ? 'Sign in' : 'Create account'}
            </button>
          </form>
          <p className="auth-footnote"><ShieldAlert size={14} /> Protected analyst workspace</p>
        </div>
      </section>
    </main>
  )
}
