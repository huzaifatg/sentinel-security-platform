'use client'

import { FormEvent, useEffect, useState } from 'react'
import { api, ApiError, clearToken, saveToken, User } from '@/lib/api'
import { LiveWorkspace } from '@/components/live-workspace'

export function AuthGate({ initialSection }: { initialSection?: 'overview' | 'devices' | 'risk-findings' | 'digital-twin' | 'anomalies' | 'simulator' | 'activity' | 'reports' | 'settings' }) {
  const [user, setUser] = useState<User | null>(null)
  const [mode, setMode] = useState<'login' | 'register'>('login')
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(true)
  const [submitting, setSubmitting] = useState(false)
  const [health, setHealth] = useState<'checking' | 'online' | 'offline'>('checking')

  useEffect(() => {
    api.health().then(() => setHealth('online')).catch(() => setHealth('offline'))
    api.me().then(setUser).catch(() => clearToken()).finally(() => setLoading(false))
  }, [])

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault(); setError(''); setSubmitting(true)
    try {
      if (mode === 'register') await api.register(email, password)
      const session = await api.login(email, password)
      saveToken(session.access_token)
      setUser(await api.me())
    } catch (caught) {
      setError(caught instanceof ApiError ? caught.message : 'Unable to reach the Sentinel backend.')
    } finally { setSubmitting(false) }
  }

  if (loading) return <main className="auth-shell"><div className="auth-card"><p className="eyebrow">Sentinel</p><h1>Connecting to your security workspace</h1><p className="muted">Verifying the live FastAPI service…</p></div></main>
  if (user) return <LiveWorkspace initialSection={initialSection as 'overview' | 'devices' | 'anomalies' | 'simulator'} user={user} onLogout={() => { clearToken(); setUser(null) }} />

  return <main className="auth-shell"><div className="auth-card">
    <div className="brand auth-brand"><div className="brand-mark">S</div><div><strong>Sentinel</strong><span>Security twin</span></div></div>
    <p className="eyebrow">Personal cybersecurity digital twin</p><h1>{mode === 'login' ? 'Welcome back' : 'Create your workspace'}</h1>
    <p className="muted">Use your Sentinel account to access live devices, assessments, anomalies and simulations.</p>
    <div className={`connection-banner ${health}`}><span className="status-dot" />{health === 'online' ? 'Backend connected' : health === 'offline' ? 'Backend unavailable' : 'Checking backend connection'}</div>
    <form className="auth-form" onSubmit={submit}><label>Email<input type="email" value={email} onChange={(e) => setEmail(e.target.value)} required autoComplete="email" /></label><label>Password<input type="password" value={password} onChange={(e) => setPassword(e.target.value)} required minLength={12} autoComplete={mode === 'login' ? 'current-password' : 'new-password'} /></label>{error && <p className="form-error" role="alert">{error}</p>}<button className="primary-button" disabled={submitting}>{submitting ? 'Working…' : mode === 'login' ? 'Sign in' : 'Create account'}</button></form>
    <button className="auth-switch" onClick={() => { setMode(mode === 'login' ? 'register' : 'login'); setError('') }}>{mode === 'login' ? 'New to Sentinel? Create an account' : 'Already have an account? Sign in'}</button>
  </div></main>
}
