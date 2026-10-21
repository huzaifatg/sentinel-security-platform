'use client'

import { useState } from 'react'

const API_BASE = process.env.NEXT_PUBLIC_API_BASE_URL ?? 'http://localhost:8000'
const signalOptions = ['disk_encryption_disabled', 'mfa_disabled', 'firewall_disabled', 'unusual_login'] as const

type Assessment = { risk_score: number; security_score: number; severity: string; findings: Array<{ label: string; evidence: string; recommended_action: string }> }

export function RiskConsole() {
  const [token, setToken] = useState('')
  const [assetId, setAssetId] = useState('')
  const [signals, setSignals] = useState<Record<string, boolean>>({})
  const [assessment, setAssessment] = useState<Assessment | null>(null)
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)

  async function submit(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault()
    setError('')
    setAssessment(null)
    setLoading(true)
    try {
      const response = await fetch(`${API_BASE}/api/v1/risk/assess`, { method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` }, body: JSON.stringify({ asset_id: assetId, signals }) })
      const body = await response.json()
      if (!response.ok) throw new Error(body.detail ?? 'Risk assessment failed')
      setAssessment(body)
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : 'Unable to reach the risk service')
    } finally {
      setLoading(false)
    }
  }

  return <article className="panel risk-console">
    <div className="panel-header"><div><p className="eyebrow">Verified backend assessment</p><h2>Run a risk assessment</h2></div><span className="status-pill">Live API</span></div>
    <p className="muted">Submit an authenticated request to the FastAPI risk engine. Scores and findings below are never fabricated by the dashboard.</p>
    <form onSubmit={submit} className="risk-form">
      <label>Access token<input value={token} onChange={(event) => setToken(event.target.value)} type="password" required placeholder="Bearer token from /auth/login" /></label>
      <label>Asset ID<input value={assetId} onChange={(event) => setAssetId(event.target.value)} required placeholder="laptop-1" /></label>
      <fieldset><legend>Observed signals</legend>{signalOptions.map((signal) => <label className="check-row" key={signal}><input type="checkbox" checked={Boolean(signals[signal])} onChange={(event) => setSignals((current) => ({ ...current, [signal]: event.target.checked }))} />{signal.replaceAll('_', ' ')}</label>)}</fieldset>
      <button type="submit" disabled={loading}>{loading ? 'Assessing…' : 'Calculate verified score'}</button>
    </form>
    {error && <p className="form-error" role="alert">{error}</p>}
    {assessment && <div className="assessment-result"><div><span>Security score</span><strong>{assessment.security_score} / 100</strong></div><div><span>Risk</span><strong>{assessment.risk_score} · {assessment.severity}</strong></div><ul>{assessment.findings.map((finding) => <li key={finding.evidence}><strong>{finding.label}</strong><span>{finding.evidence} · {finding.recommended_action}</span></li>)}</ul></div>}
  </article>
}
