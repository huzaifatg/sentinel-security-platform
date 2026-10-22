'use client'

import { useState } from 'react'
import { api, ApiError, RiskAssessment } from '@/lib/api'

const signalOptions = ['disk_encryption_disabled', 'mfa_disabled', 'firewall_disabled', 'unusual_login'] as const


export function RiskConsole() {
  const [assetId, setAssetId] = useState('')
  const [signals, setSignals] = useState<Record<string, boolean>>({})
  const [assessment, setAssessment] = useState<RiskAssessment | null>(null)
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)

  async function submit(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault()
    setError('')
    setAssessment(null)
    setLoading(true)
    try {
      setAssessment(await api.assessRisk(assetId, signals))
    } catch (caught) {
      setError(caught instanceof ApiError ? caught.message : 'Unable to reach the risk service')
    } finally {
      setLoading(false)
    }
  }

  return <article className="panel risk-console">
    <div className="panel-header"><div><p className="eyebrow">Verified backend assessment</p><h2>Run a risk assessment</h2></div><span className="status-pill">Live API</span></div>
    <p className="muted">Submit an authenticated request to the FastAPI risk engine. Scores and findings below are never fabricated by the dashboard.</p>
    <form onSubmit={submit} className="risk-form">
      <label>Asset ID<input value={assetId} onChange={(event) => setAssetId(event.target.value)} required placeholder="laptop-1" /></label>
      <fieldset><legend>Observed signals</legend>{signalOptions.map((signal) => <label className="check-row" key={signal}><input type="checkbox" checked={Boolean(signals[signal])} onChange={(event) => setSignals((current) => ({ ...current, [signal]: event.target.checked }))} />{signal.replaceAll('_', ' ')}</label>)}</fieldset>
      <button type="submit" disabled={loading}>{loading ? 'Assessing…' : 'Calculate verified score'}</button>
    </form>
    {error && <p className="form-error" role="alert">{error}</p>}
    {assessment && <div className="assessment-result"><div><span>Security score</span><strong>{assessment.security_score} / 100</strong></div><div><span>Risk</span><strong>{assessment.risk_score} · {assessment.severity}</strong></div><ul>{assessment.findings.map((finding) => <li key={finding.evidence}><strong>{finding.label}</strong><span>{finding.evidence} · {finding.recommended_action}</span></li>)}</ul></div>}
  </article>
}
