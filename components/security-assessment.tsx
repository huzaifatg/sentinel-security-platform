'use client'

import { useCallback, useEffect, useMemo, useState } from 'react'
import { ArrowDownRight, ArrowLeft, ArrowUpRight, Beaker, CheckCircle2, ClipboardCheck, Info, Play, RotateCcw, Save, ShieldAlert, Sparkles } from 'lucide-react'
import { api, ApiError, Device, Finding, Methodology, ProfileSignal, Provenance, RiskAssessment, SecurityProfile, SignalState, Simulation, StoredAssessment } from '@/lib/api'

export const STATE_LABEL: Record<SignalState, string> = { enabled: 'Enabled', disabled: 'Disabled', unknown: 'Unknown', not_applicable: 'N/A', normal: 'Normal', elevated: 'Elevated', high: 'High' }
export const SOURCE_LABEL: Record<Provenance, string> = { default: 'Not recorded', manual: 'Manual entry', telemetry: 'Submitted telemetry', synthetic_demo: 'Synthetic demo data', mixed: 'Telemetry + synthetic', hypothetical: 'Hypothetical' }
const SCOPE_LABEL: Record<string, string> = { account: 'Account control', device: 'Device control', behavioral: 'Behavioural signal' }
const CATEGORY_LABEL: Record<Finding['category'], string> = { control_gap: 'Control gap', unverified: 'Unverified', behavioral: 'Behavioural' }

// Clearly-labelled synthetic demonstration preset. Stored with source "synthetic_demo".
const DEMO_PROFILE: Record<string, SignalState> = { mfa: 'disabled', os_updates: 'disabled', endpoint_protection: 'enabled', firewall: 'enabled', disk_encryption: 'unknown', screen_lock: 'enabled' }

function stateTone(state: SignalState) { return state === 'enabled' || state === 'normal' ? 'good' : state === 'disabled' || state === 'high' ? 'high' : state === 'elevated' ? 'warning' : state === 'not_applicable' ? 'na' : 'unknown' }
function errorText(caught: unknown, fallback: string) { return caught instanceof ApiError || caught instanceof Error ? caught.message : fallback }
function fmt(value: number) { return Number.isInteger(value) ? String(value) : value.toFixed(1) }
function signed(value: number) { return `${value > 0 ? '+' : ''}${fmt(value)}` }

export function StatePill({ state }: { state: SignalState }) { return <span className={`state-pill ${stateTone(state)}`}>{STATE_LABEL[state]}</span> }
export function SeverityPill({ severity }: { severity: string }) { return <span className={`sev-pill ${severity}`}>{severity}</span> }

function ScoreTiles({ assessment }: { assessment: RiskAssessment }) {
  return <div className="score-tiles">
    <div className={`score-tile risk ${assessment.severity}`}><span>Risk score</span><strong>{assessment.risk_score}<small>/100</small></strong><SeverityPill severity={assessment.severity} /></div>
    <div className="score-tile"><span>Security score</span><strong>{assessment.security_score}<small>/100</small></strong><em>= 100 − risk</em></div>
    <div className="score-tile"><span>Evidence coverage</span><strong>{assessment.coverage}<small>%</small></strong><em>of applicable weight verified</em></div>
    <div className="score-tile"><span>Findings</span><strong>{assessment.findings.length}</strong><em>{assessment.findings.filter((item) => item.category !== 'unverified').length} confirmed · {assessment.findings.filter((item) => item.category === 'unverified').length} unverified</em></div>
  </div>
}

function Breakdown({ assessment }: { assessment: RiskAssessment }) {
  const max = Math.max(1, ...assessment.signals.map((signal) => signal.contribution))
  return <div className="breakdown">
    <div className="breakdown-row head"><span>Signal</span><span>State</span><span>Weight</span><span>Factor</span><span>Risk points</span></div>
    {assessment.signals.map((signal) => <div className={`breakdown-row ${signal.applicable ? '' : 'excluded'}`} key={signal.key} title={signal.evidence}>
      <span><strong>{signal.label}</strong><small>{SCOPE_LABEL[signal.scope]} · {SOURCE_LABEL[signal.source]}</small></span>
      <span><StatePill state={signal.state} /></span>
      <span className="mono">{signal.weight}</span>
      <span className="mono">{signal.applicable ? fmt(signal.risk_factor) : 'excl.'}</span>
      <span className="points"><b><i style={{ width: `${(signal.contribution / max) * 100}%` }} /></b><span className="mono">{fmt(signal.contribution)}</span></span>
    </div>)}
    <div className="breakdown-row total"><span><strong>Total</strong><small>Applicable weight {assessment.applicable_weight}</small></span><span /><span /><span /><span className="mono">{fmt(assessment.raw_risk)} → {assessment.risk_score}</span></div>
  </div>
}

function FindingList({ findings }: { findings: Finding[] }) {
  if (!findings.length) return <div className="empty-inline"><CheckCircle2 /><div><strong>No findings</strong><p>Every applicable signal is verified and contributes zero risk.</p></div></div>
  return <div className="finding-list">{findings.map((finding) => <div className="finding-row" key={finding.rule}>
    <div className={`severity-bar ${finding.severity}`} />
    <div className="finding-main">
      <div className="finding-title"><strong>{finding.label}</strong><span className="finding-meta"><span className="chip">{CATEGORY_LABEL[finding.category]}</span><SeverityPill severity={finding.severity} /><span className="mono contribution">+{fmt(finding.contribution)} pts</span></span></div>
      <p><b>Evidence:</b> {finding.evidence}</p>
      <p><b>Calculation:</b> weight {finding.weight} × factor {fmt(finding.risk_factor)}, normalised = {fmt(finding.contribution)} points · source: {SOURCE_LABEL[finding.source]}</p>
      <small>Recommended: {finding.recommended_action}</small>
    </div>
  </div>)}</div>
}

export function AssessmentReport({ assessment, title = 'Assessment result' }: { assessment: RiskAssessment; title?: string }) {
  return <>
    <ScoreTiles assessment={assessment} />
    <article className="panel"><div className="panel-header"><div><p className="eyebrow">How this score was calculated</p><h2>{title}</h2></div><span className="status-pill">{assessment.methodology_version}</span></div>
      <p className="formula">{assessment.explanation}</p>
      <Breakdown assessment={assessment} />
    </article>
    <article className="panel section-gap"><div className="panel-header"><div><p className="eyebrow">Findings</p><h2>Evidence &amp; recommendations</h2></div><ShieldAlert className="panel-icon" /></div><FindingList findings={assessment.findings} /></article>
  </>
}

function StateSelector({ signal, value, onChange, disabled }: { signal: ProfileSignal; value: SignalState; onChange: (state: SignalState) => void; disabled?: boolean }) {
  return <div className="segmented" role="radiogroup" aria-label={signal.label}>{signal.allowed_states.map((state) => <button type="button" key={state} role="radio" aria-checked={value === state} id={`ctl-${signal.key}-${state}`} className={value === state ? `active ${stateTone(state)}` : ''} onClick={() => onChange(state)} disabled={disabled}>{STATE_LABEL[state]}</button>)}</div>
}

function useMethodology() {
  const [methodology, setMethodology] = useState<Methodology | null>(null)
  useEffect(() => { let alive = true; api.methodology().then((value) => { if (alive) setMethodology(value) }).catch(() => undefined); return () => { alive = false } }, [])
  return methodology
}

export function MethodologyPanel() {
  const methodology = useMethodology()
  if (!methodology) return null
  return <details className="panel methodology"><summary><Info /> Scoring methodology ({methodology.version}) — formula, weights &amp; thresholds</summary>
    <p className="formula">{methodology.formula}</p>
    <div className="method-grid">
      <div><h3>Risk factors</h3>{Object.entries(methodology.risk_factors).map(([state, factor]) => <p key={state}><span>{STATE_LABEL[state as SignalState] ?? state}</span><b className="mono">{factor}</b></p>)}<p className="muted small">{methodology.unknown_policy} {methodology.not_applicable}</p></div>
      <div><h3>Weights</h3>{methodology.signals.map((signal) => <p key={signal.key} title={signal.rationale}><span>{signal.label} <small>({SCOPE_LABEL[signal.scope]})</small></span><b className="mono">{signal.weight}</b></p>)}</div>
      <div><h3>Severity bands</h3>{methodology.severity_bands.map((band, index) => <p key={band.severity}><span><SeverityPill severity={band.severity} /></span><b className="mono">{index === 0 ? 0 : methodology.severity_bands[index - 1].max_score + 1}–{band.max_score}</b></p>)}<h3>Limitations</h3>{methodology.limitations.map((item) => <p key={item} className="muted small">{item}</p>)}</div>
    </div>
  </details>
}

export function DeviceAssessment({ device, onBack }: { device: Device; onBack: () => void }) {
  const [profile, setProfile] = useState<SecurityProfile | null>(null)
  const [draft, setDraft] = useState<Record<string, SignalState>>({})
  const [history, setHistory] = useState<StoredAssessment[]>([])
  const [selected, setSelected] = useState<StoredAssessment | null>(null)
  const [busy, setBusy] = useState<'' | 'load' | 'save' | 'demo' | 'telemetry' | 'assess'>('load')
  const [error, setError] = useState('')
  const [message, setMessage] = useState('')

  const applyProfile = useCallback((value: SecurityProfile) => { setProfile(value); setDraft(Object.fromEntries(value.signals.filter((signal) => signal.kind === 'control').map((signal) => [signal.key, signal.state]))) }, [])
  const load = useCallback(async () => {
    setBusy('load'); setError('')
    try { const [profileResult, historyResult] = await Promise.all([api.securityProfile(device.id), api.assessments(device.id)]); applyProfile(profileResult); setHistory(historyResult); setSelected(historyResult[0] ?? null) }
    catch (caught) { setError(errorText(caught, 'Unable to load the security profile.')) } finally { setBusy('') }
  }, [device.id, applyProfile])
  useEffect(() => { const timer = window.setTimeout(() => { void load() }, 0); return () => window.clearTimeout(timer) }, [load])

  const controls = profile?.signals.filter((signal) => signal.kind === 'control') ?? []
  const behavioural = profile?.signals.filter((signal) => signal.kind === 'behavioral') ?? []
  const dirty = controls.filter((signal) => draft[signal.key] !== signal.state)

  async function save() {
    if (!dirty.length) return
    setBusy('save'); setError(''); setMessage('')
    try { applyProfile(await api.updateSecurityProfile(device.id, Object.fromEntries(dirty.map((signal) => [signal.key, draft[signal.key]])), 'manual')); setMessage(`Saved ${dirty.length} control(s) as manual entries. Run an assessment to score the new configuration.`) }
    catch (caught) { setError(errorText(caught, 'Unable to save controls.')) } finally { setBusy('') }
  }
  async function applyDemo() {
    setBusy('demo'); setError(''); setMessage('')
    try { applyProfile(await api.updateSecurityProfile(device.id, DEMO_PROFILE, 'synthetic_demo')); setMessage('Applied the synthetic demonstration profile. These values are labelled "Synthetic demo data" and are not read from the device.') }
    catch (caught) { setError(errorText(caught, 'Unable to apply demo profile.')) } finally { setBusy('') }
  }
  async function addDemoTelemetry() {
    setBusy('telemetry'); setError(''); setMessage('')
    try {
      await api.sendTelemetry(device.id, 'auth_success', { source: 'synthetic_demo' })
      await api.sendTelemetry(device.id, 'auth_failure', { source: 'synthetic_demo', count: 4 })
      await api.sendTelemetry(device.id, 'network_summary', { source: 'synthetic_demo' })
      applyProfile(await api.securityProfile(device.id))
      setMessage('Submitted 3 synthetic telemetry events (1 successful login, 4 failed logins, 1 normal network summary).')
    } catch (caught) { setError(errorText(caught, 'Unable to submit synthetic telemetry.')) } finally { setBusy('') }
  }
  async function runAssessment() {
    setBusy('assess'); setError(''); setMessage('')
    try { const result = await api.runAssessment(device.id); setHistory((items) => [result, ...items].slice(0, 10)); setSelected(result); setMessage(`Assessment #${result.id} saved.`) }
    catch (caught) { setError(errorText(caught, 'Assessment failed.')) } finally { setBusy('') }
  }

  return <>
    <header className="page-header"><div><button className="text-button back-link" onClick={onBack}><ArrowLeft />All devices</button><h1>{device.name}</h1><p className="muted">Serial {device.serial_number} · Configure recorded security signals, then run an assessment with the backend scoring engine.</p></div>
      <button className="primary-button" id="run-assessment" onClick={runAssessment} disabled={!!busy || dirty.length > 0} title={dirty.length ? 'Save or discard control changes first' : undefined}><Play />{busy === 'assess' ? 'Assessing…' : 'Run assessment'}</button></header>
    <div className="notice subtle"><div className="notice-icon"><Info /></div><div><strong>Recorded, not scanned</strong><p>Sentinel does not inspect your device. Control states are entered manually or loaded from labelled synthetic demo data; behavioural signals come only from telemetry submitted to the API. Unknown values are scored as unverified risk, never as protection.</p></div></div>
    {error && <div className="notice notice-error" role="alert"><div className="notice-icon"><ShieldAlert /></div><div><strong>Request failed</strong><p>{error}</p></div></div>}
    {message && <div className="notice"><div className="notice-icon"><CheckCircle2 /></div><div><p>{message}</p></div></div>}
    {busy === 'load' && !profile ? <div className="page-grid"><div className="skeleton" /><div className="skeleton" /></div> : profile && <div className="assess-grid">
      <article className="panel"><div className="panel-header"><div><p className="eyebrow">Security controls</p><h2>Recorded configuration</h2></div><ClipboardCheck className="panel-icon" /></div>
        <div className="control-table">{controls.map((signal) => <div className={`control-line ${draft[signal.key] !== signal.state ? 'changed' : ''}`} key={signal.key}>
          <div><strong>{signal.label}</strong><small>{SCOPE_LABEL[signal.scope]} · weight {signal.weight} · {SOURCE_LABEL[signal.source]}{signal.updated_at ? ` · ${new Date(signal.updated_at).toLocaleString()}` : ''}</small></div>
          <StateSelector signal={signal} value={draft[signal.key] ?? signal.state} onChange={(state) => setDraft((current) => ({ ...current, [signal.key]: state }))} disabled={!!busy} />
        </div>)}</div>
        <p className="muted small">MFA is an account-level control: it applies to every device on your Sentinel account.</p>
        <div className="button-row"><button className="primary-button" id="save-controls" onClick={save} disabled={!dirty.length || !!busy}><Save />{busy === 'save' ? 'Saving…' : `Save ${dirty.length || ''} change${dirty.length === 1 ? '' : 's'}`}</button>{dirty.length > 0 && <button className="secondary-button" onClick={() => applyProfile(profile)} disabled={!!busy}><RotateCcw />Discard</button>}<button className="secondary-button" id="apply-demo-profile" onClick={applyDemo} disabled={!!busy}><Beaker />{busy === 'demo' ? 'Applying…' : 'Load synthetic demo profile'}</button></div>
      </article>
      <article className="panel"><div className="panel-header"><div><p className="eyebrow">Behavioural evidence · last {profile.evidence_window_days} days</p><h2>Observed activity</h2></div><Sparkles className="panel-icon" /></div>
        <div className="control-table">{behavioural.map((signal) => <div className="control-line" key={signal.key}><div><strong>{signal.label}</strong><small>weight {signal.weight} · {SOURCE_LABEL[signal.source]}</small><p className="evidence">{signal.evidence}</p></div><StatePill state={signal.state} /></div>)}</div>
        <p className="muted small">Derived from <code>auth_failure</code>, <code>auth_success</code>, <code>network_alert</code> and <code>network_summary</code> telemetry plus anomaly-model events. Failed logins from telemetry and anomaly events are combined with max(), not summed, to avoid double counting.</p>
        <button className="secondary-button" id="add-demo-telemetry" onClick={addDemoTelemetry} disabled={!!busy}><Beaker />{busy === 'telemetry' ? 'Submitting…' : 'Submit synthetic telemetry'}</button>
      </article>
    </div>}
    {selected ? <>
      <div className="history-bar"><span className="eyebrow">Assessment history</span>{history.map((item) => <button key={item.id} className={item.id === selected.id ? 'filter-active' : ''} onClick={() => setSelected(item)}>#{item.id} · {item.risk_score} · {new Date(item.created_at).toLocaleTimeString()}</button>)}</div>
      <AssessmentReport assessment={selected} title={`Assessment #${selected.id} · ${new Date(selected.created_at).toLocaleString()}`} />
    </> : profile && <article className="panel"><div className="empty-inline"><Play /><div><strong>No assessment yet</strong><p>Review the recorded controls above, then run an assessment. The result is stored and stays available after refreshing.</p></div></div></article>}
  </>
}

export function WhatIfSimulator({ devices, onCreated }: { devices: Device[]; onCreated: () => Promise<void> }) {
  const [deviceId, setDeviceId] = useState('')
  const [profile, setProfile] = useState<SecurityProfile | null>(null)
  const [proposal, setProposal] = useState<Record<string, SignalState>>({})
  const [result, setResult] = useState<Simulation | null>(null)
  const [history, setHistory] = useState<Simulation[]>([])
  const [loading, setLoading] = useState(false)
  const [running, setRunning] = useState(false)
  const [error, setError] = useState('')

  const selectDevice = useCallback(async (value: string) => {
    setDeviceId(value); setResult(null); setError(''); setProfile(null)
    if (!value) return
    setLoading(true)
    try { const [profileResult, historyResult] = await Promise.all([api.securityProfile(Number(value)), api.simulations(Number(value))]); setProfile(profileResult); setProposal(Object.fromEntries(profileResult.signals.filter((signal) => signal.kind === 'control').map((signal) => [signal.key, signal.state]))); setHistory(historyResult); setResult(historyResult[0] ?? null) }
    catch (caught) { setError(errorText(caught, 'Unable to load device profile.')) } finally { setLoading(false) }
  }, [])

  const controls = useMemo(() => profile?.signals.filter((signal) => signal.kind === 'control') ?? [], [profile])
  const changes = controls.filter((signal) => proposal[signal.key] !== signal.state)

  async function run() {
    if (!deviceId || running || !changes.length) return
    setRunning(true); setError('')
    try { const value = await api.simulateDevice(Number(deviceId), Object.fromEntries(changes.map((signal) => [signal.key, proposal[signal.key]]))); setResult(value); setHistory((items) => [value, ...items]); await onCreated() }
    catch (caught) { setError(errorText(caught, 'Simulation failed.')) } finally { setRunning(false) }
  }
  function quickFix() { setProposal((current) => Object.fromEntries(Object.entries(current).map(([key, state]) => [key, state === 'not_applicable' ? state : 'enabled']))) }

  return <>
    <header className="page-header"><div><p className="eyebrow">LIVE WORKSPACE</p><h1>What-if simulator</h1><p className="muted">Compare the recorded configuration with a hypothetical one. Both are scored by the same backend engine; the device&apos;s stored controls are never changed.</p></div><span className="status-pill warning"><span className="status-dot" />Hypothetical only</span></header>
    <div className="simulator-grid">
      <article className="panel"><div className="panel-header"><div><p className="eyebrow">Scenario</p><h2>Propose control changes</h2></div><Sparkles className="panel-icon" /></div>
        <label className="field">Device<select id="sim-device" value={deviceId} onChange={(event) => void selectDevice(event.target.value)}><option value="">Select a registered device</option>{devices.map((item) => <option key={item.id} value={String(item.id)}>{item.name}</option>)}</select></label>
        {!devices.length && <p className="muted small">Register a device first.</p>}
        {loading && <div className="skeleton short" />}
        {profile && <><div className="control-table">{controls.map((signal) => <div className={`control-line ${proposal[signal.key] !== signal.state ? 'changed' : ''}`} key={signal.key}>
          <div><strong>{signal.label}</strong><small>Recorded: {STATE_LABEL[signal.state]} ({SOURCE_LABEL[signal.source]}) · weight {signal.weight}</small></div>
          <StateSelector signal={signal} value={proposal[signal.key] ?? signal.state} onChange={(state) => setProposal((current) => ({ ...current, [signal.key]: state }))} disabled={running} />
        </div>)}</div>
          <p className="muted small">Behavioural signals are observations, not settings, so they are carried over from the baseline unchanged.</p>
          <div className="button-row"><button className="primary-button" id="run-simulation" onClick={run} disabled={running || !changes.length}><Play />{running ? 'Running…' : changes.length ? `Simulate ${changes.length} change${changes.length === 1 ? '' : 's'}` : 'Change a control to simulate'}</button><button className="secondary-button" onClick={quickFix} disabled={running}><CheckCircle2 />Propose all enabled</button>{changes.length > 0 && <button className="secondary-button" onClick={() => setProposal(Object.fromEntries(controls.map((signal) => [signal.key, signal.state])))} disabled={running}><RotateCcw />Reset</button>}</div></>}
        {error && <p className="form-error" role="alert">{error}</p>}
      </article>
      <article className="panel comparison">{result ? <SimulationSummary simulation={result} /> : <div className="empty-state"><strong>No simulation yet</strong><p>Select a device, change one or more controls and run the simulation to compare baseline and proposed scores.</p></div>}</article>
    </div>
    {result?.baseline && result.proposed && <SimulationDetail simulation={result} />}
    {history.length > 1 && <article className="panel section-gap"><div className="panel-header"><div><p className="eyebrow">Persisted history</p><h2>Previous simulations for this device</h2></div></div><div className="event-list">{history.map((item) => <button className={`history-row ${item.id === result?.id ? 'active' : ''}`} key={item.id} onClick={() => setResult(item)}><span className="mono">#{item.id}</span><span>{item.changed_signals.map((change) => `${change.label}: ${STATE_LABEL[change.to_state]}`).join(', ') || 'Legacy simulation'}</span><span className="mono">{item.before_risk_score} → {item.after_risk_score}</span><time>{new Date(item.created_at).toLocaleString()}</time></button>)}</div></article>}
  </>
}

function Delta({ value, invert = false }: { value: number; invert?: boolean }) {
  const good = invert ? value > 0 : value < 0
  if (value === 0) return <span className="delta neutral">±0</span>
  return <span className={`delta ${good ? 'good' : 'bad'}`}>{value < 0 ? <ArrowDownRight /> : <ArrowUpRight />}{signed(value)}</span>
}

function SimulationSummary({ simulation }: { simulation: Simulation }) {
  const riskDelta = simulation.risk_delta ?? simulation.after_risk_score - simulation.before_risk_score
  const securityDelta = simulation.security_delta ?? simulation.after_security_score - simulation.before_security_score
  return <>
    <div className="panel-header"><div><p className="eyebrow">Backend result · simulation #{simulation.id}</p><h2>Baseline vs proposed</h2></div></div>
    <div className="compare-grid">
      <div /><span className="eyebrow">Baseline</span><span className="eyebrow">Proposed</span><span className="eyebrow">Change</span>
      <strong>Risk</strong><b className="mono">{simulation.before_risk_score}</b><b className="mono">{simulation.after_risk_score}</b><Delta value={riskDelta} />
      <strong>Security</strong><b className="mono">{simulation.before_security_score}</b><b className="mono">{simulation.after_security_score}</b><Delta value={securityDelta} invert />
      {simulation.baseline && simulation.proposed && <><strong>Severity</strong><SeverityPill severity={simulation.baseline.severity} /><SeverityPill severity={simulation.proposed.severity} /><span /></>}
    </div>
    <p className="formula">{simulation.explanation}</p>
    {simulation.recommendations.length > 0 && <><p className="eyebrow">Recommended next actions</p><ol className="next-actions">{simulation.recommendations.map((item) => <li key={item}>{item}</li>)}</ol></>}
  </>
}

function SimulationDetail({ simulation }: { simulation: Simulation }) {
  const baseline = simulation.baseline as RiskAssessment
  const proposed = simulation.proposed as RiskAssessment
  const labels = Object.fromEntries([...baseline.findings, ...proposed.findings].map((finding) => [finding.rule, finding]))
  return <div className="panel-grid">
    <article className="panel"><div className="panel-header"><div><p className="eyebrow">Why the score changed</p><h2>Changed controls</h2></div></div>
      <div className="breakdown">
        <div className="breakdown-row head four"><span>Control</span><span>Baseline → proposed</span><span>Points before → after</span><span>Δ risk</span></div>
        {simulation.changed_signals.map((change) => <div className="breakdown-row four" key={change.key}><span><strong>{change.label}</strong></span><span><StatePill state={change.from_state} /> → <StatePill state={change.to_state} /></span><span className="mono">{fmt(change.contribution_before)} → {fmt(change.contribution_after)}</span><span><Delta value={change.delta} /></span></div>)}
      </div>
    </article>
    <article className="panel"><div className="panel-header"><div><p className="eyebrow">Findings</p><h2>Resolved &amp; introduced</h2></div></div>
      <div className="event-list">
        {simulation.removed_findings.map((rule) => <div className="event-row" key={`r-${rule}`}><span className="event-dot green" /><div><strong>Resolved: {labels[rule]?.label ?? rule}</strong><p>−{fmt(labels[rule]?.contribution ?? 0)} pts in the baseline</p></div></div>)}
        {simulation.added_findings.map((rule) => <div className="event-row" key={`a-${rule}`}><span className="event-dot amber" /><div><strong>Introduced: {labels[rule]?.label ?? rule}</strong><p>+{fmt(labels[rule]?.contribution ?? 0)} pts in the proposal</p></div></div>)}
        {!simulation.removed_findings.length && !simulation.added_findings.length && <p className="muted small">No findings were resolved or introduced.</p>}
        <p className="muted small">{proposed.findings.length} finding(s) remain in the proposed configuration · coverage {baseline.coverage}% → {proposed.coverage}%.</p>
      </div>
    </article>
  </div>
}
