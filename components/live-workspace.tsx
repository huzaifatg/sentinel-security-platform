'use client'

import { FormEvent, useCallback, useEffect, useState } from 'react'
import { Activity, AlertTriangle, ArrowUpRight, Cpu, LogOut, Plus, RefreshCw, ShieldCheck, Smartphone, Sparkles, X } from 'lucide-react'
import { api, ApiError, AnomalyEvent, Device, Simulation } from '@/lib/api'
import { DeviceAssessment, WhatIfSimulator, MethodologyPanel } from '@/components/security-assessment'

type Section = 'overview' | 'devices' | 'anomalies' | 'simulator'

function Notice({ children, tone = 'info' }: { children: React.ReactNode; tone?: 'info' | 'error' | 'success' }) { return <div className={`notice ${tone === 'error' ? 'notice-error' : ''}`} role={tone === 'error' ? 'alert' : undefined}><div className="notice-icon">{tone === 'error' ? <AlertTriangle /> : <ShieldCheck />}</div><div>{children}</div></div> }
function Card({ children, className = '' }: { children: React.ReactNode; className?: string }) { return <article className={`panel ${className}`}>{children}</article> }
function Header({ title, description, action }: { title: string; description: string; action?: React.ReactNode }) { return <header className="page-header"><div><p className="eyebrow">LIVE WORKSPACE</p><h1>{title}</h1><p className="muted">{description}</p></div>{action}</header> }

export function LiveWorkspace({ initialSection = 'overview', user, onLogout }: { initialSection?: Section; user: { email: string; id: number }; onLogout: () => void }) {
  const [section, setSection] = useState<Section>(initialSection)
  const [devices, setDevices] = useState<Device[]>([])
  const [anomalies, setAnomalies] = useState<AnomalyEvent[]>([])
  const [simulations, setSimulations] = useState<Simulation[]>([])
  const [health, setHealth] = useState<'checking' | 'online' | 'degraded'>('checking')
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(true)

  const refresh = useCallback(async (silent = false) => {
    if (!silent) setLoading(true); setError('')
    try {
      const [healthResult, deviceResult, anomalyResult, simulationResult] = await Promise.all([api.health(), api.devices(), api.anomalies(), api.simulations()])
      setHealth(healthResult.status === 'ok' ? 'online' : 'degraded'); setDevices(deviceResult); setAnomalies(anomalyResult); setSimulations(simulationResult)
    } catch (caught) { if (caught instanceof ApiError && caught.status === 401) { onLogout(); return }; setError(caught instanceof Error ? caught.message : 'Unable to load live workspace data.'); setHealth('degraded') } finally { setLoading(false) }
  }, [onLogout])
  useEffect(() => { const timer = window.setTimeout(() => { void refresh() }, 0); return () => window.clearTimeout(timer) }, [refresh])

  const activeAnomalies = anomalies.filter((event) => event.is_anomaly).length
  const nav = (next: Section) => setSection(next)
  return <div className="app-shell"><aside className="sidebar"><div className="brand"><div className="brand-mark">S</div><div><strong>Sentinel</strong><span>Security twin</span></div></div><nav className="nav-list" aria-label="Main navigation"><button className={section === 'overview' ? 'nav-item active' : 'nav-item'} onClick={() => nav('overview')}><ShieldCheck />Overview</button><button className={section === 'devices' ? 'nav-item active' : 'nav-item'} onClick={() => nav('devices')}><Smartphone />Devices</button><button className={section === 'anomalies' ? 'nav-item active' : 'nav-item'} onClick={() => nav('anomalies')}><Activity />Anomalies</button><button className={section === 'simulator' ? 'nav-item active' : 'nav-item'} onClick={() => nav('simulator')}><Sparkles />Simulator</button></nav><div className="sidebar-bottom"><p className="muted">{user.email}</p><button className="secondary-button" onClick={onLogout}><LogOut />Sign out</button></div></aside><main className="content"><div className="mobile-topbar"><strong>Sentinel</strong><button className="icon-button" onClick={onLogout} aria-label="Sign out"><LogOut /></button></div><div className="topbar-actions live-toolbar"><span className={`status-pill ${health === 'online' ? 'good' : health === 'degraded' ? 'warning' : ''}`}><span className="status-dot" />{health === 'online' ? 'Backend connected' : health === 'degraded' ? 'Backend degraded' : 'Checking backend'}</span><button className="icon-button" onClick={() => void refresh()} aria-label="Refresh live data"><RefreshCw /></button></div>{error && <Notice tone="error"><strong>Live data unavailable</strong><p>{error}</p></Notice>}{loading ? <LoadingState /> : section === 'overview' ? <Overview devices={devices} anomalies={anomalies} simulations={simulations} activeAnomalies={activeAnomalies} nav={nav} /> : section === 'devices' ? <Devices devices={devices} onCreated={() => refresh(true)} /> : section === 'anomalies' ? <Anomalies anomalies={anomalies} onRefresh={() => refresh(true)} /> : <WhatIfSimulator devices={devices} onCreated={() => refresh(true)} />}</main></div>
}

function LoadingState() { return <div className="page-grid"><div className="skeleton" /><div className="skeleton" /><div className="skeleton wide" /></div> }
function Overview({ devices, anomalies, simulations, activeAnomalies, nav }: { devices: Device[]; anomalies: AnomalyEvent[]; simulations: Simulation[]; activeAnomalies: number; nav: (section: Section) => void }) { return <><Header title="Live security posture" description="Only records returned by the authenticated Sentinel API appear here." action={<span className="status-pill good"><span className="status-dot" />Live data</span>} /><Notice><strong>Authenticated workspace</strong><p>Device inventory, anomaly events and simulations below are loaded from your account. Empty states are real and safe.</p></Notice><div className="metric-grid"><Metric label="Registered devices" value={String(devices.length)} foot="Authenticated records" icon={Smartphone} /><Metric label="Anomalies" value={String(activeAnomalies)} foot={`${anomalies.length} events returned`} icon={AlertTriangle} tone="warning" /><Metric label="Simulations" value={String(simulations.length)} foot="Persisted scenarios" icon={Sparkles} /><Metric label="API state" value="OK" foot="Database-backed service" icon={ShieldCheck} tone="accent" /></div><div className="panel-grid"><Card><div className="panel-header"><div><p className="eyebrow">Inventory</p><h2>Your devices</h2></div><button className="text-button" onClick={() => nav('devices')}>Manage <ArrowUpRight /></button></div>{devices.length ? <div className="event-list">{devices.slice(0, 4).map((device) => <div className="event-row" key={device.id}><span className="event-dot green" /><div><strong>{device.name}</strong><p>{device.serial_number}</p></div><time>#{device.id}</time></div>)}</div> : <EmptyState title="No devices registered" detail="Add your first device to begin collecting an honest security posture." />}</Card><Card><div className="panel-header"><div><p className="eyebrow">Detection</p><h2>Recent anomaly events</h2></div><button className="text-button" onClick={() => nav('anomalies')}>Review <ArrowUpRight /></button></div>{anomalies.length ? <div className="event-list">{anomalies.slice(-4).reverse().map((event) => <div className="event-row" key={event.id}><span className={`event-dot ${event.is_anomaly ? 'amber' : 'green'}`} /><div><strong>{event.is_anomaly ? 'Anomaly detected' : 'Normal event'}</strong><p>{event.explanation}</p></div><time>{new Date(event.observed_at).toLocaleDateString()}</time></div>)}</div> : <EmptyState title="No anomaly events" detail="Events will appear after the anomaly endpoint receives a device signal." />}</Card></div><div className="section-gap"><MethodologyPanel /></div></> }
function Metric({ label, value, foot, icon: Icon, tone = '' }: { label: string; value: string; foot: string; icon: typeof ShieldCheck; tone?: string }) { return <article className={`metric-card ${tone}`}><div className="metric-heading"><span>{label}</span><Icon /></div><div className="metric-value">{value}</div><p className="metric-foot">{foot}</p></article> }
function EmptyState({ title, detail }: { title: string; detail: string }) { return <div className="empty-state"><strong>{title}</strong><p>{detail}</p></div> }

function Devices({ devices, onCreated }: { devices: Device[]; onCreated: () => Promise<void> }) {
  const [selectedDevice, setSelectedDevice] = useState<Device | null>(null)
  const [open, setOpen] = useState(false)
  const [name, setName] = useState('')
  const [serial, setSerial] = useState('')
  const [error, setError] = useState('')
  const [saving, setSaving] = useState(false)

  if (selectedDevice) {
    return <DeviceAssessment device={selectedDevice} onBack={() => setSelectedDevice(null)} />
  }

  async function submit(event: FormEvent) {
    event.preventDefault()
    setSaving(true)
    setError('')
    try {
      await api.createDevice(name, serial)
      setName('')
      setSerial('')
      setOpen(false)
      await onCreated()
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : 'Unable to create device.')
    } finally {
      setSaving(false)
    }
  }

  return <>
    <Header title="Devices & assets" description="Authenticated devices owned by your Sentinel account. Click any device to review signals and run an assessment." action={<button className="primary-button" onClick={() => setOpen(true)}><Plus />Add device</button>} />
    {devices.length ? <div className="device-grid">{devices.map((device) => <Card key={device.id}>
      <div className="device-icon"><Cpu /></div>
      <div className="device-top">
        <div><strong>{device.name}</strong><p>{device.serial_number}</p></div>
        <span className="status-pill good"><span className="status-dot" />Registered</span>
      </div>
      <div className="device-controls">
        <span>Owner #{device.owner_id}</span>
        <span>{new Date(device.created_at).toLocaleDateString()}</span>
      </div>
      <div style={{ marginTop: '14px' }}>
        <button className="primary-button" style={{ width: '100%' }} id={`assess-device-${device.id}`} onClick={() => setSelectedDevice(device)}>
          <ShieldCheck /> Configure &amp; Assess
        </button>
      </div>
    </Card>)}</div> : <Card><EmptyState title="Your inventory is empty" detail="Add a device using its name and serial number. Sentinel stores the record; it does not scan or modify the device." /><button className="primary-button" onClick={() => setOpen(true)}><Plus />Add your first device</button></Card>}
    {open && <div className="modal-backdrop"><div className="modal-card"><div className="panel-header"><div><p className="eyebrow">LIVE API</p><h2>Add device</h2></div><button className="icon-button" onClick={() => setOpen(false)} aria-label="Close"><X /></button></div><form className="auth-form" onSubmit={submit}><label>Device name<input value={name} onChange={(event) => setName(event.target.value)} required maxLength={120} /></label><label>Serial number<input value={serial} onChange={(event) => setSerial(event.target.value)} required maxLength={120} /></label>{error && <p className="form-error" role="alert">{error}</p>}<button className="primary-button" disabled={saving}>{saving ? 'Creating…' : 'Create device'}</button></form></div></div>}
  </>
}

function Anomalies({ anomalies, onRefresh }: { anomalies: AnomalyEvent[]; onRefresh: () => Promise<void> }) { const [training, setTraining] = useState(false); const [message, setMessage] = useState(''); async function train() { setTraining(true); setMessage(''); try { const result = await api.trainModel(); setMessage(`Model trained: ${result.training_events} events, version ${result.model_version}.`) } catch (caught) { setMessage(caught instanceof Error ? caught.message : 'Training failed.') } finally { setTraining(false) } } return <><Header title="Anomaly detection" description="Authenticated model events returned by the Sentinel backend." action={<button className="secondary-button" onClick={train} disabled={training}><Activity />{training ? 'Training…' : 'Train model'}</button>} />{message && <Notice tone={message.startsWith('Model') ? 'success' : 'error'}><p>{message}</p></Notice>}<Card>{anomalies.length ? <div className="finding-list">{anomalies.slice().reverse().map((event) => <div className="finding-row" key={event.id}><div className={`severity-bar ${event.is_anomaly ? 'high' : 'low'}`} /><div className="finding-main"><div className="finding-title"><strong>{event.is_anomaly ? 'Anomaly detected' : 'Normal activity'}</strong><span className={`status-pill ${event.is_anomaly ? 'high' : 'good'}`}>{event.source}</span></div><p>{event.explanation}</p><small>Device #{event.device_id} · score {event.score.toFixed(3)} · {new Date(event.observed_at).toLocaleString()}</small></div></div>)}</div> : <EmptyState title="No anomaly events recorded" detail="Train the model first, then submit a supported event through the API to create a reviewable record." />}</Card><button className="secondary-button" onClick={() => void onRefresh()}><RefreshCw />Refresh events</button></> }

