export const API_BASE_URL = (
  process.env.NEXT_PUBLIC_API_BASE_URL ??
  (typeof window !== 'undefined' && (window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1')
    ? 'http://localhost:8000'
    : 'https://sentinel-security-platform-9kuj.onrender.com')
).replace(/\/$/, '')

export type User = { id: number; email: string; created_at: string }
export type Token = { access_token: string; token_type: string }
export type Device = { id: number; owner_id: number; name: string; serial_number: string; created_at: string }
export type Health = { status: string; database: string; connectivity: string; schema: string }
export type Severity = 'low' | 'medium' | 'high' | 'critical'
export type SignalState = 'enabled' | 'disabled' | 'unknown' | 'not_applicable' | 'normal' | 'elevated' | 'high'
export type Provenance = 'default' | 'manual' | 'telemetry' | 'synthetic_demo' | 'mixed' | 'hypothetical'
export type Finding = { rule: string; signal: string; label: string; category: 'control_gap' | 'unverified' | 'behavioral'; affected_asset: string; state: SignalState; source: Provenance; evidence: string; weight: number; risk_factor: number; contribution: number; severity: Severity; timestamp: string; recommended_action: string }
export type SignalResult = { key: string; label: string; scope: string; state: SignalState; source: Provenance; weight: number; applicable: boolean; risk_factor: number; contribution: number; evidence: string }
export type RiskAssessment = { asset_id: string; methodology_version: string; risk_score: number; security_score: number; severity: Severity; raw_risk: number; applicable_weight: number; coverage: number; signals: SignalResult[]; findings: Finding[]; explanation: string; recommendations: string[]; assessed_at: string }
export type StoredAssessment = RiskAssessment & { id: number; device_id: number; created_at: string }
export type ProfileSignal = { key: string; label: string; scope: 'account' | 'device' | 'behavioral'; kind: 'control' | 'behavioral'; weight: number; state: SignalState; source: Provenance; updated_at: string | null; evidence: string; allowed_states: SignalState[] }
export type SecurityProfile = { device_id: number; signals: ProfileSignal[]; evidence_window_days: number; behavioral_evidence: Record<string, number> }
export type Methodology = { version: string; formula: string; risk_factors: Record<string, number>; not_applicable: string; unknown_policy: string; signals: Array<{ key: string; label: string; scope: string; kind: string; weight: number; rationale: string }>; severity_bands: Array<{ max_score: number; severity: Severity }>; limitations: string[] }
export type Telemetry = { id: number; device_id: number; event_type: string; payload: Record<string, unknown>; observed_at: string }
export type AnomalyEvent = { id: number; device_id: number; features: Record<string, number | boolean>; source: string; is_anomaly: boolean; score: number; explanation: string; model_version: string; observed_at: string }
export type ChangedSignal = { key: string; label: string; from_state: SignalState; to_state: SignalState; contribution_before: number; contribution_after: number; delta: number }
export type Simulation = { id: number; asset_id: string; device_id: number | null; before_risk_score: number; after_risk_score: number; before_security_score: number; after_security_score: number; removed_findings: string[]; added_findings: string[]; explanation: string; created_at: string; methodology_version: string | null; risk_delta: number | null; security_delta: number | null; changed_signals: ChangedSignal[]; recommendations: string[]; baseline: RiskAssessment | null; proposed: RiskAssessment | null }
export type ModelTraining = { model_version: string; feature_names: string[]; training_events: number }

export class ApiError extends Error {
  constructor(public status: number, message: string) { super(message) }
}

function token() { return typeof window === 'undefined' ? null : sessionStorage.getItem('sentinel_access_token') }

async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
  const headers = new Headers(init.headers)
  if (!headers.has('Content-Type') && init.body) headers.set('Content-Type', 'application/json')
  const accessToken = token()
  if (accessToken) headers.set('Authorization', `Bearer ${accessToken}`)
  const response = await fetch(`${API_BASE_URL}${path}`, { ...init, headers })
  const text = await response.text()
  let body: unknown = null
  try { body = text ? JSON.parse(text) : null } catch { body = text }
  if (!response.ok) {
    const detail = typeof body === 'object' && body && 'detail' in body ? String(body.detail) : 'The Sentinel API request failed.'
    throw new ApiError(response.status, detail)
  }
  return body as T
}

export const api = {
  health: () => request<Health>('/api/v1/health'),
  me: () => request<User>('/api/v1/auth/me'),
  register: (email: string, password: string) => request<User>('/api/v1/auth/register', { method: 'POST', body: JSON.stringify({ email, password }) }),
  login: (email: string, password: string) => {
    const body = new URLSearchParams({ username: email, password })
    return request<Token>('/api/v1/auth/login', { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body })
  },
  devices: () => request<Device[]>('/api/v1/devices'),
  createDevice: (name: string, serial_number: string) => request<Device>('/api/v1/devices', { method: 'POST', body: JSON.stringify({ name, serial_number }) }),
  device: (id: number) => request<Device>(`/api/v1/devices/${id}`),
  telemetry: (id: number) => request<Telemetry[]>(`/api/v1/devices/${id}/telemetry`),
  anomalies: () => request<AnomalyEvent[]>('/api/v1/anomalies/events'),
  trainModel: (events?: Array<Record<string, number | boolean>>) => request<ModelTraining>('/api/v1/anomalies/model/train', { method: 'POST', body: JSON.stringify({ events }) }),
  simulations: (deviceId?: number) => request<Simulation[]>(`/api/v1/simulations${deviceId ? `?device_id=${deviceId}` : ''}`),
  createSimulation: (assetId: string, changes: Record<string, boolean>) => request<Simulation>('/api/v1/simulations', { method: 'POST', body: JSON.stringify({ asset_id: assetId, current_signals: {}, changes }) }),
  simulateDevice: (deviceId: number, proposedControls: Record<string, SignalState>) => request<Simulation>('/api/v1/simulations', { method: 'POST', body: JSON.stringify({ device_id: deviceId, proposed_controls: proposedControls }) }),
  assessRisk: (assetId: string, signals: Record<string, boolean>) => request<RiskAssessment>('/api/v1/risk/assess', { method: 'POST', body: JSON.stringify({ asset_id: assetId, signals }) }),
  methodology: () => request<Methodology>('/api/v1/risk/methodology'),
  securityProfile: (deviceId: number) => request<SecurityProfile>(`/api/v1/devices/${deviceId}/security-profile`),
  updateSecurityProfile: (deviceId: number, controls: Record<string, SignalState>, source: 'manual' | 'synthetic_demo' = 'manual') => request<SecurityProfile>(`/api/v1/devices/${deviceId}/security-profile`, { method: 'PUT', body: JSON.stringify({ controls, source }) }),
  runAssessment: (deviceId: number) => request<StoredAssessment>(`/api/v1/devices/${deviceId}/assessments`, { method: 'POST' }),
  assessments: (deviceId: number) => request<StoredAssessment[]>(`/api/v1/devices/${deviceId}/assessments`),
  sendTelemetry: (deviceId: number, eventType: string, payload: Record<string, unknown>) => request<Telemetry>(`/api/v1/devices/${deviceId}/telemetry`, { method: 'POST', body: JSON.stringify({ event_type: eventType, payload }) }),
}

export function saveToken(value: string) { sessionStorage.setItem('sentinel_access_token', value) }
export function clearToken() { sessionStorage.removeItem('sentinel_access_token') }
