export const API_BASE_URL = (process.env.NEXT_PUBLIC_API_BASE_URL ?? 'https://sentinel-security-platform-9kuj.onrender.com').replace(/\/$/, '')

export type User = { id: number; email: string; created_at: string }
export type Token = { access_token: string; token_type: string }
export type Device = { id: number; owner_id: number; name: string; serial_number: string; created_at: string }
export type Health = { status: string; database: string; connectivity: string; schema: string }
export type RiskAssessment = { risk_score: number; security_score: number; severity: string; findings: Array<{ label: string; evidence: string; recommended_action: string }> }

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
  assessRisk: (assetId: string, signals: Record<string, boolean>) => request<RiskAssessment>('/api/v1/risk/assess', { method: 'POST', body: JSON.stringify({ asset_id: assetId, signals }) }),
}

export function saveToken(value: string) { sessionStorage.setItem('sentinel_access_token', value) }
export function clearToken() { sessionStorage.removeItem('sentinel_access_token') }
