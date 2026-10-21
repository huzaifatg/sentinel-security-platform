import { Activity, AlertTriangle, ArrowUpRight, CircleHelp, Cpu, LayoutDashboard, Network, Settings, ShieldCheck, Smartphone, Sparkles } from 'lucide-react'
import { RiskConsole } from '@/components/risk-console'

const navItems = [
  { label: 'Overview', icon: LayoutDashboard, active: true },
  { label: 'Devices', icon: Smartphone },
  { label: 'Risk findings', icon: AlertTriangle },
  { label: 'Digital twin', icon: Network },
  { label: 'Anomalies', icon: Activity },
  { label: 'Simulator', icon: Sparkles },
]

function StatusPill({ children, tone = 'neutral' }: { children: React.ReactNode; tone?: 'neutral' | 'good' | 'warning' }) {
  return <span className={`status-pill ${tone}`}>{children}</span>
}

export default function Home() {
  return (
    <main className="app-shell">
      <aside className="sidebar">
        <div className="brand"><div className="brand-mark"><ShieldCheck /></div><div><strong>Sentinel</strong><span>Security twin</span></div></div>
        <nav aria-label="Primary navigation" className="nav-list">
          <p className="nav-label">Workspace</p>
          {navItems.map(({ label, icon: Icon, active }) => <a key={label} className={active ? 'nav-item active' : 'nav-item'} href={active ? '#overview' : `#${label.toLowerCase().replaceAll(' ', '-')}`}><Icon />{label}</a>)}
        </nav>
        <div className="sidebar-footer"><a className="nav-item" href="#settings"><Settings />Settings</a><a className="nav-item" href="#help"><CircleHelp />Help & limitations</a><div className="profile"><div className="avatar">AR</div><div><strong>Alex Rahman</strong><span>Personal workspace</span></div></div></div>
      </aside>
      <section className="content" id="overview">
        <header className="topbar"><div><p className="eyebrow">Security posture</p><h1>Good morning, Alex</h1><p className="muted">A transparent view of your authorized digital environment.</p></div><div className="topbar-actions"><StatusPill tone="good"><span className="dot" />System operational</StatusPill><button className="icon-button" aria-label="Open settings"><Settings /></button></div></header>
        <div className="notice"><div className="notice-icon"><ShieldCheck /></div><div><strong>Prototype environment</strong><p>Sentinel is currently showing the application shell. Security results will appear once telemetry and risk services are connected.</p></div><a href="#status">View system status <ArrowUpRight /></a></div>
        <div className="metric-grid"><article className="metric-card accent"><div className="metric-heading"><span>Security score</span><ShieldCheck /></div><div className="metric-value">—<small>/ 100</small></div><StatusPill>Awaiting data</StatusPill></article><article className="metric-card"><div className="metric-heading"><span>Registered devices</span><Smartphone /></div><div className="metric-value">—</div><p className="metric-foot">No devices connected</p></article><article className="metric-card"><div className="metric-heading"><span>Active risks</span><AlertTriangle /></div><div className="metric-value">—</div><p className="metric-foot">Risk engine not connected</p></article><article className="metric-card"><div className="metric-heading"><span>Last activity</span><Activity /></div><div className="metric-value text-value">—</div><p className="metric-foot">No telemetry recorded</p></article></div>
        <div className="panel-grid"><article className="panel chart-panel"><div className="panel-header"><div><p className="eyebrow">Posture trend</p><h2>Security score over time</h2></div><StatusPill>Not available</StatusPill></div><div className="empty-state"><div className="empty-icon"><Activity /></div><strong>Waiting for verified telemetry</strong><p>This chart will use calculated backend scores. No placeholder or fabricated security data is shown.</p></div></article><article className="panel"><div className="panel-header"><div><p className="eyebrow">Digital twin</p><h2>Environment coverage</h2></div><Network /></div><div className="coverage-list"><div><span><Cpu />Assets</span><strong>—</strong></div><div><span><Network />Networks</span><strong>—</strong></div><div><span><AlertTriangle />Findings</span><strong>—</strong></div></div><a className="panel-link" href="#digital-twin">Explore digital twin <ArrowUpRight /></a></article></div>
        <RiskConsole />
        <div className="lower-grid"><article className="panel"><div className="panel-header"><div><p className="eyebrow">Next steps</p><h2>Recommendations</h2></div><Sparkles /></div><div className="empty-row"><ShieldCheck /><div><strong>Recommendations will be evidence-based</strong><p>The rule engine will generate actions from verified findings.</p></div></div></article><article className="panel"><div className="panel-header"><div><p className="eyebrow">Recent activity</p><h2>Telemetry events</h2></div><Activity /></div><div className="empty-row"><Activity /><div><strong>No events yet</strong><p>Collection and simulation sources will be labeled separately.</p></div></div></article></div>
        <footer className="page-footer"><span>Sentinel v0.1 · University prototype</span><span>Data coverage depends on authorized sources.</span></footer>
      </section>
    </main>
  )
}
