import { AuthGate } from '@/components/auth-gate'

type Props = { params: Promise<{ slug: string[] }> }

export default async function CatchAllPage({ params }: Props) {
  const { slug } = await params
  const requested = slug.join('/')
  const allowed = ['devices', 'risk-findings', 'digital-twin', 'anomalies', 'simulator', 'activity', 'reports', 'settings']
  const section = allowed.includes(requested) ? requested : 'overview'
  return <AuthGate initialSection={section as Parameters<typeof AuthGate>[0]['initialSection']} />
}
