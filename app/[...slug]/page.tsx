import { SentinelApp } from '@/components/sentinel-app'

type Props = { params: Promise<{ slug: string[] }> }

export default async function CatchAllPage({ params }: Props) {
  const { slug } = await params
  const requested = slug.join('/')
  const allowed = ['devices', 'risk-findings', 'digital-twin', 'anomalies', 'simulator', 'activity', 'reports', 'settings']
  const section = allowed.includes(requested) ? requested : 'overview'
  return <SentinelApp initialSection={section as Parameters<typeof SentinelApp>[0]['initialSection']} />
}
