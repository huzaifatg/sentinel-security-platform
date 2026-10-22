import { AuthGate } from '@/components/auth-gate'

export default function Home() {
  return <AuthGate initialSection="overview" />
}
