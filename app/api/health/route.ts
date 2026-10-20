import { NextResponse } from 'next/server'

export function GET() {
  return NextResponse.json({
    status: 'ok',
    service: 'sentinel-web',
    version: '0.1.0',
    checks: { web: 'ok', database: 'not_configured', graph: 'not_configured' },
  })
}
