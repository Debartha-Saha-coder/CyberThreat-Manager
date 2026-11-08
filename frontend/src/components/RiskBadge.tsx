import React from 'react'
import type { RiskClassification } from '../types'

interface Props {
  classification: RiskClassification | null | undefined
  score?: number | null
  size?: 'sm' | 'md' | 'lg'
}

const config: Record<string, { label: string; className: string; color: string }> = {
  CRITICAL:    { label: 'CRITICAL',    className: 'badge-critical',  color: '#ef4444' },
  HIGH_RISK:   { label: 'HIGH RISK',   className: 'badge-high',      color: '#f97316' },
  MEDIUM_RISK: { label: 'MEDIUM RISK', className: 'badge-medium',    color: '#f59e0b' },
  GUARDED:     { label: 'GUARDED',     className: 'badge-guarded',   color: '#3b82f6' },
  LOW_RISK:    { label: 'LOW RISK',    className: 'badge-low',       color: '#10b981' },
  UNKNOWN:     { label: 'UNKNOWN',     className: 'badge-unknown',   color: '#6b7280' },
}

export function RiskBadge({ classification, score, size = 'md' }: Props) {
  const c = config[classification || 'UNKNOWN'] || config['UNKNOWN']
  const sizeClass = size === 'sm' ? 'text-xs px-2 py-0.5' : size === 'lg' ? 'text-sm px-4 py-1.5' : 'text-xs px-3 py-1'

  return (
    <span className={`inline-flex items-center gap-1.5 rounded-full font-semibold tracking-wide ${c.className} ${sizeClass}`}>
      <span className="w-1.5 h-1.5 rounded-full" style={{ backgroundColor: c.color }} />
      {c.label}
      {score != null && <span className="opacity-70 font-normal">({score.toFixed(0)})</span>}
    </span>
  )
}

export function RiskScoreBar({ score, classification }: { score: number; classification?: RiskClassification | null }) {
  const c = config[classification || 'UNKNOWN'] || config['UNKNOWN']
  return (
    <div className="space-y-1">
      <div className="flex justify-between text-sm">
        <span className="text-gray-400">Risk Score</span>
        <span className="font-bold" style={{ color: c.color }}>{score.toFixed(1)}/100</span>
      </div>
      <div className="h-2 bg-navy-600 rounded-full overflow-hidden">
        <div
          className="h-full rounded-full transition-all duration-700"
          style={{ width: `${Math.min(score, 100)}%`, backgroundColor: c.color }}
        />
      </div>
    </div>
  )
}
