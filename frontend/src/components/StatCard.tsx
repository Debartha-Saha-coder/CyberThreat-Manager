import React from 'react'
import { motion } from 'framer-motion'

interface Props {
  label: string
  value: string | number
  icon: React.ReactNode
  color?: string
  subtext?: string
}

export function StatCard({ label, value, icon, subtext }: Props) {
  return (
    <motion.div
      initial={{ opacity: 0, y: 12 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      className="card card-hover p-5 min-h-[112px] flex items-start justify-between gap-4"
    >
      <div className="min-w-0">
        <p style={{ color: 'var(--muted)' }} className="text-xs mb-3">{label}</p>
        <p className="text-3xl leading-none" style={{ fontFamily: 'DM Serif Display, Georgia, serif' }}>{value}</p>
        {subtext && <p style={{ color: 'var(--muted)' }} className="text-xs mt-2">{subtext}</p>}
      </div>
      <div className="w-9 h-9 rounded-xl flex items-center justify-center flex-shrink-0" style={{ color: 'var(--accent)', border: '1px solid var(--border)', background: 'var(--field)' }}>
        {icon}
      </div>
    </motion.div>
  )
}
