import React, { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import {
  BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer,
  PieChart, Pie, Cell,
} from 'recharts'
import { Shield, AlertTriangle, Globe, Activity, Search, ArrowUpRight } from 'lucide-react'
import { motion } from 'framer-motion'
import { dashboardService } from '../services'
import { StatCard } from '../components/StatCard'
import { RiskBadge } from '../components/RiskBadge'
import type { DashboardStats } from '../types'

const PIE_COLORS = ['var(--danger)', 'var(--warning)', 'var(--accent)', 'var(--success)']

export default function Dashboard() {
  const [stats, setStats] = useState<DashboardStats | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    dashboardService.stats()
      .then((r) => setStats(r.data))
      .catch(() => setError('Failed to load dashboard statistics.'))
      .finally(() => setLoading(false))
  }, [])

  if (loading) return (
    <div className="flex items-center justify-center h-64">
      <div className="w-8 h-8 border-2 border-blue-500 border-t-transparent rounded-full animate-spin" />
    </div>
  )

  if (error) return (
    <div className="card p-6 text-red-400">
      <AlertTriangle size={20} className="inline mr-2" />{error}
    </div>
  )

  if (!stats) return null

  const pieData = stats.risk_distribution.map((d) => ({ name: d.classification, value: d.count }))
  const chartTick = { fill: 'var(--muted)', fontSize: 11 }
  const tooltipStyle = { backgroundColor: 'var(--card)', border: '1px solid var(--border)', borderRadius: 8, color: 'var(--text)' }

  return (
    <div className="bento-grid">
      <section className="card welcome-panel">
        <div>
          <p className="eyebrow">Threat intelligence</p>
          <h1>Know what is<br />coming next.</h1>
        </div>
        <div className="welcome-meta">
          <span className="status-dot" />
          <span>Protection systems operational</span>
        </div>
      </section>

      <section className="card scan-panel">
        <div className="flex items-start justify-between">
          <div>
            <p className="panel-label">Quick scan</p>
            <h2 className="mt-2 text-xl">Inspect a target</h2>
          </div>
          <Search size={18} style={{ color: 'var(--accent)' }} />
        </div>
        <p className="text-sm mt-5" style={{ color: 'var(--muted)' }}>Run URL, certificate, community and threat analysis.</p>
        <Link to="/scanner" className="btn-primary w-full mt-6">
          Open scanner <ArrowUpRight size={16} />
        </Link>
      </section>

      <div className="stats-grid">
        <StatCard label="Total scans" value={stats.total_scans} icon={<Globe size={17} />} subtext={`+${stats.scans_today} today`} />
        <StatCard label="Threats detected" value={stats.threats_detected} icon={<AlertTriangle size={17} />} />
        <StatCard label="High-risk domains" value={stats.high_risk_domains} icon={<Shield size={17} />} />
        <StatCard label="Critical alerts" value={stats.critical_count} icon={<Activity size={17} />} />
      </div>

      <section className="card chart-panel">
        <div className="flex items-center justify-between mb-4">
          <div><p className="panel-label">Exposure</p><h2 className="mt-1 text-xl">Risk overview</h2></div>
          <span style={{ color: 'var(--muted)' }} className="text-xs">By classification</span>
        </div>
        {stats.total_scans === 0 ? (
          <div className="h-[240px] flex items-center justify-center text-sm" style={{ color: 'var(--muted)' }}>No scan data yet.</div>
        ) : (
          <ResponsiveContainer width="100%" height={240}>
            <BarChart data={stats.risk_distribution} barSize={34}>
              <CartesianGrid strokeDasharray="3 3" stroke="var(--border)" vertical={false} />
              <XAxis dataKey="classification" tick={chartTick} axisLine={false} tickLine={false} />
              <YAxis tick={chartTick} axisLine={false} tickLine={false} />
              <Tooltip cursor={{ fill: 'var(--field)' }} contentStyle={tooltipStyle} />
              <Bar dataKey="count" radius={[6, 6, 0, 0]}>
                {stats.risk_distribution.map((_, i) => <Cell key={i} fill={PIE_COLORS[i % PIE_COLORS.length]} />)}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        )}
      </section>

      <section className="card threat-panel">
        <div><p className="panel-label">Composition</p><h2 className="mt-1 text-xl">Threat distribution</h2></div>
        {stats.total_scans === 0 ? (
          <div className="h-[240px] flex items-center justify-center text-sm" style={{ color: 'var(--muted)' }}>No distribution yet.</div>
        ) : (
          <div className="flex items-center gap-2 mt-3">
            <ResponsiveContainer width="52%" height={220}>
              <PieChart><Pie data={pieData} cx="50%" cy="50%" innerRadius={50} outerRadius={78} paddingAngle={3} dataKey="value">{pieData.map((_, i) => <Cell key={i} fill={PIE_COLORS[i % PIE_COLORS.length]} />)}</Pie><Tooltip contentStyle={tooltipStyle} /></PieChart>
            </ResponsiveContainer>
            <div className="flex-1 space-y-3">
              {pieData.map((item, i) => (
                <div key={item.name} className="flex items-center gap-2 text-xs">
                  <span className="w-2 h-2 rounded-full flex-shrink-0" style={{ backgroundColor: PIE_COLORS[i % PIE_COLORS.length] }} />
                  <span className="truncate" style={{ color: 'var(--muted)' }}>{item.name}</span>
                  <span className="ml-auto font-medium">{((item.value / stats.total_scans) * 100).toFixed(0)}%</span>
                </div>
              ))}
            </div>
          </div>
        )}
      </section>

      <section className="card recent-panel overflow-hidden">
        <div className="flex items-center justify-between px-5 py-4" style={{ borderBottom: '1px solid var(--border)' }}>
          <div><p className="panel-label">Archive</p><h2 className="mt-1 text-xl">Recent scans</h2></div>
          <Link to="/scanner" className="text-xs" style={{ color: 'var(--accent)' }}>New scan →</Link>
        </div>
        {stats.recent_scans.length === 0 ? (
          <div className="p-8 text-center text-sm" style={{ color: 'var(--muted)' }}>No scans yet. <Link to="/scanner" style={{ color: 'var(--accent)' }}>Start your first scan.</Link></div>
        ) : stats.recent_scans.map((scan) => (
          <Link key={scan.id} to={`/scan/${scan.id}`} className="flex items-center gap-4 px-5 py-4 transition-colors card-hover" style={{ borderTop: '1px solid var(--border)' }}>
            <div className="flex-1 min-w-0">
              <p className="text-sm truncate mono">{scan.url}</p>
              <p className="text-xs mt-1" style={{ color: 'var(--muted)' }}>{new Date(scan.created_at).toLocaleString()}</p>
            </div>
            {scan.risk_classification ? <RiskBadge classification={scan.risk_classification} score={scan.overall_risk_score} /> : <span className="text-xs capitalize" style={{ color: 'var(--muted)' }}>{scan.status}</span>}
          </Link>
        ))}
      </section>

      <section className="card feed-panel p-5">
        <p className="panel-label">Intelligence feed</p>
        <h2 className="mt-1 text-xl">Latest signals</h2>
        <div className="mt-5 space-y-3">
          {stats.recent_scans.length === 0 ? (
            <p className="text-sm py-10 text-center" style={{ color: 'var(--muted)' }}>No live signals recorded.</p>
          ) : stats.recent_scans.slice(0, 4).map((scan) => (
            <Link key={scan.id} to={`/scan/${scan.id}`} className="block card-soft p-3 card-hover">
              <div className="flex items-center gap-2 text-xs"><span className="status-dot" /><span style={{ color: 'var(--muted)' }}>Scan signal</span></div>
              <p className="mt-2 text-sm truncate mono">{scan.url}</p>
            </Link>
          ))}
        </div>
      </section>
    </div>
  )
}
