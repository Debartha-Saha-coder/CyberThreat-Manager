import React, { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import {
  BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer,
  PieChart, Pie, Cell,
} from 'recharts'
import { Shield, AlertTriangle, Globe, Clock, TrendingUp, Activity } from 'lucide-react'
import { motion } from 'framer-motion'
import { dashboardService } from '../services'
import { StatCard } from '../components/StatCard'
import { RiskBadge } from '../components/RiskBadge'
import type { DashboardStats } from '../types'

const PIE_COLORS = ['#ef4444', '#f97316', '#f59e0b', '#10b981']

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

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold text-white">Security Dashboard</h1>
        <p className="text-gray-400 text-sm mt-1">Real-time threat intelligence overview</p>
      </div>

      {/* Stat cards */}
      <div className="grid grid-cols-2 xl:grid-cols-4 gap-4">
        <StatCard label="Total Scans" value={stats.total_scans} icon={<Globe size={20} />} color="#3b82f6" subtext={`+${stats.scans_today} today`} />
        <StatCard label="Threats Detected" value={stats.threats_detected} icon={<AlertTriangle size={20} />} color="#ef4444" />
        <StatCard label="High-Risk Domains" value={stats.high_risk_domains} icon={<Shield size={20} />} color="#f97316" />
        <StatCard label="Critical Alerts" value={stats.critical_count} icon={<Activity size={20} />} color="#7c3aed" />
      </div>

      {/* Charts */}
      <div className="grid grid-cols-1 xl:grid-cols-2 gap-6">
        {/* Bar chart */}
        <div className="card p-5">
          <h2 className="text-sm font-semibold text-gray-300 mb-4">Risk Distribution</h2>
          {stats.total_scans === 0 ? (
            <div className="h-48 flex items-center justify-center text-gray-500 text-sm">No scan data yet.</div>
          ) : (
            <ResponsiveContainer width="100%" height={200}>
              <BarChart data={stats.risk_distribution} barSize={32}>
                <CartesianGrid strokeDasharray="3 3" stroke="#1e2640" />
                <XAxis dataKey="classification" tick={{ fill: '#6b7280', fontSize: 11 }} />
                <YAxis tick={{ fill: '#6b7280', fontSize: 11 }} />
                <Tooltip
                  cursor={false}
                  contentStyle={{ backgroundColor: '#0d1224', border: '1px solid #1e2640', borderRadius: 8 }}
                  labelStyle={{ color: '#e5e7eb' }}
                  itemStyle={{ color: '#e5e7eb' }}
                />
                <Bar dataKey="count" radius={[4, 4, 0, 0]}>
                  {stats.risk_distribution.map((_, i) => (
                    <Cell key={i} fill={PIE_COLORS[i % PIE_COLORS.length]} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          )}
        </div>

        {/* Pie chart */}
        <div className="card p-5">
          <h2 className="text-sm font-semibold text-gray-300 mb-4">Threat Composition</h2>
          {stats.total_scans === 0 ? (
            <div className="h-48 flex items-center justify-center text-gray-500 text-sm">No scan data yet.</div>
          ) : (
            <div>
              <ResponsiveContainer width="100%" height={160}>
                <PieChart>
                  <Pie data={pieData} cx="50%" cy="50%" outerRadius={64} dataKey="value">
                    {pieData.map((_, i) => <Cell key={i} fill={PIE_COLORS[i % PIE_COLORS.length]} />)}
                  </Pie>
                  <Tooltip contentStyle={{ backgroundColor: '#0d1224', border: '1px solid #1e2640', borderRadius: 8 }} />
                </PieChart>
              </ResponsiveContainer>
              <div className="grid grid-cols-2 gap-x-4 gap-y-2 mt-2 text-xs">
                {pieData.map((item, i) => {
                  const percent = stats.total_scans > 0 ? (item.value / stats.total_scans) * 100 : 0
                  return (
                    <div key={item.name} className="flex items-center justify-between gap-2 min-w-0">
                      <span className="flex items-center gap-2 min-w-0 text-gray-400">
                        <span className="w-2.5 h-2.5 rounded-sm flex-shrink-0" style={{ backgroundColor: PIE_COLORS[i % PIE_COLORS.length] }} />
                        <span className="truncate">{item.name}</span>
                      </span>
                      <span className="font-medium text-gray-200 flex-shrink-0">{percent.toFixed(0)}%</span>
                    </div>
                  )
                })}
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Recent scans */}
      <div className="card">
        <div className="flex items-center justify-between p-5 border-b border-gray-800">
          <h2 className="text-sm font-semibold text-gray-300">Recent Scans</h2>
          <Link to="/scanner" className="text-xs text-blue-400 hover:text-blue-300">New Scan →</Link>
        </div>
        {stats.recent_scans.length === 0 ? (
          <div className="p-8 text-center text-gray-500 text-sm">No scans yet. <Link to="/scanner" className="text-blue-400">Submit your first URL.</Link></div>
        ) : (
          <div className="divide-y divide-gray-800">
            {stats.recent_scans.map((scan) => (
              <Link key={scan.id} to={`/scan/${scan.id}`} className="flex items-center gap-4 px-5 py-3.5 hover:bg-navy-700 transition-colors">
                <div className="flex-1 min-w-0">
                  <p className="text-sm text-gray-200 truncate font-mono">{scan.url}</p>
                  <p className="text-xs text-gray-500 mt-0.5">{new Date(scan.created_at).toLocaleString()}</p>
                </div>
                <div className="flex-shrink-0">
                  {scan.risk_classification
                    ? <RiskBadge classification={scan.risk_classification} score={scan.overall_risk_score} />
                    : <span className="text-xs text-gray-500 capitalize">{scan.status}</span>
                  }
                </div>
              </Link>
            ))}
          </div>
        )}
      </div>
    </div>
  )
}
