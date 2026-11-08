import React, { useEffect, useState } from 'react'
import { Shield, Target, Link as LinkIcon } from 'lucide-react'
import { intelligenceService } from '../services'

export default function ThreatExplorer() {
  const [campaigns, setCampaigns] = useState<Array<{
    id: number; name: string; description?: string; category?: string;
    report_count: number; indicator_count: number; created_at?: string
  }>>([])
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    intelligenceService.campaigns().then((r) => setCampaigns(r.data)).finally(() => setLoading(false))
  }, [])

  return (
    <div className="space-y-6 max-w-4xl">
      <div>
        <h1 className="text-2xl font-bold text-white">Threat Explorer</h1>
        <p className="text-gray-400 text-sm mt-1">Known threat campaigns and indicators of compromise.</p>
      </div>

      <div className="card">
        <div className="p-5 border-b border-gray-800">
          <h2 className="text-sm font-semibold text-gray-300">Active Threat Campaigns</h2>
        </div>
        {loading ? (
          <div className="p-8 text-center"><div className="w-6 h-6 border-2 border-blue-500 border-t-transparent rounded-full animate-spin mx-auto" /></div>
        ) : campaigns.length === 0 ? (
          <div className="p-8 text-center text-gray-500 text-sm">No threat campaigns recorded yet.</div>
        ) : (
          <div className="divide-y divide-gray-800">
            {campaigns.map((c) => (
              <div key={c.id} className="p-4 hover:bg-navy-700 transition-colors">
                <div className="flex items-start gap-3">
                  <Shield size={16} className="text-red-400 mt-0.5 flex-shrink-0" />
                  <div className="flex-1">
                    <p className="text-sm font-medium text-gray-200">{c.name}</p>
                    {c.description && <p className="text-xs text-gray-500 mt-0.5">{c.description}</p>}
                    <div className="flex gap-3 mt-2">
                      {c.category && <span className="text-xs bg-navy-900 text-gray-400 px-2 py-0.5 rounded">{c.category}</span>}
                      <span className="text-xs text-gray-600">{c.report_count} reports · {c.indicator_count} indicators</span>
                    </div>
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  )
}
