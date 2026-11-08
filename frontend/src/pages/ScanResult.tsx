import React, { useEffect, useState } from 'react'
import { useParams, Link } from 'react-router-dom'
import {
  Shield, Globe, Lock, Users, AlertTriangle, CheckCircle,
  XCircle, Info, ChevronDown, ChevronUp, ExternalLink,
} from 'lucide-react'
import { motion } from 'framer-motion'
import { scanService } from '../services'
import { RiskBadge, RiskScoreBar } from '../components/RiskBadge'
import type { ScanReport } from '../types'

function EngineCard({
  title, icon, score, children, className = '',
}: {
  title: string
  icon: React.ReactNode
  score?: number | null
  children: React.ReactNode
  className?: string
}) {
  const [open, setOpen] = useState(true)
  return (
    <div className={`card ${className}`}>
      <button
        onClick={() => setOpen((o) => !o)}
        className="w-full flex items-center justify-between p-4 text-left"
      >
        <div className="flex items-center gap-3">
          <div className="text-blue-400">{icon}</div>
          <span className="font-semibold text-gray-200 text-sm">{title}</span>
          {score != null && (
            <span className="text-xs text-gray-400 ml-2">Score: <span className="text-white font-medium">{score.toFixed(1)}</span></span>
          )}
        </div>
        {open ? <ChevronUp size={16} className="text-gray-500" /> : <ChevronDown size={16} className="text-gray-500" />}
      </button>
      {open && <div className="px-4 pb-4 border-t border-gray-800 pt-4">{children}</div>}
    </div>
  )
}

function FindingRow({ f }: { f: { title: string; description: string; severity: string; evidence?: string; recommendation?: string } }) {
  const [open, setOpen] = useState(false)
  const colors: Record<string, string> = {
    critical: 'text-red-400', high: 'text-orange-400', medium: 'text-yellow-400',
    low: 'text-blue-400', info: 'text-gray-400',
  }
  return (
    <div className="border border-gray-800 rounded-lg overflow-hidden">
      <button onClick={() => setOpen((o) => !o)} className="w-full text-left flex items-start gap-3 p-3 hover:bg-navy-700 transition-colors">
        <AlertTriangle size={14} className={`mt-0.5 flex-shrink-0 ${colors[f.severity] || 'text-gray-400'}`} />
        <div className="flex-1 min-w-0">
          <p className="text-sm text-gray-200">{f.title}</p>
          <p className="text-xs text-gray-500 capitalize">{f.severity}</p>
        </div>
        {open ? <ChevronUp size={14} className="text-gray-500 mt-0.5 flex-shrink-0" /> : <ChevronDown size={14} className="text-gray-500 mt-0.5 flex-shrink-0" />}
      </button>
      {open && (
        <div className="px-4 pb-4 space-y-2">
          <p className="text-sm text-gray-300">{f.description}</p>
          {f.evidence && <p className="text-xs font-mono bg-navy-900 text-gray-400 rounded p-2 break-all">{f.evidence}</p>}
          {f.recommendation && (
            <div className="flex items-start gap-2 text-xs text-green-400">
              <CheckCircle size={12} className="mt-0.5 flex-shrink-0" />
              {f.recommendation}
            </div>
          )}
        </div>
      )}
    </div>
  )
}

export default function ScanResultPage() {
  const { id } = useParams<{ id: string }>()
  const [report, setReport] = useState<ScanReport | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    if (!id) return
    const load = async () => {
      try {
        const scanResp = await scanService.get(Number(id))
        const scan = scanResp.data
        if (['pending', 'running'].includes(scan.status)) {
          // Poll
          await scanService.pollUntilComplete(Number(id))
        }
        const reportResp = await scanService.report(Number(id))
        setReport(reportResp.data)
      } catch (err: unknown) {
        const detail = (err as { response?: { data?: { detail?: string } } })?.response?.data?.detail
        setError(detail || 'Failed to load scan report.')
      } finally {
        setLoading(false)
      }
    }
    load()
  }, [id])

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

  if (!report) return null

  const { scan, scoring, threat, web, certificate, community } = report

  const findings: Array<{ title: string; description: string; severity: string; evidence?: string; recommendation?: string }> =
    (web as { findings?: Array<{ title: string; description: string; severity: string; evidence?: string; recommendation?: string }> } | null)?.findings || []

  const certFindings: Array<{ title: string; description: string; severity: string; evidence?: string; recommendation?: string }> =
    (certificate as { findings?: Array<{ title: string; description: string; severity: string; evidence?: string; recommendation?: string }> } | null)?.findings || []

  return (
    <div className="space-y-6 max-w-5xl">
      {/* Header */}
      <div>
        <div className="flex items-start justify-between gap-4 flex-wrap">
          <div>
            <h1 className="text-2xl font-bold text-white">Scan Report</h1>
            <p className="text-sm font-mono text-gray-400 mt-1 break-all">{scan.normalized_url}</p>
          </div>
          <a
            href={scan.normalized_url}
            target="_blank"
            rel="noopener noreferrer"
            className="text-xs text-blue-400 flex items-center gap-1 flex-shrink-0 mt-2"
          >
            <ExternalLink size={12} />Open URL
          </a>
        </div>
        <p className="text-xs text-gray-500 mt-2">
          Scanned: {scan.completed_at ? new Date(scan.completed_at).toLocaleString() : 'In progress'}
          {scan.status === 'partial' && <span className="ml-3 text-yellow-500">⚠ Partial assessment — some engines unavailable</span>}
        </p>
      </div>

      {/* Risk overview */}
      <div className="card p-6">
        <div className="flex items-center gap-4 flex-wrap mb-5">
          <RiskBadge classification={scan.risk_classification} score={scan.overall_risk_score} size="lg" />
          {scoring && <p className="text-sm text-gray-400 flex-1">{/* verdict explanation omitted for brevity */}</p>}
        </div>
        {scan.overall_risk_score != null && (
          <RiskScoreBar score={scan.overall_risk_score} classification={scan.risk_classification} />
        )}
        {/* Engine score breakdown */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3 mt-5">
          {[
            { label: 'Threat Intel', score: scan.threat_score, ran: scan.threat_engine_ran },
            { label: 'Web Security', score: scan.web_score, ran: scan.web_engine_ran },
            { label: 'Certificate', score: scan.certificate_score, ran: scan.cert_engine_ran },
            { label: 'Community', score: scan.community_score, ran: scan.community_engine_ran },
          ].map(({ label, score, ran }) => (
            <div key={label} className="bg-navy-900 rounded-lg p-3">
              <p className="text-xs text-gray-500">{label}</p>
              {ran && score != null ? (
                <p className="text-xl font-bold text-white mt-1">{score.toFixed(0)}<span className="text-xs text-gray-500">/100</span></p>
              ) : (
                <p className="text-sm text-gray-600 mt-1">N/A</p>
              )}
            </div>
          ))}
        </div>
      </div>

      {/* Threat Intelligence */}
      <EngineCard title="Threat Intelligence" icon={<Shield size={18} />} score={scan.threat_score}>
        {threat ? (
          <div className="space-y-3">
            <div className="grid grid-cols-3 gap-3">
              {(threat as { adapters?: Array<{ name: string; status: string; score: number; categories?: string[]; is_confirmed?: boolean; error?: string }> }).adapters?.map((a) => (
                <div key={a.name} className="bg-navy-900 rounded-lg p-3">
                  <p className="text-xs text-gray-500 mb-1">{a.name}</p>
                  <p className={`text-sm font-medium capitalize ${
                    a.status === 'malicious' ? 'text-red-400' :
                    a.status === 'suspicious' ? 'text-yellow-400' :
                    a.status === 'clean' ? 'text-green-400' :
                    'text-gray-500'
                  }`}>{a.status.replace('_', ' ')}</p>
                  {a.error && <p className="text-xs text-gray-600 mt-1">{a.error}</p>}
                </div>
              ))}
            </div>
            {(threat as { is_confirmed_malicious?: boolean }).is_confirmed_malicious && (
              <div className="flex items-center gap-2 p-3 rounded-lg bg-red-900/20 border border-red-800 text-red-400 text-sm">
                <XCircle size={16} />
                Confirmed malicious by at least one threat intelligence provider.
              </div>
            )}
          </div>
        ) : (
          <p className="text-gray-500 text-sm">Engine did not run or produced no data.</p>
        )}
      </EngineCard>

      {/* Web Security */}
      <EngineCard title="Web Security Assessment" icon={<Globe size={18} />} score={scan.web_score}>
        {web ? (
          <div className="space-y-3">
            <div className="grid grid-cols-2 md:grid-cols-4 gap-2 text-xs">
              {[
                { label: 'HTTPS', val: (web as { enforces_https?: boolean }).enforces_https },
                { label: 'HSTS', val: (web as { headers?: { strict_transport_security?: string } }).headers },
                { label: 'CSP', val: (web as { has_csp?: boolean }).has_csp },
                { label: 'X-Content-Type', val: (web as { has_x_content_type?: boolean }).has_x_content_type },
              ].map(({ label, val }) => (
                <div key={label} className="flex items-center gap-2 bg-navy-900 rounded px-2 py-1.5">
                  {val ? <CheckCircle size={12} className="text-green-400" /> : <XCircle size={12} className="text-red-400" />}
                  {label}
                </div>
              ))}
            </div>
            {findings.length > 0 && (
              <div className="space-y-2">
                <p className="text-xs text-gray-500 font-medium">{findings.length} finding(s)</p>
                {findings.map((f, i) => <FindingRow key={i} f={f} />)}
              </div>
            )}
          </div>
        ) : (
          <p className="text-gray-500 text-sm">Engine did not run or produced no data.</p>
        )}
      </EngineCard>

      {/* Certificate */}
      <EngineCard title="Certificate Analysis" icon={<Lock size={18} />} score={scan.certificate_score}>
        {certificate ? (
          <div className="space-y-3">
            {(certificate as { certificate?: { subject_cn?: string; issuer_cn?: string; not_after?: string; days_until_expiry?: number; sha256_fingerprint?: string; key_algorithm?: string; key_size?: number } }).certificate && (() => {
              const c = (certificate as { certificate: { subject_cn?: string; issuer_cn?: string; not_after?: string; days_until_expiry?: number; sha256_fingerprint?: string; key_algorithm?: string; key_size?: number } }).certificate
              return (
                <div className="grid grid-cols-2 gap-2 text-xs">
                  {[
                    ['Subject', c.subject_cn], ['Issuer', c.issuer_cn],
                    ['Expires', c.not_after ? new Date(c.not_after).toLocaleDateString() : 'N/A'],
                    ['Days Left', c.days_until_expiry],
                    ['Key', c.key_algorithm ? `${c.key_algorithm} ${c.key_size ? c.key_size + 'bit' : ''}` : 'N/A'],
                    ['Fingerprint', c.sha256_fingerprint ? c.sha256_fingerprint.slice(0, 16) + '…' : 'N/A'],
                  ].map(([label, value]) => (
                    <div key={label as string} className="bg-navy-900 rounded p-2">
                      <p className="text-gray-500">{label}</p>
                      <p className="text-gray-200 font-mono break-all">{value ?? 'N/A'}</p>
                    </div>
                  ))}
                </div>
              )
            })()}
            {certFindings.length > 0 && (
              <div className="space-y-2">
                <p className="text-xs text-gray-500 font-medium">{certFindings.length} finding(s)</p>
                {certFindings.map((f, i) => <FindingRow key={i} f={f} />)}
              </div>
            )}
          </div>
        ) : (
          <p className="text-gray-500 text-sm">Engine did not run or produced no data.</p>
        )}
      </EngineCard>

      {/* Community */}
      <EngineCard title="Community Intelligence" icon={<Users size={18} />} score={scan.community_score}>
        {community ? (
          <div className="space-y-3">
            <div className="grid grid-cols-3 gap-3 text-center">
              {[
                { label: 'Total Reports', val: (community as { total_reports?: number }).total_reports ?? 0 },
                { label: 'Verified', val: (community as { verified_reports?: number }).verified_reports ?? 0 },
                { label: 'Support Votes', val: (community as { support_votes?: number }).support_votes ?? 0 },
              ].map(({ label, val }) => (
                <div key={label} className="bg-navy-900 rounded-lg p-3">
                  <p className="text-2xl font-bold text-white">{val}</p>
                  <p className="text-xs text-gray-500">{label}</p>
                </div>
              ))}
            </div>
          </div>
        ) : (
          <p className="text-gray-500 text-sm">No community data available for this domain.</p>
        )}
      </EngineCard>
    </div>
  )
}
