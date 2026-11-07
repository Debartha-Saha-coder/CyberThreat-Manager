// Shared TypeScript types for the Hackmetrix frontend

export type RiskClassification =
  | 'LOW_RISK'
  | 'GUARDED'
  | 'MEDIUM_RISK'
  | 'HIGH_RISK'
  | 'CRITICAL'
  | 'UNKNOWN'

export type ScanStatus = 'pending' | 'running' | 'completed' | 'failed' | 'partial'

export interface ScanListItem {
  id: number
  url: string
  status: ScanStatus
  overall_risk_score: number | null
  risk_classification: RiskClassification | null
  created_at: string
  completed_at: string | null
}

export interface ScanDetail extends ScanListItem {
  normalized_url: string
  domain: string
  threat_score: number | null
  web_score: number | null
  certificate_score: number | null
  community_score: number | null
  threat_engine_ran: boolean
  web_engine_ran: boolean
  cert_engine_ran: boolean
  community_engine_ran: boolean
  error_message: string | null
  started_at: string | null
}

export interface ScanReport {
  scan: ScanDetail
  scoring: {
    overall_score: number
    classification: RiskClassification
    threat_score: number | null
    web_score: number | null
    certificate_score: number | null
    community_score: number | null
  } | null
  threat: Record<string, unknown> | null
  web: Record<string, unknown> | null
  certificate: Record<string, unknown> | null
  community: Record<string, unknown> | null
}

export interface DashboardStats {
  total_scans: number
  scans_today: number
  threats_detected: number
  high_risk_domains: number
  critical_count: number
  high_risk_count: number
  medium_risk_count: number
  low_risk_count: number
  recent_scans: ScanListItem[]
  risk_distribution: Array<{ classification: string; count: number }>
}

export interface CommunityReport {
  id: number
  url: string
  domain: string
  category: string
  title: string
  status: string
  support_count: number
  dispute_count: number
  created_at: string
  description?: string
  analyst_notes?: string
  verified_at?: string
  evidence?: Array<{ type: string; content: string }>
}

export interface User {
  id: number
  email: string
  username: string
  role: string
  is_active: boolean
  is_verified: boolean
  created_at: string
}

export interface TokenResponse {
  access_token: string
  token_type: string
  expires_in: number
}
