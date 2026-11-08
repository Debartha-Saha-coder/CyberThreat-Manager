import api from './api'
import type {
  DashboardStats, ScanListItem, ScanReport, CommunityReport,
  User, TokenResponse, RiskClassification,
} from '../types'

// ------------------------------------------------------------------ //
// Auth
// ------------------------------------------------------------------ //
export const authService = {
  register: (email: string, username: string, password: string) =>
    api.post<User>('/auth/register', { email, username, password }),

  login: async (email: string, password: string): Promise<User> => {
    const resp = await api.post<TokenResponse>('/auth/login', { email, password })
    localStorage.setItem('hackmetrix_token', resp.data.access_token)
    const me = await api.get<User>('/auth/me')
    localStorage.setItem('hackmetrix_user', JSON.stringify(me.data))
    return me.data
  },

  logout: () => {
    localStorage.removeItem('hackmetrix_token')
    localStorage.removeItem('hackmetrix_user')
  },

  me: () => api.get<User>('/auth/me'),

  currentUser: (): User | null => {
    const raw = localStorage.getItem('hackmetrix_user')
    return raw ? JSON.parse(raw) : null
  },
}

// ------------------------------------------------------------------ //
// Scanning
// ------------------------------------------------------------------ //
export const scanService = {
  submit: (url: string) =>
    api.post<{ scan_id: number; status: string }>('/scans', { url }),

  list: (skip = 0, limit = 20) =>
    api.get<ScanListItem[]>(`/scans?skip=${skip}&limit=${limit}`),

  get: (id: number) =>
    api.get<ScanListItem>(`/scans/${id}`),

  report: (id: number) =>
    api.get<ScanReport>(`/scans/${id}/report`),

  pollUntilComplete: async (
    scanId: number,
    onUpdate?: (scan: ScanListItem) => void,
    maxAttempts = 60,
  ): Promise<ScanListItem> => {
    let attempts = 0
    while (attempts < maxAttempts) {
      await new Promise((r) => setTimeout(r, 2000))
      const resp = await api.get<ScanListItem>(`/scans/${scanId}`)
      const scan = resp.data
      onUpdate?.(scan)
      if (['completed', 'failed', 'partial'].includes(scan.status)) {
        return scan
      }
      attempts++
    }
    throw new Error('Scan timed out')
  },
}

// ------------------------------------------------------------------ //
// Dashboard
// ------------------------------------------------------------------ //
export const dashboardService = {
  stats: () => api.get<DashboardStats>('/dashboard/stats'),
}

// ------------------------------------------------------------------ //
// Community
// ------------------------------------------------------------------ //
export const communityService = {
  list: (skip = 0, limit = 20) =>
    api.get<CommunityReport[]>(`/reports?skip=${skip}&limit=${limit}`),

  get: (id: number) =>
    api.get<CommunityReport>(`/reports/${id}`),

  submit: (data: {
    url: string
    category: string
    title: string
    description: string
    evidence?: Array<{ type: string; content: string }>
  }) => api.post('/reports', data),

  vote: (id: number, vote_type: 'support' | 'dispute') =>
    api.post(`/reports/${id}/vote`, { vote_type }),
}

// ------------------------------------------------------------------ //
// Domain
// ------------------------------------------------------------------ //
export const domainService = {
  reputation: (domain: string) =>
    api.get(`/domains/${domain}/reputation`),
}

// ------------------------------------------------------------------ //
// Intelligence
// ------------------------------------------------------------------ //
export const intelligenceService = {
  campaigns: () => api.get('/intelligence/campaigns'),
}
