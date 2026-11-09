import axios from 'axios'

const api = axios.create({
  baseURL: '/api/v1',
  headers: { 'Content-Type': 'application/json' },
})

// Attach JWT token from localStorage if present
api.interceptors.request.use((config) => {
  const token = localStorage.getItem('threxis_token') || localStorage.getItem('hackmetrix_token')
  if (token) {
    config.headers.Authorization = `Bearer ${token}`
  }
  return config
})

// Handle 401 — clear stored token
api.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response?.status === 401) {
      localStorage.removeItem('hackmetrix_token')
      localStorage.removeItem('hackmetrix_user')
      localStorage.removeItem('threxis_token')
      localStorage.removeItem('threxis_user')
    }
    return Promise.reject(error)
  },
)

export default api
