import React, { useEffect, useState } from 'react'
import { Settings, Users, ShieldCheck } from 'lucide-react'
import api from '../services/api'

export default function AdminPanel() {
  const [users, setUsers] = useState<Array<{
    id: number; email: string; username: string; role: string;
    is_active: boolean; created_at: string
  }>>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')

  useEffect(() => {
    api.get('/admin/users')
      .then((r) => setUsers(r.data))
      .catch((e) => setError(e.response?.data?.detail || 'Access denied or error loading users.'))
      .finally(() => setLoading(false))
  }, [])

  return (
    <div className="space-y-6 max-w-4xl">
      <div>
        <h1 className="text-2xl font-bold text-white">Admin Panel</h1>
        <p className="text-gray-400 text-sm mt-1">Platform administration — requires Admin role.</p>
      </div>

      {error ? (
        <div className="card p-5 text-red-400 text-sm">{error}</div>
      ) : (
        <div className="card">
          <div className="flex items-center gap-2 p-5 border-b border-gray-800">
            <Users size={16} className="text-blue-400" />
            <h2 className="text-sm font-semibold text-gray-300">User Management</h2>
            <span className="ml-auto text-xs text-gray-500">{users.length} users</span>
          </div>
          {loading ? (
            <div className="p-8 text-center"><div className="w-6 h-6 border-2 border-blue-500 border-t-transparent rounded-full animate-spin mx-auto" /></div>
          ) : (
            <div className="divide-y divide-gray-800">
              {users.map((u) => (
                <div key={u.id} className="px-5 py-3 flex items-center gap-4">
                  <div className="w-8 h-8 rounded-full bg-blue-700 flex items-center justify-center text-xs font-bold text-white flex-shrink-0">
                    {u.username[0].toUpperCase()}
                  </div>
                  <div className="flex-1 min-w-0">
                    <p className="text-sm text-gray-200">{u.username}</p>
                    <p className="text-xs text-gray-500">{u.email}</p>
                  </div>
                  <span className={`text-xs px-2 py-0.5 rounded capitalize ${
                    u.role === 'admin' ? 'bg-purple-900/40 text-purple-400' :
                    u.role === 'analyst' ? 'bg-blue-900/40 text-blue-400' :
                    'bg-gray-800 text-gray-400'
                  }`}>{u.role}</span>
                  <span className={`text-xs ${u.is_active ? 'text-green-400' : 'text-red-400'}`}>
                    {u.is_active ? 'Active' : 'Inactive'}
                  </span>
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  )
}
