import React from 'react'
import { NavLink, useNavigate } from 'react-router-dom'
import {
  LayoutDashboard, Search, FileText, Shield, Users,
  BookOpen, Settings, LogOut, ShieldAlert,
} from 'lucide-react'
import { authService } from '../services'

const navItems = [
  { to: '/',               label: 'Dashboard',           icon: LayoutDashboard },
  { to: '/scanner',        label: 'Scanner',             icon: Search },
  { to: '/community',      label: 'Community',           icon: Users },
  { to: '/threats',        label: 'Threat Explorer',     icon: Shield },
  { to: '/admin',          label: 'Admin',               icon: Settings },
]

export function Sidebar() {
  const navigate = useNavigate()
  const user = authService.currentUser()

  const handleLogout = () => {
    authService.logout()
    navigate('/login')
  }

  return (
    <aside className="w-60 bg-navy-800 border-r border-gray-800 flex flex-col min-h-screen">
      {/* Logo */}
      <div className="p-5 border-b border-gray-800">
        <div className="flex items-center gap-3">
          <div className="w-9 h-9 rounded-lg bg-blue-600 flex items-center justify-center">
            <ShieldAlert size={18} className="text-white" />
          </div>
          <div>
            <p className="font-bold text-white text-sm leading-tight">Hackmetrix</p>
            <p className="text-xs text-gray-500">Threat Intelligence</p>
          </div>
        </div>
      </div>

      {/* Nav */}
      <nav className="flex-1 p-3 space-y-0.5">
        {navItems.map(({ to, label, icon: Icon }) => (
          <NavLink
            key={to}
            to={to}
            end={to === '/'}
            className={({ isActive }) =>
              `flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm transition-colors ${
                isActive
                  ? 'bg-blue-600/15 text-blue-400 font-medium'
                  : 'text-gray-400 hover:text-gray-200 hover:bg-navy-600'
              }`
            }
          >
            <Icon size={16} />
            {label}
          </NavLink>
        ))}
      </nav>

      {/* User */}
      {user && (
        <div className="p-3 border-t border-gray-800">
          <div className="flex items-center gap-3 px-2 py-2 rounded-lg">
            <div className="w-8 h-8 rounded-full bg-blue-700 flex items-center justify-center text-xs font-bold text-white">
              {user.username[0].toUpperCase()}
            </div>
            <div className="flex-1 min-w-0">
              <p className="text-sm font-medium text-gray-200 truncate">{user.username}</p>
              <p className="text-xs text-gray-500 capitalize">{user.role}</p>
            </div>
            <button onClick={handleLogout} className="text-gray-500 hover:text-red-400 transition-colors" title="Logout">
              <LogOut size={15} />
            </button>
          </div>
        </div>
      )}
    </aside>
  )
}
