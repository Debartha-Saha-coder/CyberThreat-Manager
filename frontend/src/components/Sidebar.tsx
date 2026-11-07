import React from 'react'
import { NavLink, useNavigate } from 'react-router-dom'
import {
  LayoutDashboard, Search, Shield, Users,
  Settings, LogOut, ShieldAlert,
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
    <aside className="group w-[72px] hover:w-[220px] m-3 mr-0 bg-navy-800 border border-gray-800 flex flex-col h-[calc(100vh-24px)] rounded-[28px] flex-shrink-0 overflow-hidden transition-[width] duration-300 ease-out shadow-2xl shadow-black/20 z-40">
      {/* Logo */}
      <div className="h-[72px] border-b border-gray-800 flex items-center px-[13px] flex-shrink-0">
        <div className="w-11 h-11 rounded-full bg-blue-600 flex items-center justify-center flex-shrink-0">
          <ShieldAlert size={20} className="text-white" />
        </div>
        <div className="ml-3 min-w-[132px] opacity-0 translate-x-2 group-hover:opacity-100 group-hover:translate-x-0 transition-all duration-200 delay-100">
          <p className="font-bold text-white text-sm leading-tight whitespace-nowrap">Hackmetrix</p>
          <p className="text-xs text-gray-500 whitespace-nowrap">Threat Intelligence</p>
        </div>
      </div>

      {/* Nav */}
      <nav className="flex-1 px-[13px] py-4 space-y-1.5 overflow-y-auto">
        {navItems.map(({ to, label, icon: Icon }) => (
          <NavLink
            key={to}
            to={to}
            end={to === '/'}
            title={label}
            className={({ isActive }) =>
              `h-11 flex items-center rounded-full text-sm transition-colors overflow-hidden ${
                isActive
                  ? 'bg-blue-600/15 text-blue-400 font-medium'
                  : 'text-gray-400 hover:text-gray-200 hover:bg-navy-600'
              }`
            }
          >
            <span className="w-11 h-11 flex items-center justify-center flex-shrink-0">
              <Icon size={18} />
            </span>
            <span className="ml-1 min-w-[145px] opacity-0 translate-x-2 group-hover:opacity-100 group-hover:translate-x-0 transition-all duration-200 delay-100 whitespace-nowrap">
              {label}
            </span>
          </NavLink>
        ))}
      </nav>

      {/* User */}
      {user && (
        <div className="px-[13px] py-3 border-t border-gray-800 flex-shrink-0">
          <div className="h-11 flex items-center overflow-hidden">
            <div className="w-11 h-11 rounded-full bg-blue-700 flex items-center justify-center text-xs font-bold text-white flex-shrink-0">
              {user.username[0].toUpperCase()}
            </div>
            <div className="ml-3 min-w-[105px] opacity-0 translate-x-2 group-hover:opacity-100 group-hover:translate-x-0 transition-all duration-200 delay-100">
              <p className="text-sm font-medium text-gray-200 truncate">{user.username}</p>
              <p className="text-xs text-gray-500 capitalize">{user.role}</p>
            </div>
            <button
              onClick={handleLogout}
              className="ml-2 w-8 h-8 flex items-center justify-center rounded-full text-gray-500 hover:text-red-400 hover:bg-red-950/30 opacity-0 group-hover:opacity-100 transition-all duration-200 delay-100 flex-shrink-0"
              title="Logout"
            >
              <LogOut size={15} />
            </button>
          </div>
        </div>
      )}
    </aside>
  )
}
