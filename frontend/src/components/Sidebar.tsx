import React from 'react'
import { NavLink, useNavigate } from 'react-router-dom'
import { LayoutDashboard, Search, Shield, Users, Settings, LogOut, Moon, Sun } from 'lucide-react'
import { authService } from '../services'
import { useTheme } from '../theme'
import { BrandMark } from './BrandMark'

const navItems = [
  { to: '/', label: 'Dashboard', icon: LayoutDashboard },
  { to: '/scanner', label: 'Scanner', icon: Search },
  { to: '/community', label: 'Community', icon: Users },
  { to: '/threats', label: 'Threats', icon: Shield },
  { to: '/admin', label: 'Admin', icon: Settings },
]

export function Sidebar() {
  const navigate = useNavigate()
  const user = authService.currentUser()
  const { theme, toggleTheme } = useTheme()

  const handleLogout = () => {
    authService.logout()
    navigate('/login')
  }

  return (
    <header className="site-header">
      <NavLink to="/" className="brand" aria-label="THREXIS dashboard">
        <span className="brand-mark"><BrandMark /></span>
        <span className="brand-wordmark">THRE<span className="brand-accent">X</span>IS</span>
      </NavLink>

      <nav className="top-nav" aria-label="Primary navigation">
        {navItems.map(({ to, label, icon: Icon }) => (
          <NavLink key={to} to={to} end={to === '/'} className={({ isActive }) => `nav-link ${isActive ? 'active' : ''}`}>
            <Icon size={15} />
            <span>{label}</span>
          </NavLink>
        ))}
      </nav>

      <div className="header-actions">
        <button className="icon-button" onClick={toggleTheme} title={`Switch to ${theme === 'dark' ? 'light' : 'dark'} theme`} aria-label="Toggle color theme">
          {theme === 'dark' ? <Sun size={16} /> : <Moon size={16} />}
        </button>
        {user && (
          <div className="profile">
            <span className="profile-avatar">{user.username[0].toUpperCase()}</span>
            <button onClick={handleLogout} className="logout-button" title="Logout" aria-label="Logout"><LogOut size={15} /></button>
          </div>
        )}
      </div>
    </header>
  )
}
