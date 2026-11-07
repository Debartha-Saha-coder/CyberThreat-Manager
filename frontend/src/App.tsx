import React from 'react'
import { BrowserRouter, Routes, Route, Navigate, Outlet } from 'react-router-dom'
import { Sidebar } from './components/Sidebar'
import Dashboard from './pages/Dashboard'
import Scanner from './pages/Scanner'
import ScanResult from './pages/ScanResult'
import Community from './pages/Community'
import ThreatExplorer from './pages/ThreatExplorer'
import AdminPanel from './pages/AdminPanel'
import Auth from './pages/Auth'
import { authService } from './services'

function AppLayout() {
  return (
    <div className="flex min-h-screen">
      <Sidebar />
      <main className="flex-1 min-w-0 p-6 pl-5 overflow-auto">
        <Outlet />
      </main>
    </div>
  )
}

function RequireAuth({ children }: { children: React.ReactNode }) {
  const user = authService.currentUser()
  if (!user) return <Navigate to="/login" replace />
  return <>{children}</>
}

export default function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/login" element={<Auth />} />
        <Route
          element={
            <RequireAuth>
              <AppLayout />
            </RequireAuth>
          }
        >
          <Route path="/" element={<Dashboard />} />
          <Route path="/scanner" element={<Scanner />} />
          <Route path="/scan/:id" element={<ScanResult />} />
          <Route path="/community" element={<Community />} />
          <Route path="/reports/:id" element={<Community />} />
          <Route path="/threats" element={<ThreatExplorer />} />
          <Route path="/admin" element={<AdminPanel />} />
        </Route>
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </BrowserRouter>
  )
}
