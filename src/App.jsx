import React from 'react';
import { Routes, Route, Navigate } from 'react-router-dom';
import { AuthProvider, useAuth } from './context/AuthContext';
import LoginPage from './pages/LoginPage';
import Dashboard from './pages/Dashboard';
import TraceDetail from './pages/TraceDetail';
import EmailAnalysis from './pages/EmailAnalysis';
import Sidebar from './components/layout/Sidebar';
import TopBar from './components/layout/TopBar';

function ProtectedLayout({ children }) {
  const { isAuthenticated } = useAuth();

  if (!isAuthenticated) {
    return <Navigate to="/" replace />;
  }

  return (
    <div className="app-shell">
      <Sidebar />
      <div style={{ display: 'flex', flexDirection: 'column', minWidth: 0, height: '100vh', overflow: 'hidden' }}>
        <TopBar />
        <main style={{ flex: 1, padding: 'var(--sp-6) var(--sp-6)', overflowY: 'auto' }} className="scrollbar-thin">
          {children}
        </main>
      </div>
    </div>
  );
}

function RootRoute() {
  const { isAuthenticated } = useAuth();
  if (isAuthenticated) {
    return <Navigate to="/dashboard" replace />;
  }
  return <LoginPage />;
}

function AppRoutes() {
  return (
    <Routes>
      <Route path="/" element={<RootRoute />} />
      <Route
        path="/dashboard"
        element={
          <ProtectedLayout>
            <Dashboard />
          </ProtectedLayout>
        }
      />
      <Route
        path="/analysis"
        element={
          <ProtectedLayout>
            <EmailAnalysis />
          </ProtectedLayout>
        }
      />
      <Route
        path="/case/:caseId"
        element={
          <ProtectedLayout>
            <TraceDetail />
          </ProtectedLayout>
        }
      />
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  );
}

export default function App() {
  return (
    <AuthProvider>
      <AppRoutes />
    </AuthProvider>
  );
}
