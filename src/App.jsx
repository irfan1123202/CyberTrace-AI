import React from 'react';
import { Routes, Route, Navigate } from 'react-router-dom';
import { AuthProvider, useAuth } from './context/AuthContext';
import LoginPage from './pages/LoginPage';
import Dashboard from './pages/Dashboard';
import TraceDetail from './pages/TraceDetail';
import EmailAnalysis from './pages/EmailAnalysis';
import ForensicReportPage from './pages/ForensicReportPage';
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

// Minimal full-screen layout for the standalone forensic report page (print-friendly)
function ReportLayout({ children }) {
  const { isAuthenticated } = useAuth();
  if (!isAuthenticated) {
    return <Navigate to="/" replace />;
  }
  return (
    <div
      style={{
        minHeight: '100vh',
        background: '#f8fafc',
        display: 'flex',
        flexDirection: 'column',
      }}
    >
      {children}
    </div>
  );
}

function RootRoute({ initialMode = 'login' }) {
  const { isAuthenticated } = useAuth();
  if (isAuthenticated) {
    return <Navigate to="/dashboard" replace />;
  }
  return <LoginPage initialMode={initialMode} />;
}

function AppRoutes() {
  return (
    <Routes>
      <Route path="/" element={<RootRoute initialMode="login" />} />
      <Route path="/login" element={<RootRoute initialMode="login" />} />
      <Route path="/signup" element={<RootRoute initialMode="signup" />} />
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
      <Route
        path="/report/:caseId"
        element={
          <ReportLayout>
            <ForensicReportPage />
          </ReportLayout>
        }
      />
      <Route
        path="/report"
        element={
          <ReportLayout>
            <ForensicReportPage />
          </ReportLayout>
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
