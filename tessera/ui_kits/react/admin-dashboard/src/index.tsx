import React from 'react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { Toaster } from 'react-hot-toast';
import { Sidebar, Header } from './components/Layout';
import { DashboardOverview } from './components/Dashboard';
import { RoleManager } from './components/RBACManager';
import { LoginPage } from './components/Login';
import { EnterprisePage } from './components/EnterpriseFeatures';
import { isTokenValid } from './lib/auth';
import { useAuthStore } from './store';

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      retry: 1,
      refetchOnWindowFocus: false,
    },
  },
});

// Placeholder components for pages that do not have dedicated views yet.
const UsersPage = () => <div className="p-6"><h1 className="text-2xl font-bold">Users Management</h1></div>;
const OrganizationsPage = () => <div className="p-6"><h1 className="text-2xl font-bold">Organizations</h1></div>;
const SecurityPage = () => <div className="p-6"><h1 className="text-2xl font-bold">Security Center</h1></div>;
const AuditLogsPage = () => <div className="p-6"><h1 className="text-2xl font-bold">Audit Logs</h1></div>;
const SessionsPage = () => <div className="p-6"><h1 className="text-2xl font-bold">Session Management</h1></div>;
const WebhooksPage = () => <div className="p-6"><h1 className="text-2xl font-bold">Webhooks Configuration</h1></div>;
const HealthPage = () => <div className="p-6"><h1 className="text-2xl font-bold">System Health</h1></div>;
const SettingsPage = () => <div className="p-6"><h1 className="text-2xl font-bold">Settings</h1></div>;
const RBACPage = () => <div className="p-6"><RoleManager /></div>;

const ProtectedRoute: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const { isAuthenticated, token, expiresAt, checkExpiry } = useAuthStore();

  // Drop the session automatically when the token reaches its expiry.
  React.useEffect(() => {
    if (!token || expiresAt === null) return;
    const delayMs = Math.max(1000, (expiresAt - Math.floor(Date.now() / 1000)) * 1000);
    const timer = window.setTimeout(() => {
      checkExpiry();
    }, delayMs);
    return () => window.clearTimeout(timer);
  }, [token, expiresAt, checkExpiry]);

  // Real gate: a session is valid only when a token exists AND its `exp`
  // claim (when present) has not passed.
  if (!isAuthenticated || !token || !isTokenValid(token)) {
    return <Navigate to="/login" replace />;
  }

  return (
    <div className="flex min-h-screen bg-gray-50">
      <Sidebar />
      <div className="flex-1 lg:ml-64">
        <Header />
        <main className="p-6">
          {children}
        </main>
      </div>
    </div>
  );
};

export function AdminDashboard() {
  return (
    <QueryClientProvider client={queryClient}>
      <BrowserRouter>
        <Routes>
          <Route path="/login" element={<LoginPage />} />
          <Route
            path="/"
            element={
              <ProtectedRoute>
                <DashboardOverview />
              </ProtectedRoute>
            }
          />
          <Route
            path="/users"
            element={
              <ProtectedRoute>
                <UsersPage />
              </ProtectedRoute>
            }
          />
          <Route
            path="/organizations"
            element={
              <ProtectedRoute>
                <OrganizationsPage />
              </ProtectedRoute>
            }
          />
          <Route
            path="/security"
            element={
              <ProtectedRoute>
                <SecurityPage />
              </ProtectedRoute>
            }
          />
          <Route
            path="/audit-logs"
            element={
              <ProtectedRoute>
                <AuditLogsPage />
              </ProtectedRoute>
            }
          />
          <Route
            path="/sessions"
            element={
              <ProtectedRoute>
                <SessionsPage />
              </ProtectedRoute>
            }
          />
          <Route
            path="/webhooks"
            element={
              <ProtectedRoute>
                <WebhooksPage />
              </ProtectedRoute>
            }
          />
          <Route
            path="/health"
            element={
              <ProtectedRoute>
                <HealthPage />
              </ProtectedRoute>
            }
          />
          <Route
            path="/settings"
            element={
              <ProtectedRoute>
                <SettingsPage />
              </ProtectedRoute>
            }
          />
          <Route
            path="/rbac"
            element={
              <ProtectedRoute>
                <RBACPage />
              </ProtectedRoute>
            }
          />
          <Route
            path="/enterprise"
            element={
              <ProtectedRoute>
                <EnterprisePage />
              </ProtectedRoute>
            }
          />
        </Routes>
        <Toaster position="top-right" />
      </BrowserRouter>
    </QueryClientProvider>
  );
}

export {
  Sidebar,
  Header,
  DashboardOverview,
  LoginPage,
  useAuthStore
};

export {
  ApiKeyManager,
  BrandingConfigurator,
  AIAnomalyDashboard,
  PredictiveAnalytics,
  NaturalLanguageQuery,
  AdvancedAuditSearch,
  EnterprisePage,
} from './components/EnterpriseFeatures';

export type { User, Organization, AuditEvent, Session, DashboardMetrics, LoginResponse } from './types';
