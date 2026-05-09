import React from 'react';
import ReactDOM from 'react-dom/client';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { Toaster } from 'react-hot-toast';
import { Sidebar, Header } from './components/Layout';
import { DashboardOverview } from './components/Dashboard';
import { RoleManager } from './components/RBACManager';
import { useAuthStore } from './store';

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      retry: 1,
      refetchOnWindowFocus: false,
    },
  },
});

// Placeholder components for other pages
const UsersPage = () => <div className="p-6"><h1 className="text-2xl font-bold">Users Management</h1></div>;
const OrganizationsPage = () => <div className="p-6"><h1 className="text-2xl font-bold">Organizations</h1></div>;
const SecurityPage = () => <div className="p-6"><h1 className="text-2xl font-bold">Security Center</h1></div>;
const AuditLogsPage = () => <div className="p-6"><h1 className="text-2xl font-bold">Audit Logs</h1></div>;
const SessionsPage = () => <div className="p-6"><h1 className="text-2xl font-bold">Session Management</h1></div>;
const WebhooksPage = () => <div className="p-6"><h1 className="text-2xl font-bold">Webhooks Configuration</h1></div>;
const HealthPage = () => <div className="p-6"><h1 className="text-2xl font-bold">System Health</h1></div>;
const SettingsPage = () => <div className="p-6"><h1 className="text-2xl font-bold">Settings</h1></div>;
const RBACPage = () => <div className="p-6"><RoleManager /></div>;
const LoginPage = () => <div className="min-h-screen flex items-center justify-center bg-gray-50">
  <div className="max-w-md w-full p-8 bg-white rounded-xl shadow-lg">
    <h1 className="text-2xl font-bold text-center mb-6">Authy Admin Login</h1>
    <p className="text-gray-600 text-center">Login functionality to be implemented</p>
  </div>
</div>;

const ProtectedRoute: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const { isAuthenticated } = useAuthStore();
  
  if (!isAuthenticated) {
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
  useAuthStore 
};

export type { User, Organization, AuditEvent, Session, DashboardMetrics } from './types';
