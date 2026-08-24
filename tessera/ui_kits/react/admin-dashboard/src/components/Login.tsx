import React, { useState } from 'react';
import { Navigate, useNavigate } from 'react-router-dom';
import axios from 'axios';
import { Shield, LogIn } from 'lucide-react';
import { authAPI } from '../lib/api';
import { useAuthStore } from '../store';

/**
 * Admin login form.
 *
 * POSTs `{username_or_email, password}` as JSON to
 * `/admin/api/v1/auth/login` (via the v1 API client), stores the returned
 * access token under `tessera_admin_token` and redirects to the dashboard.
 */
export const LoginPage: React.FC = () => {
  const navigate = useNavigate();
  const { isAuthenticated, login } = useAuthStore();
  const [identifier, setIdentifier] = useState('');
  const [password, setPassword] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (submitting) return;
    setSubmitting(true);
    setError(null);
    try {
      const data = await authAPI.login(identifier.trim(), password);
      if (!data?.access_token) {
        throw new Error('Login response did not include an access token');
      }
      login(data.access_token, data.user ?? null);
      navigate('/', { replace: true });
    } catch (err) {
      if (axios.isAxiosError(err)) {
        const status = err.response?.status;
        const detail = (err.response?.data as { detail?: string } | undefined)?.detail;
        if (status === 401 || status === 403) {
          setError('Invalid username/email or password.');
        } else if (status === 429) {
          setError('Too many login attempts. Please try again shortly.');
        } else if (status === 404) {
          setError('Login endpoint not available on this server yet.');
        } else if (detail) {
          setError(detail);
        } else if (err.code === 'ERR_NETWORK') {
          setError('Unable to reach the authentication server.');
        } else {
          setError('Login failed. Please try again.');
        }
      } else if (err instanceof Error) {
        setError(err.message);
      } else {
        setError('Login failed. Please try again.');
      }
    } finally {
      setSubmitting(false);
    }
  };

  // Already signed in: skip the login screen.
  if (isAuthenticated) {
    return <Navigate to="/" replace />;
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-gray-50 px-4">
      <div className="max-w-md w-full p-8 bg-white rounded-xl shadow-lg border border-gray-200">
        <div className="flex flex-col items-center mb-6">
          <div className="w-12 h-12 bg-gradient-to-br from-blue-500 to-purple-600 rounded-xl flex items-center justify-center mb-3">
            <Shield size={24} className="text-white" />
          </div>
          <h1 className="text-2xl font-bold text-gray-900">Tessera Admin Login</h1>
          <p className="text-sm text-gray-500 mt-1">Sign in to manage your authentication system</p>
        </div>

        <form onSubmit={handleSubmit} className="space-y-4">
          {error && (
            <div role="alert" className="bg-red-50 border border-red-200 text-red-700 text-sm rounded-lg px-4 py-3">
              {error}
            </div>
          )}

          <div>
            <label htmlFor="identifier" className="block text-sm font-medium text-gray-700 mb-1">
              Username or email
            </label>
            <input
              id="identifier"
              name="username_or_email"
              type="text"
              autoComplete="username"
              value={identifier}
              onChange={(e) => setIdentifier(e.target.value)}
              required
              disabled={submitting}
              className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 disabled:bg-gray-50"
              placeholder="admin@example.com"
            />
          </div>

          <div>
            <label htmlFor="password" className="block text-sm font-medium text-gray-700 mb-1">
              Password
            </label>
            <input
              id="password"
              name="password"
              type="password"
              autoComplete="current-password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              required
              disabled={submitting}
              className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 disabled:bg-gray-50"
              placeholder="••••••••"
            />
          </div>

          <button
            type="submit"
            disabled={submitting || !identifier.trim() || password.length === 0}
            className="w-full flex items-center justify-center gap-2 px-4 py-2.5 bg-blue-600 text-white font-medium rounded-lg hover:bg-blue-700 transition-colors disabled:opacity-60 disabled:cursor-not-allowed"
          >
            <LogIn size={16} />
            {submitting ? 'Signing in...' : 'Sign in'}
          </button>
        </form>
      </div>
    </div>
  );
};
