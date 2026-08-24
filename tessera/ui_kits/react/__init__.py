"""
Tessera UI Kit - React scaffold templates.

These are SOURCE-TEMPLATE STRINGS for the `tessera` CLI scaffolding and for
copy/paste use; they are not importable React components. The real React
artifact in this package is the admin dashboard app under
`react/admin-dashboard/`.

Conventions kept in sync with the admin dashboard:
- the access token is persisted under localStorage key `tessera_admin_token`;
- the API location is configurable via `apiBaseUrl` + `loginPath` props
  (same convention as the Svelte/Vue LoginForms in this package).
"""

ADMIN_TOKEN_KEY = "tessera_admin_token"

REACT_COMPONENTS = {
    'LoginForm.tsx': '''
import React, { useState } from 'react';

const ADMIN_TOKEN_KEY = 'tessera_admin_token';

interface LoginFormProps {
  /** Auth backend origin; empty string means the current origin. */
  apiBaseUrl?: string;
  /** Login route served by the backend. */
  loginPath?: string;
  onSuccess?: (user: unknown, token: string) => void;
  onError?: (error: Error) => void;
}

export function LoginForm({
  apiBaseUrl = '',
  loginPath = '/api/auth/login',
  onSuccess,
  onError,
}: LoginFormProps) {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);

    try {
      const response = await fetch(`${apiBaseUrl}${loginPath}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password })
      });

      if (!response.ok) throw new Error('Login failed');

      const data = await response.json();
      window.localStorage.setItem(ADMIN_TOKEN_KEY, data.access_token);
      onSuccess?.(data.user, data.access_token);
    } catch (error) {
      onError?.(error as Error);
    } finally {
      setLoading(false);
    }
  };

  return (
    <form onSubmit={handleSubmit} className="tessera-login-form">
      <input
        type="email"
        placeholder="Email"
        value={email}
        onChange={(e) => setEmail(e.target.value)}
        required
      />
      <input
        type="password"
        placeholder="Password"
        value={password}
        onChange={(e) => setPassword(e.target.value)}
        required
      />
      <button type="submit" disabled={loading}>
        {loading ? 'Signing in...' : 'Sign In'}
      </button>
    </form>
  );
}
''',

    'MagicLinkButton.tsx': '''
import React, { useState } from 'react';

interface MagicLinkButtonProps {
  /** Auth backend origin; empty string means the current origin. */
  apiBaseUrl?: string;
  email?: string;
  text?: string;
}

export function MagicLinkButton({
  apiBaseUrl = '',
  email,
  text = 'Send Magic Link',
}: MagicLinkButtonProps) {
  const [sent, setSent] = useState(false);

  const handleSend = async () => {
    const userEmail = email || window.prompt('Enter your email:');
    if (!userEmail) return;

    const response = await fetch(`${apiBaseUrl}/api/auth/magic-link`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: userEmail })
    });

    if (response.ok) {
      setSent(true);
    }
  };

  return (
    <button type="button" onClick={handleSend} disabled={sent}>
      {sent ? 'Check your email' : text}
    </button>
  );
}
''',

    'SocialLogin.tsx': '''
import React from 'react';

interface SocialLoginProps {
  /** Auth backend origin; empty string means the current origin. */
  apiBaseUrl?: string;
  providers?: ('google' | 'github' | 'apple' | 'microsoft')[];
}

export function SocialLogin({
  apiBaseUrl = '',
  providers = ['google'],
}: SocialLoginProps) {
  const handleSocialLogin = (provider: string) => {
    // Redirect to the backend's social auth entry point.
    window.location.href = `${apiBaseUrl}/api/auth/social/${provider}`;
  };

  const providerIcons: Record<string, string> = {
    google: 'G',
    github: 'GH',
    apple: 'A',
    microsoft: 'M'
  };

  return (
    <div className="social-login">
      {providers.map(provider => (
        <button
          key={provider}
          type="button"
          onClick={() => handleSocialLogin(provider)}
          className={`social-btn ${provider}`}
        >
          {providerIcons[provider]} Continue with {provider.charAt(0).toUpperCase() + provider.slice(1)}
        </button>
      ))}
    </div>
  );
}
'''
}

__all__ = ['ADMIN_TOKEN_KEY', 'REACT_COMPONENTS']
