"""
Authy UI Kit - React Components

Pre-built, accessible authentication components for React/TypeScript
"""

# These are template files that would be installed via npm
# Located here for reference and CLI scaffolding

REACT_COMPONENTS = {
    'LoginForm.tsx': '''
import React, { useState } from 'react';

interface LoginFormProps {
  onSuccess?: (user: any) => void;
  onError?: (error: Error) => void;
}

export function LoginForm({ onSuccess, onError }: LoginFormProps) {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    
    try {
      const response = await fetch('/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password })
      });
      
      if (!response.ok) throw new Error('Login failed');
      
      const data = await response.json();
      localStorage.setItem('access_token', data.access_token);
      onSuccess?.(data.user);
    } catch (error) {
      onError?.(error as Error);
    } finally {
      setLoading(false);
    }
  };

  return (
    <form onSubmit={handleSubmit} className="authy-login-form">
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
  email?: string;
  text?: string;
}

export function MagicLinkButton({ email, text = 'Send Magic Link' }: MagicLinkButtonProps) {
  const [sent, setSent] = useState(false);

  const handleSend = async () => {
    const userEmail = email || prompt('Enter your email:');
    if (!userEmail) return;

    const response = await fetch('/auth/magic-link', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: userEmail })
    });

    if (response.ok) {
      setSent(true);
    }
  };

  return (
    <button onClick={handleSend} disabled={sent}>
      {sent ? '✓ Check your email' : text}
    </button>
  );
}
''',

    'SocialLogin.tsx': '''
import React from 'react';

interface SocialLoginProps {
  providers?: ('google' | 'github' | 'apple' | 'microsoft')[];
  onSuccess?: (user: any) => void;
}

export function SocialLogin({ providers = ['google'], onSuccess }: SocialLoginProps) {
  const handleSocialLogin = async (provider: string) => {
    // Redirect to provider auth endpoint
    window.location.href = `/auth/social/${provider}`;
  };

  const providerIcons: Record<string, string> = {
    google: '🔵',
    github: '⚫',
    apple: '🍎',
    microsoft: '🪟'
  };

  return (
    <div className="social-login">
      {providers.map(provider => (
        <button
          key={provider}
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

__all__ = ['REACT_COMPONENTS']
