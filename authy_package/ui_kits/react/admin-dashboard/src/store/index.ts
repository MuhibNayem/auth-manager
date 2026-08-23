import { create } from 'zustand';
import type { User, DashboardMetrics, HealthStatus } from '../types';
import {
  clearStoredToken,
  getTokenExpiry,
  isTokenValid,
  readStoredToken,
  storeToken,
} from '../lib/auth';

interface AuthState {
  user: User | null;
  token: string | null;
  /** `exp` claim of the current token (epoch seconds), when present. */
  expiresAt: number | null;
  isAuthenticated: boolean;
  login: (token: string, userData?: User | null) => void;
  logout: () => void;
  /**
   * Re-validate the current session against the token's `exp` claim.
   * Logs out and returns false when the token has expired.
   */
  checkExpiry: () => boolean;
}

/**
 * Hydrate the session synchronously from localStorage so the first render
 * already knows whether a valid admin token is present (no redirect flash).
 * Invalid/expired stored tokens are discarded immediately.
 */
function loadInitialSession(): { token: string | null; expiresAt: number | null } {
  const stored = readStoredToken();
  if (!stored) return { token: null, expiresAt: null };
  if (!isTokenValid(stored)) {
    clearStoredToken();
    return { token: null, expiresAt: null };
  }
  return { token: stored, expiresAt: getTokenExpiry(stored) };
}

const initialSession = loadInitialSession();

export const useAuthStore = create<AuthState>((set, get) => ({
  user: null,
  token: initialSession.token,
  expiresAt: initialSession.expiresAt,
  isAuthenticated: initialSession.token !== null,
  login: (token, userData) => {
    storeToken(token);
    set({
      user: userData ?? null,
      token,
      expiresAt: getTokenExpiry(token),
      isAuthenticated: true,
    });
  },
  logout: () => {
    clearStoredToken();
    set({ user: null, token: null, expiresAt: null, isAuthenticated: false });
  },
  checkExpiry: () => {
    const { token, expiresAt, logout } = get();
    if (!token) return false;
    if (expiresAt !== null && expiresAt <= Math.floor(Date.now() / 1000)) {
      logout();
      return false;
    }
    return true;
  },
}));

interface DashboardState {
  metrics: DashboardMetrics | null;
  health: HealthStatus | null;
  refreshInterval: number;
  setMetrics: (metrics: DashboardMetrics) => void;
  setHealth: (health: HealthStatus) => void;
  setRefreshInterval: (interval: number) => void;
}

export const useDashboardStore = create<DashboardState>((set) => ({
  metrics: null,
  health: null,
  refreshInterval: 30000, // 30 seconds
  setMetrics: (metrics) => set({ metrics }),
  setHealth: (health) => set({ health }),
  setRefreshInterval: (interval) => set({ refreshInterval: interval }),
}));

interface UIState {
  sidebarOpen: boolean;
  theme: 'light' | 'dark';
  toggleSidebar: () => void;
  setTheme: (theme: 'light' | 'dark') => void;
}

export const useUIStore = create<UIState>((set) => ({
  sidebarOpen: true,
  theme: 'light',
  toggleSidebar: () => set((state) => ({ sidebarOpen: !state.sidebarOpen })),
  setTheme: (theme) => set({ theme }),
}));
