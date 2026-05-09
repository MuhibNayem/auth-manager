import { create } from 'zustand';
import type { User, DashboardMetrics, HealthStatus } from '../types';

interface AuthState {
  user: User | null;
  token: string | null;
  isAuthenticated: boolean;
  login: (token: string, userData: User) => void;
  logout: () => void;
}

export const useAuthStore = create<AuthState>((set) => ({
  user: null,
  token: null,
  isAuthenticated: false,
  login: (token, userData) => {
    localStorage.setItem('authy_admin_token', token);
    set({ user: userData, token, isAuthenticated: true });
  },
  logout: () => {
    localStorage.removeItem('authy_admin_token');
    set({ user: null, token: null, isAuthenticated: false });
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
