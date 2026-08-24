import axios from 'axios';
import type { InternalAxiosRequestConfig } from 'axios';
import type {
  User, Organization, AuditEvent, Session,
  DashboardMetrics, WebhookEndpoint, HealthStatus,
  SecurityAnalysis, UsersListResponse, AuditEventsListResponse, OrganizationsListResponse,
  LoginResponse,
} from '../types';
import { readStoredToken } from './auth';

export const API_BASE = '/admin/api/v1';
export const API_V2_BASE = '/admin/v2';

/**
 * Attach the admin bearer token (stored under `tessera_admin_token`) to a
 * request when present. Shared by the v1 and v2 clients.
 */
function attachAdminToken(config: InternalAxiosRequestConfig): InternalAxiosRequestConfig {
  const token = readStoredToken();
  if (token) {
    config.headers.set('Authorization', `Bearer ${token}`);
  }
  return config;
}

// Admin API v1 client (dashboard, users, orgs, audit, sessions, webhooks, health)
export const apiClient = axios.create({
  baseURL: API_BASE,
  headers: {
    'Content-Type': 'application/json',
  },
});
export const api = apiClient;

// Admin API v2 client (RBAC, API keys, branding, reports, security analytics).
// v2 routes live under /admin/v2 — NOT under /admin/api/v1 — so they must be
// issued from this client to avoid double-prefixed URLs.
export const apiClientV2 = axios.create({
  baseURL: API_V2_BASE,
  headers: {
    'Content-Type': 'application/json',
  },
});
export const apiV2 = apiClientV2;

apiClient.interceptors.request.use((config) => attachAdminToken(config));
apiClientV2.interceptors.request.use((config) => attachAdminToken(config));

// Auth (admin login)
export const authAPI = {
  /**
   * POST {username_or_email, password} to /admin/api/v1/auth/login and
   * return the issued access token plus (optionally) the admin user record.
   */
  login: async (usernameOrEmail: string, password: string): Promise<LoginResponse> => {
    const { data } = await apiClient.post<LoginResponse>('/auth/login', {
      username_or_email: usernameOrEmail,
      password,
    });
    return data;
  },
};

// Dashboard Metrics
export const dashboardAPI = {
  getMetrics: async (days: number = 7): Promise<DashboardMetrics> => {
    const { data } = await apiClient.get('/dashboard/metrics', { params: { days } });
    return data;
  },

  getChartData: async (metric: string, days: number = 30, granularity: string = 'day') => {
    const { data } = await apiClient.get('/dashboard/chart-data', {
      params: { metric, days, granularity },
    });
    return data;
  },
};

// Users
export const usersAPI = {
  list: async (params: {
    page?: number;
    page_size?: number;
    search?: string;
    status?: string;
    organization_id?: string;
    role?: string;
  }): Promise<UsersListResponse> => {
    const { data } = await apiClient.get('/users', { params });
    return data;
  },

  getById: async (userId: string): Promise<User> => {
    const { data } = await apiClient.get(`/users/${userId}`);
    return data;
  },

  create: async (userData: Partial<User>): Promise<{ user: User }> => {
    const { data } = await apiClient.post('/users', userData);
    return data;
  },

  update: async (userId: string, userData: Partial<User>): Promise<{ message: string }> => {
    const { data } = await apiClient.put(`/users/${userId}`, userData);
    return data;
  },

  delete: async (userId: string): Promise<{ message: string }> => {
    const { data } = await apiClient.delete(`/users/${userId}`);
    return data;
  },

  bulkOperation: async (userIds: string[], action: string, reason?: string) => {
    const { data } = await apiClient.post('/users/bulk', { user_ids: userIds, action, reason });
    return data;
  },

  impersonate: async (userId: string): Promise<{ impersonation_token: string; expires_in: number }> => {
    const { data } = await apiClient.post(`/users/${userId}/impersonate`);
    return data;
  },
};

// Organizations
export const organizationsAPI = {
  list: async (params: { page?: number; page_size?: number; search?: string }): Promise<OrganizationsListResponse> => {
    const { data } = await apiClient.get('/organizations', { params });
    return data;
  },

  getById: async (orgId: string): Promise<Organization & { members: any[]; pending_invitations: any[] }> => {
    const { data } = await apiClient.get(`/organizations/${orgId}`);
    return data;
  },

  create: async (orgData: { name: string; owner_id: string; description?: string; plan?: string }) => {
    const { data } = await apiClient.post('/organizations', orgData);
    return data;
  },
};

// Audit Logs
export const auditAPI = {
  list: async (params: {
    page?: number;
    page_size?: number;
    actor_id?: string;
    event_type?: string;
    organization_id?: string;
    start_date?: string;
    end_date?: string;
    severity?: string;
    status?: string;
  }): Promise<AuditEventsListResponse> => {
    const { data } = await apiClient.get('/audit-logs', { params });
    return data;
  },

  getById: async (eventId: string): Promise<AuditEvent> => {
    const { data } = await apiClient.get(`/audit-logs/${eventId}`);
    return data;
  },

  export: async (params: { format?: string; [key: string]: any }) => {
    const { data } = await apiClient.get('/audit-logs/export', {
      params,
      responseType: 'blob',
    });
    return data;
  },
};

// Sessions
export const sessionsAPI = {
  list: async (params?: { user_id?: string; active_only?: boolean }): Promise<Session[]> => {
    const { data } = await apiClient.get('/sessions', { params });
    return data;
  },

  revoke: async (sessionId: string): Promise<{ message: string }> => {
    const { data } = await apiClient.delete(`/sessions/${sessionId}`);
    return data;
  },

  revokeAllForUser: async (userId: string): Promise<{ message: string }> => {
    const { data } = await apiClient.post(`/sessions/user/${userId}/revoke-all`);
    return data;
  },
};

// Webhooks
export const webhooksAPI = {
  list: async (): Promise<{ webhooks: WebhookEndpoint[] }> => {
    const { data } = await apiClient.get('/webhooks');
    return data;
  },

  create: async (webhookData: { url: string; events?: string[]; is_active?: boolean; description?: string }) => {
    const { data } = await apiClient.post('/webhooks', webhookData);
    return data;
  },

  update: async (webhookId: string, webhookData: Partial<WebhookEndpoint>) => {
    const { data } = await apiClient.put(`/webhooks/${webhookId}`, webhookData);
    return data;
  },

  delete: async (webhookId: string): Promise<{ message: string }> => {
    const { data } = await apiClient.delete(`/webhooks/${webhookId}`);
    return data;
  },

  test: async (webhookId: string) => {
    const { data } = await apiClient.post(`/webhooks/${webhookId}/test`);
    return data;
  },

  getDeliveries: async (webhookId: string, page?: number, page_size?: number) => {
    const { data } = await apiClient.get(`/webhooks/${webhookId}/deliveries`, { params: { page, page_size } });
    return data;
  },
};

// Security
export const securityAPI = {
  getEvents: async (hours: number = 24, limit: number = 100) => {
    const { data } = await apiClient.get('/security/events', { params: { hours, limit } });
    return data;
  },

  getSuspiciousActivity: async (days: number = 7): Promise<SecurityAnalysis> => {
    const { data } = await apiClient.get('/security/suspicious-activity', { params: { days } });
    return data;
  },
};

// System Health
export const healthAPI = {
  getStatus: async (): Promise<HealthStatus> => {
    const { data } = await apiClient.get('/health');
    return data;
  },
};

// Reports
export const reportsAPI = {
  getDailySummary: async (date?: string) => {
    const { data } = await apiClient.get('/reports/daily-summary', { params: { date } });
    return data;
  },
};
