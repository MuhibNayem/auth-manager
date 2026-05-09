import axios from 'axios';
import type { 
  User, Organization, AuditEvent, Session, 
  DashboardMetrics, WebhookEndpoint, HealthStatus,
  SecurityAnalysis, PaginatedResponse 
} from '../types';

const API_BASE = '/admin/api/v1';

// Create axios instance with auth interceptor
export const apiClient = axios.create({
  baseURL: API_BASE,
  headers: {
    'Content-Type': 'application/json',
  },
});

// Add token interceptor (token will be set from store)
apiClient.interceptors.request.use((config) => {
  const token = localStorage.getItem('authy_admin_token');
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

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
  }): Promise<PaginatedResponse<User>> => {
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
  list: async (params: { page?: number; page_size?: number; search?: string }) => {
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
  }): Promise<PaginatedResponse<AuditEvent>> => {
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
