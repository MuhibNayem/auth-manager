import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { usersAPI, organizationsAPI, auditAPI, sessionsAPI, webhooksAPI, securityAPI, healthAPI, dashboardAPI } from '../lib/api';

// Dashboard Queries
export const useDashboardMetrics = (days: number = 7) => {
  return useQuery({
    queryKey: ['dashboard', 'metrics', days],
    queryFn: () => dashboardAPI.getMetrics(days),
    refetchInterval: 30000, // 30 seconds
  });
};

export const useChartData = (metric: string, days: number = 30, granularity: string = 'day') => {
  return useQuery({
    queryKey: ['dashboard', 'chart', metric, days, granularity],
    queryFn: () => dashboardAPI.getChartData(metric, days, granularity),
  });
};

// User Queries
export const useUsers = (params: any = {}) => {
  return useQuery({
    queryKey: ['users', params],
    queryFn: () => usersAPI.list(params),
  });
};

export const useUser = (userId: string) => {
  return useQuery({
    queryKey: ['user', userId],
    queryFn: () => usersAPI.getById(userId),
    enabled: !!userId,
  });
};

export const useCreateUser = () => {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: usersAPI.create,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['users'] });
    },
  });
};

export const useUpdateUser = () => {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({ userId, data }: { userId: string; data: any }) => 
      usersAPI.update(userId, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['users'] });
    },
  });
};

export const useDeleteUser = () => {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: usersAPI.delete,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['users'] });
    },
  });
};

export const useImpersonateUser = () => {
  return useMutation({
    mutationFn: usersAPI.impersonate,
  });
};

// Organization Queries
export const useOrganizations = (params: any = {}) => {
  return useQuery({
    queryKey: ['organizations', params],
    queryFn: () => organizationsAPI.list(params),
  });
};

export const useOrganization = (orgId: string) => {
  return useQuery({
    queryKey: ['organization', orgId],
    queryFn: () => organizationsAPI.getById(orgId),
    enabled: !!orgId,
  });
};

export const useCreateOrganization = () => {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: organizationsAPI.create,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['organizations'] });
    },
  });
};

// Audit Log Queries
export const useAuditLogs = (params: any = {}) => {
  return useQuery({
    queryKey: ['audit-logs', params],
    queryFn: () => auditAPI.list(params),
  });
};

export const useAuditEvent = (eventId: string) => {
  return useQuery({
    queryKey: ['audit-event', eventId],
    queryFn: () => auditAPI.getById(eventId),
    enabled: !!eventId,
  });
};

// Session Queries
export const useSessions = (params?: { user_id?: string; active_only?: boolean }) => {
  return useQuery({
    queryKey: ['sessions', params],
    queryFn: () => sessionsAPI.list(params),
  });
};

export const useRevokeSession = () => {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: sessionsAPI.revoke,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['sessions'] });
    },
  });
};

export const useRevokeAllUserSessions = () => {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: sessionsAPI.revokeAllForUser,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['sessions'] });
    },
  });
};

// Webhook Queries
export const useWebhooks = () => {
  return useQuery({
    queryKey: ['webhooks'],
    queryFn: webhooksAPI.list,
  });
};

export const useCreateWebhook = () => {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: webhooksAPI.create,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['webhooks'] });
    },
  });
};

export const useUpdateWebhook = () => {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({ webhookId, data }: { webhookId: string; data: any }) =>
      webhooksAPI.update(webhookId, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['webhooks'] });
    },
  });
};

export const useDeleteWebhook = () => {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: webhooksAPI.delete,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['webhooks'] });
    },
  });
};

export const useTestWebhook = () => {
  return useMutation({
    mutationFn: webhooksAPI.test,
  });
};

// Security Queries
export const useSecurityEvents = (hours: number = 24, limit: number = 100) => {
  return useQuery({
    queryKey: ['security', 'events', hours, limit],
    queryFn: () => securityAPI.getEvents(hours, limit),
    refetchInterval: 60000, // 1 minute
  });
};

export const useSuspiciousActivity = (days: number = 7) => {
  return useQuery({
    queryKey: ['security', 'suspicious', days],
    queryFn: () => securityAPI.getSuspiciousActivity(days),
  });
};

// Health Query
export const useHealthStatus = () => {
  return useQuery({
    queryKey: ['health'],
    queryFn: healthAPI.getStatus,
    refetchInterval: 10000, // 10 seconds
  });
};
