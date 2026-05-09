// API Types for Authy Admin Dashboard

export interface User {
  id: string;
  username?: string;
  email: string;
  phone?: string;
  role: string;
  status: 'active' | 'inactive' | 'locked' | 'pending_verification';
  mfa_enabled: boolean;
  created_at: string;
  updated_at: string;
  last_login?: string;
  metadata?: Record<string, any>;
}

export interface Organization {
  id: string;
  name: string;
  description?: string;
  owner_id: string;
  plan: 'free' | 'pro' | 'enterprise';
  member_count: number;
  created_at: string;
  metadata?: Record<string, any>;
}

export interface AuditEvent {
  id: string;
  event_type: string;
  actor_id?: string;
  actor_email?: string;
  target_id?: string;
  target_type?: string;
  action: string;
  timestamp: string;
  ip_address?: string;
  user_agent?: string;
  metadata?: Record<string, any>;
  organization_id?: string;
  severity: 'info' | 'warning' | 'error' | 'critical';
  status: 'success' | 'failure';
}

export interface Session {
  session_id: string;
  user_id: string;
  device_info?: string;
  ip_address?: string;
  created_at: string;
  last_active: string;
  is_active: boolean;
}

export interface DashboardMetrics {
  total_users: number;
  active_users_24h: number;
  new_users_7d: number;
  total_organizations: number;
  active_sessions: number;
  login_success_rate: number;
  mfa_adoption_rate: number;
  security_events_24h: number;
  webhook_delivery_rate: number;
}

export interface WebhookEndpoint {
  id: string;
  url: string;
  events: string[];
  is_active: boolean;
  description?: string;
  created_at: string;
  last_delivery?: string;
  delivery_success_rate?: number;
}

export interface ChartDataPoint {
  label: string;
  value: number;
  timestamp: string;
}

export interface PaginationParams {
  page: number;
  page_size: number;
}

export interface PaginatedResponse<T> {
  data: T[];
  pagination: {
    page: number;
    page_size: number;
    total: number;
    total_pages: number;
  };
}

export interface UsersListResponse {
  users: User[];
  pagination: PaginatedResponse<User>['pagination'];
}

export interface OrganizationsListResponse {
  organizations: Organization[];
  pagination: PaginatedResponse<Organization>['pagination'];
}

export interface AuditEventsListResponse {
  events: AuditEvent[];
  pagination: PaginatedResponse<AuditEvent>['pagination'];
}

export interface Permission {
  id: string;
  name: string;
  description: string;
  category: string;
  scope: 'global' | 'organization' | 'team' | 'resource';
  created_at: string;
}

export interface Role {
  id: string;
  name: string;
  description: string;
  permissions: string[];
  inherits_from?: string;
  is_system: boolean;
  organization_id?: string;
  created_at: string;
  updated_at: string;
}

export interface RoleAssignment {
  id: string;
  user_id: string;
  role_id: string;
  scope_type: 'global' | 'organization' | 'team' | 'resource';
  scope_id?: string;
  expires_at?: string;
  granted_by: string;
  created_at: string;
}

export type UserRole = 'owner' | 'admin' | 'member' | 'guest';

export interface OrgMember {
  user_id: string;
  email: string;
  role: UserRole;
  joined_at: string;
}

export interface Invitation {
  id: string;
  email: string;
  role: UserRole;
  invited_by: string;
  invited_at: string;
  expires_at: string;
  status: 'pending' | 'accepted' | 'expired';
}

export interface HealthStatus {
  status: 'healthy' | 'degraded' | 'unhealthy';
  timestamp: string;
  components: {
    database: string;
    cache: string;
    webhooks?: string;
  };
}

export interface SecurityAnalysis {
  total_incidents: number;
  by_type: Record<string, number>;
  by_ip: Record<string, number>;
  by_user: Record<string, number>;
  timeline: Array<{
    timestamp: string;
    count: number;
  }>;
}
