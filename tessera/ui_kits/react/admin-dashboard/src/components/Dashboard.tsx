import React, { useState } from 'react';
import { Users, Activity, Building2, Shield, Clock, TrendingUp } from 'lucide-react';
import { useDashboardMetrics, useHealthStatus } from '../hooks/useQueries';

interface MetricCardProps {
  title: string;
  value: number | string;
  /** Period-over-period delta in percent; undefined means "not available". */
  change?: number;
  icon: React.ReactNode;
  color: string;
}

const MetricCard: React.FC<MetricCardProps> = ({ title, value, change, icon, color }) => (
  <div className="bg-white rounded-xl p-6 border border-gray-200 shadow-sm">
    <div className="flex items-center justify-between mb-4">
      <div className={`p-3 rounded-lg ${color}`}>
        {icon}
      </div>
      {change !== undefined ? (
        <div className={`flex items-center gap-1 text-sm font-medium ${change >= 0 ? 'text-green-600' : 'text-red-600'}`}>
          <TrendingUp size={16} className={change < 0 ? 'rotate-180' : ''} />
          {Math.abs(change)}%
        </div>
      ) : (
        // The metrics API does not return deltas; render an explicit
        // "not available" marker instead of a fabricated number.
        <div className="text-sm font-medium text-gray-400" title="Change not available">—</div>
      )}
    </div>
    <h3 className="text-3xl font-bold text-gray-900 mb-1">
      {typeof value === 'number' ? value.toLocaleString() : value}
    </h3>
    <p className="text-sm text-gray-500">{title}</p>
  </div>
);

interface ComponentTone {
  label: string;
  bar: string;
  text: string;
  width: string;
}

/** Map a backend health component status string to presentation. */
const componentTone = (status: string | undefined): ComponentTone => {
  if (!status) {
    return { label: '—', bar: 'bg-gray-300', text: 'text-gray-400', width: '0%' };
  }
  if (status === 'healthy') {
    return { label: 'Healthy', bar: 'bg-green-500', text: 'text-green-600', width: '100%' };
  }
  if (status === 'not_configured') {
    return { label: 'Not configured', bar: 'bg-gray-400', text: 'text-gray-500', width: '100%' };
  }
  if (status.startsWith('unhealthy')) {
    return { label: 'Unhealthy', bar: 'bg-red-500', text: 'text-red-600', width: '100%' };
  }
  return { label: status, bar: 'bg-amber-500', text: 'text-amber-600', width: '100%' };
};

const OVERALL_TONE: Record<string, string> = {
  healthy: 'bg-green-100 text-green-700',
  degraded: 'bg-amber-100 text-amber-700',
  unhealthy: 'bg-red-100 text-red-700',
};

const HealthBar: React.FC<{ name: string; status: string | undefined }> = ({ name, status }) => {
  const tone = componentTone(status);
  return (
    <div className="flex-1">
      <div className="flex items-center justify-between mb-2">
        <span className="text-sm text-gray-600">{name}</span>
        <span className={`text-sm font-medium ${tone.text}`}>{tone.label}</span>
      </div>
      <div className="w-full bg-gray-200 rounded-full h-2">
        <div className={`${tone.bar} h-2 rounded-full`} style={{ width: tone.width }}></div>
      </div>
    </div>
  );
};

export const DashboardOverview: React.FC = () => {
  const [days, setDays] = useState<number>(7);
  const { data: metrics, isLoading, error } = useDashboardMetrics(days);
  const { data: health, isError: healthError } = useHealthStatus();

  if (isLoading) {
    return (
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        {[...Array(8)].map((_, i) => (
          <div key={i} className="bg-white rounded-xl p-6 border border-gray-200 animate-pulse">
            <div className="h-12 bg-gray-200 rounded-lg mb-4"></div>
            <div className="h-8 bg-gray-200 rounded w-24 mb-2"></div>
            <div className="h-4 bg-gray-200 rounded w-32"></div>
          </div>
        ))}
      </div>
    );
  }

  if (error || !metrics) {
    return (
      <div className="bg-red-50 border border-red-200 rounded-xl p-6 text-red-700">
        Failed to load dashboard metrics
      </div>
    );
  }

  // Deltas (change) are intentionally omitted: the /dashboard/metrics API
  // does not return them, so MetricCard renders "—" for every card rather
  // than showing invented numbers.
  const metricCards = [
    {
      title: 'Total Users',
      value: metrics.total_users,
      icon: <Users size={24} className="text-white" />,
      color: 'bg-gradient-to-br from-blue-500 to-blue-600',
    },
    {
      title: 'Active (24h)',
      value: metrics.active_users_24h,
      icon: <Activity size={24} className="text-white" />,
      color: 'bg-gradient-to-br from-green-500 to-green-600',
    },
    {
      title: 'Organizations',
      value: metrics.total_organizations,
      icon: <Building2 size={24} className="text-white" />,
      color: 'bg-gradient-to-br from-purple-500 to-purple-600',
    },
    {
      title: 'Active Sessions',
      value: metrics.active_sessions,
      icon: <Clock size={24} className="text-white" />,
      color: 'bg-gradient-to-br from-orange-500 to-orange-600',
    },
    {
      title: 'Security Events (24h)',
      value: metrics.security_events_24h,
      icon: <Shield size={24} className="text-white" />,
      color: 'bg-gradient-to-br from-red-500 to-red-600',
    },
    {
      title: 'Login Success Rate',
      value: `${metrics.login_success_rate}%`,
      icon: <TrendingUp size={24} className="text-white" />,
      color: 'bg-gradient-to-br from-emerald-500 to-emerald-600',
    },
    {
      title: 'MFA Adoption',
      value: `${metrics.mfa_adoption_rate}%`,
      icon: <Shield size={24} className="text-white" />,
      color: 'bg-gradient-to-br from-indigo-500 to-indigo-600',
    },
    {
      title: 'Webhook Delivery Rate',
      value: `${metrics.webhook_delivery_rate}%`,
      icon: <Activity size={24} className="text-white" />,
      color: 'bg-gradient-to-br from-cyan-500 to-cyan-600',
    },
  ];

  const components = health?.components;
  const healthAvailable = !healthError && !!health;

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold text-gray-900">Dashboard Overview</h1>
        <select
          aria-label="Metrics time range"
          value={days}
          onChange={(e) => setDays(Number(e.target.value))}
          className="px-4 py-2 border border-gray-300 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
        >
          <option value={7}>Last 7 days</option>
          <option value={30}>Last 30 days</option>
          <option value={90}>Last 90 days</option>
        </select>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        {metricCards.map((card) => (
          <MetricCard key={card.title} {...card} />
        ))}
      </div>

      {/* Quick Stats */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="bg-white rounded-xl p-6 border border-gray-200">
          <h3 className="text-lg font-semibold text-gray-900 mb-4">New Users (Last 7 Days)</h3>
          <div className="text-3xl font-bold text-gray-900">{metrics.new_users_7d.toLocaleString()}</div>
          <p className="text-sm text-gray-500 mt-1">Average of {Math.round(metrics.new_users_7d / 7)} per day</p>
        </div>

        <div className="bg-white rounded-xl p-6 border border-gray-200">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-lg font-semibold text-gray-900">System Health</h3>
            {healthAvailable ? (
              <span className={`px-2 py-0.5 text-xs font-semibold rounded-full ${OVERALL_TONE[health.status] ?? 'bg-gray-100 text-gray-600'}`}>
                {health.status}
              </span>
            ) : (
              <span className="text-sm text-gray-400">—</span>
            )}
          </div>

          {healthAvailable && components ? (
            <div className="flex items-center gap-4">
              <HealthBar name="Database" status={components.database} />
              <HealthBar name="Cache" status={components.cache} />
              {components.webhooks !== undefined && (
                <HealthBar name="Webhooks" status={typeof components.webhooks === 'string' ? components.webhooks : undefined} />
              )}
            </div>
          ) : (
            <p className="text-sm text-gray-500">
              Health data unavailable. Check the <code>/health</code> admin endpoint and try again.
            </p>
          )}
        </div>
      </div>
    </div>
  );
};
