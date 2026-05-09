import React from 'react';
import { Users, Activity, Building2, Shield, Clock, TrendingUp } from 'lucide-react';
import type { DashboardMetrics } from '../types';
import { useDashboardMetrics } from '../hooks/useQueries';

interface MetricCardProps {
  title: string;
  value: number | string;
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
      {change !== undefined && (
        <div className={`flex items-center gap-1 text-sm font-medium ${change >= 0 ? 'text-green-600' : 'text-red-600'}`}>
          <TrendingUp size={16} className={change < 0 ? 'rotate-180' : ''} />
          {Math.abs(change)}%
        </div>
      )}
    </div>
    <h3 className="text-3xl font-bold text-gray-900 mb-1">{value.toLocaleString()}</h3>
    <p className="text-sm text-gray-500">{title}</p>
  </div>
);

export const DashboardOverview: React.FC = () => {
  const { data: metrics, isLoading, error } = useDashboardMetrics(7);

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

  const metricCards = [
    {
      title: 'Total Users',
      value: metrics.total_users,
      change: 12.5,
      icon: <Users size={24} className="text-white" />,
      color: 'bg-gradient-to-br from-blue-500 to-blue-600',
    },
    {
      title: 'Active (24h)',
      value: metrics.active_users_24h,
      change: 8.2,
      icon: <Activity size={24} className="text-white" />,
      color: 'bg-gradient-to-br from-green-500 to-green-600',
    },
    {
      title: 'Organizations',
      value: metrics.total_organizations,
      change: 5.7,
      icon: <Building2 size={24} className="text-white" />,
      color: 'bg-gradient-to-br from-purple-500 to-purple-600',
    },
    {
      title: 'Active Sessions',
      value: metrics.active_sessions,
      change: -2.4,
      icon: <Clock size={24} className="text-white" />,
      color: 'bg-gradient-to-br from-orange-500 to-orange-600',
    },
    {
      title: 'Security Events (24h)',
      value: metrics.security_events_24h,
      change: -15.3,
      icon: <Shield size={24} className="text-white" />,
      color: 'bg-gradient-to-br from-red-500 to-red-600',
    },
    {
      title: 'Login Success Rate',
      value: `${metrics.login_success_rate}%`,
      change: 1.2,
      icon: <TrendingUp size={24} className="text-white" />,
      color: 'bg-gradient-to-br from-emerald-500 to-emerald-600',
    },
    {
      title: 'MFA Adoption',
      value: `${metrics.mfa_adoption_rate}%`,
      change: 22.8,
      icon: <Shield size={24} className="text-white" />,
      color: 'bg-gradient-to-br from-indigo-500 to-indigo-600',
    },
    {
      title: 'Webhook Delivery Rate',
      value: `${metrics.webhook_delivery_rate}%`,
      change: 0.5,
      icon: <Activity size={24} className="text-white" />,
      color: 'bg-gradient-to-br from-cyan-500 to-cyan-600',
    },
  ];

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold text-gray-900">Dashboard Overview</h1>
        <select className="px-4 py-2 border border-gray-300 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-blue-500">
          <option>Last 7 days</option>
          <option>Last 30 days</option>
          <option>Last 90 days</option>
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
          <h3 className="text-lg font-semibold text-gray-900 mb-4">System Health</h3>
          <div className="flex items-center gap-4">
            <div className="flex-1">
              <div className="flex items-center justify-between mb-2">
                <span className="text-sm text-gray-600">Database</span>
                <span className="text-sm font-medium text-green-600">Healthy</span>
              </div>
              <div className="w-full bg-gray-200 rounded-full h-2">
                <div className="bg-green-500 h-2 rounded-full" style={{ width: '100%' }}></div>
              </div>
            </div>
            <div className="flex-1">
              <div className="flex items-center justify-between mb-2">
                <span className="text-sm text-gray-600">Cache</span>
                <span className="text-sm font-medium text-green-600">Healthy</span>
              </div>
              <div className="w-full bg-gray-200 rounded-full h-2">
                <div className="bg-green-500 h-2 rounded-full" style={{ width: '100%' }}></div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
