import React from 'react';
import { 
  Users, Building2, Shield, Activity, Settings, LogOut, 
  Menu, Bell, Search, ChevronDown, Key, FileText, Webhook, Heart,
  Sparkles, UserCog 
} from 'lucide-react';
import { useUIStore, useAuthStore } from '../store';
import clsx from 'clsx';

interface NavItem {
  icon: React.ReactNode;
  label: string;
  href: string;
  badge?: number;
}

export const Sidebar: React.FC = () => {
  const { sidebarOpen, toggleSidebar } = useUIStore();
  const { user, logout } = useAuthStore();

  const navItems: NavItem[] = [
    { icon: <Activity size={20} />, label: 'Dashboard', href: '/' },
    { icon: <Users size={20} />, label: 'Users', href: '/users' },
    { icon: <Building2 size={20} />, label: 'Organizations', href: '/organizations' },
    { icon: <Shield size={20} />, label: 'Security', href: '/security', badge: 3 },
    { icon: <FileText size={20} />, label: 'Audit Logs', href: '/audit-logs' },
    { icon: <Key size={20} />, label: 'Sessions', href: '/sessions' },
    { icon: <Webhook size={20} />, label: 'Webhooks', href: '/webhooks' },
    { icon: <Heart size={20} />, label: 'Health', href: '/health' },
    { icon: <UserCog size={20} />, label: 'RBAC', href: '/rbac' },
    { icon: <Sparkles size={20} />, label: 'Enterprise', href: '/enterprise' },
    { icon: <Settings size={20} />, label: 'Settings', href: '/settings' },
  ];

  return (
    <>
      {/* Mobile overlay */}
      {sidebarOpen && (
        <div 
          className="fixed inset-0 bg-black/50 z-40 lg:hidden"
          onClick={toggleSidebar}
        />
      )}

      {/* Sidebar */}
      <aside
        className={clsx(
          'fixed top-0 left-0 z-50 h-full w-64 bg-white border-r border-gray-200 transform transition-transform duration-300 ease-in-out lg:translate-x-0',
          sidebarOpen ? 'translate-x-0' : '-translate-x-full'
        )}
      >
        {/* Logo */}
        <div className="h-16 flex items-center px-6 border-b border-gray-200">
          <div className="flex items-center gap-2">
            <div className="w-8 h-8 bg-gradient-to-br from-blue-500 to-purple-600 rounded-lg flex items-center justify-center">
              <Shield size={18} className="text-white" />
            </div>
            <span className="font-bold text-xl text-gray-900">Authy Admin</span>
          </div>
        </div>

        {/* Navigation */}
        <nav className="p-4 space-y-1">
          {navItems.map((item) => (
            <a
              key={item.label}
              href={item.href}
              className="flex items-center gap-3 px-3 py-2.5 rounded-lg text-gray-700 hover:bg-gray-100 transition-colors group"
            >
              <span className="text-gray-500 group-hover:text-gray-700">{item.icon}</span>
              <span className="flex-1 font-medium">{item.label}</span>
              {item.badge && (
                <span className="px-2 py-0.5 text-xs font-semibold bg-red-100 text-red-700 rounded-full">
                  {item.badge}
                </span>
              )}
            </a>
          ))}
        </nav>

        {/* User section */}
        <div className="absolute bottom-0 left-0 right-0 p-4 border-t border-gray-200">
          <div className="flex items-center gap-3 mb-3">
            <div className="w-10 h-10 bg-gradient-to-br from-green-400 to-blue-500 rounded-full flex items-center justify-center text-white font-semibold">
              {user?.email?.charAt(0).toUpperCase() || 'A'}
            </div>
            <div className="flex-1 min-w-0">
              <p className="text-sm font-medium text-gray-900 truncate">
                {user?.email || 'Admin'}
              </p>
              <p className="text-xs text-gray-500 capitalize">{user?.role || 'Administrator'}</p>
            </div>
          </div>
          <button
            onClick={logout}
            className="w-full flex items-center gap-2 px-3 py-2 text-sm text-red-600 hover:bg-red-50 rounded-lg transition-colors"
          >
            <LogOut size={16} />
            Sign Out
          </button>
        </div>
      </aside>
    </>
  );
};

export const Header: React.FC = () => {
  const { toggleSidebar } = useUIStore();
  const { user } = useAuthStore();

  return (
    <header className="h-16 bg-white border-b border-gray-200 flex items-center justify-between px-4 lg:px-6">
      <div className="flex items-center gap-4">
        <button
          onClick={toggleSidebar}
          className="lg:hidden p-2 hover:bg-gray-100 rounded-lg"
        >
          <Menu size={20} />
        </button>

        {/* Search */}
        <div className="hidden md:flex items-center gap-2 px-3 py-2 bg-gray-100 rounded-lg w-96">
          <Search size={18} className="text-gray-500" />
          <input
            type="text"
            placeholder="Search users, organizations, events..."
            className="bg-transparent border-none outline-none text-sm w-full"
          />
        </div>
      </div>

      <div className="flex items-center gap-3">
        {/* Notifications */}
        <button className="relative p-2 hover:bg-gray-100 rounded-lg">
          <Bell size={20} className="text-gray-600" />
          <span className="absolute top-1 right-1 w-2 h-2 bg-red-500 rounded-full"></span>
        </button>

        {/* User menu */}
        <button className="flex items-center gap-2 px-3 py-2 hover:bg-gray-100 rounded-lg">
          <div className="w-8 h-8 bg-gradient-to-br from-green-400 to-blue-500 rounded-full flex items-center justify-center text-white text-sm font-semibold">
            {user?.email?.charAt(0).toUpperCase() || 'A'}
          </div>
          <ChevronDown size={16} className="text-gray-600" />
        </button>
      </div>
    </header>
  );
};
