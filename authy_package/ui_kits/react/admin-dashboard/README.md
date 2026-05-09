# Authy Admin Dashboard - Enterprise Grade Implementation

## 🎯 Overview

State-of-the-art enterprise-grade admin dashboard for the Authy Package authentication system. Built with modern React, TypeScript, and TailwindCSS for a premium developer experience.

## ✨ Features

### Core Capabilities
- **Dashboard Analytics**: Real-time metrics, charts, and KPIs
- **User Management**: CRUD operations, bulk actions, impersonation
- **Organization Management**: Multi-tenancy support, member management
- **Audit Logs**: Advanced filtering, export (CSV/JSON), compliance ready
- **Session Management**: Active session monitoring, remote revocation
- **Webhook Configuration**: Endpoint management, delivery tracking, testing
- **Security Center**: Threat detection, suspicious activity analysis
- **System Health**: Real-time component monitoring
- **Role-Based Access Control**: Granular permissions

### Technical Excellence
- ⚡ **React 18** with modern hooks
- 📘 **TypeScript** for type safety
- 🎨 **TailwindCSS** for styling
- 🔍 **TanStack Query** for data fetching
- 🗃️ **Zustand** for state management
- 📊 **Recharts** for data visualization
- 🎭 **Framer Motion** for animations
- 🔔 **React Hot Toast** for notifications

## 📦 Installation

```bash
cd authy_package/ui_kits/react/admin-dashboard
npm install
```

## 🚀 Usage

### As a Standalone App

```bash
npm run dev
```

The dashboard will be available at `http://localhost:3000`

### As a Component Library

```tsx
import { AdminDashboard } from '@authy/admin-dashboard';

function App() {
  return <AdminDashboard />;
}
```

## 🏗️ Architecture

```
src/
├── components/       # Reusable UI components
│   ├── Layout.tsx    # Sidebar, Header
│   └── Dashboard.tsx # Dashboard overview
├── hooks/            # Custom React hooks
│   └── useQueries.ts # TanStack Query hooks
├── lib/              # Utilities and API client
│   └── api.ts        # REST API integration
├── pages/            # Page components
├── store/            # Zustand stores
│   └── index.ts      # Auth, Dashboard, UI state
├── types/            # TypeScript definitions
│   └── index.ts      # API types
└── index.ts          # Main entry point
```

## 🔌 API Integration

The dashboard connects to the Authy Admin API (`/admin/api/v1`):

### Endpoints Used

| Category | Endpoints |
|----------|-----------|
| Dashboard | `GET /dashboard/metrics`, `GET /dashboard/chart-data` |
| Users | `GET/POST/PUT/DELETE /users`, `POST /users/bulk` |
| Organizations | `GET/POST /organizations` |
| Audit Logs | `GET /audit-logs`, `GET /audit-logs/export` |
| Sessions | `GET /sessions`, `DELETE /sessions/:id` |
| Webhooks | `GET/POST/PUT/DELETE /webhooks` |
| Security | `GET /security/events`, `GET /security/suspicious-activity` |
| Health | `GET /health` |
| WebSocket | `WS /ws/realtime` |

### Authentication

```typescript
// Set admin token
localStorage.setItem('authy_admin_token', 'your-jwt-token');

// The API client automatically includes it in requests
```

## 🎨 Customization

### Theme

```tsx
import { useUIStore } from './store';

function ThemeToggle() {
  const { theme, setTheme } = useUIStore();
  
  return (
    <button onClick={() => setTheme(theme === 'light' ? 'dark' : 'light')}>
      Toggle Theme
    </button>
  );
}
```

### Components

All components are exported for custom compositions:

```tsx
import { Sidebar, Header, DashboardOverview } from '@authy/admin-dashboard';
```

## 📊 Example: Custom Dashboard

```tsx
import { AdminDashboard, useDashboardMetrics } from '@authy/admin-dashboard';

function CustomDashboard() {
  const { data: metrics } = useDashboardMetrics(30);
  
  return (
    <div>
      <h1>Custom Metrics View</h1>
      {metrics && (
        <div>Total Users: {metrics.total_users}</div>
      )}
    </div>
  );
}
```

## 🔒 Security Features

- JWT-based authentication
- Role-based access control (RBAC)
- Session management with revocation
- Audit logging of all admin actions
- User impersonation with time-limited tokens
- CORS protection
- Rate limiting support

## 🧪 Development

```bash
# Run development server
npm run dev

# Build for production
npm run build

# Run tests
npm run test

# Lint code
npm run lint
```

## 📝 License

MIT License - See LICENSE file for details

## 🤝 Contributing

Contributions welcome! Please read our contributing guidelines before submitting PRs.

## 📞 Support

- Documentation: [Link to docs]
- Issues: [GitHub Issues]
- Email: support@authy.io

---

**Built with ❤️ by the Authy Team**
