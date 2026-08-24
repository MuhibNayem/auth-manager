/**
 * Tessera Admin Dashboard - Enterprise Extensions
 *
 * Features (all backed by the admin API v2, see
 * tessera/admin/dashboard_enterprise.py):
 * - Advanced audit log search builder      POST /admin/v2/audit-logs/search
 * - White-label branding configuration     GET/PUT /admin/v2/config/branding
 * - API key management                     GET/POST/DELETE /admin/v2/api-keys
 * - Security analytics (rule-based heuristics, not ML):
 *     GET /admin/v2/ai/anomalies, GET /admin/v2/ai/predictions,
 *     POST /admin/v2/ai/nlq
 *
 * v2 routes live under /admin/v2 (NOT under /admin/api/v1), so every call
 * below goes through `apiV2` to avoid double-prefixed URLs.
 */

import React, { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { apiV2 } from '../lib/api';
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer } from 'recharts';
import {
  ShieldAlert,
  TrendingUp,
  TrendingDown,
  Activity,
  Key,
  Palette,
  Search,
  Bot,
  BrainCircuit,
  MessageSquare,
  X
} from 'lucide-react';
import { motion } from 'framer-motion';

// ============================================================================
// MINIMAL UI PRIMITIVES
// ============================================================================

const Card: React.FC<React.HTMLAttributes<HTMLDivElement>> = ({ children, ...props }) => (
  <div className="bg-white rounded-xl border border-gray-200 shadow-sm" {...props}>{children}</div>
);
const CardContent: React.FC<React.HTMLAttributes<HTMLDivElement>> = ({ children, ...props }) => (
  <div className="p-6 pt-0" {...props}>{children}</div>
);
const CardHeader: React.FC<React.HTMLAttributes<HTMLDivElement>> = ({ children, ...props }) => (
  <div className="p-6 pb-2" {...props}>{children}</div>
);
const CardTitle: React.FC<React.HTMLAttributes<HTMLHeadingElement>> = ({ children, ...props }) => (
  <h3 className="text-lg font-semibold text-gray-900 flex items-center gap-2" {...props}>{children}</h3>
);
const Button: React.FC<React.ButtonHTMLAttributes<HTMLButtonElement>> = ({ children, ...props }) => (
  <button
    className="px-4 py-2 bg-blue-600 text-white text-sm font-medium rounded-md hover:bg-blue-700 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
    {...props}
  >
    {children}
  </button>
);
const Input: React.FC<React.InputHTMLAttributes<HTMLInputElement>> = (props) => (
  <input
    className="w-full px-3 py-2 border border-gray-300 rounded-md text-sm focus:outline-none focus:ring-2 focus:ring-blue-500 disabled:bg-gray-50"
    {...props}
  />
);
const Badge: React.FC<React.HTMLAttributes<HTMLSpanElement>> = ({ children, ...props }) => (
  <span className="px-2 py-0.5 text-xs font-semibold rounded-full bg-gray-100 text-gray-700" {...props}>{children}</span>
);
const Alert: React.FC<React.HTMLAttributes<HTMLDivElement>> = ({ children, ...props }) => (
  <div className="flex items-start gap-2 rounded-lg border border-gray-200 bg-gray-50 p-4 text-sm text-gray-700" {...props}>{children}</div>
);
const AlertDescription: React.FC<React.HTMLAttributes<HTMLParagraphElement>> = ({ children, ...props }) => (
  <p className="flex-1" {...props}>{children}</p>
);
const AlertTitle: React.FC<React.HTMLAttributes<HTMLHeadingElement>> = ({ children, ...props }) => (
  <h4 className="font-semibold" {...props}>{children}</h4>
);
const Table: React.FC<React.TableHTMLAttributes<HTMLTableElement>> = ({ children, ...props }) => (
  <table className="min-w-full divide-y divide-gray-200 text-sm" {...props}>{children}</table>
);
const TableBody: React.FC<React.HTMLAttributes<HTMLTableSectionElement>> = ({ children, ...props }) => (
  <tbody className="bg-white divide-y divide-gray-200" {...props}>{children}</tbody>
);
const TableCell: React.FC<React.TdHTMLAttributes<HTMLTableCellElement>> = ({ children, ...props }) => (
  <td className="px-4 py-3 align-middle" {...props}>{children}</td>
);
const TableHead: React.FC<React.ThHTMLAttributes<HTMLTableCellElement>> = ({ children, ...props }) => (
  <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider" {...props}>{children}</th>
);
const TableHeader: React.FC<React.HTMLAttributes<HTMLTableSectionElement>> = ({ children, ...props }) => (
  <thead className="bg-gray-50" {...props}>{children}</thead>
);
const TableRow: React.FC<React.HTMLAttributes<HTMLTableRowElement>> = ({ children, ...props }) => (
  <tr className="hover:bg-gray-50" {...props}>{children}</tr>
);

// --- Dialog with real open/close state -------------------------------------

interface DialogContextValue {
  open: boolean;
  setOpen: (open: boolean) => void;
}

const DialogContext = React.createContext<DialogContextValue | null>(null);

function useDialogContext(component: string): DialogContextValue {
  const ctx = React.useContext(DialogContext);
  if (!ctx) {
    throw new Error(`${component} must be rendered inside <Dialog>`);
  }
  return ctx;
}

interface DialogProps {
  children?: React.ReactNode;
  /** Controlled open state; omit for internal (uncontrolled) state. */
  open?: boolean;
  defaultOpen?: boolean;
  onOpenChange?: (open: boolean) => void;
}

const Dialog: React.FC<DialogProps> = ({ children, open: controlledOpen, defaultOpen = false, onOpenChange }) => {
  const [uncontrolledOpen, setUncontrolledOpen] = useState(defaultOpen);
  const open = controlledOpen ?? uncontrolledOpen;
  const setOpen = React.useCallback(
    (next: boolean) => {
      setUncontrolledOpen(next);
      onOpenChange?.(next);
    },
    [onOpenChange],
  );
  const value = React.useMemo(() => ({ open, setOpen }), [open, setOpen]);
  return <DialogContext.Provider value={value}>{children}</DialogContext.Provider>;
};

const DialogTrigger: React.FC<React.ButtonHTMLAttributes<HTMLButtonElement>> = ({ children, onClick, type, ...props }) => {
  const { setOpen } = useDialogContext('DialogTrigger');
  const handleClick = (event: React.MouseEvent<HTMLButtonElement>) => {
    onClick?.(event);
    if (!event.defaultPrevented) setOpen(true);
  };
  return (
    <button type={type ?? 'button'} onClick={handleClick} {...props}>
      {children}
    </button>
  );
};

const DialogContent: React.FC<React.HTMLAttributes<HTMLDivElement>> = ({ children, ...props }) => {
  const { open, setOpen } = useDialogContext('DialogContent');

  React.useEffect(() => {
    if (!open) return;
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Escape') setOpen(false);
    };
    window.addEventListener('keydown', onKeyDown);
    return () => window.removeEventListener('keydown', onKeyDown);
  }, [open, setOpen]);

  if (!open) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center">
      <div className="absolute inset-0 bg-black/50" aria-hidden="true" onClick={() => setOpen(false)} />
      <div
        role="dialog"
        aria-modal="true"
        className="relative bg-white rounded-lg shadow-xl max-w-lg w-full m-4 p-6"
        {...props}
      >
        <button
          type="button"
          aria-label="Close dialog"
          onClick={() => setOpen(false)}
          className="absolute top-3 right-3 p-1 text-gray-400 hover:text-gray-600 rounded"
        >
          <X size={16} />
        </button>
        {children}
      </div>
    </div>
  );
};

const DialogHeader: React.FC<React.HTMLAttributes<HTMLDivElement>> = ({ children, ...props }) => (
  <div className="mb-4" {...props}>{children}</div>
);
const DialogTitle: React.FC<React.HTMLAttributes<HTMLHeadingElement>> = ({ children, ...props }) => (
  <h4 className="text-xl font-bold text-gray-900" {...props}>{children}</h4>
);

// ============================================================================
// TYPES
// ============================================================================

export interface ApiKey {
  id: string;
  name: string;
  prefix: string;
  scopes: string[];
  created_at: string;
  expires_at?: string;
  last_used_at?: string;
}

export interface BrandingConfig {
  app_name: string;
  primary_color: string;
  logo_url?: string;
  favicon_url?: string;
  support_email: string;
  custom_css?: string;
}

export interface Anomaly {
  id: string;
  type: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  description: string;
  affected_users: number;
  confidence_score: number;
  recommended_action: string;
  detected_at: string;
}

export interface PredictiveMetric {
  metric_name: string;
  current_value: number;
  predicted_value_7d: number;
  predicted_value_30d: number;
  trend: 'up' | 'down' | 'stable';
  confidence_interval: { lower: number; upper: number };
}

export interface NLQResponse {
  sql_generated: string;
  data: any[];
  chart_suggestion: string;
  explanation: string;
}

interface AuditSearchRow {
  id: string | number;
  event: string;
  actor?: string;
  ip?: string;
  timestamp: string;
}

interface AuditSearchResponse {
  total: number;
  page?: number;
  results?: AuditSearchRow[];
}

// ============================================================================
// API KEY MANAGEMENT
// ============================================================================

/** Scopes accepted by POST /admin/v2/api-keys (see ApiKeyScope in the backend). */
const API_KEY_SCOPES = ['read:only', 'full:access', 'audit:logs', 'user:manage'] as const;

/**
 * Create-key dialog body. Must render inside <Dialog> so it can close the
 * dialog itself once the key has been issued.
 */
function CreateApiKeyDialogContent({ onCreated }: { onCreated: (secret: string) => void }) {
  const { setOpen } = useDialogContext('CreateApiKeyDialogContent');
  const queryClient = useQueryClient();
  const [name, setName] = useState('');
  const [scopes, setScopes] = useState<string[]>([]);
  const [error, setError] = useState<string | null>(null);

  const createKeyMutation = useMutation({
    mutationFn: (data: { name: string; scopes: string[] }) =>
      apiV2.post('/api-keys', data).then(res => res.data),
    onSuccess: (data: { full_secret: string }) => {
      queryClient.invalidateQueries({ queryKey: ['apiKeys'] });
      setOpen(false);
      onCreated(data.full_secret);
    },
    onError: () => {
      setError('Failed to create the API key. Check the name and scopes, then try again.');
    },
  });

  const toggleScope = (scope: string) => {
    setScopes(prev => (prev.includes(scope) ? prev.filter(s => s !== scope) : [...prev, scope]));
  };

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    if (scopes.length === 0) {
      setError('Select at least one scope.');
      return;
    }
    createKeyMutation.mutate({ name, scopes });
  };

  return (
    <>
      <DialogTrigger className="px-4 py-2 bg-blue-600 text-white text-sm font-medium rounded-md hover:bg-blue-700 transition-colors">
        Create New API Key
      </DialogTrigger>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Generate API Key</DialogTitle>
        </DialogHeader>
        <form onSubmit={handleSubmit}>
          <div className="space-y-4 py-2">
            {error && (
              <div role="alert" className="bg-red-50 border border-red-200 text-red-700 text-sm rounded-md px-3 py-2">
                {error}
              </div>
            )}
            <div>
              <label htmlFor="api-key-name" className="block text-sm font-medium text-gray-700 mb-1">Key name</label>
              <Input
                id="api-key-name"
                placeholder="Key Name (e.g., Production App)"
                value={name}
                onChange={(e: React.ChangeEvent<HTMLInputElement>) => setName(e.target.value)}
                required
              />
            </div>
            <div>
              <span className="block text-sm font-medium text-gray-700 mb-1">Scopes</span>
              <div className="space-y-1">
                {API_KEY_SCOPES.map(scope => (
                  <label key={scope} className="flex items-center gap-2 text-sm text-gray-700">
                    <input
                      type="checkbox"
                      checked={scopes.includes(scope)}
                      onChange={() => toggleScope(scope)}
                      className="h-4 w-4 text-blue-600 rounded focus:ring-blue-500"
                    />
                    {scope}
                  </label>
                ))}
              </div>
            </div>
            <Button type="submit" className="w-full" disabled={createKeyMutation.isPending}>
              {createKeyMutation.isPending ? 'Generating...' : 'Generate Key'}
            </Button>
          </div>
        </form>
      </DialogContent>
    </>
  );
}

export function ApiKeyManager() {
  const queryClient = useQueryClient();
  const [showSecret, setShowSecret] = useState<string | null>(null);

  const { data: keys = [] } = useQuery<ApiKey[]>({
    queryKey: ['apiKeys'],
    queryFn: () => apiV2.get('/api-keys').then(res => res.data),
  });

  const revokeKeyMutation = useMutation({
    mutationFn: (id: string) =>
      apiV2.delete(`/api-keys/${id}`).then(res => res.data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['apiKeys'] });
    },
  });

  return (
    <Card className="w-full">
      <CardHeader>
        <CardTitle>
          <Key className="w-5 h-5" />
          API Key Management
        </CardTitle>
      </CardHeader>
      <CardContent>
        <div className="mb-6">
          <Dialog>
            <CreateApiKeyDialogContent onCreated={(secret) => setShowSecret(secret)} />
          </Dialog>
        </div>

        {showSecret && (
          <Alert className="mb-4 border-yellow-300 bg-yellow-50 text-yellow-800">
            <AlertTitle>New API secret</AlertTitle>
            <AlertDescription>
              Save this secret now — it is shown only once and cannot be retrieved again.
              <code className="block mt-1 font-mono text-xs break-all">{showSecret}</code>
            </AlertDescription>
          </Alert>
        )}

        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Name</TableHead>
              <TableHead>Prefix</TableHead>
              <TableHead>Scopes</TableHead>
              <TableHead>Created</TableHead>
              <TableHead>Expires</TableHead>
              <TableHead>Last Used</TableHead>
              <TableHead>Actions</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {keys.map((key) => (
              <TableRow key={key.id}>
                <TableCell className="font-medium">{key.name}</TableCell>
                <TableCell className="font-mono text-xs">{key.prefix}...</TableCell>
                <TableCell>
                  <div className="flex gap-1 flex-wrap">
                    {key.scopes.map(scope => (
                      <Badge key={scope}>{scope}</Badge>
                    ))}
                  </div>
                </TableCell>
                <TableCell>{new Date(key.created_at).toLocaleDateString()}</TableCell>
                <TableCell>{key.expires_at ? new Date(key.expires_at).toLocaleDateString() : 'Never'}</TableCell>
                <TableCell>{key.last_used_at ? new Date(key.last_used_at).toLocaleDateString() : 'Never'}</TableCell>
                <TableCell>
                  <button
                    type="button"
                    className="text-red-600 hover:text-red-800 text-sm font-medium"
                    onClick={() => revokeKeyMutation.mutate(key.id)}
                  >
                    Revoke
                  </button>
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </CardContent>
    </Card>
  );
}

// ============================================================================
// WHITE-LABEL BRANDING CONFIGURATION
// ============================================================================

export function BrandingConfigurator() {
  const queryClient = useQueryClient();

  const { data: config } = useQuery<BrandingConfig>({
    queryKey: ['branding'],
    queryFn: () => apiV2.get('/config/branding').then(res => res.data),
  });

  const updateMutation = useMutation({
    mutationFn: (data: Partial<BrandingConfig>) =>
      apiV2.put('/config/branding', { ...config, ...data }).then(res => res.data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['branding'] });
    },
  });

  if (!config) return <div>Loading...</div>;

  return (
    <Card className="w-full">
      <CardHeader>
        <CardTitle>
          <Palette className="w-5 h-5" />
          White-Label Configuration
        </CardTitle>
      </CardHeader>
      <CardContent>
        <form
          onSubmit={(e) => {
            e.preventDefault();
            const form = e.target as HTMLFormElement;
            updateMutation.mutate({
              app_name: (form.elements.namedItem('app_name') as HTMLInputElement).value,
              primary_color: (form.elements.namedItem('primary_color') as HTMLInputElement).value,
              support_email: (form.elements.namedItem('support_email') as HTMLInputElement).value,
            });
          }}
          className="space-y-4"
        >
          <div>
            <label className="block text-sm font-medium mb-1">Application Name</label>
            <Input name="app_name" defaultValue={config.app_name} />
          </div>

          <div>
            <label className="block text-sm font-medium mb-1">Primary Brand Color</label>
            <div className="flex gap-2">
              <Input name="primary_color" type="color" defaultValue={config.primary_color} className="w-20 h-10" />
              <Input readOnly value={config.primary_color} className="flex-1" />
            </div>
          </div>

          <div>
            <label className="block text-sm font-medium mb-1">Support Email</label>
            <Input name="support_email" type="email" defaultValue={config.support_email} />
          </div>

          <div>
            <label className="block text-sm font-medium mb-1">Custom CSS</label>
            <textarea
              name="custom_css"
              defaultValue={config.custom_css || ''}
              className="w-full min-h-[100px] p-2 border border-gray-300 rounded-md font-mono text-sm"
              placeholder="/* Add custom CSS overrides here */"
            />
          </div>

          <Button type="submit" disabled={updateMutation.isPending}>
            {updateMutation.isPending ? 'Saving...' : 'Save Branding'}
          </Button>
        </form>

        <div className="mt-8 p-4 border rounded-lg bg-gray-50">
          <h4 className="font-semibold mb-2">Live Preview</h4>
          <div
            className="p-4 rounded-lg text-white"
            style={{ backgroundColor: config.primary_color }}
          >
            <h3 className="text-lg font-bold">{config.app_name}</h3>
            <p className="text-sm opacity-90">This is how your primary buttons will look.</p>
          </div>
        </div>
      </CardContent>
    </Card>
  );
}

// ============================================================================
// SECURITY ANOMALY DETECTION (rule-based heuristics on the backend)
// ============================================================================

export function AIAnomalyDashboard() {
  const { data: anomalies = [] } = useQuery<Anomaly[]>({
    queryKey: ['aiAnomalies'],
    queryFn: () => apiV2.get('/ai/anomalies').then(res => res.data),
    refetchInterval: 30000, // Refresh every 30s
  });

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'critical': return 'bg-red-500';
      case 'high': return 'bg-orange-500';
      case 'medium': return 'bg-yellow-500';
      default: return 'bg-blue-500';
    }
  };

  return (
    <Card className="w-full">
      <CardHeader>
        <CardTitle>
          <BrainCircuit className="w-5 h-5 text-purple-600" />
          Security Anomaly Detection
          <Badge className="ml-auto bg-purple-100 text-purple-700">Rule-based heuristics</Badge>
        </CardTitle>
      </CardHeader>
      <CardContent>
        <div className="space-y-4">
          {anomalies.length === 0 ? (
            <Alert>
              <Activity className="h-4 w-4" />
              <AlertTitle>All Clear</AlertTitle>
              <AlertDescription>No anomalies detected in the last 24 hours.</AlertDescription>
            </Alert>
          ) : (
            anomalies.map((anomaly) => (
              <motion.div
                key={anomaly.id}
                initial={{ opacity: 0, x: -20 }}
                animate={{ opacity: 1, x: 0 }}
                className="border-l-4 p-4 bg-gray-50 rounded-r-lg"
                style={{ borderLeftColor: anomaly.severity === 'critical' ? '#ef4444' : anomaly.severity === 'high' ? '#f97316' : '#eab308' }}
              >
                <div className="flex justify-between items-start">
                  <div>
                    <div className="flex items-center gap-2 mb-1">
                      <ShieldAlert className={`w-4 h-4 ${getSeverityColor(anomaly.severity)}`} />
                      <span className="font-semibold capitalize">{anomaly.type.replace('_', ' ')}</span>
                      <Badge className={getSeverityColor(anomaly.severity)}>{anomaly.severity.toUpperCase()}</Badge>
                    </div>
                    <p className="text-sm text-gray-600 mb-2">{anomaly.description}</p>
                    <div className="text-xs text-gray-500 space-x-3">
                      <span>Affected Users: <strong>{anomaly.affected_users}</strong></span>
                      <span>Confidence: <strong>{(anomaly.confidence_score * 100).toFixed(0)}%</strong></span>
                      <span>Detected: {new Date(anomaly.detected_at).toLocaleString()}</span>
                    </div>
                  </div>
                </div>
                <div className="mt-3 pt-3 border-t text-sm">
                  <span className="font-medium text-purple-700">Recommended action:</span> {anomaly.recommended_action}
                </div>
              </motion.div>
            ))
          )}
        </div>
      </CardContent>
    </Card>
  );
}

// ============================================================================
// PREDICTIVE ANALYTICS
// ============================================================================

export function PredictiveAnalytics() {
  const { data: predictions = [] } = useQuery<PredictiveMetric[]>({
    queryKey: ['predictions'],
    queryFn: () => apiV2.get('/ai/predictions').then(res => res.data),
  });

  const chartData = predictions.map(p => ({
    name: p.metric_name,
    Current: p.current_value,
    '7 Days': p.predicted_value_7d,
    '30 Days': p.predicted_value_30d,
  }));

  return (
    <Card className="w-full">
      <CardHeader>
        <CardTitle>
          <TrendingUp className="w-5 h-5 text-green-600" />
          Predictive Analytics
        </CardTitle>
      </CardHeader>
      <CardContent>
        <div className="h-[300px] w-full">
          <ResponsiveContainer width="100%" height="100%">
            <BarChart data={chartData}>
              <CartesianGrid strokeDasharray="3 3" />
              <XAxis dataKey="name" />
              <YAxis />
              <Tooltip />
              <Legend />
              <Bar dataKey="Current" fill="#3b82f6" />
              <Bar dataKey="7 Days" fill="#8b5cf6" />
              <Bar dataKey="30 Days" fill="#10b981" />
            </BarChart>
          </ResponsiveContainer>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mt-6">
          {predictions.map((pred) => (
            <div key={pred.metric_name} className="p-4 border rounded-lg">
              <div className="flex justify-between items-center mb-2">
                <h4 className="font-medium">{pred.metric_name}</h4>
                {pred.trend === 'up' ? (
                  <TrendingUp className="w-4 h-4 text-green-500" />
                ) : pred.trend === 'down' ? (
                  <TrendingDown className="w-4 h-4 text-red-500" />
                ) : (
                  <Activity className="w-4 h-4 text-gray-500" />
                )}
              </div>
              <div className="text-2xl font-bold">{pred.current_value.toLocaleString()}</div>
              <div className="text-sm text-gray-500 mt-1">
                Forecast (30d): <span className="font-medium text-purple-600">{pred.predicted_value_30d.toLocaleString()}</span>
              </div>
              <div className="text-xs text-gray-400 mt-1">
                Confidence: {pred.confidence_interval.lower.toFixed(0)} - {pred.confidence_interval.upper.toFixed(0)}
              </div>
            </div>
          ))}
        </div>
      </CardContent>
    </Card>
  );
}

// ============================================================================
// NATURAL LANGUAGE QUERY INTERFACE
// ============================================================================

export function NaturalLanguageQuery() {
  const [query, setQuery] = useState('');
  const [result, setResult] = useState<NLQResponse | null>(null);
  const [isLoading, setIsLoading] = useState(false);

  const handleQuery = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsLoading(true);
    try {
      const response = await apiV2.post('/ai/nlq', { query });
      setResult(response.data);
    } catch (error) {
      console.error(error);
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <Card className="w-full">
      <CardHeader>
        <CardTitle>
          <MessageSquare className="w-5 h-5 text-blue-600" />
          Ask Your Data (Natural Language)
        </CardTitle>
      </CardHeader>
      <CardContent>
        <form onSubmit={handleQuery} className="flex gap-2 mb-6">
          <Input
            value={query}
            onChange={(e: React.ChangeEvent<HTMLInputElement>) => setQuery(e.target.value)}
            placeholder="Try: 'Show me failed logins from yesterday' or 'How many new users this week?'"
            className="flex-1"
          />
          <Button type="submit" disabled={isLoading || !query}>
            {isLoading ? 'Thinking...' : 'Ask'}
          </Button>
        </form>

        {result && (
          <motion.div
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            className="space-y-4"
          >
            <Alert>
              <Bot className="h-4 w-4" />
              <AlertTitle>Explanation</AlertTitle>
              <AlertDescription>{result.explanation}</AlertDescription>
            </Alert>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div className="p-4 border rounded-lg bg-gray-50">
                <h4 className="font-mono text-sm font-bold mb-2">Generated SQL</h4>
                <pre className="text-xs overflow-x-auto text-blue-700">{result.sql_generated}</pre>
              </div>

              <div className="p-4 border rounded-lg bg-gray-50">
                <h4 className="font-bold mb-2">Results</h4>
                <pre className="text-xs overflow-x-auto">{JSON.stringify(result.data, null, 2)}</pre>
              </div>
            </div>

            {result.chart_suggestion && (
              <div className="text-center text-sm text-gray-500">
                Suggested Visualization: <Badge>{result.chart_suggestion}</Badge>
              </div>
            )}
          </motion.div>
        )}
      </CardContent>
    </Card>
  );
}

// ============================================================================
// ADVANCED AUDIT SEARCH BUILDER
// ============================================================================

export function AdvancedAuditSearch() {
  const [filters, setFilters] = useState({
    event_types: '',
    actor_id: '',
    ip_address: '',
    search_text: '',
    date_start: new Date(Date.now() - 7 * 24 * 60 * 60 * 1000).toISOString().split('T')[0],
    date_end: new Date().toISOString().split('T')[0],
  });

  const searchMutation = useMutation({
    mutationFn: (payload: {
      event_types?: string[];
      actor_id?: string;
      ip_address?: string;
      search_text?: string;
      date_start: string;
      date_end: string;
    }) => apiV2.post<AuditSearchResponse>('/audit-logs/search', payload).then(res => res.data),
  });

  /**
   * Run Search: compile the form fields into the AuditSearchFilter body the
   * backend expects (event_types as a list, ISO datetimes for the range)
   * and POST it to /admin/v2/audit-logs/search.
   */
  const runSearch = () => {
    const eventTypes = filters.event_types
      .split(',')
      .map(s => s.trim())
      .filter(Boolean);
    searchMutation.mutate({
      event_types: eventTypes.length > 0 ? eventTypes : undefined,
      actor_id: filters.actor_id.trim() || undefined,
      ip_address: filters.ip_address.trim() || undefined,
      search_text: filters.search_text.trim() || undefined,
      date_start: new Date(`${filters.date_start}T00:00:00Z`).toISOString(),
      date_end: new Date(`${filters.date_end}T23:59:59Z`).toISOString(),
    });
  };

  const data = searchMutation.data;

  return (
    <Card className="w-full">
      <CardHeader>
        <CardTitle>
          <Search className="w-5 h-5" />
          Advanced Audit Log Search
        </CardTitle>
      </CardHeader>
      <CardContent>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-6">
          <Input
            placeholder="Event Types (comma-separated, e.g. login.failed)"
            value={filters.event_types}
            onChange={(e: React.ChangeEvent<HTMLInputElement>) => setFilters({...filters, event_types: e.target.value})}
          />
          <Input
            placeholder="Actor ID / Email"
            value={filters.actor_id}
            onChange={(e: React.ChangeEvent<HTMLInputElement>) => setFilters({...filters, actor_id: e.target.value})}
          />
          <Input
            placeholder="IP Address"
            value={filters.ip_address}
            onChange={(e: React.ChangeEvent<HTMLInputElement>) => setFilters({...filters, ip_address: e.target.value})}
          />
          <Input
            type="date"
            aria-label="Start date"
            value={filters.date_start}
            onChange={(e: React.ChangeEvent<HTMLInputElement>) => setFilters({...filters, date_start: e.target.value})}
          />
          <Input
            type="date"
            aria-label="End date"
            value={filters.date_end}
            onChange={(e: React.ChangeEvent<HTMLInputElement>) => setFilters({...filters, date_end: e.target.value})}
          />
          <Input
            placeholder="Free text search..."
            value={filters.search_text}
            onChange={(e: React.ChangeEvent<HTMLInputElement>) => setFilters({...filters, search_text: e.target.value})}
          />
        </div>

        <Button onClick={runSearch} disabled={searchMutation.isPending} className="w-full mb-6">
          {searchMutation.isPending ? 'Searching...' : 'Run Search'}
        </Button>

        {searchMutation.isError && (
          <Alert role="alert" className="mb-4 border-red-200 bg-red-50 text-red-700">
            <AlertTitle>Search failed</AlertTitle>
            <AlertDescription>The audit search endpoint returned an error. Adjust the filters and try again.</AlertDescription>
          </Alert>
        )}

        {data && (
          <div>
            <div className="flex justify-between mb-4">
              <span className="font-bold">Found {data.total} results</span>
            </div>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>ID</TableHead>
                  <TableHead>Event</TableHead>
                  <TableHead>Actor</TableHead>
                  <TableHead>IP</TableHead>
                  <TableHead>Timestamp</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {data.results?.map((log: AuditSearchRow) => (
                  <TableRow key={log.id}>
                    <TableCell>#{log.id}</TableCell>
                    <TableCell><Badge>{log.event}</Badge></TableCell>
                    <TableCell>{log.actor ?? '—'}</TableCell>
                    <TableCell className="font-mono text-xs">{log.ip ?? '—'}</TableCell>
                    <TableCell>{new Date(log.timestamp).toLocaleString()}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        )}
      </CardContent>
    </Card>
  );
}

// ============================================================================
// PAGE COMPOSITION + EXPORTS
// ============================================================================

/** Reachable at /enterprise in the dashboard router. */
export function EnterprisePage() {
  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-gray-900">Enterprise Features</h1>
        <p className="text-sm text-gray-500 mt-1">
          API keys, branding, advanced audit search and security analytics — served by the admin API v2.
        </p>
      </div>
      <div className="grid grid-cols-1 xl:grid-cols-2 gap-6 items-start">
        <ApiKeyManager />
        <BrandingConfigurator />
        <AdvancedAuditSearch />
        <AIAnomalyDashboard />
        <PredictiveAnalytics />
        <NaturalLanguageQuery />
      </div>
    </div>
  );
}

// Main export for easy import
export const EnterpriseFeatures = {
  ApiKeyManager,
  BrandingConfigurator,
  AIAnomalyDashboard,
  PredictiveAnalytics,
  NaturalLanguageQuery,
  AdvancedAuditSearch,
  EnterprisePage,
};
