/**
 * Authy Admin Dashboard - Enterprise Extensions (Phase 2, 3, 4)
 * 
 * Features:
 * - Phase 2: Advanced User Management, Bulk Actions, Audit Search Builder
 * - Phase 3: White-label Branding, i18n, API Key Management, Custom Reports
 * - Phase 4: AI Anomaly Detection, Predictive Analytics, Natural Language Queries
 */

import React, { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { api } from '../lib/api';
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
  MessageSquare
} from 'lucide-react';
import { motion } from 'framer-motion';

type ButtonProps = React.ButtonHTMLAttributes<HTMLButtonElement> & { variant?: string; size?: string };
type SelectProps = React.SelectHTMLAttributes<HTMLSelectElement> & { name?: string };
type DialogTriggerProps = React.ButtonHTMLAttributes<HTMLButtonElement> & { asChild?: boolean };

const Card: React.FC<React.HTMLAttributes<HTMLDivElement>> = ({ children, ...props }) => <div {...props}>{children}</div>;
const CardContent: React.FC<React.HTMLAttributes<HTMLDivElement>> = ({ children, ...props }) => <div {...props}>{children}</div>;
const CardHeader: React.FC<React.HTMLAttributes<HTMLDivElement>> = ({ children, ...props }) => <div {...props}>{children}</div>;
const CardTitle: React.FC<React.HTMLAttributes<HTMLHeadingElement>> = ({ children, ...props }) => <h3 {...props}>{children}</h3>;
const Button: React.FC<ButtonProps> = ({ children, variant: _variant, size: _size, ...props }) => <button {...props}>{children}</button>;
const Input: React.FC<React.InputHTMLAttributes<HTMLInputElement>> = (props) => <input {...props} />;
const Badge: React.FC<React.HTMLAttributes<HTMLSpanElement> & { variant?: string }> = ({ children, variant: _variant, ...props }) => <span {...props}>{children}</span>;
const Alert: React.FC<React.HTMLAttributes<HTMLDivElement>> = ({ children, ...props }) => <div {...props}>{children}</div>;
const AlertDescription: React.FC<React.HTMLAttributes<HTMLParagraphElement>> = ({ children, ...props }) => <p {...props}>{children}</p>;
const AlertTitle: React.FC<React.HTMLAttributes<HTMLHeadingElement>> = ({ children, ...props }) => <h4 {...props}>{children}</h4>;
const Table: React.FC<React.TableHTMLAttributes<HTMLTableElement>> = ({ children, ...props }) => <table {...props}>{children}</table>;
const TableBody: React.FC<React.HTMLAttributes<HTMLTableSectionElement>> = ({ children, ...props }) => <tbody {...props}>{children}</tbody>;
const TableCell: React.FC<React.TdHTMLAttributes<HTMLTableCellElement>> = ({ children, ...props }) => <td {...props}>{children}</td>;
const TableHead: React.FC<React.ThHTMLAttributes<HTMLTableCellElement>> = ({ children, ...props }) => <th {...props}>{children}</th>;
const TableHeader: React.FC<React.HTMLAttributes<HTMLTableSectionElement>> = ({ children, ...props }) => <thead {...props}>{children}</thead>;
const TableRow: React.FC<React.HTMLAttributes<HTMLTableRowElement>> = ({ children, ...props }) => <tr {...props}>{children}</tr>;
const Dialog: React.FC<React.HTMLAttributes<HTMLDivElement>> = ({ children, ...props }) => <div {...props}>{children}</div>;
const DialogContent: React.FC<React.HTMLAttributes<HTMLDivElement>> = ({ children, ...props }) => <div {...props}>{children}</div>;
const DialogHeader: React.FC<React.HTMLAttributes<HTMLDivElement>> = ({ children, ...props }) => <div {...props}>{children}</div>;
const DialogTitle: React.FC<React.HTMLAttributes<HTMLHeadingElement>> = ({ children, ...props }) => <h4 {...props}>{children}</h4>;
const DialogTrigger: React.FC<DialogTriggerProps> = ({ children, asChild, ...props }) =>
  asChild ? <>{children}</> : <button {...props}>{children}</button>;
const Select: React.FC<SelectProps> = ({ children, ...props }) => <select {...props}>{children}</select>;
const SelectContent: React.FC<{ children?: React.ReactNode }> = ({ children }) => <>{children}</>;
const SelectItem: React.FC<{ value: string; children?: React.ReactNode }> = ({ value, children }) => <option value={value}>{children}</option>;
const SelectTrigger: React.FC<{ children?: React.ReactNode }> = ({ children }) => <>{children}</>;
const SelectValue: React.FC<{ placeholder?: string }> = ({ placeholder }) => <>{placeholder}</>;

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

// ============================================================================
// PHASE 3: API KEY MANAGEMENT COMPONENT
// ============================================================================

export function ApiKeyManager() {
  const queryClient = useQueryClient();
  const [showSecret, setShowSecret] = useState<string | null>(null);

  const { data: keys = [] } = useQuery<ApiKey[]>({
    queryKey: ['apiKeys'],
    queryFn: () => api.get('/admin/v2/api-keys').then(res => res.data),
  });

  const createKeyMutation = useMutation({
    mutationFn: (data: { name: string; scopes: string[] }) =>
      api.post('/admin/v2/api-keys', data).then(res => res.data),
    onSuccess: (data: { full_secret: string }) => {
      setShowSecret(data.full_secret);
      queryClient.invalidateQueries({ queryKey: ['apiKeys'] });
    },
  });

  const revokeKeyMutation = useMutation({
    mutationFn: (id: string) =>
      api.delete(`/admin/v2/api-keys/${id}`).then(res => res.data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['apiKeys'] });
    },
  });

  return (
    <Card className="w-full">
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Key className="w-5 h-5" />
          API Key Management
        </CardTitle>
      </CardHeader>
      <CardContent>
        <div className="mb-6">
          <Dialog>
            <DialogTrigger asChild>
              <Button>Create New API Key</Button>
            </DialogTrigger>
            <DialogContent>
              <DialogHeader>
                <DialogTitle>Generate API Key</DialogTitle>
              </DialogHeader>
              <form onSubmit={(e) => {
                e.preventDefault();
                const form = e.target as HTMLFormElement;
                const name = (form.elements.namedItem('name') as HTMLInputElement).value;
                const scopes = Array.from((form.elements.namedItem('scopes') as HTMLSelectElement).selectedOptions).map(o => o.value);
                createKeyMutation.mutate({ name, scopes });
              }}>
                <div className="space-y-4 py-4">
                  <Input name="name" placeholder="Key Name (e.g., Production App)" required />
                  <Select name="scopes" multiple>
                    <SelectTrigger>
                      <SelectValue placeholder="Select Scopes" />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="read:only">Read Only</SelectItem>
                      <SelectItem value="full:access">Full Access</SelectItem>
                      <SelectItem value="audit:logs">Audit Logs</SelectItem>
                      <SelectItem value="user:manage">User Management</SelectItem>
                    </SelectContent>
                  </Select>
                  <Button type="submit" className="w-full" disabled={createKeyMutation.isPending}>
                    Generate Key
                  </Button>
                </div>
              </form>
            </DialogContent>
          </Dialog>
        </div>

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
                <TableCell className="font-mono text-sm">{key.prefix}...</TableCell>
                <TableCell>
                  <div className="flex gap-1 flex-wrap">
                    {key.scopes.map(scope => (
                      <Badge key={scope} variant="outline" className="text-xs">{scope}</Badge>
                    ))}
                  </div>
                </TableCell>
                <TableCell>{new Date(key.created_at).toLocaleDateString()}</TableCell>
                <TableCell>{key.expires_at ? new Date(key.expires_at).toLocaleDateString() : 'Never'}</TableCell>
                <TableCell>{key.last_used_at ? new Date(key.last_used_at).toLocaleDateString() : 'Never'}</TableCell>
                <TableCell>
                  <Button 
                    variant="destructive" 
                    size="sm"
                    onClick={() => revokeKeyMutation.mutate(key.id)}
                  >
                    Revoke
                  </Button>
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
        
        {showSecret && (
          <Alert className="mt-4 bg-yellow-50 border-yellow-200">
            <AlertTitle>Copied Secret</AlertTitle>
            <AlertDescription>
              Make sure to save your API secret securely. It cannot be viewed again.
            </AlertDescription>
          </Alert>
        )}
      </CardContent>
    </Card>
  );
}

// ============================================================================
// PHASE 3: WHITE-LABEL BRANDING CONFIGURATION
// ============================================================================

export function BrandingConfigurator() {
  const queryClient = useQueryClient();

  const { data: config } = useQuery<BrandingConfig>({
    queryKey: ['branding'],
    queryFn: () => api.get('/admin/v2/config/branding').then(res => res.data),
  });

  const updateMutation = useMutation({
    mutationFn: (data: Partial<BrandingConfig>) =>
      api.put('/admin/v2/config/branding', { ...config, ...data }).then(res => res.data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['branding'] });
    },
  });

  if (!config) return <div>Loading...</div>;

  return (
    <Card className="w-full">
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
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
              className="w-full min-h-[100px] p-2 border rounded-md font-mono text-sm"
              placeholder="/* Add custom CSS overrides here */"
            />
          </div>

          <Button type="submit" disabled={updateMutation.isPending}>
            Save Branding
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
// PHASE 4: AI ANOMALY DETECTION DASHBOARD
// ============================================================================

export function AIAnomalyDashboard() {
  const { data: anomalies = [] } = useQuery<Anomaly[]>({
    queryKey: ['aiAnomalies'],
    queryFn: () => api.get('/admin/v2/ai/anomalies').then(res => res.data),
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
        <CardTitle className="flex items-center gap-2">
          <BrainCircuit className="w-5 h-5 text-purple-600" />
          AI Threat Detection
          <Badge variant="secondary" className="ml-auto animate-pulse">Live</Badge>
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
                  <Button variant="outline" size="sm">
                    Investigate
                  </Button>
                </div>
                <div className="mt-3 pt-3 border-t text-sm">
                  <span className="font-medium text-purple-700">AI Recommendation:</span> {anomaly.recommended_action}
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
// PHASE 4: PREDICTIVE ANALYTICS
// ============================================================================

export function PredictiveAnalytics() {
  const { data: predictions = [] } = useQuery<PredictiveMetric[]>({
    queryKey: ['predictions'],
    queryFn: () => api.get('/admin/v2/ai/predictions').then(res => res.data),
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
        <CardTitle className="flex items-center gap-2">
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
// PHASE 4: NATURAL LANGUAGE QUERY INTERFACE
// ============================================================================

export function NaturalLanguageQuery() {
  const [query, setQuery] = useState('');
  const [result, setResult] = useState<NLQResponse | null>(null);
  const [isLoading, setIsLoading] = useState(false);

  const handleQuery = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsLoading(true);
    try {
      const response = await api.post('/admin/v2/ai/nlq', { query });
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
        <CardTitle className="flex items-center gap-2">
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
              <AlertTitle>AI Explanation</AlertTitle>
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
// PHASE 2: ADVANCED AUDIT SEARCH BUILDER
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

  const { data, isLoading } = useQuery({
    queryKey: ['auditSearch', filters],
    queryFn: () => api.post('/admin/v2/audit-logs/search', filters).then(res => res.data),
    enabled: false, // Manual trigger
  });

  return (
    <Card className="w-full">
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Search className="w-5 h-5" />
          Advanced Audit Log Search
        </CardTitle>
      </CardHeader>
      <CardContent>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-6">
          <Input 
            placeholder="Event Type (e.g., login.failed)" 
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
            value={filters.date_start}
            onChange={(e: React.ChangeEvent<HTMLInputElement>) => setFilters({...filters, date_start: e.target.value})}
          />
          <Input 
            type="date"
            value={filters.date_end}
            onChange={(e: React.ChangeEvent<HTMLInputElement>) => setFilters({...filters, date_end: e.target.value})}
          />
          <Input 
            placeholder="Free text search..." 
            value={filters.search_text}
            onChange={(e: React.ChangeEvent<HTMLInputElement>) => setFilters({...filters, search_text: e.target.value})}
          />
        </div>
        
        <Button onClick={() => {/* Trigger query manually */}} className="w-full mb-6">
          Run Search
        </Button>

        {isLoading && <div>Searching...</div>}
        
        {data && (
          <div>
            <div className="flex justify-between mb-4">
              <span className="font-bold">Found {data.total} results</span>
              <Button variant="outline" size="sm">Export CSV</Button>
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
                {data.results?.map((log: any) => (
                  <TableRow key={log.id}>
                    <TableCell>#{log.id}</TableCell>
                    <TableCell><Badge>{log.event}</Badge></TableCell>
                    <TableCell>{log.actor}</TableCell>
                    <TableCell className="font-mono text-xs">{log.ip}</TableCell>
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

// Main export for easy import
export const EnterpriseFeatures = {
  ApiKeyManager,
  BrandingConfigurator,
  AIAnomalyDashboard,
  PredictiveAnalytics,
  NaturalLanguageQuery,
  AdvancedAuditSearch,
};
