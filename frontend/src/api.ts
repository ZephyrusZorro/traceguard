import type {
  BenchmarkReport,
  CapabilityPolicy,
  CounterfactualReplay,
  ScenarioItem,
  TraceDetail,
  TraceSummary,
} from './types';

const ADMIN_KEY = 'tg-admin-local-dev-key';

async function request<T>(path: string, init?: RequestInit, useAdmin = false): Promise<T> {
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    ...(useAdmin ? { 'X-API-Key': ADMIN_KEY } : {}),
    ...(init?.headers as Record<string, string> | undefined),
  };
  const res = await fetch(path, { ...init, headers });
  if (!res.ok) {
    const text = await res.text();
    throw new Error(`HTTP ${res.status}: ${text}`);
  }
  return res.json() as Promise<T>;
}

export const api = {
  health: () => request<{ status: string; version: string; stats: Record<string, number> }>('/api/v1/health'),
  listTraces: () => request<TraceSummary[]>('/api/v1/traces'),
  getTrace: (id: string) => request<TraceDetail>(`/api/v1/traces/${id}`),
  listScenarios: () => request<ScenarioItem[]>('/api/v1/scenarios'),
  runScenario: (scenario_key: string, inject_controlled_failure = false) =>
    request<{ trace_id: string }>('/api/v1/scenarios/run', {
      method: 'POST',
      body: JSON.stringify({ scenario_key, inject_controlled_failure, use_ollama: false }),
    }),
  runCounterfactual: (
    traceId: string,
    intervention_step_index: number,
    intervention_type: string,
    patched_content?: string,
  ) =>
    request<CounterfactualReplay>(`/api/v1/traces/${traceId}/counterfactual`, {
      method: 'POST',
      body: JSON.stringify({
        intervention_step_index,
        intervention_type,
        patched_content: patched_content || null,
      }),
    }),
  redteamTest: (payload: string, target_tool: string, contains_secret_in_context: boolean) =>
    request<{
      decision: 'ALLOW' | 'BLOCK';
      injection_probability: number;
      taint_active: boolean;
      is_external_sink: boolean;
      capability_rule_triggered: string;
      reasons: string[];
    }>('/api/v1/security/redteam', {
      method: 'POST',
      body: JSON.stringify({
        payload,
        source_provenance: 'UNTRUSTED_TOOL',
        target_tool,
        contains_secret_in_context,
      }),
    }),
  listPolicies: () => request<CapabilityPolicy[]>('/api/v1/policies'),
  approvePolicy: (id: string) => request<CapabilityPolicy>(`/api/v1/policies/${id}/approve`, { method: 'POST' }, true),
  disablePolicy: (id: string) => request<CapabilityPolicy>(`/api/v1/policies/${id}/disable`, { method: 'POST' }, true),
  getBenchmarks: () => request<BenchmarkReport>('/api/v1/benchmarks'),
  rerunBenchmarks: () => request<BenchmarkReport>('/api/v1/benchmarks/run', { method: 'POST' }),
  listWebhooks: () =>
    request<{ endpoints: Array<Record<string, unknown>>; deliveries: Array<Record<string, unknown>>; mock_inbox_count: number }>('/api/v1/webhooks'),
  registerWebhook: (target_url: string, min_severity: string) =>
    request<Record<string, unknown>>(
      '/api/v1/webhooks',
      {
        method: 'POST',
        body: JSON.stringify({
          target_url,
          events: ['diagnosis.completed', 'security.alert'],
          min_severity,
        }),
      },
      true,
    ),
  recentEvents: () => request<Array<{ event_type: string; timestamp: string; payload: Record<string, unknown> }>>('/api/v1/events/recent'),
  auditLogs: () => request<Array<{ id: string; actor: string; action: string; resource_type: string; resource_id: string; created_at: string }>>('/api/v1/audit-logs'),
};
