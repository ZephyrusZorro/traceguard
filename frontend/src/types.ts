export interface TraceSummary {
  id: string;
  external_trace_id: string;
  scenario_name: string;
  framework: string;
  status: 'PASSED' | 'FAILED' | 'COMPROMISED';
  root_goal: string;
  total_tokens: number;
  total_latency_ms: number;
  span_count: number;
  attributed_agent: string | null;
  attributed_step_index: number | null;
  mast_mode: string | null;
  confidence: number | null;
  causal_verification_score: number | null;
  security_verdict: string | null;
  contradiction_detected: number | null;
  created_at: string;
}

export interface SpanRecord {
  id: string;
  span_id: string;
  step_index: number;
  parent_span_id: string | null;
  agent_name: string;
  operation_name: string;
  tool_name: string | null;
  input_text: string;
  output_text: string;
  provenance: string;
  latency_ms: number;
  tokens_in: number;
  tokens_out: number;
  status: string;
  attributes: Record<string, unknown>;
}

export interface StepScore {
  step_index: number;
  span_id: string;
  agent_name: string;
  ml_fault_prob: number;
  rule_signal_score: number;
  injection_prob: number;
  counterfactual_delta: number | null;
  combined_c3_score: number;
  tainted: boolean;
  key_signals: string[];
}

export interface AgentReport {
  agent_name: string;
  status: 'SUCCESS' | 'DEGRADED' | 'FAILED' | 'TIMEOUT';
  duration_ms: number;
  confidence: number;
  findings: Record<string, unknown>;
  warnings: string[];
}

export interface SecurityViolation {
  step_index: number;
  agent_name: string;
  rule_id: string;
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  injection_probability: number;
  taint_sources: string[];
  sink_tool: string | null;
  explanation: string;
}

export interface CounterfactualReplay {
  id: string;
  trace_id: string;
  intervention_step_index: number;
  intervention_type: string;
  patched_content: string;
  original_outcome: string;
  counterfactual_outcome: string;
  causal_flip: boolean;
  delta_score: number;
  downstream_recovered_steps: number;
  replayed_spans: Array<{
    step_index: number;
    agent_name: string;
    tool_name: string | null;
    original_status: string;
    replayed_status: string;
    changed: boolean;
    note: string;
  }>;
  created_at: string;
}

export interface Diagnosis {
  id: string;
  trace_id: string;
  council_run_id: string;
  attributed_agent: string;
  attributed_step_index: number;
  mast_pillar: string;
  mast_mode: string;
  confidence: number;
  causal_verification_score: number;
  contradiction_detected: boolean;
  contradiction_note: string | null;
  security_verdict: string;
  security_violations: SecurityViolation[];
  summary: string;
  step_scores: StepScore[];
  agent_reports: AgentReport[];
  causal_graph: {
    nodes: Array<{
      id: number;
      span_id: string;
      agent: string;
      tool: string | null;
      status: string;
      provenance: string;
      tainted: boolean;
      injection_prob: number;
      downstream_errors: number;
    }>;
    edges: Array<{
      source: number;
      target: number;
      edge_type: string;
    }>;
  };
  counterfactual: CounterfactualReplay | null;
  created_at: string;
}

export interface TraceDetail {
  trace: TraceSummary;
  spans: SpanRecord[];
  latest_diagnosis: Diagnosis | null;
  replays: CounterfactualReplay[];
}

export interface CapabilityPolicy {
  id: string;
  name: string;
  description: string;
  rule: Record<string, unknown>;
  status: 'PENDING_APPROVAL' | 'ACTIVE' | 'DISABLED';
  created_by: string;
  approved_by: string | null;
  created_at: string;
}

export interface ScenarioItem {
  key: string;
  title: string;
  topology: string;
  mode: string;
  description: string;
}

export interface BenchmarkReport {
  seed: number;
  trace_benchmark: {
    total_traces: number;
    train_traces: number;
    val_traces: number;
    test_traces: number;
    feature_count: number;
    methods: Array<{
      method: string;
      top1_step_accuracy: number;
      top3_step_accuracy: number;
      agent_attribution_accuracy: number;
      mrr: number;
      ece: number;
      mean_latency_ms: number;
    }>;
    c3_mast_macro_f1: number;
    c3_counterfactual_recovery_rate: number;
    c3_per_mode_top1_accuracy: Record<string, number>;
  };
  injection_benchmark: {
    dataset_sizes: Record<string, number>;
    val: Record<string, number>;
    test: Record<string, number>;
    keyword_baseline_test: Record<string, number>;
  };
}
