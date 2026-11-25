import { useCallback, useEffect, useState } from 'react';
import {
  Activity,
  AlertOctagon,
  BarChart3,
  Cpu,
  GitBranch,
  Play,
  Radio,
  Shield,
  Webhook,
  CheckCircle2,
  AlertTriangle,
} from 'lucide-react';
import { api } from './api';
import { BenchmarkLab } from './components/BenchmarkLab';
import { CausalGraphView } from './components/CausalGraphView';
import { CounterfactualLab } from './components/CounterfactualLab';
import { SecurityFirewall } from './components/SecurityFirewall';
import { TraceWaterfall } from './components/TraceWaterfall';
import type {
  BenchmarkReport,
  CapabilityPolicy,
  ScenarioItem,
  TraceDetail,
  TraceSummary,
} from './types';

type Tab = 'forensics' | 'counterfactual' | 'firewall' | 'benchmarks' | 'automation';

export default function App() {
  const [tab, setTab] = useState<Tab>('forensics');
  const [traces, setTraces] = useState<TraceSummary[]>([]);
  const [selectedTraceId, setSelectedTraceId] = useState<string | null>(null);
  const [detail, setDetail] = useState<TraceDetail | null>(null);
  const [selectedStep, setSelectedStep] = useState<number>(0);
  const [scenarios, setScenarios] = useState<ScenarioItem[]>([]);
  const [scenarioKey, setScenarioKey] = useState<string>('ebanking_prompt_injection');
  const [injectFault, setInjectFault] = useState<boolean>(false);
  const [runningScenario, setRunningScenario] = useState<boolean>(false);
  const [policies, setPolicies] = useState<CapabilityPolicy[]>([]);
  const [benchmark, setBenchmark] = useState<BenchmarkReport | null>(null);
  const [wsConnected, setWsConnected] = useState<boolean>(false);
  const [liveEvents, setLiveEvents] = useState<Array<{ event_type: string; timestamp: string; payload: Record<string, unknown> }>>([]);
  const [webhooks, setWebhooks] = useState<{ endpoints: Array<Record<string, unknown>>; deliveries: Array<Record<string, unknown>>; mock_inbox_count: number }>({
    endpoints: [],
    deliveries: [],
    mock_inbox_count: 0,
  });
  const [newWebhookUrl, setNewWebhookUrl] = useState('http://127.0.0.1:8000/api/v1/webhooks/mock-receiver');
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  const loadCore = useCallback(async () => {
    try {
      const [tr, sc, pol, ev, wh] = await Promise.all([
        api.listTraces(),
        api.listScenarios(),
        api.listPolicies(),
        api.recentEvents(),
        api.listWebhooks(),
      ]);
      setTraces(tr);
      setScenarios(sc);
      setPolicies(pol);
      setLiveEvents(ev);
      setWebhooks(wh);
      if (!selectedTraceId && tr.length > 0) {
        setSelectedTraceId(tr[0].id);
      }
      setErrorMsg(null);
    } catch (e) {
      setErrorMsg(e instanceof Error ? e.message : 'Failed to connect to TraceGuard API');
    }
  }, [selectedTraceId]);

  const loadTraceDetail = useCallback(async (id: string) => {
    try {
      const d = await api.getTrace(id);
      setDetail(d);
      const rootStep = d.latest_diagnosis?.attributed_step_index ?? 0;
      setSelectedStep(rootStep >= 0 ? rootStep : 0);
    } catch (e) {
      setErrorMsg(e instanceof Error ? e.message : 'Failed to load trace detail');
    }
  }, []);

  useEffect(() => {
    void loadCore();
    void api.getBenchmarks().then(setBenchmark).catch(() => {});
  }, [loadCore]);

  useEffect(() => {
    if (selectedTraceId) {
      void loadTraceDetail(selectedTraceId);
    }
  }, [selectedTraceId, loadTraceDetail]);

  // Live WebSocket subscription
  useEffect(() => {
    const proto = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const ws = new WebSocket(`${proto}//${window.location.host}/ws/events`);
    ws.onopen = () => setWsConnected(true);
    ws.onclose = () => setWsConnected(false);
    ws.onmessage = (evt) => {
      try {
        const msg = JSON.parse(evt.data);
        if (msg.event_type && msg.event_type !== 'connection.ready') {
          setLiveEvents((prev) => [msg, ...prev].slice(0, 40));
        }
      } catch {
        // ignore malformed frame
      }
    };
    return () => ws.close();
  }, []);

  async function handleRunScenario() {
    setRunningScenario(true);
    try {
      const res = await api.runScenario(scenarioKey, injectFault);
      await loadCore();
      setSelectedTraceId(res.trace_id);
      await loadTraceDetail(res.trace_id);
    } catch (e) {
      setErrorMsg(e instanceof Error ? e.message : 'Scenario execution failed');
    } finally {
      setRunningScenario(false);
    }
  }

  async function handleRegisterWebhook() {
    if (!newWebhookUrl.trim()) return;
    await api.registerWebhook(newWebhookUrl.trim(), 'HIGH');
    const wh = await api.listWebhooks();
    setWebhooks(wh);
  }

  const diag = detail?.latest_diagnosis;
  const pendingPolicies = policies.filter((p) => p.status === 'PENDING_APPROVAL').length;

  return (
    <div className="min-h-screen bg-[#090B10] text-[#E6E9F0] flex flex-col">
      {/* Top Operational Bar */}
      <header className="h-14 border-b border-[#1B2230] bg-[#0C0F17] px-5 flex items-center justify-between gap-4 sticky top-0 z-20">
        <div className="flex items-center gap-3">
          <div className="w-7 h-7 rounded bg-amber-500/15 border border-amber-500/40 flex items-center justify-center">
            <Shield className="w-4 h-4 text-amber-400" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className="font-semibold tracking-tight text-sm text-slate-100">TRACEGUARD</span>
              <span className="font-mono text-[10px] px-1.5 py-0.5 rounded bg-[#161D2C] text-slate-400 border border-[#232D42]">
                C³-ATTRIBUTOR v1.0
              </span>
            </div>
            <p className="text-[11px] text-slate-500 hidden sm:block">
              Causal Multi-Agent Failure Attribution · CaMeL Capability Firewall · Counterfactual Replay
            </p>
          </div>
        </div>

        {/* Live Scenario Launcher */}
        <div className="flex items-center gap-2">
          <select
            aria-label="Select multi-agent scenario"
            value={scenarioKey}
            onChange={(e) => setScenarioKey(e.target.value)}
            className="rounded bg-[#10141D] border border-[#232C3F] px-2.5 h-8 text-xs text-slate-200 max-w-[230px] truncate"
          >
            {scenarios.map((s) => (
              <option key={s.key} value={s.key}>{s.title}</option>
            ))}
          </select>
          <label className="hidden md:flex items-center gap-1.5 text-[11px] font-mono text-slate-400 px-2 cursor-pointer" title="Inject controlled verifier timeout to test fault recovery">
            <input
              type="checkbox"
              checked={injectFault}
              onChange={(e) => setInjectFault(e.target.checked)}
              className="accent-amber-500"
            />
            Fault-Inject
          </label>
          <button
            type="button"
            onClick={handleRunScenario}
            disabled={runningScenario}
            className="inline-flex items-center gap-1.5 rounded bg-amber-500 hover:bg-amber-400 disabled:opacity-50 text-slate-950 font-semibold text-xs px-3 py-1.5 transition-colors"
          >
            <Play className="w-3.5 h-3.5" />
            {runningScenario ? 'Running...' : 'Run Trace'}
          </button>
          <div className="hidden lg:flex items-center gap-1.5 pl-2 text-[11px] font-mono text-slate-400">
            <Radio className={`w-3.5 h-3.5 ${wsConnected ? 'text-emerald-400' : 'text-slate-600'}`} />
            {wsConnected ? 'LIVE' : 'OFFLINE'}
          </div>
        </div>
      </header>

      {errorMsg && (
        <div className="bg-red-500/15 border-b border-red-500/40 px-5 py-2 text-xs font-mono text-red-300">
          {errorMsg}
        </div>
      )}

      {/* Navigation Tabs */}
      <nav className="border-b border-[#1B2230] bg-[#0B0E16] px-5 flex items-center gap-1 overflow-x-auto">
        {(
          [
            { id: 'forensics', label: 'Trace Forensics', icon: Activity },
            { id: 'counterfactual', label: 'Counterfactual Replay', icon: GitBranch },
            { id: 'firewall', label: `Capability Firewall${pendingPolicies ? ` (${pendingPolicies})` : ''}`, icon: Shield },
            { id: 'benchmarks', label: 'ML Evaluation Lab', icon: BarChart3 },
            { id: 'automation', label: 'Automation & Stream', icon: Webhook },
          ] as const
        ).map((item) => {
          const Icon = item.icon;
          const active = tab === item.id;
          return (
            <button
              key={item.id}
              type="button"
              onClick={() => setTab(item.id)}
              className={`inline-flex items-center gap-2 px-3.5 py-2.5 text-xs font-medium border-b-2 transition-colors whitespace-nowrap ${
                active
                  ? 'border-amber-400 text-amber-300'
                  : 'border-transparent text-slate-400 hover:text-slate-200'
              }`}
            >
              <Icon className="w-3.5 h-3.5" />
              {item.label}
            </button>
          );
        })}
      </nav>

      {/* Main Workspace */}
      <main className="flex-1 p-5 max-w-[1600px] w-full mx-auto">
        {(tab === 'forensics' || tab === 'counterfactual') && (
          <div className="grid grid-cols-1 lg:grid-cols-12 gap-5">
            {/* Left Trace List */}
            <aside className="lg:col-span-3 space-y-2">
              <div className="flex items-center justify-between text-[11px] font-mono text-slate-500 px-1">
                <span>INGESTED OTEL TRACES</span>
                <span>{traces.length}</span>
              </div>
              <div className="space-y-1.5 max-h-[calc(100vh-190px)] overflow-y-auto pr-1">
                {traces.map((t) => {
                  const active = t.id === selectedTraceId;
                  return (
                    <button
                      key={t.id}
                      type="button"
                      onClick={() => setSelectedTraceId(t.id)}
                      className={`w-full text-left rounded-lg border p-3 transition-colors space-y-1.5 ${
                        active
                          ? 'bg-[#151C2B] border-amber-500/50'
                          : 'bg-[#10141D] border-[#1B2230] hover:border-[#2A354D]'
                      }`}
                    >
                      <div className="flex items-center justify-between gap-2">
                        <span
                          className={`px-1.5 py-0.5 rounded text-[10px] font-mono font-semibold ${
                            t.status === 'COMPROMISED'
                              ? 'bg-red-500/20 text-red-300'
                              : t.status === 'FAILED'
                                ? 'bg-amber-500/20 text-amber-300'
                                : 'bg-emerald-500/15 text-emerald-300'
                          }`}
                        >
                          {t.status}
                        </span>
                        <span className="font-mono text-[10px] text-slate-500">{t.span_count} spans</span>
                      </div>
                      <div className="text-xs font-medium text-slate-100 line-clamp-2">{t.scenario_name}</div>
                      <div className="text-[11px] font-mono text-slate-400 truncate">
                        {t.attributed_agent && t.attributed_agent !== 'NONE'
                          ? `↳ ${t.attributed_agent} · step #${t.attributed_step_index}`
                          : '↳ Healthy execution'}
                      </div>
                    </button>
                  );
                })}
              </div>
            </aside>

            {/* Right Forensic Detail */}
            <section className="lg:col-span-9 space-y-4">
              {detail && diag && (
                <>
                  {/* Executive Attribution Banner */}
                  <div className="rounded-lg border border-[#1B2230] bg-[#10141D] p-4 space-y-3">
                    <div className="flex flex-wrap items-start justify-between gap-3">
                      <div>
                        <div className="flex items-center gap-2">
                          <h2 className="text-base font-semibold text-slate-100">{detail.trace.scenario_name}</h2>
                          <span className="font-mono text-[11px] text-slate-500">{detail.trace.id}</span>
                        </div>
                        <p className="text-xs text-slate-400 mt-0.5">Goal: {detail.trace.root_goal}</p>
                      </div>
                      <div className="flex flex-wrap items-center gap-2 font-mono text-xs">
                        <span className="px-2.5 py-1 rounded bg-[#0A0D14] border border-[#232C3F] text-amber-300">
                          {diag.mast_mode}
                        </span>
                        <span
                          className={`px-2.5 py-1 rounded border ${
                            diag.security_verdict === 'COMPROMISED'
                              ? 'bg-red-500/15 border-red-500/40 text-red-300'
                              : diag.security_verdict === 'CLEAN'
                                ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-300'
                                : 'bg-amber-500/10 border-amber-500/30 text-amber-300'
                          }`}
                        >
                          SEC: {diag.security_verdict}
                        </span>
                      </div>
                    </div>

                    <p className="text-xs text-slate-200 bg-[#0A0D14] border border-[#1B2230] rounded p-3 leading-relaxed">
                      {diag.summary}
                    </p>

                    {diag.contradiction_detected && diag.contradiction_note && (
                      <div className="flex items-start gap-2 rounded bg-amber-500/10 border border-amber-500/35 px-3 py-2 text-xs text-amber-200">
                        <AlertTriangle className="w-4 h-4 shrink-0 mt-0.5 text-amber-400" />
                        <span><strong>Supervisor Contradiction / Degradation Alert:</strong> {diag.contradiction_note}</span>
                      </div>
                    )}

                    {/* 4-Agent Diagnostic Council Execution Strip */}
                    <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-2.5 pt-1">
                      {diag.agent_reports.map((ag) => (
                        <div key={ag.agent_name} className="rounded bg-[#0A0D14] border border-[#1B2230] p-2.5">
                          <div className="flex items-center justify-between text-[11px]">
                            <span className="font-medium text-slate-200 flex items-center gap-1.5">
                              <Cpu className="w-3 h-3 text-sky-400" />
                              {ag.agent_name}
                            </span>
                            <span
                              className={`font-mono text-[10px] ${
                                ag.status === 'SUCCESS'
                                  ? 'text-emerald-400'
                                  : ag.status === 'TIMEOUT'
                                    ? 'text-red-400'
                                    : 'text-amber-400'
                              }`}
                            >
                              {ag.status}
                            </span>
                          </div>
                          <div className="mt-1 flex items-center justify-between font-mono text-[10px] text-slate-500">
                            <span>conf {(ag.confidence * 100).toFixed(0)}%</span>
                            <span>{ag.duration_ms.toFixed(1)} ms</span>
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>

                  {tab === 'forensics' ? (
                    <>
                      <CausalGraphView
                        graph={diag.causal_graph}
                        attributedStep={diag.attributed_step_index}
                        selectedStep={selectedStep}
                        onSelectStep={setSelectedStep}
                      />
                      <TraceWaterfall
                        spans={detail.spans}
                        stepScores={diag.step_scores}
                        attributedStep={diag.attributed_step_index}
                        selectedStep={selectedStep}
                        onSelectStep={setSelectedStep}
                      />
                    </>
                  ) : (
                    <CounterfactualLab
                      detail={detail}
                      onReplayComplete={() => void loadTraceDetail(detail.trace.id)}
                    />
                  )}
                </>
              )}
            </section>
          </div>
        )}

        {tab === 'firewall' && (
          <SecurityFirewall
            policies={policies}
            onPolicyChanged={() => void loadCore()}
          />
        )}

        {tab === 'benchmarks' && (
          <BenchmarkLab report={benchmark} onUpdated={setBenchmark} />
        )}

        {tab === 'automation' && (
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
            <div className="rounded-lg border border-[#1B2230] bg-[#10141D] p-4 space-y-4">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <Webhook className="w-4 h-4 text-sky-400" />
                  <h3 className="text-sm font-semibold text-slate-100">Signed Webhook &amp; n8n Automation Dispatcher</h3>
                </div>
                <span className="font-mono text-[11px] text-emerald-400">
                  Mock Inbox: {webhooks.mock_inbox_count} received
                </span>
              </div>
              <div className="flex gap-2">
                <input
                  type="text"
                  value={newWebhookUrl}
                  onChange={(e) => setNewWebhookUrl(e.target.value)}
                  className="flex-1 rounded bg-[#090B10] border border-[#232C3F] px-3 py-2 text-xs font-mono text-slate-200"
                />
                <button
                  type="button"
                  onClick={handleRegisterWebhook}
                  className="rounded bg-sky-600 hover:bg-sky-500 px-3.5 py-2 text-xs font-semibold text-white"
                >
                  Register
                </button>
              </div>
              <div className="space-y-2">
                <div className="text-[11px] font-mono text-slate-500">RECENT HMAC-SHA256 DELIVERIES ({webhooks.deliveries.length})</div>
                {webhooks.deliveries.length === 0 ? (
                  <div className="text-xs text-slate-500 bg-[#0A0D14] border border-[#1A202E] rounded p-3">
                    Register the local mock receiver above and click &ldquo;Run Trace&rdquo; to observe live HMAC-SHA256 signed webhook deliveries.
                  </div>
                ) : (
                  webhooks.deliveries.map((d, idx) => (
                    <div key={String(d.id ?? idx)} className="rounded bg-[#0A0D14] border border-[#1A202E] p-2.5 text-xs font-mono flex items-center justify-between">
                      <div>
                        <span className="text-slate-200">{String(d.event_type)}</span>
                        <div className="text-[10px] text-slate-500 truncate max-w-xs">{String(d.target_url)}</div>
                      </div>
                      <span className={d.status === 'DELIVERED' ? 'text-emerald-400 flex items-center gap-1' : 'text-red-400 flex items-center gap-1'}>
                        {d.status === 'DELIVERED' ? <CheckCircle2 className="w-3.5 h-3.5" /> : <AlertOctagon className="w-3.5 h-3.5" />}
                        {String(d.status)} ({String(d.attempts)}x)
                      </span>
                    </div>
                  ))
                )}
              </div>
            </div>

            <div className="rounded-lg border border-[#1B2230] bg-[#10141D] p-4 space-y-3">
              <div className="flex items-center justify-between">
                <h3 className="text-sm font-semibold text-slate-100">Live WebSocket Event Stream</h3>
                <span className="font-mono text-[11px] text-slate-500">{liveEvents.length} events</span>
              </div>
              <div className="space-y-2 max-h-[460px] overflow-y-auto pr-1">
                {liveEvents.map((ev, i) => (
                  <div key={`${ev.timestamp}-${i}`} className="rounded bg-[#0A0D14] border border-[#1A202E] p-2.5 font-mono text-[11px]">
                    <div className="flex items-center justify-between text-amber-300">
                      <span>{ev.event_type}</span>
                      <span className="text-slate-500">{ev.timestamp?.slice(11, 19)}</span>
                    </div>
                    <pre className="mt-1 text-slate-400 whitespace-pre-wrap break-all text-[10px]">
                      {JSON.stringify(ev.payload)}
                    </pre>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}
      </main>
    </div>
  );
}
