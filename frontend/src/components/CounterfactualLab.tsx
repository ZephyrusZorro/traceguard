import { useState } from 'react';
import { GitBranch, Play, CheckCircle2, XCircle } from 'lucide-react';
import { api } from '../api';
import type { CounterfactualReplay, TraceDetail } from '../types';

const INTERVENTIONS = [
  'BLOCK_UNAUTHORIZED_TOOL',
  'SANITIZE_TAINT',
  'RESTORE_CONTEXT',
  'REPAIR_TOOL_ARGS',
  'BREAK_LOOP',
  'FORCE_VERIFICATION',
  'CUSTOM_PATCH',
];

interface Props {
  detail: TraceDetail;
  onReplayComplete: () => void;
}

export function CounterfactualLab({ detail, onReplayComplete }: Props) {
  const defaultStep = detail.latest_diagnosis?.attributed_step_index ?? 0;
  const defaultIntervention = detail.latest_diagnosis?.counterfactual?.intervention_type ?? 'BLOCK_UNAUTHORIZED_TOOL';
  const [stepIdx, setStepIdx] = useState<number>(Math.max(0, defaultStep));
  const [intervention, setIntervention] = useState<string>(defaultIntervention);
  const [patchText, setPatchText] = useState<string>('');
  const [running, setRunning] = useState(false);
  const [activeReplay, setActiveReplay] = useState<CounterfactualReplay | null>(
    detail.replays[0] ?? detail.latest_diagnosis?.counterfactual ?? null,
  );
  const [error, setError] = useState<string | null>(null);

  async function handleRun() {
    setRunning(true);
    setError(null);
    try {
      const res = await api.runCounterfactual(detail.trace.id, stepIdx, intervention, patchText);
      setActiveReplay(res);
      onReplayComplete();
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Replay failed');
    } finally {
      setRunning(false);
    }
  }

  return (
    <div className="space-y-4">
      <div className="rounded-lg border border-[#1B2230] bg-[#10141D] p-4 space-y-4">
        <div className="flex items-center gap-2">
          <GitBranch className="w-4 h-4 text-emerald-400" />
          <h3 className="text-sm font-semibold text-slate-100">Time-Travel Counterfactual Intervention</h3>
        </div>
        <p className="text-xs text-slate-400">
          Rewind execution to any step <span className="font-mono text-slate-300">k</span>, inject a surgical intervention,
          and deterministically replay downstream state transitions to prove whether step <span className="font-mono text-slate-300">k</span> is causally responsible for the failure.
        </p>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
          <div>
            <label className="block text-[11px] font-mono text-slate-400 mb-1">REWIND STEP</label>
            <select
              value={stepIdx}
              onChange={(e) => setStepIdx(Number(e.target.value))}
              className="w-full rounded bg-[#090B10] border border-[#232C3F] px-3 py-2 text-xs text-slate-200 font-mono"
            >
              {detail.spans.map((s) => (
                <option key={s.span_id} value={s.step_index}>
                  #{s.step_index} · {s.agent_name} ({s.tool_name ?? s.operation_name})
                </option>
              ))}
            </select>
          </div>
          <div>
            <label className="block text-[11px] font-mono text-slate-400 mb-1">INTERVENTION TYPE</label>
            <select
              value={intervention}
              onChange={(e) => setIntervention(e.target.value)}
              className="w-full rounded bg-[#090B10] border border-[#232C3F] px-3 py-2 text-xs text-slate-200 font-mono"
            >
              {INTERVENTIONS.map((iv) => (
                <option key={iv} value={iv}>{iv}</option>
              ))}
            </select>
          </div>
          <div className="flex items-end">
            <button
              type="button"
              disabled={running}
              onClick={handleRun}
              className="w-full inline-flex items-center justify-center gap-2 rounded bg-emerald-600 hover:bg-emerald-500 disabled:opacity-50 px-4 py-2 text-xs font-semibold text-white transition-colors"
            >
              <Play className="w-3.5 h-3.5" />
              {running ? 'Replaying Timeline...' : 'Execute Counterfactual Replay'}
            </button>
          </div>
        </div>

        <div>
          <label className="block text-[11px] font-mono text-slate-400 mb-1">OPTIONAL CUSTOM PATCH PAYLOAD</label>
          <input
            type="text"
            value={patchText}
            onChange={(e) => setPatchText(e.target.value)}
            placeholder="Leave blank to apply recommended surgical intervention..."
            className="w-full rounded bg-[#090B10] border border-[#232C3F] px-3 py-2 text-xs text-slate-200 font-mono"
          />
        </div>

        {error && <div className="text-xs text-red-400 font-mono">{error}</div>}
      </div>

      {activeReplay && (
        <div className="rounded-lg border border-[#1B2230] bg-[#10141D] p-4 space-y-4">
          <div className="flex flex-wrap items-center justify-between gap-2 pb-3 border-b border-[#1B2230]">
            <div className="flex items-center gap-2.5">
              {activeReplay.causal_flip ? (
                <CheckCircle2 className="w-5 h-5 text-emerald-400" />
              ) : (
                <XCircle className="w-5 h-5 text-slate-500" />
              )}
              <div>
                <div className="text-sm font-semibold text-slate-100">
                  {activeReplay.causal_flip ? 'Causal Recovery Verified (Outcome Flipped)' : 'No Causal Flip Observed'}
                </div>
                <div className="text-xs font-mono text-slate-400">
                  {activeReplay.original_outcome} → {activeReplay.counterfactual_outcome} · Intervention @ Step #{activeReplay.intervention_step_index} ({activeReplay.intervention_type})
                </div>
              </div>
            </div>
            <div className="flex items-center gap-3 font-mono text-xs">
              <span className="px-2.5 py-1 rounded bg-[#0A0D14] border border-[#232C3F] text-emerald-300">
                Δ Score: {(activeReplay.delta_score * 100).toFixed(1)}%
              </span>
              <span className="px-2.5 py-1 rounded bg-[#0A0D14] border border-[#232C3F] text-slate-300">
                Steps Recovered: {activeReplay.downstream_recovered_steps}
              </span>
            </div>
          </div>

          <div className="space-y-1.5">
            {activeReplay.replayed_spans.map((rs) => (
              <div
                key={rs.step_index}
                className={`flex flex-wrap items-center justify-between gap-2 px-3 py-2 rounded text-xs border ${
                  rs.changed
                    ? 'bg-emerald-500/10 border-emerald-500/30'
                    : 'bg-[#0A0D14] border-[#1A202E]'
                }`}
              >
                <div className="flex items-center gap-2.5">
                  <span className="font-mono text-slate-500">#{rs.step_index}</span>
                  <span className="font-medium text-slate-200">{rs.agent_name}</span>
                  <span className="font-mono text-slate-500">{rs.tool_name ?? 'chat'}</span>
                </div>
                <div className="flex items-center gap-3 font-mono">
                  <span className="text-slate-400">{rs.original_status} → <strong className={rs.changed ? 'text-emerald-300' : 'text-slate-300'}>{rs.replayed_status}</strong></span>
                </div>
                <div className="w-full text-[11px] text-slate-400 pl-7">{rs.note}</div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
