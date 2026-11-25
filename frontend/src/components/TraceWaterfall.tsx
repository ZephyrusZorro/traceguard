import { AlertTriangle, CheckCircle2, ShieldAlert, Terminal } from 'lucide-react';
import type { SpanRecord, StepScore } from '../types';

interface Props {
  spans: SpanRecord[];
  stepScores: StepScore[];
  attributedStep: number;
  selectedStep: number;
  onSelectStep: (step: number) => void;
}

export function TraceWaterfall({
  spans,
  stepScores,
  attributedStep,
  selectedStep,
  onSelectStep,
}: Props) {
  const scoreMap = new Map(stepScores.map((s) => [s.step_index, s]));
  const totalLat = Math.max(1, spans.reduce((acc, s) => acc + s.latency_ms, 0));
  let cumulative = 0;

  const selectedSpan = spans.find((s) => s.step_index === selectedStep) ?? spans[0];
  const selectedScore = selectedSpan ? scoreMap.get(selectedSpan.step_index) : undefined;

  return (
    <div className="space-y-4">
      <div className="rounded-lg border border-[#1B2230] bg-[#10141D] overflow-hidden">
        <div className="flex items-center justify-between px-4 py-2.5 border-b border-[#1B2230] text-xs font-medium text-slate-400">
          <span>OTEL GENAI SPAN WATERFALL &amp; C³ ATTRIBUTION HEATMAP</span>
          <span className="font-mono text-slate-500">{spans.length} spans · {totalLat.toFixed(0)} ms</span>
        </div>
        <div className="divide-y divide-[#171D29]">
          {spans.map((sp) => {
            const sc = scoreMap.get(sp.step_index);
            const c3 = sc?.combined_c3_score ?? 0;
            const leftPct = (cumulative / totalLat) * 100;
            const widthPct = Math.max(4, (sp.latency_ms / totalLat) * 100);
            cumulative += sp.latency_ms;

            const isRoot = sp.step_index === attributedStep;
            const isSelected = sp.step_index === selectedStep;

            return (
              <button
                key={sp.span_id}
                type="button"
                onClick={() => onSelectStep(sp.step_index)}
                className={`w-full text-left px-4 py-2.5 transition-colors flex items-center gap-3 ${
                  isSelected ? 'bg-[#171E2E]' : 'hover:bg-[#141925]'
                } ${isRoot ? 'border-l-2 border-l-amber-400' : 'border-l-2 border-l-transparent'}`}
              >
                <span className="font-mono text-xs text-slate-500 w-7">#{sp.step_index}</span>
                <div className="w-48 shrink-0">
                  <div className="flex items-center gap-1.5">
                    <span className="text-xs font-medium text-slate-200 truncate">{sp.agent_name}</span>
                    {isRoot && (
                      <span className="px-1.5 py-0.5 rounded text-[10px] font-mono font-semibold bg-amber-500/20 text-amber-300 border border-amber-500/40">
                        ROOT CAUSE
                      </span>
                    )}
                  </div>
                  <div className="text-[11px] font-mono text-slate-500 truncate">
                    {sp.operation_name}{sp.tool_name ? ` · ${sp.tool_name}` : ''}
                  </div>
                </div>

                {/* Timeline bar */}
                <div className="flex-1 h-5 bg-[#0A0D14] rounded relative overflow-hidden border border-[#1A202E]">
                  <div
                    className={`absolute top-1 bottom-1 rounded-sm ${
                      sp.status === 'ERROR'
                        ? 'bg-red-500/80'
                        : sc?.tainted
                          ? 'bg-rose-500/80'
                          : isRoot
                            ? 'bg-amber-400/90'
                            : sp.status === 'WARNING'
                              ? 'bg-amber-500/50'
                              : 'bg-sky-500/60'
                    }`}
                    style={{ left: `${Math.min(94, leftPct)}%`, width: `${Math.min(100 - leftPct, widthPct)}%` }}
                  />
                </div>

                {/* Provenance / Taint badge */}
                <div className="w-28 shrink-0 flex justify-end">
                  {sc?.tainted ? (
                    <span className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[10px] font-mono bg-red-500/15 text-red-300 border border-red-500/30">
                      <ShieldAlert className="w-3 h-3" /> TAINTED
                    </span>
                  ) : sp.provenance === 'SECRET_DATA' ? (
                    <span className="px-1.5 py-0.5 rounded text-[10px] font-mono bg-amber-500/10 text-amber-300 border border-amber-500/25">
                      SECRET
                    </span>
                  ) : (
                    <span className="px-1.5 py-0.5 rounded text-[10px] font-mono bg-slate-800/80 text-slate-400">
                      {sp.provenance.replace('_', ' ')}
                    </span>
                  )}
                </div>

                {/* C3 score */}
                <div className="w-24 shrink-0 text-right font-mono text-xs">
                  <span className={c3 >= 0.6 ? 'text-amber-300 font-semibold' : 'text-slate-400'}>
                    C³ {(c3 * 100).toFixed(0)}%
                  </span>
                  <div className="text-[10px] text-slate-500">{sp.latency_ms.toFixed(0)}ms</div>
                </div>
              </button>
            );
          })}
        </div>
      </div>

      {/* Selected Span Forensic Inspector */}
      {selectedSpan && (
        <div className="rounded-lg border border-[#1B2230] bg-[#10141D] p-4 space-y-3">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <div className="flex items-center gap-2">
              <Terminal className="w-4 h-4 text-sky-400" />
              <h4 className="text-sm font-semibold text-slate-100">
                Step #{selectedSpan.step_index} — {selectedSpan.agent_name}
              </h4>
              <span className="font-mono text-xs px-2 py-0.5 rounded bg-[#182030] text-slate-300">
                {selectedSpan.tool_name ?? selectedSpan.operation_name}
              </span>
            </div>
            <div className="flex items-center gap-3 text-xs font-mono text-slate-400">
              <span>in: {selectedSpan.tokens_in} tok</span>
              <span>out: {selectedSpan.tokens_out} tok</span>
              <span className={selectedSpan.status === 'ERROR' ? 'text-red-400' : selectedSpan.status === 'OK' ? 'text-emerald-400' : 'text-amber-400'}>
                {selectedSpan.status}
              </span>
            </div>
          </div>

          {selectedScore && (
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 text-xs">
              <div className="rounded bg-[#0A0D14] border border-[#1A202E] p-2.5">
                <div className="text-slate-500">ML Fault Prob</div>
                <div className="font-mono text-sm font-semibold text-slate-100">{(selectedScore.ml_fault_prob * 100).toFixed(1)}%</div>
              </div>
              <div className="rounded bg-[#0A0D14] border border-[#1A202E] p-2.5">
                <div className="text-slate-500">Injection ML Prob</div>
                <div className={`font-mono text-sm font-semibold ${selectedScore.injection_prob >= 0.55 ? 'text-red-400' : 'text-slate-100'}`}>
                  {(selectedScore.injection_prob * 100).toFixed(1)}%
                </div>
              </div>
              <div className="rounded bg-[#0A0D14] border border-[#1A202E] p-2.5">
                <div className="text-slate-500">Counterfactual Δ</div>
                <div className="font-mono text-sm font-semibold text-emerald-400">
                  {selectedScore.counterfactual_delta !== null ? `${(selectedScore.counterfactual_delta * 100).toFixed(1)}%` : '—'}
                </div>
              </div>
              <div className="rounded bg-[#0A0D14] border border-[#1A202E] p-2.5">
                <div className="text-slate-500">Combined C³ Score</div>
                <div className="font-mono text-sm font-semibold text-amber-300">{(selectedScore.combined_c3_score * 100).toFixed(1)}%</div>
              </div>
            </div>
          )}

          {selectedScore && selectedScore.key_signals.length > 0 && (
            <div className="flex flex-wrap gap-1.5">
              {selectedScore.key_signals.map((sig) => (
                <span key={sig} className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[11px] font-mono bg-amber-500/10 text-amber-300 border border-amber-500/25">
                  <AlertTriangle className="w-3 h-3" /> {sig}
                </span>
              ))}
            </div>
          )}

          <div className="grid grid-cols-1 lg:grid-cols-2 gap-3 text-xs">
            <div>
              <div className="text-slate-500 mb-1 font-medium">SPAN INPUT</div>
              <pre className="p-2.5 rounded bg-[#0A0D14] border border-[#1A202E] font-mono text-slate-300 whitespace-pre-wrap break-words max-h-32 overflow-y-auto">
                {selectedSpan.input_text || '(empty)'}
              </pre>
            </div>
            <div>
              <div className="text-slate-500 mb-1 font-medium flex items-center gap-1.5">
                SPAN OUTPUT
                {selectedSpan.status === 'OK' && <CheckCircle2 className="w-3.5 h-3.5 text-emerald-500" />}
              </div>
              <pre className="p-2.5 rounded bg-[#0A0D14] border border-[#1A202E] font-mono text-slate-300 whitespace-pre-wrap break-words max-h-32 overflow-y-auto">
                {selectedSpan.output_text || '(empty)'}
              </pre>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
