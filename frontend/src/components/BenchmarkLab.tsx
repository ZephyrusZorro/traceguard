import { useState } from 'react';
import { BarChart3, RefreshCw } from 'lucide-react';
import { api } from '../api';
import type { BenchmarkReport } from '../types';

interface Props {
  report: BenchmarkReport | null;
  onUpdated: (r: BenchmarkReport) => void;
}

const LABELS: Record<string, string> = {
  random_baseline: 'Baseline 1 · Random Step',
  last_error_heuristic: 'Baseline 2 · Last-Error Heuristic',
  lexical_drift_only: 'Baseline 3 · Lexical Drift + Latency',
  rule_only_mast: 'Baseline 4 · Rule-Only MAST',
  ml_ranker_only_ablation: 'Ablation · ML Step-Fault Ranker Only',
  c3_attributor_full: 'Proposed · C³-Attributor (ML + Counterfactual)',
};

export function BenchmarkLab({ report, onUpdated }: Props) {
  const [running, setRunning] = useState(false);

  async function handleRerun() {
    setRunning(true);
    try {
      const r = await api.rerunBenchmarks();
      onUpdated(r);
    } finally {
      setRunning(false);
    }
  }

  if (!report) {
    return <div className="text-xs text-slate-400 font-mono">Loading benchmark artifacts...</div>;
  }

  const tb = report.trace_benchmark;
  const ib = report.injection_benchmark;

  return (
    <div className="space-y-5">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-2">
          <BarChart3 className="w-4 h-4 text-sky-400" />
          <div>
            <h3 className="text-sm font-semibold text-slate-100">Reproducible ML Benchmark &amp; Ablation Suite</h3>
            <p className="text-xs text-slate-400">
              TraceBench-MAS ({tb.total_traces} traces: {tb.train_traces} train / {tb.val_traces} val / {tb.test_traces} held-out test · {tb.feature_count} features) &amp; InjectBench-ToolIO ({ib.dataset_sizes.train}/{ib.dataset_sizes.val}/{ib.dataset_sizes.test})
            </p>
          </div>
        </div>
        <button
          type="button"
          onClick={handleRerun}
          disabled={running}
          className="inline-flex items-center gap-1.5 rounded bg-[#182032] hover:bg-[#222D45] border border-[#2A3650] px-3 py-1.5 text-xs font-medium text-slate-200 disabled:opacity-50"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${running ? 'animate-spin' : ''}`} />
          {running ? 'Running Live Benchmark...' : 'Re-Run Evaluation'}
        </button>
      </div>

      {/* 6-Method Attribution Comparison */}
      <div className="rounded-lg border border-[#1B2230] bg-[#10141D] p-4 space-y-3">
        <div className="text-xs font-medium text-slate-400">STEP-LEVEL FAILURE ATTRIBUTION (HELD-OUT TEST SPLIT, n={tb.test_traces})</div>
        <div className="overflow-x-auto">
          <table className="w-full text-xs text-left border-collapse">
            <thead>
              <tr className="border-b border-[#1E2638] text-slate-400 font-mono text-[11px]">
                <th className="py-2 pr-4">METHOD</th>
                <th className="py-2 px-3">TOP-1 STEP</th>
                <th className="py-2 px-3">TOP-3 STEP</th>
                <th className="py-2 px-3">AGENT (WHO)</th>
                <th className="py-2 px-3">MRR</th>
                <th className="py-2 px-3">ECE ↓</th>
                <th className="py-2 pl-3 text-right">LATENCY</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#171D29] font-mono">
              {tb.methods.map((m) => {
                const isProp = m.method === 'c3_attributor_full';
                return (
                  <tr key={m.method} className={isProp ? 'bg-amber-500/5 text-amber-200' : 'text-slate-300'}>
                    <td className="py-2.5 pr-4 font-sans font-medium">
                      <div>{LABELS[m.method] ?? m.method}</div>
                      <div className="mt-1 h-1.5 w-48 bg-[#090B10] rounded overflow-hidden">
                        <div
                          className={`h-full ${isProp ? 'bg-amber-400' : 'bg-sky-500/70'}`}
                          style={{ width: `${m.top1_step_accuracy * 100}%` }}
                        />
                      </div>
                    </td>
                    <td className="py-2.5 px-3 font-semibold">{(m.top1_step_accuracy * 100).toFixed(1)}%</td>
                    <td className="py-2.5 px-3">{(m.top3_step_accuracy * 100).toFixed(1)}%</td>
                    <td className="py-2.5 px-3">{(m.agent_attribution_accuracy * 100).toFixed(1)}%</td>
                    <td className="py-2.5 px-3">{m.mrr.toFixed(3)}</td>
                    <td className="py-2.5 px-3">{m.ece.toFixed(3)}</td>
                    <td className="py-2.5 pl-3 text-right text-slate-400">{m.mean_latency_ms.toFixed(1)} ms</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>

      {/* Injection Benchmark + Per-Mode Accuracy */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <div className="rounded-lg border border-[#1B2230] bg-[#10141D] p-4 space-y-3">
          <div className="text-xs font-medium text-slate-400">INDIRECT PROMPT-INJECTION DETECTION (UNSEEN TEST FAMILIES)</div>
          <table className="w-full text-xs font-mono text-left">
            <thead>
              <tr className="border-b border-[#1E2638] text-slate-500">
                <th className="py-1.5">MODEL</th>
                <th className="py-1.5">PREC</th>
                <th className="py-1.5">REC</th>
                <th className="py-1.5">F1</th>
                <th className="py-1.5">HN-FPR ↓</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#171D29]">
              <tr className="text-slate-400">
                <td className="py-2 font-sans">Keyword Heuristic Baseline</td>
                <td>{(ib.keyword_baseline_test.precision * 100).toFixed(1)}%</td>
                <td>{(ib.keyword_baseline_test.recall * 100).toFixed(1)}%</td>
                <td>{(ib.keyword_baseline_test.f1 * 100).toFixed(1)}%</td>
                <td>{(ib.keyword_baseline_test.hard_negative_fpr * 100).toFixed(1)}%</td>
              </tr>
              <tr className="text-emerald-300 font-semibold">
                <td className="py-2 font-sans">Calibrated Word+Char TF-IDF + LogReg</td>
                <td>{(ib.test.precision * 100).toFixed(1)}%</td>
                <td>{(ib.test.recall * 100).toFixed(1)}%</td>
                <td>{(ib.test.f1 * 100).toFixed(1)}%</td>
                <td>{(ib.test.hard_negative_fpr * 100).toFixed(1)}%</td>
              </tr>
            </tbody>
          </table>
          <div className="text-[11px] font-mono text-slate-400 pt-1">
            Held-out ROC-AUC: <span className="text-sky-300">{ib.test.roc_auc.toFixed(4)}</span> · MAST Macro-F1: <span className="text-amber-300">{tb.c3_mast_macro_f1.toFixed(4)}</span> · Causal Flip Rate: <span className="text-emerald-300">{(tb.c3_counterfactual_recovery_rate * 100).toFixed(1)}%</span>
          </div>
        </div>

        <div className="rounded-lg border border-[#1B2230] bg-[#10141D] p-4 space-y-3">
          <div className="text-xs font-medium text-slate-400">C³-ATTRIBUTOR TOP-1 ACCURACY BY MAST FAILURE MODE</div>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
            {Object.entries(tb.c3_per_mode_top1_accuracy).map(([mode, acc]) => (
              <div key={mode} className="rounded bg-[#0A0D14] border border-[#1A202E] px-2.5 py-2 flex items-center justify-between text-[11px] font-mono">
                <span className="text-slate-300 truncate pr-2">{mode}</span>
                <span className="text-emerald-400 font-semibold">{(acc * 100).toFixed(0)}%</span>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}
