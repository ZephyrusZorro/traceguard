import type { Diagnosis } from '../types';

interface Props {
  graph: Diagnosis['causal_graph'];
  attributedStep: number;
  selectedStep: number;
  onSelectStep: (step: number) => void;
}

export function CausalGraphView({ graph, attributedStep, selectedStep, onSelectStep }: Props) {
  const nodes = graph?.nodes ?? [];
  const edges = graph?.edges ?? [];
  if (nodes.length === 0) return null;

  const colWidth = 172;
  const svgW = Math.max(680, nodes.length * colWidth + 40);
  const svgH = 190;

  const posMap = new Map<number, { x: number; y: number }>();
  nodes.forEach((n, idx) => {
    posMap.set(n.id, {
      x: 30 + idx * colWidth,
      y: idx % 2 === 0 ? 52 : 98,
    });
  });

  return (
    <div className="rounded-lg border border-[#1B2230] bg-[#10141D] p-4">
      <div className="flex flex-wrap items-center justify-between gap-2 mb-3">
        <span className="text-xs font-medium text-slate-400">CAUSAL EXECUTION &amp; TAINT PROVENANCE DAG</span>
        <div className="flex items-center gap-4 text-[11px] font-mono text-slate-400">
          <span className="flex items-center gap-1.5"><span className="w-3 h-0.5 bg-slate-500 inline-block" /> Control</span>
          <span className="flex items-center gap-1.5"><span className="w-3 h-0.5 bg-red-500 inline-block" /> Taint Flow</span>
          <span className="flex items-center gap-1.5"><span className="w-3 h-0.5 bg-amber-400 inline-block" /> Secret Flow</span>
        </div>
      </div>

      <div className="overflow-x-auto pb-1">
        <svg width={svgW} height={svgH} className="block">
          <defs>
            <marker id="arrow-slate" markerWidth="7" markerHeight="7" refX="6" refY="3.5" orient="auto">
              <polygon points="0 0, 7 3.5, 0 7" fill="#475569" />
            </marker>
            <marker id="arrow-red" markerWidth="7" markerHeight="7" refX="6" refY="3.5" orient="auto">
              <polygon points="0 0, 7 3.5, 0 7" fill="#EF4444" />
            </marker>
            <marker id="arrow-amber" markerWidth="7" markerHeight="7" refX="6" refY="3.5" orient="auto">
              <polygon points="0 0, 7 3.5, 0 7" fill="#F59E0B" />
            </marker>
          </defs>

          {edges.map((e, i) => {
            const p1 = posMap.get(e.source);
            const p2 = posMap.get(e.target);
            if (!p1 || !p2) return null;
            const x1 = p1.x + 132;
            const y1 = p1.y + 24;
            const x2 = p2.x;
            const y2 = p2.y + 24;
            const isTaint = e.edge_type === 'taint_flow';
            const isSecret = e.edge_type === 'secret_flow';
            const stroke = isTaint ? '#EF4444' : isSecret ? '#F59E0B' : '#475569';
            const marker = isTaint ? 'url(#arrow-red)' : isSecret ? 'url(#arrow-amber)' : 'url(#arrow-slate)';
            const cy = isTaint ? Math.min(y1, y2) - 28 : isSecret ? Math.max(y1, y2) + 28 : (y1 + y2) / 2;

            return (
              <path
                key={`${e.source}-${e.target}-${i}`}
                d={`M ${x1} ${y1} Q ${(x1 + x2) / 2} ${cy} ${x2} ${y2}`}
                fill="none"
                stroke={stroke}
                strokeWidth={isTaint || isSecret ? 2 : 1.3}
                strokeDasharray={isTaint ? '5 3' : isSecret ? '3 3' : undefined}
                markerEnd={marker}
              />
            );
          })}

          {nodes.map((n) => {
            const p = posMap.get(n.id)!;
            const isRoot = n.id === attributedStep;
            const isSel = n.id === selectedStep;
            const border = isRoot
              ? '#F59E0B'
              : n.tainted
                ? '#EF4444'
                : n.status === 'ERROR'
                  ? '#F87171'
                  : isSel
                    ? '#38BDF8'
                    : '#263044';

            return (
              <g
                key={n.id}
                transform={`translate(${p.x}, ${p.y})`}
                onClick={() => onSelectStep(n.id)}
                className="cursor-pointer"
              >
                <rect
                  width={132}
                  height={48}
                  rx={6}
                  fill={isSel ? '#192235' : '#0C1018'}
                  stroke={border}
                  strokeWidth={isRoot || isSel ? 2 : 1.2}
                />
                <text x={8} y={17} fill="#94A3B8" fontSize={10} fontFamily="JetBrains Mono">
                  #{n.id} {isRoot ? '★ ROOT' : n.tainted ? 'TAINT' : n.status}
                </text>
                <text x={8} y={32} fill="#E2E8F0" fontSize={11} fontWeight={600}>
                  {n.agent.length > 16 ? `${n.agent.slice(0, 15)}…` : n.agent}
                </text>
                <text x={8} y={43} fill="#64748B" fontSize={9.5} fontFamily="JetBrains Mono">
                  {(n.tool ?? 'chat').length > 17 ? `${(n.tool ?? 'chat').slice(0, 16)}…` : (n.tool ?? 'chat')}
                </text>
              </g>
            );
          })}
        </svg>
      </div>
    </div>
  );
}
