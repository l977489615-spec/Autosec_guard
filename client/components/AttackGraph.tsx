import React, { useMemo, useState } from 'react';
import { AttackGraph as AttackGraphModel, AttackGraphNode, PhysicalImpactAssessment, RemediationPlan } from '../types';
import { AlertTriangle, GitBranch, ShieldCheck, Wrench } from 'lucide-react';

interface AttackGraphProps {
  graph?: AttackGraphModel;
  physicalImpact?: PhysicalImpactAssessment;
  remediationPlan?: RemediationPlan;
  compact?: boolean;
}

const severityColor = (severity?: string) => {
  const value = (severity || '').toLowerCase();
  if (value === 'critical') return 'border-red-500/60 text-red-300 bg-red-950/30';
  if (value === 'high') return 'border-orange-500/60 text-orange-300 bg-orange-950/20';
  if (value === 'medium') return 'border-yellow-500/60 text-yellow-300 bg-yellow-950/20';
  return 'border-cyan-900/60 text-cyan-200 bg-cyan-950/10';
};

// 不同节点类型的填充/描边色（SVG）
const NODE_STYLE: Record<string, { fill: string; stroke: string; text: string }> = {
  entry: { fill: '#062a33', stroke: '#22d3ee', text: '#a5f3fc' },
  vulnerability: { fill: '#2a0f12', stroke: '#f87171', text: '#fecaca' },
  capability: { fill: '#1e1433', stroke: '#a78bfa', text: '#ddd6fe' },
  impact: { fill: '#2a0a0a', stroke: '#ef4444', text: '#fca5a5' },
};

const sevStroke = (severity?: string) => {
  const v = (severity || '').toLowerCase();
  if (v === 'critical') return '#ef4444';
  if (v === 'high') return '#fb923c';
  if (v === 'medium') return '#facc15';
  return '#22d3ee';
};

const NODE_W = 132;
const NODE_H = 40;
const COL_GAP = 196;
const ROW_GAP = 60;
const PAD_X = 24;
const PAD_Y = 28;

interface Placed {
  node: AttackGraphNode;
  x: number;
  y: number;
  layer: number;
}

const AttackGraph: React.FC<AttackGraphProps> = ({ graph, physicalImpact, remediationPlan, compact = false }) => {
  const paths = graph?.paths || [];
  const [selectedPathId, setSelectedPathId] = useState<string | null>(null);

  const selectedPath = useMemo(
    () => paths.find((p) => p.id === selectedPathId) || paths[0],
    [paths, selectedPathId],
  );

  // ── 布局：基于多源 BFS 的分层（对含环的转移图安全），列=层、行=层内序号 ──
  const layout = useMemo(() => {
    if (!graph || graph.nodes.length === 0) return null;
    const nodeMap = new Map<string, AttackGraphNode>();
    graph.nodes.forEach((n) => nodeMap.set(n.id, n));

    const adj = new Map<string, string[]>();
    const indeg = new Map<string, number>();
    graph.nodes.forEach((n) => { adj.set(n.id, []); indeg.set(n.id, 0); });
    graph.edges.forEach((e) => {
      if (!nodeMap.has(e.source) || !nodeMap.has(e.target)) return;
      adj.get(e.source)!.push(e.target);
      indeg.set(e.target, (indeg.get(e.target) || 0) + 1);
    });

    // 源点：入度 0；若全有环则退化为 entry 类型节点
    let sources = graph.nodes.filter((n) => (indeg.get(n.id) || 0) === 0).map((n) => n.id);
    if (sources.length === 0) sources = graph.nodes.filter((n) => n.type === 'entry').map((n) => n.id);

    const layer = new Map<string, number>();
    const queue: string[] = [];
    sources.forEach((id) => { layer.set(id, 0); queue.push(id); });
    while (queue.length) {
      const u = queue.shift()!;
      const lu = layer.get(u)!;
      for (const v of adj.get(u) || []) {
        if (!layer.has(v) || layer.get(v)! < lu + 1) {
          // 仅在能增大且未形成回退访问时更新，BFS visited 防止环路死循环
          if (!layer.has(v)) { layer.set(v, lu + 1); queue.push(v); }
        }
      }
    }
    // 未被 BFS 触达者按类型兜底分层
    const typeLayer: Record<string, number> = { entry: 0, vulnerability: 1, capability: 2, impact: 3 };
    graph.nodes.forEach((n) => { if (!layer.has(n.id)) layer.set(n.id, typeLayer[n.type] ?? 0); });

    const byLayer = new Map<number, AttackGraphNode[]>();
    graph.nodes.forEach((n) => {
      const l = layer.get(n.id)!;
      if (!byLayer.has(l)) byLayer.set(l, []);
      byLayer.get(l)!.push(n);
    });

    const placed = new Map<string, Placed>();
    let maxRows = 0;
    const layers = Array.from(byLayer.keys()).sort((a, b) => a - b);
    layers.forEach((l) => {
      const col = byLayer.get(l)!.sort((a, b) => a.type.localeCompare(b.type) || a.label.localeCompare(b.label));
      maxRows = Math.max(maxRows, col.length);
      col.forEach((n, row) => {
        placed.set(n.id, { node: n, layer: l, x: PAD_X + l * COL_GAP, y: PAD_Y + row * ROW_GAP });
      });
    });

    // 各列垂直居中对齐
    layers.forEach((l) => {
      const col = byLayer.get(l)!;
      const offset = ((maxRows - col.length) * ROW_GAP) / 2;
      col.forEach((n) => { placed.get(n.id)!.y += offset; });
    });

    const width = PAD_X * 2 + (layers.length - 1) * COL_GAP + NODE_W;
    const height = PAD_Y * 2 + Math.max(1, maxRows) * ROW_GAP;
    return { placed, width, height };
  }, [graph]);

  // 选中路径上的节点与相邻边集合，用于高亮
  const highlight = useMemo(() => {
    const nodes = new Set<string>();
    const edges = new Set<string>();
    if (selectedPath) {
      selectedPath.nodes.forEach((id) => nodes.add(id));
      for (let i = 0; i < selectedPath.nodes.length - 1; i++) {
        edges.add(`${selectedPath.nodes[i]}->${selectedPath.nodes[i + 1]}`);
      }
    }
    return { nodes, edges };
  }, [selectedPath]);

  const renderSvg = () => {
    if (!layout) return null;
    const { placed, width, height } = layout;
    return (
      <div className="overflow-x-auto rounded-lg border border-cyan-900/40 bg-black/40">
        <svg
          viewBox={`0 0 ${width} ${height}`}
          width="100%"
          style={{ minWidth: Math.min(width, 720), maxHeight: compact ? 280 : 460 }}
          role="img"
          aria-label="Attack graph node-link diagram"
        >
          <defs>
            <marker id="ag-arrow" markerWidth="8" markerHeight="8" refX="7" refY="3" orient="auto">
              <path d="M0,0 L7,3 L0,6 Z" fill="#475569" />
            </marker>
            <marker id="ag-arrow-hot" markerWidth="8" markerHeight="8" refX="7" refY="3" orient="auto">
              <path d="M0,0 L7,3 L0,6 Z" fill="#f59e0b" />
            </marker>
            <marker id="ag-arrow-gated" markerWidth="8" markerHeight="8" refX="7" refY="3" orient="auto">
              <path d="M0,0 L7,3 L0,6 Z" fill="#ef4444" />
            </marker>
          </defs>

          {/* 边 */}
          {graph!.edges.map((e, i) => {
            const s = placed.get(e.source);
            const t = placed.get(e.target);
            if (!s || !t) return null;
            const x1 = s.x + NODE_W;
            const y1 = s.y + NODE_H / 2;
            const x2 = t.x;
            const y2 = t.y + NODE_H / 2;
            const mx = (x1 + x2) / 2;
            const isPivot = e.relation === 'pivots_to';
            const isGated = !!e.gated;
            const hot = highlight.edges.has(`${e.source}->${e.target}`);
            let stroke = '#334155';
            let marker = 'url(#ag-arrow)';
            if (isGated) { stroke = '#ef4444'; marker = 'url(#ag-arrow-gated)'; }
            else if (isPivot) { stroke = '#b45309'; }
            if (hot) { stroke = '#f59e0b'; marker = 'url(#ag-arrow-hot)'; }
            return (
              <path
                key={i}
                d={`M${x1},${y1} C${mx},${y1} ${mx},${y2} ${x2},${y2}`}
                fill="none"
                stroke={stroke}
                strokeWidth={hot ? 2.4 : 1.3}
                strokeDasharray={isPivot ? '5,4' : undefined}
                markerEnd={marker}
                opacity={hot ? 1 : 0.75}
              />
            );
          })}

          {/* 节点 */}
          {Array.from(placed.values()).map(({ node, x, y }) => {
            const st = NODE_STYLE[node.type] || NODE_STYLE.entry;
            const on = highlight.nodes.has(node.id);
            const stroke = node.type === 'vulnerability' ? sevStroke(node.severity) : st.stroke;
            const label = node.label.length > 16 ? node.label.slice(0, 15) + '…' : node.label;
            return (
              <g key={node.id} style={{ cursor: 'default' }}>
                <title>{node.evidence || `${node.type}: ${node.label}`}</title>
                <rect
                  x={x} y={y} rx={7} width={NODE_W} height={NODE_H}
                  fill={st.fill}
                  stroke={on ? '#f59e0b' : stroke}
                  strokeWidth={on ? 2.4 : 1.4}
                  opacity={on ? 1 : 0.92}
                />
                <text x={x + 9} y={y + 16} fontSize="9" fill="#64748b" style={{ textTransform: 'uppercase' }}>
                  {node.type}
                </text>
                <text x={x + 9} y={y + 30} fontSize="11" fill={st.text} fontWeight={600}>
                  {label}
                </text>
              </g>
            );
          })}
        </svg>
      </div>
    );
  };

  return (
    <div className={`bg-black/30 border border-cyan-900/40 rounded-lg ${compact ? 'p-4' : 'p-5'} space-y-4`}>
      <div className="flex items-center justify-between gap-2">
        <div className="flex items-center gap-2">
          <GitBranch className="w-4 h-4 text-cyan-400" />
          <h3 className="text-sm font-bold text-cyan-300 uppercase tracking-wider">Attack Graph</h3>
        </div>
        {typeof graph?.killChainCount === 'number' && graph.killChainCount > 0 && (
          <span className="text-[10px] px-2 py-0.5 rounded bg-red-950/40 border border-red-800/50 text-red-300">
            {graph.killChainCount} kill chain{graph.killChainCount > 1 ? 's' : ''}
          </span>
        )}
      </div>

      {graph && graph.nodes.length > 0 ? (
        <>
          {graph.summary && <p className="text-xs text-gray-400">{graph.summary}</p>}

          {renderSvg()}

          {/* 图例 */}
          <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-[10px] text-gray-400">
            <span className="flex items-center gap-1"><span className="inline-block w-3 h-0.5 bg-slate-500" />利用边</span>
            <span className="flex items-center gap-1"><span className="inline-block w-3 h-0.5 bg-amber-700" style={{ borderTop: '1px dashed' }} />跨漏洞转移 pivots_to</span>
            <span className="flex items-center gap-1"><span className="inline-block w-3 h-0.5 bg-red-500" style={{ borderTop: '1px dashed' }} />网关门控</span>
            <span className="flex items-center gap-1"><span className="inline-block w-3 h-0.5 bg-amber-500" />选中链</span>
          </div>

          {/* 路径选择器：点击高亮对应攻击链 */}
          {paths.length > 0 && (
            <div className="space-y-1.5">
              <div className="text-[11px] text-gray-500">攻击链（点击高亮，按风险排序）：</div>
              <div className="flex flex-wrap gap-2">
                {paths.slice(0, compact ? 4 : 8).map((p) => {
                  const active = selectedPath?.id === p.id;
                  return (
                    <button
                      key={p.id}
                      onClick={() => setSelectedPathId(p.id)}
                      className={`text-[10px] px-2 py-1 rounded border transition-colors ${
                        active
                          ? 'border-amber-500/70 text-amber-200 bg-amber-950/30'
                          : 'border-cyan-900/50 text-cyan-300 bg-cyan-950/20 hover:border-cyan-700/60'
                      }`}
                      title={p.title}
                    >
                      <span className="font-semibold">{p.riskScore}</span>
                      {typeof p.hops === 'number' && <span className="text-gray-500"> · {p.hops}跳</span>}
                      {p.reachesPhysical && <span className="text-red-400"> · 物理</span>}
                      {typeof p.gatedHops === 'number' && p.gatedHops > 0 && <span className="text-orange-400"> · 网关×{p.gatedHops}</span>}
                    </button>
                  );
                })}
              </div>
              {selectedPath && (
                <div className="text-[11px] text-gray-400 pt-0.5">
                  <span className="text-amber-300">▸</span> {selectedPath.title}
                </div>
              )}
            </div>
          )}
        </>
      ) : (
        <div className="text-xs text-gray-500">当前没有可解释攻击路径。</div>
      )}

      {(physicalImpact || remediationPlan) && (
        <div className={`grid ${compact ? 'grid-cols-1' : 'grid-cols-1 lg:grid-cols-2'} gap-3`}>
          {physicalImpact && (
            <div className="border border-cyan-900/40 rounded-lg bg-black/20 p-3">
              <div className="flex items-center gap-2 mb-2">
                <AlertTriangle className="w-4 h-4 text-amber-400" />
                <span className="text-xs font-semibold text-amber-300 uppercase tracking-wider">Physical Impact</span>
              </div>
              <div className="text-xs text-gray-300 space-y-1">
                <div>Safety Level: <span className="text-white">{physicalImpact.safetyLevel}</span></div>
                <div>Domains: <span className="text-white">{physicalImpact.impactDomains.join(', ') || 'none'}</span></div>
                <div>Effects: <span className="text-white">{physicalImpact.likelyEffects.join(', ') || 'none'}</span></div>
                <p className="text-gray-400 pt-1">{physicalImpact.justification}</p>
              </div>
            </div>
          )}
          {remediationPlan && (
            <div className="border border-cyan-900/40 rounded-lg bg-black/20 p-3">
              <div className="flex items-center gap-2 mb-2">
                <Wrench className="w-4 h-4 text-emerald-400" />
                <span className="text-xs font-semibold text-emerald-300 uppercase tracking-wider">Remediation Simulator</span>
              </div>
              <div className="text-xs text-gray-300 space-y-2">
                <div className="flex items-center gap-3">
                  <span>Before <span className="text-white">{remediationPlan.beforeScore}</span></span>
                  <ShieldCheck className="w-3.5 h-3.5 text-gray-500" />
                  <span>After <span className="text-emerald-300">{remediationPlan.afterScore}</span></span>
                </div>
                {remediationPlan.actions.slice(0, compact ? 2 : 3).map((action) => (
                  <div key={action.id} className="rounded border border-emerald-900/40 bg-black/20 p-2">
                    <div className="font-semibold text-white">{action.title}</div>
                    <div className="text-gray-400">{action.description}</div>
                    <div className="text-[10px] text-emerald-300 mt-1">Risk Reduction: -{action.estimatedRiskReduction}</div>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
};

export default AttackGraph;
