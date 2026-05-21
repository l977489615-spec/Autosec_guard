import React from 'react';
import { AttackGraph as AttackGraphModel, PhysicalImpactAssessment, RemediationPlan } from '../types';
import { AlertTriangle, GitBranch, ShieldCheck, Wrench } from 'lucide-react';

interface AttackGraphProps {
  graph?: AttackGraphModel;
  physicalImpact?: PhysicalImpactAssessment;
  remediationPlan?: RemediationPlan;
  compact?: boolean;
}

const severityColor = (severity: string) => {
  const value = severity.toLowerCase();
  if (value === 'critical') return 'border-red-500/60 text-red-300 bg-red-950/30';
  if (value === 'high') return 'border-orange-500/60 text-orange-300 bg-orange-950/20';
  if (value === 'medium') return 'border-yellow-500/60 text-yellow-300 bg-yellow-950/20';
  return 'border-cyan-900/60 text-cyan-200 bg-cyan-950/10';
};

const AttackGraph: React.FC<AttackGraphProps> = ({ graph, physicalImpact, remediationPlan, compact = false }) => {
  const paths = graph?.paths || [];
  const topPath = paths[0];

  return (
    <div className={`bg-black/30 border border-cyan-900/40 rounded-lg ${compact ? 'p-4' : 'p-5'} space-y-4`}>
      <div className="flex items-center gap-2">
        <GitBranch className="w-4 h-4 text-cyan-400" />
        <h3 className="text-sm font-bold text-cyan-300 uppercase tracking-wider">Attack Graph</h3>
      </div>

      {graph && graph.nodes.length > 0 ? (
        <>
          <p className="text-xs text-gray-400">{graph.summary}</p>
          <div className={`grid ${compact ? 'grid-cols-1' : 'grid-cols-1 xl:grid-cols-3'} gap-3`}>
            {paths.slice(0, compact ? 2 : 3).map((path) => (
              <div key={path.id} className="border border-cyan-900/40 rounded-lg bg-black/30 p-3">
                <div className="flex items-center justify-between mb-2">
                  <span className="text-xs font-semibold text-white">{path.title}</span>
                  <span className="text-[10px] px-2 py-0.5 rounded bg-cyan-950/40 border border-cyan-900/50 text-cyan-300">
                    {path.riskScore}/100
                  </span>
                </div>
                <div className="flex flex-wrap gap-2">
                  {path.nodes.map((nodeId) => {
                    const node = graph.nodes.find((item) => item.id === nodeId);
                    if (!node) return null;
                    return (
                      <span
                        key={node.id}
                        className={`text-[10px] px-2 py-1 rounded border ${severityColor(node.severity)}`}
                        title={node.evidence || node.label}
                      >
                        {node.label}
                      </span>
                    );
                  })}
                </div>
              </div>
            ))}
          </div>
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

      {topPath && !compact && (
        <div className="text-[11px] text-gray-500">
          Highest-risk path: <span className="text-cyan-300">{topPath.title}</span>
        </div>
      )}
    </div>
  );
};

export default AttackGraph;
