import React, { useState } from 'react';
import { ScanSession, POC, PhaseRecord, PlannerStep, SupervisorAdjustment, SupervisorEvent, SupervisorMetrics, ExecutionArtifactRecord } from '../types';
import { Clock, AlertTriangle, CheckCircle, FileText, ChevronRight, X, List, Shield, Download, Trash2, Square, CheckSquare } from 'lucide-react';
import ScanLogs from './ScanLogs';
import { POC_DATABASE } from '../data/pocDatabase';
import PocDetailModal from './PocDetailModal';
import { getBackendUrl } from '../services/api';
import AttackGraph from './AttackGraph';

interface ScanHistoryProps {
    localHistory?: ScanSession[];
    currentUser: any;
    token: string | null;
    onUnauthorized?: () => void;
    onResumeSession?: (session: ScanSession) => void;
}

const ScanHistory: React.FC<ScanHistoryProps> = ({ currentUser, token, localHistory = [], onUnauthorized, onResumeSession }) => {

    const [selectedSession, setSelectedSession] = useState<ScanSession | null>(null);
    const [selectedResultPoc, setSelectedResultPoc] = useState<POC | null>(null);
    const [dbHistory, setDbHistory] = useState<ScanSession[]>([]);
    const [supervisorSnapshots, setSupervisorSnapshots] = useState<any[]>([]);
    const [sessionArtifacts, setSessionArtifacts] = useState<ExecutionArtifactRecord[]>([]);
    const [loading, setLoading] = useState(true);
    const [selectedIds, setSelectedIds] = useState<Set<number>>(new Set());
    const [isDeleting, setIsDeleting] = useState(false);

    const fetchHistory = async () => {
        if (!token) return;
        try {
            const res = await fetch(`${getBackendUrl()}/api/history`, {
                headers: { 'Authorization': `Bearer ${token}` }
            });
            if (res.status === 401 || res.status === 403) {
                onUnauthorized?.();
                return;
            }
            if (res.ok) {
                const data = await res.json();
                // Map backend format to frontend ScanSession format
                const mappedHistory: ScanSession[] = data.history.map((h: any) => {
                    const parsedJson = h.results_json || [];
                    const isWrapper = !!parsedJson.results && Array.isArray(parsedJson.results);
                    const finalResults = isWrapper ? parsedJson.results : (Array.isArray(parsedJson) ? parsedJson : []);

                    return {
                        id: h.session_id || `hist-${h.id}`,
                        dbId: h.id, // Keep the actual database ID for deletion
                        targetName: isWrapper && parsedJson.targetName ? parsedJson.targetName : (h.target_ip || 'Unknown Target'),
                        connection: isWrapper && parsedJson.connection ? parsedJson.connection : { ip: h.target_ip, bluetoothMac: h.target_mac, port: '', canInterface: '', url: '', frequency: '', interface: '' },
                        startTime: h.started_at,
                        endTime: h.completed_at,
                        status: 'completed',
                        isConnected: true,
                        results: finalResults,
                        // Prioritize the new dedicated 'logs' column, fallback to the old results_json bundle
                        logs: (h.logs && Array.isArray(h.logs) && h.logs.length > 0)
                            ? h.logs
                            : (isWrapper && parsedJson.logs && parsedJson.logs.length > 0
                                ? parsedJson.logs
                                : [{
                                    timestamp: h.started_at ? new Date(h.started_at).toLocaleTimeString() : "N/A",
                                    type: 'warning',
                                    message: 'Logs were not saved for this historical record (pre-update). Full log persistence is now active for new scans.'
                                }]),
                        aiReport: isWrapper ? parsedJson.aiReport : null,
                        riskScore: h.risk_score,
                        username: h.username,
                        mode: isWrapper && parsedJson.mode ? parsedJson.mode : 'batch',
                        assessment: isWrapper ? parsedJson.assessment : undefined,
                        findings: h.findings || (isWrapper ? parsedJson.findings : []),
                        phase_records: h.phase_records || (isWrapper ? parsedJson.phase_records : []),
                        structured: h.structured || (isWrapper ? parsedJson.structured : {}),
                    };
                });
                setDbHistory(mappedHistory);
            }
        } catch (err) {
            console.error("Failed to fetch history:", err);
        } finally {
            setLoading(false);
        }
    };
    React.useEffect(() => {
        fetchHistory();
    }, [token]);

    React.useEffect(() => {
        const fetchSupervisorMetrics = async () => {
            if (!token) return;
            try {
                const res = await fetch(`${getBackendUrl()}/api/supervisor-metrics?limit=20`, {
                    headers: { 'Authorization': `Bearer ${token}` }
                });
                if (res.status === 401 || res.status === 403) {
                    onUnauthorized?.();
                    return;
                }
                if (res.ok) {
                    const data = await res.json();
                    setSupervisorSnapshots(Array.isArray(data.snapshots) ? data.snapshots : []);
                }
            } catch (err) {
                console.error("Failed to fetch supervisor metrics:", err);
            }
        };
        fetchSupervisorMetrics();
    }, [token, onUnauthorized]);

    React.useEffect(() => {
        const fetchArtifacts = async () => {
            if (!token || !selectedSession?.id) {
                setSessionArtifacts([]);
                return;
            }
            try {
                const res = await fetch(`${getBackendUrl()}/api/session-artifacts/${selectedSession.id}`, {
                    headers: { 'Authorization': `Bearer ${token}` }
                });
                if (res.status === 401 || res.status === 403) {
                    onUnauthorized?.();
                    return;
                }
                if (res.ok) {
                    const data = await res.json();
                    setSessionArtifacts(Array.isArray(data.artifacts) ? data.artifacts : []);
                }
            } catch (err) {
                console.error("Failed to fetch session artifacts:", err);
            }
        };
        fetchArtifacts();
    }, [selectedSession?.id, token, onUnauthorized]);

    const displayHistory = React.useMemo(() => {
        const source = dbHistory.length > 0 ? dbHistory : localHistory;
        return Array.from(
            new Map<string, ScanSession>(
                source.slice().map(session => [session.id, session])
            ).values()
        );
    }, [dbHistory, localHistory]);

    const supervisorTrend = React.useMemo(() => {
        const snapshots = supervisorSnapshots.slice().sort((a, b) => {
            const left = new Date(a.created_at || 0).getTime();
            const right = new Date(b.created_at || 0).getTime();
            return right - left;
        }).slice(0, 6);
        const totals = snapshots.reduce((acc, snapshot) => {
            const metrics = snapshot.metrics || {};
            acc.events += metrics.total_events || 0;
            acc.pruned += metrics.pruned_steps || 0;
            acc.noProgress += metrics.no_progress_events || 0;
            acc.errors += metrics.execution_errors || 0;
            return acc;
        }, { events: 0, pruned: 0, noProgress: 0, errors: 0 });
        return { snapshots, totals };
    }, [supervisorSnapshots]);

    const exportSupervisorMetrics = () => {
        const payload = supervisorTrend.snapshots;
        const blob = new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const anchor = document.createElement('a');
        anchor.href = url;
        anchor.download = 'autosec-supervisor-metrics.json';
        anchor.click();
        URL.revokeObjectURL(url);
    };

    const handleDelete = async (e: React.MouseEvent, dbId?: number) => {
        e.stopPropagation();
        if (dbId === undefined || dbId === null || !token) return;
        if (!window.confirm('Are you sure you want to delete this scan record?')) return;

        try {
            setIsDeleting(true);
            const res = await fetch(`${getBackendUrl()}/api/history/${dbId}`, {
                method: 'DELETE',
                headers: { 'Authorization': `Bearer ${token}` }
            });
            if (res.ok) {
                fetchHistory();
                setSelectedIds(prev => {
                    const next = new Set(prev);
                    next.delete(dbId);
                    return next;
                });
            } else {
                const data = await res.json();
                alert(data.message || 'Failed to delete record');
            }
        } catch (err) {
            console.error("Delete failed:", err);
        } finally {
            setIsDeleting(false);
        }
    };

    const handleDeleteBatch = async () => {
        if (selectedIds.size === 0 || !token) return;
        if (!window.confirm(`Are you sure you want to delete ${selectedIds.size} records?`)) return;

        try {
            setIsDeleting(true);
            const res = await fetch(`${getBackendUrl()}/api/history/delete-batch`, {
                method: 'POST',
                headers: { 
                    'Authorization': `Bearer ${token}`,
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ ids: Array.from(selectedIds) })
            });
            if (res.ok) {
                fetchHistory();
                setSelectedIds(new Set());
            } else {
                const data = await res.json();
                alert(data.message || 'Batch delete failed');
            }
        } catch (err) {
            console.error("Batch delete failed:", err);
        } finally {
            setIsDeleting(false);
        }
    };

    const toggleSelect = (e: React.MouseEvent, dbId?: number) => {
        e.stopPropagation();
        if (dbId === undefined || dbId === null) return;
        setSelectedIds(prev => {
            const next = new Set(prev);
            if (next.has(dbId)) next.delete(dbId);
            else next.add(dbId);
            return next;
        });
    };

    const toggleSelectAll = () => {
        if (selectedIds.size === displayHistory.filter(s => s.dbId).length) {
            setSelectedIds(new Set());
        } else {
            const allDbIds = displayHistory.map(s => s.dbId).filter((id): id is number => !!id);
            setSelectedIds(new Set(allDbIds));
        }
    };

    const exportToPdf = (session: ScanSession) => {
        if (!session.aiReport) return;

        const now = new Date(session.startTime).toLocaleString('zh-CN', { hour12: false });
        const targetInfo = session.targetName || session.connection.ip || 'Unknown Target';

        // Basic Markdown to HTML conversion for report
        const reportHtml = session.aiReport
            .replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>')
            .replace(/^### (.+)$/gm, '<h3>$1</h3>')
            .replace(/^## (.+)$/gm, '<h2>$1</h2>')
            .replace(/^# (.+)$/gm, '<h1>$1</h1>')
            .replace(/^[-*] (.+)$/gm, '<li>$1</li>')
            .replace(/\n\n/g, '</p><p>')
            .replace(/\n/g, '<br/>');

        const html = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8" />
  <title>AutoSec Guard 安全评估报告</title>
  <style>
    body { font-family: 'Arial', 'SimSun', sans-serif; color: #111; background: #fff; margin: 40px; line-height: 1.7; font-size: 14px; }
    .header { border-bottom: 2px solid #1e40af; padding-bottom: 16px; margin-bottom: 24px; }
    .header h1 { font-size: 22px; color: #1e40af; margin: 0 0 8px; }
    .meta { display: grid; grid-template-columns: 1fr 1fr; gap: 4px 24px; font-size: 13px; color: #444; }
    .meta span { display: block; }
    .meta .label { font-weight: bold; color: #222; }
    .section { margin-top: 24px; }
    h1, h2, h3 { color: #1e3a8a; page-break-after: avoid; }
    h2 { font-size: 16px; border-left: 4px solid #3b82f6; padding-left: 8px; margin-top: 20px; }
    h3 { font-size: 14px; color: #1e40af; margin-top: 14px; }
    p { margin: 6px 0; }
    li { margin: 4px 0 4px 20px; }
    .content { max-width: 800px; }
    @page { margin: 2cm; }
    @media print { body { margin: 0; } }
  </style>
</head>
<body>
  <div class="content">
    <div class="header">
      <h1>AutoSec Guard 智能网联汽车安全评估报告</h1>
      <div class="meta">
        <span><span class="label">扫描目标：</span>${targetInfo}</span>
        <span><span class="label">扫描时间：</span>${now}</span>
        <span><span class="label">报告类型：</span>历史记录导出</span>
        <span><span class="label">工具版本：</span>AutoSec Guard v2.0 · Archive</span>
      </div>
    </div>
    <div class="section">
      <p>${reportHtml}</p>
    </div>
  </div>
  <script>window.onload = function(){ window.print(); }</script>
</body>
</html>`;

        const printWindow = window.open('', '_blank');
        if (printWindow) {
            printWindow.document.write(html);
            printWindow.document.close();
        }
    };

    if (selectedSession) {
        const vulnCount = selectedSession.results.filter(r => r.vulnerable).length;
        const topAttackPath = selectedSession.assessment?.attackGraph?.paths?.[0];
        const graphSummary = selectedSession.assessment?.attackGraph?.summary;
        const phaseRecords = selectedSession.phase_records || [];
        const findings = selectedSession.findings || selectedSession.results.filter(r => r.vulnerable);
        const plannerSteps: PlannerStep[] = Array.isArray(selectedSession.structured?.planner?.steps) ? selectedSession.structured?.planner?.steps : [];
        const plannerSummary = selectedSession.structured?.planner?.strategy_summary || '';
        const plannerGuardrails: string[] = Array.isArray(selectedSession.structured?.planner?.guardrails) ? selectedSession.structured?.planner?.guardrails : [];
        const supervisorEvents: SupervisorEvent[] = Array.isArray(selectedSession.structured?.supervisor?.events) ? selectedSession.structured?.supervisor?.events : [];
        const supervisorMetrics = (selectedSession.structured?.supervisor?.metrics || {}) as Partial<SupervisorMetrics>;
        const supervisorAdjustments: SupervisorAdjustment[] = Array.isArray(selectedSession.structured?.supervisor?.adjustments) ? selectedSession.structured?.supervisor?.adjustments : [];
        const artifactSummary = sessionArtifacts.reduce<Record<string, number>>((acc, artifact) => {
            const key = artifact.artifact_type || 'unknown';
            acc[key] = (acc[key] || 0) + 1;
            return acc;
        }, {});

        return (
            <div className="p-6 h-full flex flex-col relative">
                <PocDetailModal
                    poc={selectedResultPoc}
                    isOpen={!!selectedResultPoc}
                    onClose={() => setSelectedResultPoc(null)}
                />

                <button
                    onClick={() => setSelectedSession(null)}
                    className="absolute top-6 left-6 z-10 text-xs font-bold text-gray-400 hover:text-white flex items-center gap-2 bg-cyber-900 px-3 py-1 rounded border border-cyber-700"
                >
                    ← BACK TO LIST
                </button>

                <div className="mt-10 grid grid-cols-1 lg:grid-cols-3 gap-6 h-full">
                    <div className="space-y-6 flex flex-col min-h-0">
                        <div className="bg-cyber-800 border border-cyber-700 p-6 rounded-lg">
                            <div className="flex items-center gap-3 mb-2">
                                <h2 className="text-xl font-bold text-white">{selectedSession.targetName}</h2>
                                {selectedSession.mode === 'agent' && (
                                    <span className="text-[10px] bg-purple-900/40 text-purple-300 border border-purple-700 px-2 py-0.5 rounded uppercase tracking-wider">Agent Scan</span>
                                )}
                            </div>
                            <div className="text-sm text-gray-400 font-mono mb-4">{selectedSession.id}</div>

                            {selectedSession.mode === 'agent' && onResumeSession && (
                                <button
                                    onClick={() => onResumeSession(selectedSession)}
                                    className="mb-4 text-xs font-semibold bg-emerald-950/30 text-emerald-300 border border-emerald-800 hover:border-emerald-600 px-3 py-2 rounded transition-colors"
                                >
                                    恢复到扫描页并继续执行
                                </button>
                            )}

                            <div className="space-y-3">
                                <div className="flex justify-between border-b border-cyber-700 pb-2">
                                    <span className="text-gray-500 text-xs uppercase">Scan Date</span>
                                    <span className="text-gray-300 text-sm">{new Date(selectedSession.startTime).toLocaleString()}</span>
                                </div>
                                <div className="flex justify-between border-b border-cyber-700 pb-2">
                                    <span className="text-gray-500 text-xs uppercase">IP Address</span>
                                    <span className="text-gray-300 text-sm">{selectedSession.connection.ip}</span>
                                </div>
                                <div className="flex justify-between items-center">
                                    <span className="text-gray-500 text-xs uppercase">Risk Score</span>
                                    <div className="flex items-center gap-2">
                                        <div className={`text-lg font-bold ${selectedSession.riskScore > 50 ? 'text-cyber-danger' : 'text-cyber-success'}`}>
                                            {selectedSession.riskScore}
                                        </div>
                                        <span className="text-gray-600 text-xs">/100</span>
                                    </div>
                                </div>
                            </div>
                        </div>

                        {selectedSession.assessment?.attackGraph && (
                            <div className="bg-cyber-800 border border-cyber-accent/30 p-6 rounded-lg">
                                <div className="flex items-center justify-between mb-3">
                                    <h3 className="text-sm font-bold text-cyber-accent uppercase tracking-wide">Attack Graph Snapshot</h3>
                                    {topAttackPath?.riskScore && (
                                        <span className="text-xs font-mono text-cyan-300 bg-cyan-950/40 border border-cyan-800 px-2 py-1 rounded">
                                            Top Path {topAttackPath.riskScore}/100
                                        </span>
                                    )}
                                </div>
                                {graphSummary && (
                                    <p className="text-sm text-gray-300 leading-relaxed mb-4">{graphSummary}</p>
                                )}
                                {topAttackPath ? (
                                    <div className="space-y-3">
                                        <div className="text-sm font-semibold text-white">{topAttackPath.title}</div>
                                        <div className="flex flex-wrap gap-2">
                                            {topAttackPath.nodes?.slice(0, 4).map((step: string, index: number) => (
                                                <span
                                                    key={`${step}-${index}`}
                                                    className="text-[11px] bg-amber-950/30 text-amber-300 border border-amber-800/60 px-2 py-1 rounded"
                                                >
                                                    {step}
                                                </span>
                                            ))}
                                        </div>
                                        {selectedSession.assessment?.physicalImpact?.safetyLevel && (
                                            <div className="text-xs text-gray-400">
                                                Physical Impact: <span className="text-white uppercase">{selectedSession.assessment.physicalImpact.safetyLevel}</span>
                                            </div>
                                        )}
                                    </div>
                                ) : (
                                    <div className="text-sm text-gray-500 italic">No attack path details available.</div>
                                )}
                            </div>
                        )}

                        <div className="bg-cyber-800 border border-cyber-accent/30 rounded-lg flex-1 min-h-0 overflow-y-auto relative">
                            <div className="flex justify-between items-center sticky top-0 bg-cyber-800 p-4 z-20 border-b border-cyber-700/50">
                                <h3 className="text-sm font-bold text-cyber-accent flex items-center gap-2">
                                    <FileText size={14} /> AI Analysis Report
                                </h3>
                                {selectedSession.aiReport && (
                                    <button
                                        onClick={() => exportToPdf(selectedSession)}
                                        className="text-[10px] bg-cyber-900 border border-cyber-700 hover:border-cyber-accent text-white px-2 py-1 rounded flex items-center gap-1 transition-all shadow-inner"
                                    >
                                        <Download size={10} className="text-cyber-accent" /> EXPORT PDF
                                    </button>
                                )}
                            </div>
                            <div className="p-4 pt-1">
                                {selectedSession.aiReport ? (
                                    <div className="prose prose-invert max-w-none text-xs text-gray-300 font-sans whitespace-pre-line leading-relaxed">
                                        {selectedSession.aiReport}
                                    </div>
                                ) : (
                                    <div className="text-center text-gray-600 text-sm italic py-10">
                                        No AI Report was generated for this session.
                                    </div>
                                )}
                            </div>
                        </div>
                    </div>

                    <div className="lg:col-span-2 flex flex-col gap-6 h-full overflow-y-auto pb-10 pr-2">
                        <div className="h-96 shrink-0">
                            <ScanLogs logs={selectedSession.logs} />
                        </div>

                        <div className="bg-cyber-800 border border-cyber-700 rounded-lg p-4 shrink-0">
                            <h3 className="text-sm font-bold text-white mb-3 flex items-center gap-2">
                                <AlertTriangle size={14} className="text-yellow-500" />
                                Vulnerabilities ({vulnCount})
                            </h3>
                            <div className="space-y-2">
                                {selectedSession.results.filter(r => r.vulnerable).map((res) => {
                                    const normalizeFile = (f: string) => f?.split('/').pop()?.replace(/^\d+_/, '').toLowerCase();
                                    const resName = res.pocId || res.name || "";
                                    const cleanResName = normalizeFile(resName);

                                    const poc = POC_DATABASE.find(p =>
                                        p.id === res.pocId ||
                                        p.pocFile === resName ||
                                        normalizeFile(p.pocFile) === cleanResName
                                    );
                                    return (
                                        <div key={res.pocId} onClick={() => poc && setSelectedResultPoc(poc)} className="bg-cyber-900 border-l-2 border-cyber-danger p-2 rounded cursor-pointer hover:bg-black/40">
                                            <div className="flex justify-between"><span className="text-white text-sm font-bold">{poc?.name}</span><span className="text-red-500 text-[10px]">{poc?.severity}</span></div>
                                        </div>
                                    );
                                })}
                                {vulnCount === 0 && <div className="text-center text-gray-500 text-sm py-4">No threats detected.</div>}
                            </div>
                        </div>

                        {selectedSession.mode === 'agent' && phaseRecords.length > 0 && (
                            <div className="bg-cyber-800 border border-cyber-700 rounded-lg shrink-0 overflow-y-auto max-h-96 relative">
                                <h3 className="text-sm font-bold text-white sticky top-0 bg-cyber-800 p-4 border-b border-cyber-700/50 z-20 flex items-center gap-2">
                                    <List size={14} className="text-cyan-400" />
                                    Agent Phase Replay
                                </h3>
                                <div className="space-y-2 p-4 pt-1">
                                    {phaseRecords.map((record: PhaseRecord) => (
                                        <div key={record.phase} className="bg-cyber-900 border border-cyber-700 rounded p-3">
                                            <div className="flex items-center justify-between gap-3 mb-2">
                                                <div className="text-sm font-semibold text-white uppercase">{record.phase}</div>
                                                <div className="flex items-center gap-2 text-[11px] font-mono">
                                                    <span className={`px-2 py-0.5 rounded border ${
                                                        record.status === 'done'
                                                            ? 'text-emerald-300 border-emerald-800 bg-emerald-950/30'
                                                            : record.status === 'error'
                                                                ? 'text-red-300 border-red-800 bg-red-950/30'
                                                                : record.status === 'retrying'
                                                                    ? 'text-amber-300 border-amber-800 bg-amber-950/30'
                                                                    : 'text-cyan-300 border-cyan-800 bg-cyan-950/30'
                                                    }`}>
                                                        {record.status}
                                                    </span>
                                                    {record.attempt ? <span className="text-gray-500">attempt {record.attempt}</span> : null}
                                                </div>
                                            </div>
                                            {record.error ? <div className="text-xs text-red-300 mb-2">{record.error}</div> : null}
                                            {record.structured_output && Object.keys(record.structured_output).length > 0 ? (
                                                <pre className="text-[11px] text-gray-300 bg-black/30 rounded p-2 overflow-x-auto whitespace-pre-wrap">
                                                    {JSON.stringify(record.structured_output, null, 2)}
                                                </pre>
                                            ) : (
                                                <div className="text-xs text-gray-500 italic">No structured output snapshot.</div>
                                            )}
                                        </div>
                                    ))}
                                </div>
                            </div>
                        )}

                        {selectedSession.mode === 'agent' && findings.length > 0 && (
                            <div className="bg-cyber-800 border border-cyber-700 rounded-lg p-4 shrink-0">
                                <h3 className="text-sm font-bold text-white mb-3 flex items-center gap-2">
                                    <Shield size={14} className="text-emerald-400" />
                                    Structured Findings
                                </h3>
                                <div className="space-y-2">
                                    {findings.map((finding: any, index: number) => (
                                        <div key={`${finding.name || finding.pocId || 'finding'}-${index}`} className="bg-cyber-900 border border-cyber-700 rounded p-3">
                                            <div className="flex items-center justify-between gap-3">
                                                <div className="text-sm font-semibold text-white">{finding.name || finding.pocId}</div>
                                                {finding.severity ? (
                                                    <span className="text-[10px] uppercase text-amber-300 border border-amber-800 bg-amber-950/30 px-2 py-0.5 rounded">
                                                        {finding.severity}
                                                    </span>
                                                ) : null}
                                            </div>
                                            {(finding.description || finding.details) ? (
                                                <div className="text-xs text-gray-300 mt-2 whitespace-pre-wrap">
                                                    {finding.description || finding.details}
                                                </div>
                                            ) : null}
                                            {finding.detectedAt ? (
                                                <div className="text-[11px] text-gray-500 mt-2 font-mono">
                                                    detectedAt: {finding.detectedAt}
                                                </div>
                                            ) : null}
                                        </div>
                                    ))}
                                </div>
                            </div>
                        )}

                        {selectedSession.mode === 'agent' && (plannerSteps.length > 0 || supervisorEvents.length > 0) && (
                            <div className="grid grid-cols-1 xl:grid-cols-2 gap-4">
                                <div className="bg-cyber-800 border border-cyber-700 rounded-lg p-4 shrink-0">
                                    <h3 className="text-sm font-bold text-white mb-3 flex items-center gap-2">
                                        <List size={14} className="text-cyan-400" />
                                        Planner Blueprint
                                    </h3>
                                    {plannerSummary ? (
                                        <p className="text-sm text-gray-300 mb-4 leading-relaxed">{plannerSummary}</p>
                                    ) : (
                                        <div className="text-xs text-gray-500 italic">No planner summary available.</div>
                                    )}
                                    {plannerSteps.length > 0 && (
                                        <div className="space-y-2">
                                            {plannerSteps.map((step) => (
                                                <div key={`${step.step}-${step.title}`} className="bg-cyber-900 border border-cyber-700 rounded p-3">
                                                    <div className="flex items-center justify-between gap-3 mb-1">
                                                        <div className="text-sm font-semibold text-white">{step.step}. {step.title}</div>
                                                        {Array.isArray(step.depends_on) && step.depends_on.length > 0 ? (
                                                            <span className="text-[10px] text-gray-500 font-mono">depends_on: {step.depends_on.join(', ')}</span>
                                                        ) : null}
                                                    </div>
                                                    <div className="text-xs text-gray-300">目标: {step.objective || '未提供'}</div>
                                                    <div className="text-xs text-cyan-300 mt-1">成功标准: {step.success_criteria || '未提供'}</div>
                                                </div>
                                            ))}
                                        </div>
                                    )}
                                    {plannerGuardrails.length > 0 && (
                                        <div className="mt-4 pt-3 border-t border-cyber-700">
                                            <div className="text-[11px] font-bold text-gray-400 uppercase tracking-wider mb-2">Guardrails</div>
                                            <div className="flex flex-wrap gap-2">
                                                {plannerGuardrails.map((rule, index) => (
                                                    <span key={`${rule}-${index}`} className="text-[11px] bg-cyan-950/20 text-cyan-300 border border-cyan-900/40 px-2 py-1 rounded">
                                                        {rule}
                                                    </span>
                                                ))}
                                            </div>
                                        </div>
                                    )}
                                </div>

                                <div className="bg-cyber-800 border border-cyber-700 rounded-lg p-4 shrink-0">
                                    <h3 className="text-sm font-bold text-white mb-3 flex items-center gap-2">
                                        <AlertTriangle size={14} className="text-amber-400" />
                                        Supervisor Events
                                    </h3>
                                    {(supervisorMetrics.total_events || supervisorAdjustments.length > 0) && (
                                        <div className="grid grid-cols-2 gap-2 mb-4">
                                            <div className="bg-cyber-900 border border-cyber-700 rounded p-2">
                                                <div className="text-[10px] text-gray-500 uppercase">Events</div>
                                                <div className="text-lg font-mono text-amber-300">{supervisorMetrics.total_events || 0}</div>
                                            </div>
                                            <div className="bg-cyber-900 border border-cyber-700 rounded p-2">
                                                <div className="text-[10px] text-gray-500 uppercase">Pruned Steps</div>
                                                <div className="text-lg font-mono text-red-300">{supervisorMetrics.pruned_steps || 0}</div>
                                            </div>
                                            <div className="bg-cyber-900 border border-cyber-700 rounded p-2">
                                                <div className="text-[10px] text-gray-500 uppercase">No Progress</div>
                                                <div className="text-lg font-mono text-amber-300">{supervisorMetrics.no_progress_events || 0}</div>
                                            </div>
                                            <div className="bg-cyber-900 border border-cyber-700 rounded p-2">
                                                <div className="text-[10px] text-gray-500 uppercase">Execution Errors</div>
                                                <div className="text-lg font-mono text-red-300">{supervisorMetrics.execution_errors || 0}</div>
                                            </div>
                                        </div>
                                    )}
                                    {supervisorAdjustments.length > 0 && (
                                        <div className="mb-4 pt-3 border-t border-cyber-700">
                                            <div className="text-[11px] font-bold text-gray-400 uppercase tracking-wider mb-2">Automatic Adjustments</div>
                                            <div className="space-y-2">
                                                {supervisorAdjustments.map((adjustment, index) => (
                                                    <div key={`${adjustment.type}-${adjustment.timestamp || index}`} className="bg-cyber-900 border border-cyber-700 rounded p-2">
                                                        <div className="text-xs font-semibold text-white">{adjustment.type}</div>
                                                        <div className="text-[11px] text-gray-300 mt-1">{adjustment.message}</div>
                                                        {adjustment.affected_steps && adjustment.affected_steps.length > 0 ? (
                                                            <div className="text-[10px] text-gray-500 font-mono mt-1">steps: {adjustment.affected_steps.join(', ')}</div>
                                                        ) : null}
                                                    </div>
                                                ))}
                                            </div>
                                        </div>
                                    )}
                                    {supervisorEvents.length > 0 ? (
                                        <div className="space-y-2">
                                            {supervisorEvents.map((event, index) => (
                                                <div key={`${event.scope}-${event.timestamp || index}`} className="bg-cyber-900 border border-cyber-700 rounded p-3">
                                                    <div className="flex items-center justify-between gap-3 mb-2">
                                                        <div className="text-sm font-semibold text-white">
                                                            {event.phase ? `${event.phase.toUpperCase()} · ` : ''}{event.scope}
                                                        </div>
                                                        <span className={`text-[10px] uppercase px-2 py-0.5 rounded border ${
                                                            event.severity === 'error'
                                                                ? 'text-red-300 border-red-800 bg-red-950/30'
                                                                : 'text-amber-300 border-amber-800 bg-amber-950/30'
                                                        }`}>
                                                            {event.severity}
                                                        </span>
                                                    </div>
                                                    <div className="text-xs text-gray-300 whitespace-pre-wrap">{event.message}</div>
                                                    {event.timestamp ? (
                                                        <div className="text-[11px] text-gray-500 font-mono mt-2">{event.timestamp}</div>
                                                    ) : null}
                                                </div>
                                            ))}
                                        </div>
                                    ) : (
                                        <div className="text-xs text-gray-500 italic">No supervisor events recorded.</div>
                                    )}
                                </div>
                            </div>
                        )}

                        {selectedSession.mode === 'agent' && sessionArtifacts.length > 0 && (
                            <div className="bg-cyber-800 border border-cyber-700 rounded-lg p-4 shrink-0">
                                <h3 className="text-sm font-bold text-white mb-3 flex items-center gap-2">
                                    <FileText size={14} className="text-cyan-400" />
                                    Session Artifacts
                                </h3>
                                <div className="grid grid-cols-2 md:grid-cols-4 gap-2 mb-4">
                                    {Object.entries(artifactSummary).map(([type, count]) => (
                                        <div key={type} className="bg-cyber-900 border border-cyber-700 rounded p-2">
                                            <div className="text-[10px] text-gray-500 uppercase">{type}</div>
                                            <div className="text-lg font-mono text-cyan-300">{count}</div>
                                        </div>
                                    ))}
                                </div>
                                <div className="space-y-2 max-h-52 overflow-y-auto pr-1">
                                    {sessionArtifacts.slice().reverse().map((artifact) => (
                                        <div key={artifact.id} className="bg-cyber-900 border border-cyber-700 rounded p-3">
                                            <div className="flex items-center justify-between gap-3">
                                                <div className="text-sm font-semibold text-white">{artifact.artifact_type}</div>
                                                <div className="text-[10px] text-gray-500 font-mono">{artifact.created_at || 'N/A'}</div>
                                            </div>
                                            <div className="text-xs text-gray-300 mt-1">
                                                {artifact.poc_name || artifact.poc_filename || 'session artifact'}
                                            </div>
                                            {artifact.trace_id ? (
                                                <div className="text-[10px] text-gray-500 font-mono mt-1">trace: {artifact.trace_id}</div>
                                            ) : null}
                                        </div>
                                    ))}
                                </div>
                            </div>
                        )}

                        {selectedSession.assessment?.attackGraph && (
                            <AttackGraph
                                graph={selectedSession.assessment.attackGraph}
                                physicalImpact={selectedSession.assessment.physicalImpact}
                                remediationPlan={selectedSession.assessment.remediationPlan}
                                compact
                            />
                        )}
                    </div>
                </div>
            </div>
        );
    }

    return (
        <div className="p-6 h-full flex flex-col">
            <div className="flex justify-between items-center mb-6">
                <h2 className="text-2xl font-bold text-white flex items-center gap-2">
                    <Clock className="text-cyber-accent" /> Scan History
                </h2>
                <div className="flex items-center gap-3">
                    <span className="text-sm text-gray-500">Total Records: {displayHistory.length}</span>
                    {supervisorTrend.snapshots.length > 0 && (
                        <button
                            onClick={exportSupervisorMetrics}
                            className="text-[11px] bg-cyber-900 border border-cyber-700 hover:border-cyber-accent text-white px-3 py-1.5 rounded flex items-center gap-1"
                        >
                            <Download size={12} className="text-cyber-accent" />
                            Export Supervisor Metrics
                        </button>
                    )}
                </div>
            </div>

            {loading ? (
                <div className="flex-1 flex items-center justify-center text-cyber-accent">
                    <div className="w-8 h-8 border-4 border-cyber-accent border-t-transparent rounded-full animate-spin"></div>
                </div>
            ) : dbHistory.length === 0 && localHistory.length === 0 ? (
                <div className="flex-1 flex flex-col items-center justify-center text-gray-500 border border-dashed border-cyber-700 rounded-lg">
                    <List size={48} className="mb-4 opacity-50" />
                    <p className="text-lg">No scan history available.</p>
                    <p className="text-sm">Run a Global Auto Scan to save records here.</p>
                </div>
            ) : (
                <div className="flex-1 flex flex-col min-h-0">
                    <div className="flex items-center justify-between mb-2 px-2">
                        <div className="flex items-center gap-3">
                            <button
                                onClick={toggleSelectAll}
                                className="text-gray-500 hover:text-white flex items-center gap-1.5 text-xs transition-colors"
                            >
                                {selectedIds.size > 0 && selectedIds.size === displayHistory.filter(s => s.dbId).length ? (
                                    <CheckSquare size={14} className="text-cyber-accent" />
                                ) : (
                                    <Square size={14} />
                                )}
                                {selectedIds.size > 0 ? `Deselect All (${selectedIds.size})` : 'Select All'}
                            </button>
                            
                            {selectedIds.size > 0 && (
                                <button
                                    onClick={handleDeleteBatch}
                                    disabled={isDeleting}
                                    className="text-red-400 hover:text-red-300 font-bold text-xs flex items-center gap-1 bg-red-900/20 px-2 py-1 rounded border border-red-900/50 transition-all disabled:opacity-50"
                                >
                                    <Trash2 size={13} />
                                    Delete Selected
                                </button>
                            )}
                        </div>
                    </div>

                    <div className="grid grid-cols-1 gap-4 overflow-y-auto pr-2 custom-scrollbar">
                    {supervisorTrend.snapshots.length > 0 && (
                        <div className="bg-cyber-800 border border-cyber-700 rounded-lg p-4">
                            <div className="flex items-center justify-between mb-4">
                                <h3 className="text-sm font-bold text-white uppercase tracking-wider">Supervisor Trend Snapshot</h3>
                                <span className="text-[11px] text-gray-500">Recent {supervisorTrend.snapshots.length} snapshots</span>
                            </div>
                            <div className="grid grid-cols-2 lg:grid-cols-4 gap-3 mb-4">
                                <div className="bg-cyber-900 border border-cyber-700 rounded p-3">
                                    <div className="text-[10px] text-gray-500 uppercase">Events</div>
                                    <div className="text-xl font-mono text-amber-300">{supervisorTrend.totals.events}</div>
                                </div>
                                <div className="bg-cyber-900 border border-cyber-700 rounded p-3">
                                    <div className="text-[10px] text-gray-500 uppercase">Pruned Steps</div>
                                    <div className="text-xl font-mono text-red-300">{supervisorTrend.totals.pruned}</div>
                                </div>
                                <div className="bg-cyber-900 border border-cyber-700 rounded p-3">
                                    <div className="text-[10px] text-gray-500 uppercase">No Progress</div>
                                    <div className="text-xl font-mono text-amber-300">{supervisorTrend.totals.noProgress}</div>
                                </div>
                                <div className="bg-cyber-900 border border-cyber-700 rounded p-3">
                                    <div className="text-[10px] text-gray-500 uppercase">Execution Errors</div>
                                    <div className="text-xl font-mono text-red-300">{supervisorTrend.totals.errors}</div>
                                </div>
                            </div>
                            <div className="space-y-2">
                                {supervisorTrend.snapshots.map((snapshot) => {
                                    const metrics = snapshot.metrics || {};
                                    return (
                                        <div key={`trend-${snapshot.session_id}-${snapshot.created_at}`} className="bg-cyber-900 border border-cyber-700 rounded p-3 flex flex-col lg:flex-row lg:items-center lg:justify-between gap-3">
                                            <div>
                                                <div className="text-sm font-semibold text-white">{snapshot.target_ip || snapshot.session_id}</div>
                                                <div className="text-[11px] text-gray-500 font-mono">{snapshot.created_at ? new Date(snapshot.created_at).toLocaleString() : 'N/A'}</div>
                                            </div>
                                            <div className="flex flex-wrap gap-2 text-[11px]">
                                                <span className="px-2 py-1 rounded bg-amber-950/30 text-amber-300 border border-amber-800">events {metrics.total_events || 0}</span>
                                                <span className="px-2 py-1 rounded bg-red-950/30 text-red-300 border border-red-800">pruned {metrics.pruned_steps || 0}</span>
                                                <span className="px-2 py-1 rounded bg-cyan-950/30 text-cyan-300 border border-cyan-800">profile {snapshot.model_profile || 'unknown'}</span>
                                            </div>
                                        </div>
                                    );
                                })}
                            </div>
                        </div>
                    )}
                    {displayHistory.map((session) => (
                        <div
                            key={session.id}
                            onClick={() => setSelectedSession(session)}
                            className={`bg-cyber-800 border ${selectedIds.has(session.dbId!) ? 'border-cyber-accent/50 bg-cyber-accent/5' : 'border-cyber-700'} p-5 rounded-lg hover:border-cyber-500 cursor-pointer transition-all flex justify-between items-center group relative overflow-hidden`}
                        >

                            <div className="flex items-center gap-4">
                                <button
                                    onClick={(e) => toggleSelect(e, session.dbId)}
                                    className={`w-5 h-5 shrink-0 flex items-center justify-center rounded border ${selectedIds.has(session.dbId!) ? 'border-cyber-accent bg-cyber-accent/20 text-cyber-accent' : 'border-cyber-700 text-gray-600'} hover:border-cyber-accent transition-colors`}
                                >
                                    {selectedIds.has(session.dbId!) && <CheckSquare size={14} />}
                                </button>
                                <div className={`w-10 h-10 shrink-0 rounded-full flex items-center justify-center ${session.results.filter(r => r.vulnerable).length > 0 ? 'bg-red-900/20 text-red-500' : 'bg-green-900/20 text-green-500'}`}>
                                    {session.results.filter(r => r.vulnerable).length > 0 ? <AlertTriangle size={20} /> : <Shield size={20} />}
                                </div>
                                <div className="flex flex-col justify-center">
                                    <div className="flex items-center gap-2 mb-1.5">
                                        <h3 className="font-bold text-white text-base leading-none">{session.targetName}</h3>
                                        {session.mode === 'agent' && (
                                            <span className="text-[10px] bg-purple-900/40 text-purple-300 border border-purple-700 px-2 py-0.5 rounded leading-none flex items-center">AGENT SCAN</span>
                                        )}
                                    </div>
                                    <div className="flex flex-wrap items-center gap-x-2 gap-y-1 text-xs text-gray-400 leading-none">
                                        <span className="font-mono">{session.id}</span>
                                        <span className="hidden sm:inline opacity-30">|</span>
                                        <span>{new Date(session.startTime).toLocaleString()}</span>
                                        {currentUser.role === 'admin' && (
                                            <>
                                                <span className="hidden sm:inline opacity-30">|</span>
                                                <span className="font-mono">OP: <span className="text-cyber-accent">{session.username || 'System'}</span></span>
                                            </>
                                        )}
                                    </div>
                                </div>
                            </div>

                                <div className="flex items-center gap-3">
                                    <div className="flex items-center gap-8">
                                        <div className="text-right">
                                            <div className="text-xs text-gray-500 uppercase">Risk Score</div>
                                            <div className={`font-bold font-mono ${session.riskScore > 50 ? 'text-cyber-danger' : 'text-cyber-success'}`}>{session.riskScore}</div>
                                        </div>
                                        <div className="text-right">
                                            <div className="text-xs text-gray-500 uppercase">Vulns</div>
                                            <div className="font-bold font-mono text-white">{session.results.filter(r => r.vulnerable).length}</div>
                                        </div>
                                        <ChevronRight className="text-gray-600 group-hover:text-white transition-colors" />
                                    </div>
                                    
                                    <button
                                        onClick={(e) => handleDelete(e, session.dbId)}
                                        disabled={isDeleting}
                                        className="p-2 text-gray-600 hover:text-red-400 opacity-0 group-hover:opacity-100 transition-all ml-2"
                                        title="Delete Record"
                                    >
                                        <Trash2 size={18} />
                                    </button>
                                </div>
                        </div>
                    ))}
                </div>
            </div>
        )}
        </div>
    );
};

export default ScanHistory;
