import React, { useState } from 'react';
import { ScanSession, POC } from '../types';
import { Clock, AlertTriangle, CheckCircle, FileText, ChevronRight, X, List, Shield, Download } from 'lucide-react';
import ScanLogs from './ScanLogs';
import { POC_DATABASE } from '../constants';
import PocDetailModal from './PocDetailModal';
import { getBackendUrl } from '../services/api';

interface ScanHistoryProps {
    localHistory?: ScanSession[];
    currentUser: any;
    token: string | null;
    onUnauthorized?: () => void;
}

const ScanHistory: React.FC<ScanHistoryProps> = ({ currentUser, token, localHistory = [], onUnauthorized }) => {

    const [selectedSession, setSelectedSession] = useState<ScanSession | null>(null);
    const [selectedResultPoc, setSelectedResultPoc] = useState<POC | null>(null);
    const [dbHistory, setDbHistory] = useState<ScanSession[]>([]);
    const [loading, setLoading] = useState(true);

    React.useEffect(() => {
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
                            timestamp: new Date(h.started_at).getTime(),
                            targetName: isWrapper && parsedJson.targetName ? parsedJson.targetName : (h.target_ip || 'Unknown Target'),
                            connection: isWrapper && parsedJson.connection ? parsedJson.connection : { ip: h.target_ip, bluetoothMac: h.target_mac, port: '', canInterface: '', url: '', frequency: '', interface: '' },
                            totalScans: finalResults.length,
                            vulnerabilitiesFound: finalResults.filter((r: any) => r.vulnerable).length,
                            status: h.risk_score > 0 ? 'vulnerable' : 'secure',
                            duration: 'N/A',
                            startTime: h.started_at,
                            endTime: h.completed_at,
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
                            mode: isWrapper && parsedJson.mode ? parsedJson.mode : 'batch'
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
        fetchHistory();
    }, [token]);

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
                    {/* Meta Info */}
                    <div className="space-y-6 flex flex-col">
                        <div className="bg-cyber-800 border border-cyber-700 p-6 rounded-lg">
                            <div className="flex items-center gap-3 mb-2">
                                <h2 className="text-xl font-bold text-white">{selectedSession.targetName}</h2>
                                {selectedSession.mode === 'agent' && (
                                    <span className="text-[10px] bg-purple-900/40 text-purple-300 border border-purple-700 px-2 py-0.5 rounded uppercase tracking-wider">Agent Scan</span>
                                )}
                            </div>
                            <div className="text-sm text-gray-400 font-mono mb-4">{selectedSession.id}</div>

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
                    </div>

                    {/* Main Content */}
                    <div className="lg:col-span-2 flex flex-col gap-6 h-full overflow-hidden">
                        {/* Tabs or Split view? Let's stack Logs + Report/Results */}
                        <div className="h-96 shrink-0">
                            <ScanLogs logs={selectedSession.logs} />
                        </div>

                        <div className="flex-1 flex gap-6 overflow-hidden">
                            {/* Results List */}
                            <div className="flex-1 bg-cyber-800 border border-cyber-700 rounded-lg p-4 overflow-y-auto">
                                <h3 className="text-sm font-bold text-white mb-3 flex items-center gap-2 sticky top-0 bg-cyber-800 pb-2">
                                    <AlertTriangle size={14} className="text-yellow-500" />
                                    Vulnerabilities ({vulnCount})
                                </h3>
                                <div className="space-y-2">
                                    {selectedSession.results.filter(r => r.vulnerable).map((res) => {
                                        // Helper to extract filename without index number or path
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

                            {/* AI Report */}
                            <div className="flex-1 bg-cyber-800 border border-cyber-accent/30 rounded-lg p-4 overflow-y-auto">
                                <div className="flex justify-between items-center mb-3 sticky top-0 bg-cyber-800 pb-2 z-10">
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
                <span className="text-sm text-gray-500">Total Records: {dbHistory.length}</span>
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
                <div className="grid grid-cols-1 gap-4 overflow-y-auto">
                    {Array.from(
                        new Map<string, ScanSession>(
                            (dbHistory.length > 0 ? dbHistory : localHistory)
                                .slice()
                                .map(session => [session.id, session])
                        ).values()
                    ).map((session) => (
                        <div
                            key={session.id}
                            onClick={() => setSelectedSession(session)}
                            className="bg-cyber-800 border border-cyber-700 p-5 rounded-lg hover:border-cyber-500 cursor-pointer transition-all flex justify-between items-center group relative overflow-hidden"
                        >

                            <div className="flex items-center gap-4">
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
                        </div>
                    ))}
                </div>
            )}
        </div>
    );
};

export default ScanHistory;