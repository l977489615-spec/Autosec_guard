import React, { useState, useEffect } from 'react';
import { ScanSession, ScanLog, ScanResult, Severity, POC, Category, ConnectionParams } from '../types';
import { POC_DATABASE } from '../constants';
import ScanLogs from './ScanLogs';
import { generateSecurityReport } from '../services/LLMService';
import PocDetailModal from './PocDetailModal';
import ManualTestModal from './ManualTestModal';
import { checkBackendHealth, executePocScript, setBackendUrl, getBackendUrl, listPocs, fingerprintOS, runPocPlugin, saveScanSession } from '../services/api';
import { Play, RotateCw, FileText, AlertTriangle, ShieldCheck, Wifi, Cable, Bluetooth, Power, Crosshair, List, Server, ArrowRight, Settings, Save, WifiOff, Link, CheckCircle, Radio, Activity, Download, ChevronRight } from 'lucide-react';

type ScannerMode = 'SELECTION' | 'GLOBAL' | 'MANUAL';

interface ScannerProps {
  onAddToHistory: (session: ScanSession) => void;
  mode: ScannerMode;
  setMode: (mode: ScannerMode) => void;
  session: ScanSession;
  setSession: React.Dispatch<React.SetStateAction<ScanSession>>;
  engineUrl: string;
  setEngineUrl: (url: string) => void;
  engineStatus: 'unknown' | 'online' | 'offline';
  setEngineStatus: (status: 'unknown' | 'online' | 'offline') => void;
  token: string | null;
}

// Helper to render markdown-ish text to HTML
const MarkdownRenderer: React.FC<{ content: string }> = ({ content }) => {
  if (!content) return null;

  // Very basic conversion for common patterns
  const lines = content.split('\n');
  return (
    <div className="space-y-2">
      {lines.map((line, i) => {
        if (line.startsWith('### ')) {
          return <h3 key={i} className="text-lg font-bold text-cyber-accent mt-4 mb-2 border-b border-cyber-700/50 pb-1 uppercase tracking-wider">{line.replace('### ', '')}</h3>;
        }
        if (line.startsWith('## ')) {
          return <h2 key={i} className="text-xl font-bold text-white mt-6 mb-3 border-l-4 border-cyber-accent pl-3">{line.replace('## ', '')}</h2>;
        }
        if (line.startsWith('- ')) {
          return <li key={i} className="ml-4 list-disc text-gray-300">{line.replace('- ', '')}</li>;
        }

        // Handle bold **text**
        const parts = line.split(/(\*\*.*?\*\*)/g);
        return (
          <p key={i} className="leading-relaxed">
            {parts.map((part, j) => {
              if (part.startsWith('**') && part.endsWith('**')) {
                return <strong key={j} className="text-white font-bold">{part.slice(2, -2)}</strong>;
              }
              return part;
            })}
          </p>
        );
      })}
    </div>
  );
};
const Scanner: React.FC<ScannerProps> = ({
  onAddToHistory,
  mode, setMode,
  session, setSession,
  engineUrl, setEngineUrl,
  engineStatus, setEngineStatus,
  token
}) => {
  const [isAnalysing, setIsAnalysing] = useState(false);
  const [selectedResultPoc, setSelectedResultPoc] = useState<POC | null>(null);

  // Contents of PoC scripts fetched from backend
  const [pocContents, setPocContents] = useState<Record<string, string>>({});

  // State for Manual Mode
  const [manualTestPoc, setManualTestPoc] = useState<POC | null>(null);
  // Manual View Detail Modal State
  const [manualDetailPoc, setManualDetailPoc] = useState<POC | null>(null);

  const [filterCategory, setFilterCategory] = useState<string>('All');
  const [manualSearch, setManualSearch] = useState('');

  // Effect to update API service when user types new URL
  useEffect(() => {
    setBackendUrl(engineUrl);
  }, [engineUrl]);

  // Initial check on mount
  useEffect(() => {
    checkEngine();
    fetchPocs();
  }, []);

  const fetchPocs = async () => {
    const data = await listPocs();
    if (data && data.pocs) {
      const contentsMap: Record<string, string> = {};
      data.pocs.forEach((p: any) => {
        const matchingDbPoc = POC_DATABASE.find(db => db.pocFile === p.filename);
        if (matchingDbPoc && p.content) {
          contentsMap[matchingDbPoc.id] = p.content;
        }
      });
      setPocContents(contentsMap);
    }
  };

  const checkEngine = async () => {
    setEngineStatus('unknown');
    const isUp = await checkBackendHealth();
    setEngineStatus(isUp ? 'online' : 'offline');
    if (isUp) addLog(`Execution Engine detected at ${engineUrl}`, 'success');
  };

  const addLog = (message: string, type: ScanLog['type'] = 'info') => {
    setSession(prev => ({
      ...prev,
      logs: [...prev.logs, { timestamp: new Date().toLocaleTimeString(), message, type }]
    }));
  };

  const handleGlobalConnect = async () => {
    setSession(prev => ({ ...prev, status: 'connecting', logs: [] }));

    addLog(`Targeting Execution Engine at: ${engineUrl}...`);

    // Check Backend
    const isBackendUp = await checkBackendHealth();
    setEngineStatus(isBackendUp ? 'online' : 'offline');

    if (!isBackendUp) {
      addLog(`Error: Execution Engine unavailable at ${engineUrl}`, 'error');
      addLog(`Tip: Ensure 'server.py' is running and CORS is enabled.`, 'warning');
      setSession(prev => ({ ...prev, status: 'idle' }));
      return;
    }
    addLog(`Execution Engine Online & Ready.`, 'success');

    // Relaxed validation for global mode: At least one parameter
    const { ip, bluetoothMac, canInterface, interface: wifiIf, frequency } = session.connection;
    if (!session.targetName || (!ip && !bluetoothMac && !canInterface && !wifiIf && !frequency)) {
      addLog("Error: Target Name and at least one parameter (IP, BT MAC, CAN, WiFi, or RF) are required for Global Scan.", 'error');
      setSession(prev => ({ ...prev, status: 'idle' }));
      return;
    }

    addLog(`Initiating global system handshake with ${session.targetName}...`);

    // Simulate connection phases (Visual only, since real connection happens during execution)
    await new Promise(r => setTimeout(r, 600));
    setSession(prev => ({ ...prev, isConnected: true, status: 'idle' }));
    addLog(`System ready. Parameters latched. Waiting for batch command.`, 'success');
  };

  const startBatchScan = async () => {
    if (!session.isConnected) return;

    // Reset report and ID for new run
    const newSessionId = `SCAN-${Date.now().toString().slice(-6)}`;

    setSession(prev => ({
      ...prev,
      id: newSessionId,
      startTime: new Date().toISOString(),
      status: 'running',
      results: [],
      riskScore: 0,
      aiReport: null
    }));

    addLog(`Starting batch execution of ${POC_DATABASE.length} modules...`, 'info');
    addLog(`Engine: ${engineUrl} | Target: ${session.targetName}`, 'info');

    let detectedOS = 'unknown';
    if (session.connection.ip) {
      addLog(`Fingerprinting target OS at ${session.connection.ip}...`, 'info');
      const fp = await fingerprintOS(session.connection.ip);
      detectedOS = fp.os;
      addLog(`[OS Target] Detected: ${fp.os.toUpperCase()} (${fp.details})`, 'info');
    }

    const results: ScanResult[] = [];
    let riskAccumulator = 0;
    let vulnCount = 0;
    let secureCount = 0;
    let errorCount = 0;

    for (let i = 0; i < POC_DATABASE.length; i++) {
      const poc = POC_DATABASE[i];
      const progress = `[${i + 1}/${POC_DATABASE.length}]`;

      // Check if required params are met for this PoC
      const { ip, bluetoothMac, canInterface, interface: wifiIf, frequency } = session.connection;
      const missingParams = poc.requiredParams.filter(p => {
        if (p === 'ip' && !ip) return true;
        if (p === 'bluetooth_mac' && !bluetoothMac) return true;
        if (p === 'can_interface' && !canInterface) return true;
        if (p === 'interface' && !wifiIf) return true;
        if (p === 'frequency' && !frequency) return true;
        return false;
      });

      if (missingParams.length > 0) {
        addLog(`${progress} ⏭ ${poc.id}: ${poc.name} — Skipped (Missing: ${missingParams.join(', ')})`, 'warning');
        continue;
      }

      // Check OS compatibility
      if (poc.targetOS !== undefined && detectedOS !== 'unknown') {
        if (!poc.targetOS.includes(detectedOS as any) && !poc.targetOS.includes('all')) {
          addLog(`${progress} ⏭ ${poc.id}: ${poc.name} — Skipped (OS Mismatch: Target is ${detectedOS.toUpperCase()}, PoC requires ${poc.targetOS.join('/')})`, 'warning');
          continue;
        }
      }
      addLog(`${progress} ${poc.id}: ${poc.name} — Executing...`, 'info');

      const startTime = Date.now();

      // Execute Real via the Plugin Loader (Handles parameters and subdirectories natively)
      const result = await runPocPlugin(poc.pocFile, session.connection as any);
      const elapsed = ((Date.now() - startTime) / 1000).toFixed(1);

      // Show stdout lines from the execution
      if (result.logs && result.logs.length > 0) {
        for (const line of result.logs) {
          addLog(`  ┃ ${line}`, 'terminal');
        }
      }

      // Show stderr if any
      if (result.errors && result.errors.length > 0 && !result.success) {
        for (const err of result.errors.slice(0, 3)) {
          addLog(`  ┃ [STDERR] ${err}`, 'warning');
        }
      }

      if (result.success) {
        if (result.vulnerable) {
          addLog(`${progress} ✗ ${poc.name} → VULNERABLE (${elapsed}s)`, 'error');
          vulnCount++;
          results.push({
            pocId: poc.id,
            vulnerable: true,
            details: `Exploit confirmed. ${result.logs[result.logs.length - 1] || 'Verified'}`,
            detectedAt: new Date().toISOString(),
            elapsedSeconds: parseFloat(elapsed)
          });
          const score = poc.severity === Severity.CRITICAL ? 10 : poc.severity === Severity.HIGH ? 7 : 3;
          riskAccumulator += score;
        } else {
          addLog(`${progress} ✓ ${poc.name} → Secure (${elapsed}s)`, 'success');
          secureCount++;
          results.push({
            pocId: poc.id,
            vulnerable: false,
            details: 'Target secure.',
            detectedAt: new Date().toISOString(),
            elapsedSeconds: parseFloat(elapsed)
          });
        }
      } else {
        addLog(`${progress} ! ${poc.name} → Error (${elapsed}s): ${result.errors[0] || 'Unknown'}`, 'warning');
        errorCount++;
        results.push({
          pocId: poc.id,
          vulnerable: false,
          details: `Test Error: ${result.errors[0] || 'Check Engine Connection'}`,
          detectedAt: new Date().toISOString(),
          elapsedSeconds: parseFloat(elapsed)
        });
      }
    }

    addLog(`━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━`, 'info');
    addLog(`Batch Scan Complete: ${vulnCount} Vulnerable | ${secureCount} Secure | ${errorCount} Errors`, vulnCount > 0 ? 'error' : 'success');

    const finalSession: ScanSession = {
      ...session,
      id: newSessionId, // Ensure the generated ID is used
      status: 'completed',
      endTime: new Date().toISOString(),
      results,
      riskScore: Math.min(riskAccumulator, 100)
    };

    setSession(finalSession);

    // Auto save to history (Frontend State)
    onAddToHistory(finalSession);

    // Auto save to history (Backend DB)
    saveScanSession(finalSession, token);
  };

  const handleAiAnalysis = async () => {
    setIsAnalysing(true);
    const report = await generateSecurityReport(session);
    setSession(prev => {
      const updated = { ...prev, aiReport: report };
      // Sync to DB when report is generated
      saveScanSession(updated, token);
      return updated;
    });
    setIsAnalysing(false);
  };

  const handleDownloadPdf = () => {
    if (!session.aiReport) return;

    const now = new Date(session.startTime || Date.now()).toLocaleString('zh-CN', { hour12: false });
    const targetInfo = session.targetName || session.connection.ip || 'Unknown Target';

    // Parse Markdown manually like AgentScan to ensure clean print styles
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
        <span><span class="label">报告类型：</span>常规扫描引擎报告</span>
        <span><span class="label">工具版本：</span>AutoSec Guard v2.0 · Qwen-Max (千问)</span>
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
    if (!printWindow) {
      alert("Please allow popups to generate the PDF report.");
      return;
    }

    printWindow.document.write(html);
    printWindow.document.close();
  };

  const handleLaunchManualTest = (poc: POC) => {
    setManualDetailPoc(null);
    setManualTestPoc(poc);
  };

  const filteredManualPocs = POC_DATABASE.filter(p => {
    const matchesCat = filterCategory === 'All' || p.category === filterCategory;
    const matchesSearch = p.name.toLowerCase().includes(manualSearch.toLowerCase()) || p.id.toLowerCase().includes(manualSearch.toLowerCase());
    return matchesCat && matchesSearch;
  });

  // --- RENDER HELPERS ---

  const renderSelectionScreen = () => (
    <div className="flex flex-col items-center justify-center h-full p-8 space-y-8 animate-fade-in">
      <div className="text-center space-y-2">
        <h2 className="text-3xl font-bold text-white tracking-tight">Select Scanning Operation</h2>
        <p className="text-gray-400">Choose the appropriate operational mode for your security assessment.</p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-8 w-full max-w-4xl">
        {/* Global Auto Option */}
        <button
          onClick={() => {
            setMode('GLOBAL');
            setSession(p => ({ ...p, mode: 'batch' }));
            checkEngine(); // Re-check on mode switch
          }}
          className="group relative bg-cyber-800 border border-cyber-700 hover:border-cyber-accent p-8 rounded-xl text-left transition-all duration-300 hover:shadow-[0_0_30px_rgba(0,240,255,0.1)]"
        >
          <div className="absolute top-0 left-0 w-full h-1 bg-gradient-to-r from-cyber-500 to-cyber-accent opacity-0 group-hover:opacity-100 transition-opacity rounded-t-xl" />
          <div className="mb-6 bg-cyber-900 w-16 h-16 rounded-lg flex items-center justify-center border border-cyber-700 group-hover:border-cyber-accent/50 group-hover:scale-110 transition-all">
            <Server className="text-cyber-accent w-8 h-8" />
          </div>
          <h3 className="text-xl font-bold text-white mb-2 flex items-center gap-2">
            Global Auto Scan <ArrowRight size={16} className="opacity-0 group-hover:opacity-100 transition-opacity -translate-x-2 group-hover:translate-x-0" />
          </h3>
          <p className="text-gray-400 text-sm leading-relaxed mb-4">
            Perform a comprehensive batch scan of the entire vehicle ecosystem.
            Requires local Python execution engine.
          </p>
          <div className="flex gap-2">
            <span className="text-xs bg-cyber-900 border border-cyber-700 px-2 py-1 rounded text-gray-400 font-mono">ALL INTERFACES</span>
            <span className="text-xs bg-cyber-900 border border-cyber-700 px-2 py-1 rounded text-gray-400 font-mono">REAL EXECUTION</span>
          </div>
        </button>

        {/* Manual Option */}
        <button
          onClick={() => {
            setMode('MANUAL');
            setSession(p => ({ ...p, mode: 'manual' }));
            checkEngine(); // Re-check on mode switch
          }}
          className="group relative bg-cyber-800 border border-cyber-700 hover:border-cyber-danger p-8 rounded-xl text-left transition-all duration-300 hover:shadow-[0_0_30px_rgba(255,51,102,0.1)]"
        >
          <div className="absolute top-0 left-0 w-full h-1 bg-gradient-to-r from-orange-500 to-cyber-danger opacity-0 group-hover:opacity-100 transition-opacity rounded-t-xl" />
          <div className="mb-6 bg-cyber-900 w-16 h-16 rounded-lg flex items-center justify-center border border-cyber-700 group-hover:border-cyber-danger/50 group-hover:scale-110 transition-all">
            <Crosshair className="text-cyber-danger w-8 h-8" />
          </div>
          <h3 className="text-xl font-bold text-white mb-2 flex items-center gap-2">
            Manual Diagnostic <ArrowRight size={16} className="opacity-0 group-hover:opacity-100 transition-opacity -translate-x-2 group-hover:translate-x-0" />
          </h3>
          <p className="text-gray-400 text-sm leading-relaxed mb-4">
            Select and execute specific POC modules individually.
            Target parameters are configured per vulnerability test.
          </p>
          <div className="flex gap-2">
            <span className="text-xs bg-cyber-900 border border-cyber-700 px-2 py-1 rounded text-gray-400 font-mono">SINGLE TARGET</span>
            <span className="text-xs bg-cyber-900 border border-cyber-700 px-2 py-1 rounded text-gray-400 font-mono">CONTROLLED</span>
          </div>
        </button>
      </div>
    </div>
  );

  return (
    <div className="h-full relative overflow-hidden">
      {/* Detail Modal for Result Inspection */}
      <PocDetailModal
        poc={selectedResultPoc ? { ...selectedResultPoc, codeSnippet: pocContents[selectedResultPoc.id] || selectedResultPoc.codeSnippet } : null}
        isOpen={!!selectedResultPoc}
        onClose={() => setSelectedResultPoc(null)}
      />

      {/* Detail Modal for Manual Mode Pre-flight Check */}
      <PocDetailModal
        poc={manualDetailPoc ? { ...manualDetailPoc, codeSnippet: pocContents[manualDetailPoc.id] || manualDetailPoc.codeSnippet } : null}
        isOpen={!!manualDetailPoc}
        onClose={() => setManualDetailPoc(null)}
        onRunTest={handleLaunchManualTest} // This enables the "Configure & Attack" button
      />

      {/* Execution Modal */}
      <ManualTestModal
        poc={manualTestPoc ? { ...manualTestPoc, codeSnippet: pocContents[manualTestPoc.id] || manualTestPoc.codeSnippet } : null}
        isOpen={!!manualTestPoc}
        onClose={() => setManualTestPoc(null)}
        // In Manual Mode, we pass empty connection params so user MUST input them
        globalConnection={mode === 'GLOBAL' ? session.connection : { ip: '', port: '', bluetoothMac: '', canInterface: '', url: '', frequency: '' }}
      />

      {/* Top Bar for Modes */}
      {mode !== 'SELECTION' && (
        <div className="absolute top-0 left-0 w-full h-12 bg-cyber-900 border-b border-cyber-700 flex items-center px-6 justify-between z-20">
          <button
            onClick={() => {
              setMode('SELECTION');
              setSession(p => ({ ...p, isConnected: false, status: 'idle', logs: [], results: [] }));
            }}
            className="text-xs font-bold text-gray-400 hover:text-white flex items-center gap-2"
          >
            ← CHANGE MODE
          </button>
          <div className="flex items-center gap-2">
            <span className={`w-2 h-2 rounded-full ${mode === 'GLOBAL' ? 'bg-cyber-accent' : 'bg-cyber-danger'}`}></span>
            <span className="text-xs font-mono font-bold text-white uppercase">{mode === 'GLOBAL' ? 'GLOBAL AUTO SCAN' : 'MANUAL DIAGNOSTIC'}</span>
          </div>
        </div>
      )}

      {/* Main Content Area */}
      <div className={`h-full ${mode !== 'SELECTION' ? 'pt-12' : ''}`}>

        {mode === 'SELECTION' && renderSelectionScreen()}

        {mode === 'GLOBAL' && (
          // Modified grid container to handle scrolling columns correctly
          <div className="p-6 grid grid-cols-1 lg:grid-cols-3 gap-6 h-full overflow-hidden">
            {/* Global Config Panel - Made scrollable independent of main layout */}
            <div className="lg:col-span-1 space-y-6 flex flex-col h-full overflow-y-auto pb-24 pr-2 custom-scrollbar">
              <div className="bg-cyber-800 border border-cyber-700 p-6 rounded-lg shadow-lg shrink-0">
                <h2 className="text-xl font-bold text-white mb-4 flex items-center gap-2">
                  <Settings className="text-cyber-400" />
                  Global Configuration
                </h2>

                {/* Engine Configuration Section */}
                <div className="mb-6 pb-6 border-b border-cyber-700 space-y-3">
                  <div className="flex justify-between items-center">
                    <label className="text-xs text-cyber-400 uppercase font-bold flex items-center gap-1">
                      <Link size={12} /> Execution Engine URL
                    </label>
                    <span className={`text-[10px] uppercase font-bold px-2 py-0.5 rounded ${engineStatus === 'online' ? 'bg-green-500/20 text-green-500' : 'bg-red-500/20 text-red-500'}`}>
                      {engineStatus}
                    </span>
                  </div>
                  <div className="flex gap-2">
                    <input
                      type="text"
                      value={engineUrl}
                      onChange={(e) => setEngineUrl(e.target.value)}
                      placeholder="http://localhost:5002"
                      className="flex-1 bg-cyber-900 border border-cyber-700 text-white p-2 text-sm rounded focus:border-cyber-accent outline-none font-mono"
                    />
                    <button
                      onClick={checkEngine}
                      title="Test Connection"
                      className="px-3 bg-cyber-700 hover:bg-cyber-600 text-white rounded border border-cyber-600"
                    >
                      <RotateCw size={14} className={engineStatus === 'unknown' ? 'animate-spin' : ''} />
                    </button>
                  </div>
                  {engineStatus === 'offline' && (
                    <p className="text-[10px] text-red-400">
                      * Cannot reach server. Run <code>python server.py</code> and check URL.
                    </p>
                  )}
                </div>

                <div className="space-y-4 mb-6">
                  <div>
                    <label className="text-xs text-gray-400 uppercase font-bold">Target System Name *</label>
                    <input
                      type="text"
                      value={session.targetName}
                      onChange={(e) => setSession(p => ({ ...p, targetName: e.target.value }))}
                      placeholder="e.g. Infotainment Unit A"
                      className="w-full mt-1 bg-cyber-900 border border-cyber-700 text-white p-2 rounded focus:border-cyber-500 outline-none"
                      disabled={session.isConnected}
                    />
                  </div>

                  <div className="p-3 bg-cyber-900/50 border border-cyber-700 rounded mb-2">
                    <p className="text-xs text-yellow-500 mb-2 font-mono flex items-center gap-1"><AlertTriangle size={12} /> PROVIDE AT LEAST ONE PARAMETER</p>
                    <div className="space-y-3">
                      <div>
                        <label className="text-xs text-gray-500 uppercase font-bold flex items-center gap-1"><Wifi size={10} /> IP Address (Optional)</label>
                        <input
                          type="text"
                          value={session.connection.ip}
                          onChange={(e) => setSession(p => ({ ...p, connection: { ...p.connection, ip: e.target.value } }))}
                          placeholder="192.168.x.x"
                          className="w-full mt-1 bg-cyber-900 border border-cyber-600 text-white p-1.5 text-sm rounded font-mono focus:border-cyber-accent outline-none"
                          disabled={session.isConnected}
                        />
                      </div>
                      <div>
                        <label className="text-xs text-gray-500 uppercase font-bold flex items-center gap-1"><Bluetooth size={10} /> Bluetooth MAC (Optional)</label>
                        <input
                          type="text"
                          value={session.connection.bluetoothMac}
                          onChange={(e) => setSession(p => ({ ...p, connection: { ...p.connection, bluetoothMac: e.target.value } }))}
                          placeholder="AA:BB:CC:..."
                          className="w-full mt-1 bg-cyber-900 border border-cyber-600 text-white p-1.5 text-sm rounded font-mono focus:border-cyber-accent outline-none"
                          disabled={session.isConnected}
                        />
                      </div>
                      <div>
                        <label className="text-xs text-gray-500 uppercase font-bold flex items-center gap-1"><Cable size={10} /> CAN Interface (Optional)</label>
                        <input
                          type="text"
                          value={session.connection.canInterface}
                          onChange={(e) => setSession(p => ({ ...p, connection: { ...p.connection, canInterface: e.target.value } }))}
                          placeholder="can0"
                          className="w-full mt-1 bg-cyber-900 border border-cyber-600 text-white p-1.5 text-sm rounded font-mono focus:border-cyber-accent outline-none"
                          disabled={session.isConnected}
                        />
                      </div>
                      <div>
                        <label className="text-xs text-gray-500 uppercase font-bold flex items-center gap-1"><Radio size={10} /> WiFi Interface (Optional)</label>
                        <input
                          type="text"
                          value={session.connection.interface}
                          onChange={(e) => setSession(p => ({ ...p, connection: { ...p.connection, interface: e.target.value } }))}
                          placeholder="wlan0mon"
                          className="w-full mt-1 bg-cyber-900 border border-cyber-600 text-white p-1.5 text-sm rounded font-mono focus:border-cyber-accent outline-none"
                          disabled={session.isConnected}
                        />
                      </div>
                      <div>
                        <label className="text-xs text-gray-500 uppercase font-bold flex items-center gap-1"><Activity size={10} /> RF Frequency (Optional)</label>
                        <input
                          type="text"
                          value={session.connection.frequency}
                          onChange={(e) => setSession(p => ({ ...p, connection: { ...p.connection, frequency: e.target.value } }))}
                          placeholder="433.92MHz"
                          className="w-full mt-1 bg-cyber-900 border border-cyber-600 text-white p-1.5 text-sm rounded font-mono focus:border-cyber-accent outline-none"
                          disabled={session.isConnected}
                        />
                      </div>
                    </div>
                  </div>

                  {!session.isConnected ? (
                    <button
                      onClick={handleGlobalConnect}
                      disabled={session.status === 'connecting'}
                      className={`w-full py-3 rounded font-bold flex justify-center items-center gap-2 transition-all ${session.status === 'connecting'
                        ? 'bg-cyber-700 text-gray-500 cursor-not-allowed'
                        : 'bg-cyber-500 hover:bg-cyber-400 text-white shadow-lg shadow-cyber-500/20'
                        }`}
                    >
                      {session.status === 'connecting' ? <RotateCw className="animate-spin" size={16} /> : <Power size={16} />}
                      INITIALIZE SYSTEM LINK
                    </button>
                  ) : (
                    <div className="space-y-3">
                      <button
                        onClick={startBatchScan}
                        disabled={session.status === 'running'}
                        className={`w-full py-4 rounded font-bold flex justify-center items-center gap-2 transition-all ${session.status === 'running'
                          ? 'bg-cyber-700 text-gray-400 cursor-not-allowed'
                          : 'bg-cyber-accent hover:bg-white text-black shadow-[0_0_20px_rgba(0,240,255,0.4)]'
                          }`}
                      >
                        <Play size={18} fill="currentColor" />
                        {session.status === 'running' ? 'BATCH SCANNING...' : 'EXECUTE FULL SCAN'}
                      </button>
                      <button
                        onClick={() => setSession(p => ({ ...p, isConnected: false, status: 'idle', logs: [], results: [] }))}
                        className="w-full px-4 py-2 bg-red-900/20 border border-red-500/50 text-red-400 rounded hover:bg-red-900/40 text-sm"
                      >
                        TERMINATE CONNECTION
                      </button>
                    </div>
                  )}
                </div>
              </div>
            </div>

            {/* Global Mode: Logs & Results */}
            <div className="lg:col-span-2 flex flex-col gap-6 h-full overflow-y-auto pb-24 custom-scrollbar pr-2">
              <ScanLogs logs={session.logs} />

              <div className="flex flex-col lg:flex-row gap-6 shrink-0 h-fit">
                {/* Results Column moved to center/right */}
                {session.status === 'completed' && (
                  <div className="flex-1 bg-cyber-800 border border-cyber-700 p-6 rounded-lg shadow-lg animate-slide-up">
                    <h3 className="text-lg font-bold text-white mb-4 flex items-center gap-2">
                      <ShieldCheck className="text-cyber-accent" /> Scan Summary
                    </h3>
                    <div className="grid grid-cols-2 gap-4 mb-4">
                      <div className="bg-cyber-900/50 p-3 rounded border border-cyber-700">
                        <span className="text-[10px] text-gray-500 block uppercase">Threats Detected</span>
                        <span className="font-mono text-2xl font-bold text-cyber-danger">
                          {session.results.filter(r => r.vulnerable).length}
                        </span>
                      </div>
                      <div className="bg-cyber-900/50 p-3 rounded border border-cyber-700">
                        <span className="text-[10px] text-gray-500 block uppercase">Risk Factor</span>
                        <span className="font-mono text-2xl font-bold text-orange-500">
                          {session.riskScore}%
                        </span>
                      </div>
                    </div>

                    <button
                      onClick={handleAiAnalysis}
                      disabled={isAnalysing}
                      className="w-full py-3 bg-cyber-accent/10 border border-cyber-accent text-cyber-accent hover:bg-cyber-accent hover:text-black rounded font-bold transition-all flex justify-center items-center gap-2 uppercase tracking-widest text-sm shadow-[0_0_15px_rgba(0,240,255,0.1)]"
                    >
                      {isAnalysing ? <RotateCw className="animate-spin" size={16} /> : <FileText size={16} />}
                      {session.aiReport ? 'Re-Generate AI Intelligence' : 'Generate AI Security Report'}
                    </button>

                    <div className="mt-4 flex items-center justify-center gap-2 py-2 border-t border-cyber-700/50">
                      <Save size={12} className="text-cyber-500" />
                      <span className="text-[10px] font-mono text-gray-500 uppercase tracking-tighter">Session Archive Synchronized</span>
                    </div>
                  </div>
                )}

                {/* Detected Threats (Brief List) */}
                {session.status === 'completed' && !session.aiReport && (
                  <div className="flex-1 bg-cyber-800 border border-cyber-700 rounded-lg p-6 max-h-[300px] overflow-y-auto custom-scrollbar">
                    <h3 className="text-md font-bold text-white mb-4 flex items-center gap-2">
                      <AlertTriangle className="text-yellow-500" size={18} /> Found Vectors
                    </h3>
                    <div className="space-y-2">
                      {session.results.filter(r => r.vulnerable).map((res) => {
                        const poc = POC_DATABASE.find(p => p.id === res.pocId);
                        return (
                          <div key={res.pocId} onClick={() => poc && setSelectedResultPoc(poc)} className="bg-cyber-900/80 border-l-2 border-cyber-danger p-2 rounded cursor-pointer hover:bg-cyber-700 transition-colors group">
                            <div className="flex justify-between items-center">
                              <span className="text-gray-200 font-bold text-xs truncate">{poc?.name}</span>
                              <ChevronRight size={12} className="text-gray-600 group-hover:text-cyber-accent transition-colors" />
                            </div>
                          </div>
                        );
                      })}
                      {session.results.filter(r => r.vulnerable).length === 0 && (
                        <div className="text-center text-gray-500 py-4 text-xs font-mono italic">NO THREATS IDENTIFIED</div>
                      )}
                    </div>
                  </div>
                )}
              </div>

              {session.aiReport && (
                <div className="bg-cyber-800 border border-cyber-accent/30 rounded-lg p-6 flex flex-col relative shadow-2xl shrink-0 h-auto min-h-max">
                  <div className="flex justify-between items-center mb-6 border-b border-cyber-700/50 pb-4">
                    <div className="flex items-center gap-3">
                      <div className="w-8 h-8 rounded bg-cyber-accent/10 flex items-center justify-center border border-cyber-accent/30">
                        <Activity size={18} className="text-cyber-accent" />
                      </div>
                      <h4 className="text-sm font-bold text-white tracking-[0.2em] uppercase">Tactical Security Assessment</h4>
                    </div>
                    <button
                      onClick={handleDownloadPdf}
                      className="text-xs flex items-center gap-2 bg-cyber-900 border border-cyber-700 hover:border-cyber-accent text-white px-4 py-2 rounded-lg transition-all shadow-inner"
                    >
                      <Download size={14} className="text-cyber-accent" /> EXPORT DECISION PDF
                    </button>
                  </div>
                  <div id="ai-report-content" className="prose prose-invert max-w-none text-sm text-gray-400 font-sans p-6 bg-black/40 rounded-xl border border-cyber-800 break-words h-auto min-h-max pb-12">
                    <MarkdownRenderer content={session.aiReport} />
                  </div>
                </div>
              )}
            </div>
          </div>
        )}

        {mode === 'MANUAL' && (
          <div className="p-6 h-full flex flex-col">
            <div className="flex flex-col md:flex-row justify-between items-center mb-6 gap-4">
              <div>
                <h2 className="text-2xl font-bold text-white">Manual Vulnerability Library</h2>
                <p className="text-gray-400 text-sm">Select a module to view details, configure parameters, and execute tests.</p>
              </div>
              <div className="flex gap-4">
                <input
                  type="text"
                  placeholder="Search modules..."
                  className="bg-cyber-900 border border-cyber-700 text-white px-4 py-2 rounded focus:border-cyber-accent outline-none w-64"
                  value={manualSearch}
                  onChange={e => setManualSearch(e.target.value)}
                />
                <select
                  className="bg-cyber-900 border border-cyber-700 text-white px-4 py-2 rounded focus:border-cyber-accent outline-none"
                  value={filterCategory}
                  onChange={e => setFilterCategory(e.target.value)}
                >
                  <option value="All">All Categories</option>
                  {Object.values(Category).map(c => <option key={c} value={c}>{c}</option>)}
                </select>
              </div>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4 overflow-y-auto pb-10">
              {filteredManualPocs.map(poc => (
                <div key={poc.id} className="bg-cyber-800 border border-cyber-700 p-4 rounded-lg hover:border-cyber-danger transition-all group relative">
                  <div className="flex justify-between items-start mb-2">
                    <span className={`text-xs px-2 py-0.5 rounded border ${poc.severity === Severity.CRITICAL ? 'text-red-500 border-red-500 bg-red-500/10' : 'text-orange-400 border-orange-400 bg-orange-500/10'}`}>
                      {poc.severity}
                    </span>
                    <span className="text-gray-500 font-mono text-xs">{poc.id}</span>
                  </div>
                  <h3 className="text-white font-bold mb-1 truncate pr-8">{poc.name}</h3>
                  <p className="text-gray-400 text-xs line-clamp-2 mb-4 h-8">{poc.description}</p>

                  <div className="flex justify-between items-center border-t border-cyber-700 pt-3">
                    <span className="text-xs text-cyber-400 font-mono">{poc.category}</span>
                    <button
                      onClick={() => setManualDetailPoc(poc)}
                      className="bg-cyber-700 hover:bg-cyber-500 text-white px-3 py-1.5 rounded text-xs font-bold flex items-center gap-1 transition-colors"
                    >
                      <Play size={10} fill="currentColor" /> DETAILS
                    </button>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

      </div>
    </div>
  );
};

export default Scanner;