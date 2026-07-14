import React, { useState, useEffect, useMemo, useCallback } from 'react';
import { flushSync, createPortal } from 'react-dom';
import { ScanSession, ScanLog, ScanResult, Severity, POC, Category, ConnectionParams } from '../types';
import ScanLogs from './ScanLogs';
import { generateSecurityReport } from '../services/api';
import { approveV3SessionAction, checkBackendHealth, createV3Session, executePocScript, getBackendUrl, fingerprintOS, runPocPlugin, saveScanSession, startV3SessionRun, submitPocManualVerdict, recordScanApprovalPolicy, updateV3SessionRun } from '../services/api';
import { Play, RotateCw, FileText, AlertTriangle, ShieldCheck, Wifi, Cable, Bluetooth, Power, Crosshair, List, Server, ArrowRight, Settings, Save, WifiOff, Link, CheckCircle, Radio, Activity, Download, ChevronRight, Bot, Usb, Square, FileDown } from 'lucide-react';
import { AgentScanErrorBoundary } from './AgentScanErrorBoundary';
import { findPocInCatalog } from '../services/pocCatalog';
import { usePocCatalog } from '../hooks/usePocCatalog';
import { markdownToSafeHtml, escapeHtml } from '../utils/security';
import { exportReportPdf, exportReportMarkdown } from '../utils/pdfExport';

const AgentScan = React.lazy(() => import('./AgentScan'));
const AgentVehicleScene = React.lazy(() => import('./AgentVehicleScene'));
const PocDetailModal = React.lazy(() => import('./PocDetailModal'));
const ManualTestModal = React.lazy(() => import('./ManualTestModal'));

type ScannerMode = 'SELECTION' | 'GLOBAL' | 'MANUAL' | 'AGENT';

const EMPTY_CONNECTION: ConnectionParams = {
  ip: '',
  port: '',
  bluetoothMac: '',
  canInterface: '',
  url: '',
  frequency: '',
  interface: '',
  usbAdbSerial: '',
  usbMountPoint: '',
};

const buildExecutionParams = (
  connection: ConnectionParams,
  extras: Record<string, unknown> = {},
): Record<string, unknown> => {
  const params: Record<string, unknown> = { ...connection, ...extras };
  if (connection.bluetoothMac) params.bluetooth_mac = connection.bluetoothMac;
  if (connection.canInterface) params.can_interface = connection.canInterface;
  if (connection.interface) {
    params.interface = connection.interface;
    params.wifi_interface = connection.interface;
  }
  if (connection.frequency) params.frequency = connection.frequency;
  if (connection.usbAdbSerial) {
    params.expected_usb_serial = connection.usbAdbSerial;
    params.usb_device_serial = connection.usbAdbSerial;
  }
  if (connection.usbMountPoint) params.usb_mount_point = connection.usbMountPoint;
  return params;
};

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
  currentUser: any;
}

type DisruptiveApprovalState = {
  poc: POC;
  progress: string;
  secondsLeft: number;
} | null;

type DisruptiveApprovalDecision = 'approved' | 'approved_all' | 'skipped' | 'timeout';

type ManualVerdict = 'confirmed_vulnerable' | 'confirmed_not_vulnerable' | 'inconclusive' | 'needs_retest';

type ManualVerdictState = {
  poc: POC;
  progress: string;
  result: any;
  note: string;
  evidenceFile: string;
} | null;

// Helper to render markdown-ish text to HTML
const MarkdownRenderer: React.FC<{ content: string }> = ({ content }) => {
  if (!content) return null;

  // Very basic conversion for common patterns
  const lines = content.split('\n');
  return (
    <div className="space-y-2">
      {lines.map((line, i) => {
        if (line.startsWith('# ')) {
          return <h2 key={i} className="text-xl font-bold text-white mt-6 mb-3 border-l-4 border-cyber-accent pl-3">{line.replace(/^#+\s*/, '')}</h2>;
        }
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
  token,
  currentUser
}) => {
  const [isAnalysing, setIsAnalysing] = useState(false);
  const [selectedResultPoc, setSelectedResultPoc] = useState<POC | null>(null);
  const { pocs: pocCatalog, refresh: refreshPocCatalog } = usePocCatalog(token);
  const [sessionSaveStatus, setSessionSaveStatus] = useState<'idle' | 'saved' | 'failed'>('idle');
  const [aiReportError, setAiReportError] = useState<string | null>(null);
  const [selectionPreview, setSelectionPreview] = useState<'GLOBAL' | 'AGENT' | 'MANUAL'>('AGENT');
  const [selectionWebglFailed, setSelectionWebglFailed] = useState(false);
  const handleAgentDraftChange = useCallback((draft: NonNullable<ScanSession['agentDraft']>) => {
    setSession((prev) => ({ ...prev, agentDraft: draft }));
  }, [setSession]);

  // Contents of PoC scripts fetched from backend
  const [pocContents, setPocContents] = useState<Record<string, string>>({});
  const [pocRuntimeMetadata, setPocRuntimeMetadata] = useState<Record<string, Partial<POC>>>({});

  // State for Manual Mode
  const [manualTestPoc, setManualTestPoc] = useState<POC | null>(null);
  const [manualVerdictState, setManualVerdictState] = useState<ManualVerdictState>(null);
  // Manual View Detail Modal State
  const [manualDetailPoc, setManualDetailPoc] = useState<POC | null>(null);

  const [filterCategory, setFilterCategory] = useState<string>('All');
  const [manualSearch, setManualSearch] = useState('');
  const [disruptiveApproval, setDisruptiveApproval] = useState<DisruptiveApprovalState>(null);
  const autoApproveDisruptiveForRunRef = React.useRef(false);
  const autoManualVerdictForRunRef = React.useRef<{
    verdict: ManualVerdict;
    note: string;
    evidenceFile: string;
  } | null>(null);
  const pocRuntimeMetadataRef = React.useRef<Record<string, Partial<POC>>>({});
  const approvalResolverRef = React.useRef<((decision: DisruptiveApprovalDecision) => void) | null>(null);
  const manualVerdictResolverRef = React.useRef<((result: any) => void) | null>(null);
  const approvalTimeoutRef = React.useRef<number | null>(null);
  const approvalIntervalRef = React.useRef<number | null>(null);
  const pocCatalogRef = React.useRef<POC[]>([]);
  const batchAbortControllerRef = React.useRef<AbortController | null>(null);
  const batchCancelRequestedRef = React.useRef(false);
  const batchSessionIdRef = React.useRef<string | null>(null);

  // Initial check on mount
  useEffect(() => {
    checkEngine();
    fetchPocs();
  }, []);

  useEffect(() => {
    return () => {
      if (approvalTimeoutRef.current) {
        window.clearTimeout(approvalTimeoutRef.current);
      }
      if (approvalIntervalRef.current) {
        window.clearInterval(approvalIntervalRef.current);
      }
    };
  }, []);

  useEffect(() => {
    pocRuntimeMetadataRef.current = pocRuntimeMetadata;
  }, [pocRuntimeMetadata]);

  useEffect(() => {
    pocCatalogRef.current = pocCatalog;
    applyPocCatalog(pocCatalog);
  }, [pocCatalog]);

  const buildRuntimeMetadataFromCatalog = (catalog: POC[]): {
    contentsMap: Record<string, string>;
    metadataMap: Record<string, Partial<POC>>;
  } => {
    const contentsMap: Record<string, string> = {};
    const metadataMap: Record<string, Partial<POC>> = {};
    catalog.forEach((poc) => {
      contentsMap[poc.id] = poc.codeSnippet;
      metadataMap[poc.id] = {
        executionRequirements: poc.executionRequirements,
        manualConfirmationRequired: poc.manualConfirmationRequired,
        requiresDisruptiveApproval: poc.requiresDisruptiveApproval,
        requiresPostExecutionReview: poc.requiresPostExecutionReview,
        validationTier: poc.validationTier,
        detectionConfidence: poc.detectionConfidence,
        executionSafety: poc.executionSafety,
        evidenceBasis: poc.evidenceBasis,
        expCapability: poc.expCapability,
        professionalGrade: poc.professionalGrade,
        notNativeExp: poc.notNativeExp,
      };
    });

    return { contentsMap, metadataMap };
  };

  const applyPocCatalog = (catalog: POC[]) => {
    const { contentsMap, metadataMap } = buildRuntimeMetadataFromCatalog(catalog);
    setPocContents(contentsMap);
    setPocRuntimeMetadata(metadataMap);
    pocRuntimeMetadataRef.current = metadataMap;
  };

  const fetchPocs = async (): Promise<POC[]> => {
    const catalog = await refreshPocCatalog();
    pocCatalogRef.current = catalog;
    applyPocCatalog(catalog);
    return catalog;
  };

  const checkEngine = async () => {
    setEngineStatus('unknown');
    const isUp = await checkBackendHealth(engineUrl);
    setEngineStatus(isUp ? 'online' : 'offline');
    if (isUp) addLog(`Execution Engine detected at ${engineUrl}`, 'success');
  };

  const addLog = (message: string, type: ScanLog['type'] = 'info') => {
    // Force immediate React DOM update to prevent batching and jumping blocks
    flushSync(() => {
      setSession(prev => ({
        ...prev,
        logs: [...prev.logs, { timestamp: new Date().toLocaleTimeString(), message, type }]
      }));
    });
  };

  const resolveDisruptiveApproval = (decision: DisruptiveApprovalDecision) => {
    if (approvalTimeoutRef.current) {
      window.clearTimeout(approvalTimeoutRef.current);
      approvalTimeoutRef.current = null;
    }
    if (approvalIntervalRef.current) {
      window.clearInterval(approvalIntervalRef.current);
      approvalIntervalRef.current = null;
    }
    const resolver = approvalResolverRef.current;
    approvalResolverRef.current = null;
    setDisruptiveApproval(null);
    if (resolver) {
      resolver(decision);
    }
  };

  const requestDisruptiveApproval = (poc: POC, progress: string): Promise<DisruptiveApprovalDecision> => {
    return new Promise((resolve) => {
      if (approvalTimeoutRef.current) {
        window.clearTimeout(approvalTimeoutRef.current);
      }
      if (approvalIntervalRef.current) {
        window.clearInterval(approvalIntervalRef.current);
      }

      approvalResolverRef.current = resolve;
      setDisruptiveApproval({ poc, progress, secondsLeft: 60 });

      const startedAt = Date.now();
      approvalIntervalRef.current = window.setInterval(() => {
        const elapsedSeconds = Math.floor((Date.now() - startedAt) / 1000);
        const nextSecondsLeft = Math.max(0, 60 - elapsedSeconds);
        setDisruptiveApproval((prev) => (prev ? { ...prev, secondsLeft: nextSecondsLeft } : prev));
      }, 1000);

      approvalTimeoutRef.current = window.setTimeout(() => {
        resolveDisruptiveApproval('timeout');
      }, 60000);
    });
  };

  const requestManualVerdict = (poc: POC, progress: string, result: any): Promise<any> => {
    return new Promise((resolve) => {
      manualVerdictResolverRef.current = resolve;
      setManualVerdictState({ poc, progress, result, note: '', evidenceFile: '' });
    });
  };

  const resolveManualVerdict = async (verdict: ManualVerdict, applyToRest = false) => {
    if (!manualVerdictState) return;
    const current = manualVerdictState;
    if (applyToRest) {
      autoManualVerdictForRunRef.current = {
        verdict,
        note: current.note,
        evidenceFile: current.evidenceFile,
      };
    }
    const submitted = await submitPocManualVerdict({
      trace_id: current.result?.trace_id,
      session_id: session.id,
      poc_id: current.result?.poc_id || current.poc.pocFile || current.poc.id,
      poc_name: current.poc.name,
      target_ip: session.connection.ip,
      bluetooth_mac: session.connection.bluetoothMac,
      verdict,
      operator_note: current.note,
      evidence_file: current.evidenceFile,
    }, token, engineUrl);
    const resolver = manualVerdictResolverRef.current;
    manualVerdictResolverRef.current = null;
    setManualVerdictState(null);
    if (resolver) {
      resolver({ ...current.result, ...submitted });
    }
  };

  const handleGlobalConnect = async () => {
    setSession(prev => ({ ...prev, status: 'connecting' }));

    addLog(`Targeting Execution Engine at: ${engineUrl}...`);

    // Check Backend
    const isBackendUp = await checkBackendHealth(engineUrl);
    setEngineStatus(isBackendUp ? 'online' : 'offline');

    if (!isBackendUp) {
      addLog(`Error: Execution Engine unavailable at ${engineUrl}`, 'error');
      addLog(`Tip: Ensure 'server.py' is running and CORS is enabled.`, 'warning');
      setSession(prev => ({ ...prev, status: 'idle' }));
      return;
    }
    addLog(`Execution Engine Online & Ready.`, 'success');

    // Relaxed validation for global mode: At least one parameter
    const { ip, bluetoothMac, canInterface, interface: wifiIf, frequency, usbAdbSerial, usbMountPoint } = session.connection;
    if (!session.targetName || (!ip && !bluetoothMac && !canInterface && !wifiIf && !frequency && !usbAdbSerial && !usbMountPoint)) {
      addLog("Error: Target Name and at least one parameter (IP, BT MAC, CAN, WiFi, RF, or USB) are required for Global Scan.", 'error');
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
    batchCancelRequestedRef.current = false;
    batchAbortControllerRef.current?.abort('superseded');
    batchAbortControllerRef.current = new AbortController();
    const batchSignal = batchAbortControllerRef.current.signal;

    // The server owns the durable session identifier and lifecycle.
    let newSessionId: string;
    try {
      const durableSession = await createV3Session('batch', {
        name: session.targetName,
        ip: session.connection.ip,
        bluetooth_mac: session.connection.bluetoothMac,
        can_interface: session.connection.canInterface,
        wifi_interface: session.connection.interface,
        frequency: session.connection.frequency,
        usb_adb_serial: session.connection.usbAdbSerial,
        usb_mount_point: session.connection.usbMountPoint,
      }, {}, token);
      newSessionId = durableSession.id;
      batchSessionIdRef.current = newSessionId;
      await startV3SessionRun(newSessionId, token);
    } catch (error: any) {
      addLog(`无法创建可审计扫描会话：${error?.message || '未知错误'}`, 'error');
      setSession(prev => ({ ...prev, status: 'idle' }));
      return;
    }

    setSession(prev => ({
      ...prev,
      id: newSessionId,
      startTime: new Date().toISOString(),
      status: 'running',
      results: [],
      riskScore: 0,
      aiReport: null
    }));
    autoApproveDisruptiveForRunRef.current = false;
    autoManualVerdictForRunRef.current = null;
    const refreshedCatalog = await fetchPocs();
    const catalogForRun = refreshedCatalog.length ? refreshedCatalog : pocCatalogRef.current;
    const activePocs = catalogForRun;
    const runtimeMetadata = pocRuntimeMetadataRef.current;

    if (!activePocs.length) {
      addLog(`Error: PoC catalog is empty. Check backend /api/v1/list_pocs.`, 'error');
      await updateV3SessionRun(newSessionId, 'fail', { error_code: 'EMPTY_POC_CATALOG' }, token).catch(() => undefined);
      setSession(prev => ({ ...prev, status: 'idle' }));
      return;
    }

    addLog(`Starting batch execution of ${activePocs.length} modules...`, 'info');
    addLog('Policy: regular PoCs execute directly; disruptive PoCs require operator approval.', 'info');
    addLog(`Engine: ${engineUrl} | Target: ${session.targetName}`, 'info');
    recordScanApprovalPolicy({
      session_id: newSessionId,
      target_ip: session.connection.ip,
      allow_disruptive: false,
    }, token, engineUrl).then((res) => {
      if (!res.success) addLog(`Warning: failed to persist scan policy: ${res.error}`, 'warning');
    });

    let detectedOS = 'unknown';
    if (session.connection.ip) {
      addLog(`Fingerprinting target OS at ${session.connection.ip}...`, 'info');
      const fp = await fingerprintOS(session.connection.ip, token);
      detectedOS = fp.os;
      addLog(`[OS Target] Detected: ${fp.os.toUpperCase()} (${fp.details})`, 'info');
    }

    const results: ScanResult[] = [];
    let riskAccumulator = 0;
    let vulnCount = 0;
    let secureCount = 0;
    let errorCount = 0;

    for (let i = 0; i < activePocs.length; i++) {
      if (batchCancelRequestedRef.current) break;
      const poc = activePocs[i];
      const progress = `[${i + 1}/${activePocs.length}]`;

      // Check if required params are met for this PoC
      const { ip, bluetoothMac, canInterface, interface: wifiIf, frequency, usbAdbSerial, usbMountPoint } = session.connection;
      const missingParams = poc.requiredParams.filter(p => {
        if (p === 'ip' && !ip) return true;
        if (p === 'bluetooth_mac' && !bluetoothMac) return true;
        if (p === 'can_interface' && !canInterface) return true;
        if (p === 'interface' && !wifiIf) return true;
        if (p === 'frequency' && !frequency) return true;
        if (p === 'usb_adb_serial' && !usbAdbSerial) return true;
        if (p === 'usb_mount_point' && !usbMountPoint) return true;
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
      const runtimeMeta = runtimeMetadata[poc.id] || pocRuntimeMetadataRef.current[poc.id] || {};
      const requiresDisruptiveApproval = Boolean(runtimeMeta.requiresDisruptiveApproval);
      const requiresPostExecutionReview = Boolean(runtimeMeta.requiresPostExecutionReview);
      const shouldAllowDisruptive = autoApproveDisruptiveForRunRef.current;
      const executionParams = buildExecutionParams(
        session.connection,
        shouldAllowDisruptive ? { allow_disruptive: true } : {},
      );

      if (requiresDisruptiveApproval && autoApproveDisruptiveForRunRef.current) {
        addLog(`${progress} ⇢ ${poc.name} → Auto-approved by current scan policy.`, 'warning');
      } else if (requiresDisruptiveApproval) {
        addLog(`${progress} ! ${poc.name} → High-risk PoC requires explicit confirmation. Waiting up to 60s...`, 'warning');
        const approvalDecision = await requestDisruptiveApproval(poc, progress);
        if (approvalDecision === 'skipped' || approvalDecision === 'timeout') {
          addLog(`${progress} ⏭ ${poc.name} — Skipped by user`, 'warning');
          results.push({
            pocId: poc.id,
            vulnerable: false,
            details: approvalDecision === 'timeout'
              ? 'Skipped because disruptive execution was not explicitly confirmed before timeout.'
              : 'Skipped by user during disruptive PoC confirmation.',
            detectedAt: new Date().toISOString(),
            elapsedSeconds: 0,
          });
          continue;
        }
        if (approvalDecision === 'approved_all') {
          autoApproveDisruptiveForRunRef.current = true;
          addLog(`${progress} ⇢ ${poc.name} → User confirmed and enabled auto-approval for the rest of this scan.`, 'info');
        } else {
          addLog(`${progress} ⇢ ${poc.name} → User confirmed disruptive execution.`, 'info');
        }
        executionParams.allow_disruptive = true;
      }
      if (requiresPostExecutionReview) {
        addLog(`${progress} ⇢ ${poc.name} → Post-execution operator verdict will be required.`, 'warning');
      }

      if (requiresDisruptiveApproval) {
        try {
          executionParams.approval_token = await approveV3SessionAction(
            newSessionId,
            poc.pocFile || poc.id,
            session.connection.ip || session.connection.bluetoothMac || session.connection.canInterface || 'local',
            token,
          );
        } catch (error: any) {
          addLog(`${progress} ⏭ ${poc.name} — 审批授权失败：${error?.message || '未知错误'}`, 'error');
          continue;
        }
      }

      if (runtimeMeta.executionRequirements?.requires_edge) {
        addLog(`${progress} ⇢ ${poc.name} → Using local vehicle runtime for hardware-dependent PoC.`, 'info');
      }

      // Execute Real via the Plugin Loader (Handles parameters and subdirectories natively)
      // 使用 SSE 实时流式传输执行日志，每一行日志实时显示在 System Console 中
      const result = await new Promise<any>((resolve) => {
        const params = { ...executionParams } as any;
        // Append poc metadata so the backend can print it nicely
        params.poc_id = poc.id;
        params.poc_name = poc.name;

        // 破坏性执行令牌只能由显式会话审批端点签发。
        const runOnce = (extraParams: Record<string, any>) => {
          const runParams = { ...params, ...extraParams };
          const body = JSON.stringify({ filename: poc.pocFile, params: runParams, stream: true, session_id: newSessionId });

          fetch(`${engineUrl}/api/v1/run_poc_stream`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', ...(token && token !== 'cookie-session' ? { 'Authorization': `Bearer ${token}` } : {}) },
            credentials: 'same-origin',
            signal: batchSignal,
            body,
          }).then(async (response) => {
            if (!response.ok) {
              let data: any = null;
              let message = `Server returned ${response.status}`;
              try {
                data = await response.json();
                message = data?.error?.message || data.message || data.error || message;
              } catch {
                try {
                  const text = await response.text();
                  if (text.trim()) message = text.trim();
                } catch { /* ignore */ }
              }
              resolve({ success: false, logs: [], errors: [message], vulnerable: false });
              return;
            }
            if (!response.body) {
              const fallback = await runPocPlugin(poc.pocFile, runParams, token, engineUrl, newSessionId);
              resolve(fallback);
              return;
            }
            const reader = response.body.getReader();
            const decoder = new TextDecoder();
            let buffer = '';
            let finalResult: any = null;

            while (true) {
              const { done, value } = await reader.read();
              if (done) break;
              buffer += decoder.decode(value, { stream: true });
              const lines = buffer.split('\n');
              buffer = lines.pop() || '';
              for (const line of lines) {
                if (line.startsWith('data: ')) {
                  try {
                    const payload = JSON.parse(line.slice(6));
                    if (payload.type === 'log') {
                      addLog(`  ┃ ${payload.message}`, 'terminal');
                    } else if (payload.type === 'result') {
                      finalResult = payload;
                    }
                  } catch { }
                }
              }
            }
            resolve(finalResult || { success: false, logs: [], errors: ['No result received'] });
          }).catch((error: any) => {
            if (batchSignal.aborted || error?.name === 'AbortError') {
              resolve({ success: false, cancelled: true, logs: [], errors: ['operator_cancelled'], vulnerable: false });
              return;
            }
            runPocPlugin(poc.pocFile, runParams, token, engineUrl, newSessionId).then(resolve);
          });
        };

        runOnce({});
      });
      const elapsed = ((Date.now() - startTime) / 1000).toFixed(1);
      if (batchCancelRequestedRef.current || result.cancelled) break;

      // Restore printing of batch logs in case it fell back to non-streaming or returned batched logs
      if (result.logs && result.logs.length > 0) {
        for (const line of result.logs) {
          addLog(`  ┃ ${line}`, 'terminal');
        }
      }
      if (result.errors && result.errors.length > 0 && !result.success) {
        for (const err of result.errors.slice(0, 3)) {
          addLog(`  ┃ [STDERR] ${err}`, 'warning');
        }
      }

      let resolvedResult = result;
      if (result.success && (result.requires_human_review || result.verification_status === 'pending_manual_review')) {
        const autoManualVerdict = autoManualVerdictForRunRef.current;
        if (autoManualVerdict) {
          addLog(`${progress} ⇢ ${poc.name} → Applying batch operator verdict (${autoManualVerdict.verdict}).`, 'warning');
          const submitted = await submitPocManualVerdict({
            trace_id: result?.trace_id,
            session_id: newSessionId,
            poc_id: result?.poc_id || poc.pocFile || poc.id,
            poc_name: poc.name,
            target_ip: session.connection.ip,
            bluetooth_mac: session.connection.bluetoothMac,
            verdict: autoManualVerdict.verdict,
            operator_note: autoManualVerdict.note,
            evidence_file: autoManualVerdict.evidenceFile,
          }, token, engineUrl);
          resolvedResult = { ...result, ...submitted };
        } else {
          addLog(`${progress} ? ${poc.name} → Waiting for operator verdict (${elapsed}s)`, 'warning');
          resolvedResult = await requestManualVerdict(poc, progress, result);
        }
      }

      if (resolvedResult.success) {
        if (resolvedResult.vulnerable === true) {
          addLog(`${progress} ✗ ${poc.name} → VULNERABLE (${elapsed}s)`, 'error');
          vulnCount++;
          results.push({
            pocId: poc.id,
            vulnerable: true,
            details: `Exploit confirmed. ${resolvedResult.evidence || resolvedResult.manual_review?.operator_note || 'Verified'}`,
            detectedAt: new Date().toISOString(),
            elapsedSeconds: parseFloat(elapsed),
            requiresHumanReview: Boolean(resolvedResult.requires_human_review),
            verificationStatus: resolvedResult.verification_status,
            evidenceContractValid: resolvedResult.evidence_contract_valid,
            contractError: resolvedResult.contract_error,
            manualReview: resolvedResult.manual_review,
          });
          const score = poc.severity === Severity.CRITICAL ? 10 : poc.severity === Severity.HIGH ? 7 : 3;
          riskAccumulator += score;
        } else if (resolvedResult.vulnerable === false) {
          addLog(`${progress} ✓ ${poc.name} → Secure (${elapsed}s)`, 'success');
          secureCount++;
          results.push({
            pocId: poc.id,
            vulnerable: false,
            details: resolvedResult.requires_human_review ? 'Operator confirmed no observable exploit effect.' : 'Target secure.',
            detectedAt: new Date().toISOString(),
            elapsedSeconds: parseFloat(elapsed),
            requiresHumanReview: Boolean(resolvedResult.requires_human_review),
            verificationStatus: resolvedResult.verification_status,
            evidenceContractValid: resolvedResult.evidence_contract_valid,
            contractError: resolvedResult.contract_error,
            manualReview: resolvedResult.manual_review,
          });
        } else {
          addLog(`${progress} ? ${poc.name} → Inconclusive (${elapsed}s)`, 'warning');
          errorCount++;
          results.push({
            pocId: poc.id,
            vulnerable: null,
            details: resolvedResult.manual_review?.operator_note || resolvedResult.verification_status || 'Manual review inconclusive.',
            detectedAt: new Date().toISOString(),
            elapsedSeconds: parseFloat(elapsed),
            requiresHumanReview: Boolean(resolvedResult.requires_human_review),
            verificationStatus: resolvedResult.verification_status,
            evidenceContractValid: resolvedResult.evidence_contract_valid,
            contractError: resolvedResult.contract_error,
            manualReview: resolvedResult.manual_review,
          });
        }
      } else {
        addLog(`${progress} ! ${poc.name} → Error (${elapsed}s): ${resolvedResult.errors?.[0] || 'Unknown'}`, 'warning');
        errorCount++;
        results.push({
          pocId: poc.id,
          vulnerable: false,
          details: `Test Error: ${resolvedResult.errors?.[0] || 'Check Engine Connection'}`,
          detectedAt: new Date().toISOString(),
          elapsedSeconds: parseFloat(elapsed)
        });
      }
    }

    if (batchCancelRequestedRef.current) {
      addLog('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━', 'info');
      addLog('全局扫描已由操作员终止，当前 PoC 进程和剩余队列均已停止。', 'warning');
      setSession(prev => ({
        ...prev,
        status: 'cancelled',
        endTime: new Date().toISOString(),
        results,
        riskScore: Math.min(riskAccumulator, 100),
      }));
      batchAbortControllerRef.current = null;
      return;
    }

    addLog(`━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━`, 'info');
    addLog(`Batch Scan Complete: ${vulnCount} Vulnerable | ${secureCount} Secure | ${errorCount} Errors`, vulnCount > 0 ? 'error' : 'success');

    await updateV3SessionRun(newSessionId, 'complete', {
      execution_count: results.length,
      confirmed_findings: vulnCount,
      secure_count: secureCount,
      execution_errors: errorCount,
      risk_score: Math.min(riskAccumulator, 100),
    }, token).catch((error: any) => {
      addLog(`权威会话结束状态保存失败：${error?.message || '未知错误'}`, 'error');
    });

    // Use functional update to ensure we don't wipe out the accumulated logs
    setSession(prev => {
      const finalSession: ScanSession = {
        ...prev,
        status: 'completed',
        endTime: new Date().toISOString(),
        results,
        riskScore: Math.min(riskAccumulator, 100)
      };

      // Push to history asynchronously to avoid blocking state render
      setTimeout(async () => {
        onAddToHistory(finalSession);
        const result = await saveScanSession(finalSession, token);
        setSessionSaveStatus(result.success ? 'saved' : 'failed');
      }, 0);

      return finalSession;
    });
  };

  const stopBatchScan = async () => {
    if (session.status !== 'running' || batchCancelRequestedRef.current) return;
    batchCancelRequestedRef.current = true;
    batchAbortControllerRef.current?.abort('operator-cancelled');
    resolveDisruptiveApproval('skipped');
    const manualResolver = manualVerdictResolverRef.current;
    manualVerdictResolverRef.current = null;
    setManualVerdictState(null);
    manualResolver?.({ success: false, cancelled: true, vulnerable: null, errors: ['operator_cancelled'] });
    addLog('正在终止全局扫描…', 'warning');
    setSession(prev => ({ ...prev, status: 'cancelled', endTime: new Date().toISOString() }));
    const sessionId = batchSessionIdRef.current;
    if (sessionId) {
      await updateV3SessionRun(sessionId, 'cancel', { reason: 'operator_cancelled' }, token).catch(() => undefined);
    }
  };

  const handleAiAnalysis = async () => {
    setIsAnalysing(true);
    setAiReportError(null);
    const result = await generateSecurityReport(session, token, currentUser?.ai_config);
    if (!result.success || !result.report) {
      setAiReportError(result.error || 'AI 报告生成失败');
      setIsAnalysing(false);
      return;
    }
    if (/本地确定性证据报告|本地证据引擎生成|远程评估模型未在时限内返回/.test(result.report)) {
      setAiReportError('远程 AI 报告生成失败，已拒绝本地降级报告。请检查 Profile 中的 AI 配置与网络后重试。');
      setIsAnalysing(false);
      return;
    }
    setSession(prev => {
      const updated = { ...prev, aiReport: result.report };
      saveScanSession(updated, token).then((saveResult) => {
        setSessionSaveStatus(saveResult.success ? 'saved' : 'failed');
      });
      return updated;
    });
    setIsAnalysing(false);
  };

  const buildScanSummaryMarkdown = useCallback(() => {
    const targetInfo = session.targetName || session.connection.ip || 'Unknown Target';
    const scannedAt = new Date(session.endTime || session.startTime || Date.now()).toLocaleString('zh-CN', { hour12: false });
    const vulns = session.results.filter((result) => result.vulnerable);
    const secure = session.results.filter((result) => result.vulnerable === false);
    const inconclusive = session.results.filter((result) => result.vulnerable !== true && result.vulnerable !== false);

    const lines = [
      '## 扫描概览',
      `- 扫描目标：${targetInfo}`,
      `- 目标 IP：${session.connection.ip || '未提供'}`,
      `- 扫描时间：${scannedAt}`,
      `- 风险评分：${session.riskScore}%`,
      `- 检出威胁：${vulns.length} 项`,
      `- 判定安全：${secure.length} 项`,
      `- 异常/未决：${inconclusive.length} 项`,
      '',
      '## 威胁清单',
    ];

    if (!vulns.length) {
      lines.push('- 未检出可直接确认的漏洞项。');
    } else {
      vulns.forEach((result, index) => {
        const poc = findPocInCatalog(pocCatalogRef.current, result);
        lines.push(`${index + 1}. **${poc?.name || result.pocId}** (${result.pocId})`);
        if (result.details) lines.push(`   - 证据：${result.details}`);
      });
    }

    if (session.aiReport?.trim()) {
      lines.push('', '## AI 安全评估', session.aiReport.trim());
    }

    return lines.join('\n');
  }, [session]);

  const handleExportScanPdf = async () => {
    if (session.status !== 'completed' || session.results.length === 0) return;

    const targetInfo = session.targetName || session.connection.ip || 'Unknown Target';
    const now = new Date(session.endTime || session.startTime || Date.now()).toLocaleString('zh-CN', { hour12: false });
    const reportHtml = markdownToSafeHtml(buildScanSummaryMarkdown());

    await exportReportPdf({
      filename: `AutoSec-Scan-${targetInfo}-${new Date().toISOString().slice(0, 10)}.pdf`,
      title: 'AutoSec Guard 批量扫描结果报告',
      metadata: [
        { label: '扫描目标', value: targetInfo },
        { label: '扫描时间', value: now },
        { label: '报告类型', value: '批量扫描结果导出' },
        { label: '工具版本', value: '智驭安盾 v3.0 · 常规扫描引擎' },
      ],
      reportHtml,
    });
  };

  const handleExportScanMarkdown = () => {
    if (session.status !== 'completed' || session.results.length === 0) return;

    const targetInfo = session.targetName || session.connection.ip || 'Unknown Target';
    const now = new Date(session.endTime || session.startTime || Date.now()).toLocaleString('zh-CN', { hour12: false });

    exportReportMarkdown({
      filename: `AutoSec-Scan-${targetInfo}-${new Date().toISOString().slice(0, 10)}.md`,
      title: 'AutoSec Guard 批量扫描结果报告',
      metadata: [
        { label: '扫描目标', value: targetInfo },
        { label: '扫描时间', value: now },
        { label: '报告类型', value: '批量扫描结果导出' },
        { label: '工具版本', value: '智驭安盾 v3.0 · 常规扫描引擎' },
      ],
      reportMarkdown: buildScanSummaryMarkdown(),
    });
  };

  const handleDownloadPdf = async () => {
    if (!session.aiReport) return;

    const now = new Date(session.startTime || Date.now()).toLocaleString('zh-CN', { hour12: false });
    const targetInfo = session.targetName || session.connection.ip || 'Unknown Target';

    // Parse Markdown manually like AgentScan to ensure clean print styles
    const reportHtml = markdownToSafeHtml(session.aiReport);
    const llmLabel = currentUser?.ai_config?.reportModel
      || currentUser?.ai_config?.strongModel
      || currentUser?.ai_config?.fastModel
      || 'LLM';

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
        <span><span class="label">扫描目标：</span>${escapeHtml(targetInfo)}</span>
        <span><span class="label">扫描时间：</span>${escapeHtml(now)}</span>
        <span><span class="label">报告类型：</span>常规扫描引擎报告</span>
        <span><span class="label">工具版本：</span>智驭安盾 v3.0 · ${escapeHtml(llmLabel)}</span>
      </div>
    </div>
    <div class="section">
      <p>${reportHtml}</p>
    </div>
  </div>
  <script>window.onload = function(){ window.print(); }</script>
</body>
</html>`;

    await exportReportPdf({
      filename: `AutoSec-Scan-${targetInfo}-${new Date().toISOString().slice(0, 10)}.pdf`,
      title: 'AutoSec Guard 智能网联汽车安全评估报告',
      metadata: [
        { label: '扫描目标', value: targetInfo },
        { label: '扫描时间', value: now },
        { label: '报告类型', value: '常规扫描引擎报告' },
        { label: '工具版本', value: `智驭安盾 v3.0 · ${llmLabel}` },
      ],
      reportHtml,
    });
  };

  const handleLaunchManualTest = (poc: POC) => {
    setManualDetailPoc(null);
    setManualTestPoc(poc);
  };

  const filteredManualPocs = pocCatalog.filter(p => {
    const matchesCat = filterCategory === 'All' || p.category === filterCategory;
    const matchesSearch = p.name.toLowerCase().includes(manualSearch.toLowerCase()) || p.id.toLowerCase().includes(manualSearch.toLowerCase());
    return matchesCat && matchesSearch;
  });

  // --- RENDER HELPERS ---

  const batchSummaryStats = useMemo(() => {
    const threats = session.results.filter((result) => result.vulnerable === true).length;
    const secure = session.results.filter((result) => result.vulnerable === false).length;
    const errors = session.results.filter((result) => result.vulnerable !== true && result.vulnerable !== false).length;
    return {
      threats,
      secure,
      errors,
      risk: Number.isFinite(session.riskScore) ? session.riskScore : 0,
    };
  }, [session.results, session.riskScore]);

  const showBatchSummary = session.status === 'completed' || session.results.length > 0;

  const selectionModes = [
    {
      id: 'GLOBAL' as const,
      icon: Server,
      title: '全局批量扫描',
      description: '批量编排全部已授权 PoC。',
      meta: 'ALL INTERFACES / BATCH',
      zones: ['network', 'wireless', 'execute'],
    },
    {
      id: 'AGENT' as const,
      icon: Bot,
      title: 'Agent 自主扫描',
      description: '自主完成侦察、决策与证据评估。',
      meta: 'ADAPTIVE / AI ASSISTED',
      zones: ['recon', 'network', 'wireless', 'assess'],
      recommended: true,
    },
    {
      id: 'MANUAL' as const,
      icon: Crosshair,
      title: '手动诊断',
      description: '单个 PoC 精确配置与受控执行。',
      meta: 'CONTROLLED / SINGLE POC',
      zones: ['execute'],
    },
  ];

  const selectScanningMode = (nextMode: 'GLOBAL' | 'AGENT' | 'MANUAL') => {
    setMode(nextMode);
    setSession((previous) => ({
      ...previous,
      mode: nextMode === 'GLOBAL' ? 'batch' : nextMode === 'AGENT' ? 'agent' : 'manual',
    }));
    if (nextMode !== 'AGENT') checkEngine();
  };

  const renderSelectionScreen = () => (
    <div className="scan-launcher min-h-full p-5 md:p-6 xl:p-8 animate-fade-in">
      <div className="mx-auto flex min-h-[calc(100vh-10rem)] w-full max-w-[1480px] flex-col">
        <div className="mb-4 flex flex-col justify-between gap-3 lg:flex-row lg:items-end">
          <div>
            <div className="section-kicker"><Radio size={14} /> SCAN ORCHESTRATION</div>
            <h2 className="mt-2 font-display text-3xl font-semibold tracking-[-0.035em] text-white md:text-4xl">选择执行方式</h2>
          </div>
          <p className="max-w-lg text-sm leading-6 text-slate-300/70">
            三种模式共享授权、执行与证据链；将指针移至模式上，可预览对应攻击面。
          </p>
        </div>

        <div className="grid flex-1 overflow-hidden rounded-[1.6rem] border border-cyan-200/20 bg-[#071625]/80 shadow-[0_32px_90px_rgba(0,3,12,.42),inset_0_1px_0_rgba(190,247,255,.08)] lg:grid-cols-[minmax(350px,.82fr)_minmax(0,1.55fr)]">
          <div className="relative z-10 flex flex-col border-b border-cyan-100/10 bg-[#091B2C]/82 p-4 backdrop-blur-xl lg:border-b-0 lg:border-r">
            <div className="px-2 pb-2 pt-1">
              <div className="font-mono text-[10px] tracking-[.2em] text-cyan-200/45">MISSION CONTROL</div>
            </div>

            <div className="divide-y divide-cyan-100/10 border-y border-cyan-100/10">
              {selectionModes.map((option) => {
                const Icon = option.icon;
                const isPreviewed = selectionPreview === option.id;
                return (
                  <button
                    key={option.id}
                    type="button"
                    onMouseEnter={() => setSelectionPreview(option.id)}
                    onFocus={() => setSelectionPreview(option.id)}
                    onClick={() => selectScanningMode(option.id)}
                    className={`scan-mode-row group relative flex w-full items-center gap-3 px-2 py-4 text-left ${isPreviewed ? 'scan-mode-row-active' : ''}`}
                  >
                    <span className="scan-mode-icon"><Icon size={19} /></span>
                    <span className="min-w-0 flex-1">
                      <span className="flex items-center gap-2">
                        <span className="font-display text-base font-semibold text-white">{option.title}</span>
                        {option.recommended && <span className="rounded-full border border-cyan-200/25 bg-cyan-300/10 px-2 py-0.5 text-[9px] text-cyan-100">推荐</span>}
                      </span>
                      <span className="mt-1 block text-xs leading-5 text-slate-400">{option.description}</span>
                      <span className="mt-2 block font-mono text-[8px] tracking-[.16em] text-cyan-200/40">{option.meta}</span>
                    </span>
                    <ArrowRight size={17} className="text-slate-600 transition-all group-hover:translate-x-1 group-hover:text-cyan-200" />
                  </button>
                );
              })}
            </div>

            <div className="mt-auto hidden grid-cols-3 gap-2 px-2 pt-4 text-center 2xl:grid">
              <div><div className="font-display text-lg font-semibold text-cyan-100">{pocCatalog.length || '—'}</div><div className="text-[9px] tracking-wider text-slate-500">PoC</div></div>
              <div><div className="font-display text-lg font-semibold text-emerald-300">LOCAL</div><div className="text-[9px] tracking-wider text-slate-500">执行面</div></div>
              <div><div className="font-display text-lg font-semibold text-amber-300">ON</div><div className="text-[9px] tracking-wider text-slate-500">授权门禁</div></div>
            </div>
          </div>

          <div className="relative min-h-[380px] overflow-hidden lg:min-h-[400px] 2xl:min-h-[500px]">
            <div className="pointer-events-none absolute left-5 right-5 top-5 z-20 flex items-center justify-between">
              <div className="flex items-center gap-2 rounded-full border border-cyan-200/20 bg-[#061522]/70 px-3 py-2 font-mono text-[9px] tracking-[.16em] text-cyan-100 backdrop-blur-xl">
                <span className="status-orb" /> DIGITAL TWIN / LIVE PREVIEW
              </div>
              <div className="hidden items-center gap-2 rounded-full border border-blue-300/15 bg-blue-400/10 px-3 py-2 font-mono text-[9px] text-blue-100 md:flex">
                GPU ACCELERATED · GLSL
              </div>
            </div>

            {selectionWebglFailed ? (
              <div className="grid h-full place-items-center text-sm text-slate-400">WebGL 不可用，请启用浏览器硬件加速。</div>
            ) : (
              <React.Suspense fallback={<div className="grid h-full place-items-center text-sm text-cyan-200">正在构建数字孪生…</div>}>
                <AgentVehicleScene
                  compact
                  activeZones={selectionModes.find((option) => option.id === selectionPreview)?.zones || []}
                  autoRotate
                  onFailure={() => setSelectionWebglFailed(true)}
                />
              </React.Suspense>
            )}

            <div className="pointer-events-none absolute bottom-0 left-0 right-0 z-20 bg-gradient-to-t from-[#06121f] via-[#06121f]/75 to-transparent px-6 pb-5 pt-16 md:px-8">
              <div className="flex flex-wrap items-end justify-between gap-4 border-t border-cyan-100/15 pt-4">
                <div>
                  <div className="font-mono text-[9px] tracking-[.18em] text-cyan-200/45">ACTIVE PROFILE</div>
                  <div className="mt-1 font-display text-xl font-semibold text-white">
                    {selectionModes.find((option) => option.id === selectionPreview)?.title}
                  </div>
                </div>
                <div className="flex items-center gap-5 text-xs text-slate-300/70">
                  <span><b className="mr-1 text-cyan-200">05</b> 攻击面</span>
                  <span><b className="mr-1 text-blue-300">TLS</b> 同源连接</span>
                  <span><b className="mr-1 text-amber-300">L3</b> 风险门禁</span>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );

  const disruptiveApprovalModal = disruptiveApproval && typeof document !== 'undefined'
    ? createPortal(
      <div className="fixed inset-0 z-[9999] flex items-center justify-center bg-black/80 backdrop-blur-sm p-4">
        <div className="w-full max-w-lg rounded-xl border border-amber-500/50 bg-cyber-900 shadow-[0_0_40px_rgba(245,158,11,0.2)]">
          <div className="border-b border-cyber-700 px-6 py-4">
            <div className="flex items-center gap-3 text-amber-300">
              <AlertTriangle size={20} />
              <h3 className="text-lg font-semibold">High-Risk PoC Confirmation</h3>
            </div>
          </div>
          <div className="space-y-4 px-6 py-5 text-sm text-gray-300">
            <p>{disruptiveApproval.progress} {disruptiveApproval.poc.name}</p>
            <p>这个 PoC 被标记为高风险/破坏性操作。确认后才会带 `allow_disruptive=true` 继续执行。</p>
            <p>如果你在 {disruptiveApproval.secondsLeft}s 内没有操作，系统会跳过本项，不会自动放行。</p>
          </div>
          <div className="flex items-center justify-end gap-3 border-t border-cyber-700 px-6 py-4">
            <button
              onClick={() => resolveDisruptiveApproval('skipped')}
              className="rounded-md border border-cyber-700 px-4 py-2 text-sm text-gray-300 hover:border-cyber-500 hover:text-white"
            >
              Skip This PoC
            </button>
            <button
              onClick={() => resolveDisruptiveApproval('approved')}
              className="rounded-md bg-amber-500 px-4 py-2 text-sm font-medium text-black hover:bg-amber-400"
            >
              Confirm And Execute
            </button>
            <button
              onClick={() => resolveDisruptiveApproval('approved_all')}
              className="rounded-md bg-cyber-accent px-4 py-2 text-sm font-medium text-black hover:brightness-110"
            >
              Confirm For Rest Of Scan
            </button>
          </div>
        </div>
      </div>,
      document.body
    )
    : null;

  const manualVerdictModal = manualVerdictState && typeof document !== 'undefined'
    ? createPortal(
      <div className="fixed inset-0 z-[9999] flex items-center justify-center bg-black/80 backdrop-blur-sm p-4">
        <div className="w-full max-w-xl rounded-xl border border-amber-500/50 bg-cyber-900 shadow-[0_0_40px_rgba(245,158,11,0.2)]">
          <div className="border-b border-cyber-700 px-6 py-4">
            <div className="flex items-center gap-3 text-amber-300">
              <AlertTriangle size={20} />
              <h3 className="text-lg font-semibold">Manual PoC Verdict Required</h3>
            </div>
          </div>
          <div className="space-y-4 px-6 py-5 text-sm text-gray-300">
            <p>{manualVerdictState.progress} {manualVerdictState.poc.name}</p>
            <p>{manualVerdictState.result?.manual_review?.prompt || '该 PoC 已完成执行，但目标侧效果无法由程序自动判断。请根据现场观察给出结论。'}</p>
            {manualVerdictState.result?.manual_review?.required_observations?.length ? (
              <ul className="list-disc pl-5 space-y-1 text-xs text-gray-400">
                {manualVerdictState.result.manual_review.required_observations.map((item: string, idx: number) => (
                  <li key={idx}>{item}</li>
                ))}
              </ul>
            ) : null}
            <textarea
              value={manualVerdictState.note}
              onChange={(e) => setManualVerdictState((prev) => prev ? { ...prev, note: e.target.value } : prev)}
              placeholder="观察说明，例如：车门解锁、双闪闪烁、无明显响应、ECU 返回异常帧..."
              className="w-full min-h-20 rounded border border-cyber-700 bg-black p-3 text-gray-100 outline-none focus:border-amber-400"
            />
            <input
              value={manualVerdictState.evidenceFile}
              onChange={(e) => setManualVerdictState((prev) => prev ? { ...prev, evidenceFile: e.target.value } : prev)}
              placeholder="证据文件路径，可选"
              className="w-full rounded border border-cyber-700 bg-black p-3 text-gray-100 outline-none focus:border-amber-400"
            />
          </div>
          <div className="grid grid-cols-2 gap-3 border-t border-cyber-700 px-6 py-4">
            <button onClick={() => resolveManualVerdict('confirmed_vulnerable')} className="rounded-md bg-red-600 px-4 py-2 text-sm font-medium text-white hover:bg-red-500">
              确认成功
            </button>
            <button onClick={() => resolveManualVerdict('confirmed_not_vulnerable')} className="rounded-md bg-emerald-600 px-4 py-2 text-sm font-medium text-white hover:bg-emerald-500">
              确认失败
            </button>
            <button onClick={() => resolveManualVerdict('inconclusive')} className="rounded-md border border-cyber-700 px-4 py-2 text-sm text-gray-300 hover:border-cyber-500 hover:text-white">
              无法确认
            </button>
            <button onClick={() => resolveManualVerdict('needs_retest')} className="rounded-md border border-cyber-500 px-4 py-2 text-sm text-cyber-accent hover:bg-cyber-800">
              标记复测
            </button>
            <button onClick={() => resolveManualVerdict('confirmed_vulnerable', true)} className="rounded-md border border-red-500/70 px-4 py-2 text-xs text-red-200 hover:bg-red-900/30">
              确认成功并应用剩余复核
            </button>
            <button onClick={() => resolveManualVerdict('confirmed_not_vulnerable', true)} className="rounded-md border border-emerald-500/70 px-4 py-2 text-xs text-emerald-200 hover:bg-emerald-900/30">
              确认失败并应用剩余复核
            </button>
          </div>
        </div>
      </div>,
      document.body
    )
    : null;

  return (
    <div className="min-h-full relative">
      {/* Detail Modal for Result Inspection */}
      <PocDetailModal
        poc={selectedResultPoc ? { ...selectedResultPoc, ...pocRuntimeMetadata[selectedResultPoc.id], codeSnippet: pocContents[selectedResultPoc.id] || selectedResultPoc.codeSnippet } : null}
        isOpen={!!selectedResultPoc}
        onClose={() => setSelectedResultPoc(null)}
      />

      {/* Detail Modal for Manual Mode Pre-flight Check */}
      <PocDetailModal
        poc={manualDetailPoc ? { ...manualDetailPoc, ...pocRuntimeMetadata[manualDetailPoc.id], codeSnippet: pocContents[manualDetailPoc.id] || manualDetailPoc.codeSnippet } : null}
        isOpen={!!manualDetailPoc}
        onClose={() => setManualDetailPoc(null)}
        onRunTest={handleLaunchManualTest} // This enables the "Configure & Attack" button
      />

      {/* Execution Modal */}
      <ManualTestModal
        poc={manualTestPoc ? { ...manualTestPoc, ...pocRuntimeMetadata[manualTestPoc.id], codeSnippet: pocContents[manualTestPoc.id] || manualTestPoc.codeSnippet } : null}
        isOpen={!!manualTestPoc}
        onClose={() => setManualTestPoc(null)}
        // In Manual Mode, we pass empty connection params so user MUST input them
        globalConnection={useMemo(() => (mode === 'GLOBAL' ? session.connection : EMPTY_CONNECTION), [mode, session.connection])}
        token={token}
      />

      {disruptiveApprovalModal}
      {manualVerdictModal}

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
            ← 切换模式
          </button>
          <div className="flex items-center gap-2">
            <span className={`w-2 h-2 rounded-full ${mode === 'GLOBAL' ? 'bg-cyber-accent' : mode === 'AGENT' ? 'bg-emerald-400' : 'bg-cyber-danger'}`}></span>
            <span className="text-xs font-mono font-semibold text-white">
              {mode === 'GLOBAL' ? '全局批量扫描' : mode === 'AGENT' ? 'Agent 自主扫描' : '手动诊断'}
            </span>
          </div>
        </div>
      )}

      {/* Main Content Area */}
      <div className={`h-full ${mode !== 'SELECTION' ? 'pt-12' : ''}`}>

        {mode === 'SELECTION' && renderSelectionScreen()}

        {mode === 'AGENT' && !token && (
          <div className="flex h-full items-center justify-center p-8 text-center text-gray-400">
            <p>请先登录后再使用 Agent Scan。</p>
          </div>
        )}

        {mode === 'AGENT' && token && (
          <div className="h-full flex flex-col min-h-0">
            <AgentScanErrorBoundary resetKey={`${mode}:${session.agentDraft?.targetIp || 'new'}:${session.status}`}>
              <AgentScan
                token={token}
                currentUser={currentUser}
                onSessionComplete={onAddToHistory}
                engineUrl={engineUrl}
                draft={session.agentDraft}
                onDraftChange={handleAgentDraftChange}
              />
            </AgentScanErrorBoundary>
          </div>
        )}

        {mode === 'GLOBAL' && (
          <div className="p-6 grid grid-cols-1 lg:grid-cols-3 gap-6 items-start">
            {/* Global Config Panel */}
            <div className="lg:col-span-1 space-y-6 flex flex-col lg:sticky lg:top-0 lg:max-h-[calc(100vh-6rem)] overflow-y-auto pb-6 pr-2 custom-scrollbar">
              <div className="bg-cyber-800 border border-cyber-700 p-6 rounded-lg shadow-lg shrink-0">
                <h2 className="text-xl font-bold text-white mb-4 flex items-center gap-2">
                  <Settings className="text-cyber-400" />
                  扫描配置
                </h2>

                {/* Engine Configuration Section */}
                <div className="mb-6 pb-6 border-b border-cyber-700 space-y-3">
                  <div className="flex justify-between items-center">
                    <label className="text-xs text-cyber-400 uppercase font-bold flex items-center gap-1">
                      <Link size={12} /> 本机执行引擎
                    </label>
                    <span className={`text-[10px] uppercase font-bold px-2 py-0.5 rounded ${engineStatus === 'online' ? 'bg-green-500/20 text-green-500' : 'bg-red-500/20 text-red-500'}`}>
                      {engineStatus}
                    </span>
                  </div>
                  <div className="flex gap-2">
                    <input
                      type="text"
                      value="同源本机引擎 (/api/v1)"
                      readOnly
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
                      无法连接本机引擎，请确认 <code>server.py</code> 已启动。
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
                          placeholder="PCAN_USBBUS1"
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
                      <div>
                        <label className="text-xs text-gray-500 uppercase font-bold flex items-center gap-1"><Usb size={10} /> USB ADB Serial (Optional)</label>
                        <input
                          type="text"
                          value={session.connection.usbAdbSerial}
                          onChange={(e) => setSession(p => ({ ...p, connection: { ...p.connection, usbAdbSerial: e.target.value.trim() } }))}
                          placeholder="adb devices 中的 serial"
                          className="w-full mt-1 bg-cyber-900 border border-cyber-600 text-white p-1.5 text-sm rounded font-mono focus:border-cyber-accent outline-none"
                          disabled={session.isConnected}
                        />
                      </div>
                      <div>
                        <label className="text-xs text-gray-500 uppercase font-bold flex items-center gap-1"><Usb size={10} /> USB Mount Point (Optional)</label>
                        <input
                          type="text"
                          value={session.connection.usbMountPoint}
                          onChange={(e) => setSession(p => ({ ...p, connection: { ...p.connection, usbMountPoint: e.target.value.trim() } }))}
                          placeholder="/media/usb0 或 IVI U 盘挂载路径"
                          className="w-full mt-1 bg-cyber-900 border border-cyber-600 text-white p-1.5 text-sm rounded font-mono focus:border-cyber-accent outline-none"
                          disabled={session.isConnected}
                        />
                      </div>
                    </div>
                  </div>

                  <div className="p-3 bg-cyber-900/70 border border-cyber-700 rounded space-y-3">
                    <div className="flex items-start gap-2">
                      <ShieldCheck size={14} className="mt-0.5 text-cyber-accent" />
                      <div>
                        <p className="text-xs text-cyber-300 uppercase font-bold">Execution Safety Policy</p>
                        <p className="text-[11px] text-gray-400">
                          常规 PoC 直接执行；重启、拒绝服务、数据修改等危险 PoC 在执行前请求人工确认。
                        </p>
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
                      {session.status === 'running' && (
                        <button
                          onClick={stopBatchScan}
                          className="w-full rounded border border-red-400/70 bg-red-500/15 px-4 py-3 font-bold text-red-200 transition-colors hover:bg-red-500/25 flex items-center justify-center gap-2"
                        >
                          <Square size={17} fill="currentColor" />
                          停止扫描
                        </button>
                      )}
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

            {/* Global Mode: Logs & Results — natural document flow, no viewport stretch gap */}
            <div className="lg:col-span-2 flex flex-col gap-4">
              <ScanLogs logs={session.logs} onClearLogs={() => setSession(prev => ({ ...prev, logs: [] }))} />

              {showBatchSummary && (
                <div className="flex flex-col gap-4">
                  <div className="grid grid-cols-1 xl:grid-cols-2 gap-4">
                    <div className="bg-cyber-800 border border-cyber-700 p-6 rounded-lg shadow-lg">
                      <h3 className="text-lg font-bold text-white mb-4 flex items-center gap-2">
                        <ShieldCheck className="text-cyber-accent" /> Scan Summary
                      </h3>
                      <div className="grid grid-cols-2 gap-4 mb-4">
                        <div className="bg-cyber-900/50 p-3 rounded border border-cyber-700">
                          <span className="text-[10px] text-gray-500 block uppercase">Threats Detected</span>
                          <span className="font-mono text-2xl font-bold text-red-400">
                            {batchSummaryStats.threats}
                          </span>
                        </div>
                        <div className="bg-cyber-900/50 p-3 rounded border border-cyber-700">
                          <span className="text-[10px] text-gray-500 block uppercase">Risk Factor</span>
                          <span className="font-mono text-2xl font-bold text-orange-400">
                            {batchSummaryStats.risk}%
                          </span>
                        </div>
                      </div>
                      <div className="grid grid-cols-3 gap-2 mb-4 text-center">
                        <div className="rounded border border-cyber-700 bg-cyber-900/40 px-2 py-2">
                          <div className="text-[10px] uppercase text-gray-500">Secure</div>
                          <div className="font-mono text-lg text-emerald-400">{batchSummaryStats.secure}</div>
                        </div>
                        <div className="rounded border border-cyber-700 bg-cyber-900/40 px-2 py-2">
                          <div className="text-[10px] uppercase text-gray-500">Errors</div>
                          <div className="font-mono text-lg text-amber-300">{batchSummaryStats.errors}</div>
                        </div>
                        <div className="rounded border border-cyber-700 bg-cyber-900/40 px-2 py-2">
                          <div className="text-[10px] uppercase text-gray-500">Total</div>
                          <div className="font-mono text-lg text-cyan-300">{session.results.length}</div>
                        </div>
                      </div>

                      <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 mb-3">
                        <button
                          onClick={handleExportScanPdf}
                          disabled={session.results.length === 0}
                          className="py-2.5 bg-cyber-900 border border-cyber-700 hover:border-cyber-accent disabled:opacity-40 text-white rounded font-semibold transition-all flex justify-center items-center gap-2 text-xs uppercase tracking-wide"
                        >
                          <Download size={14} className="text-cyber-accent" />
                          导出扫描报告 PDF
                        </button>
                        <button
                          onClick={handleExportScanMarkdown}
                          disabled={session.results.length === 0}
                          className="py-2.5 bg-cyber-900 border border-cyber-700 hover:border-cyan-400 disabled:opacity-40 text-white rounded font-semibold transition-all flex justify-center items-center gap-2 text-xs uppercase tracking-wide"
                        >
                          <FileDown size={14} className="text-cyan-300" />
                          导出 Markdown
                        </button>
                      </div>

                      <button
                        onClick={handleAiAnalysis}
                        disabled={isAnalysing || session.results.length === 0}
                        className="w-full py-3 bg-cyber-accent/10 border border-cyber-accent text-cyber-accent hover:bg-cyber-accent hover:text-black disabled:opacity-40 rounded font-bold transition-all flex justify-center items-center gap-2 uppercase tracking-widest text-sm shadow-[0_0_15px_rgba(0,240,255,0.1)]"
                      >
                        {isAnalysing ? <RotateCw className="animate-spin" size={16} /> : <FileText size={16} />}
                        {session.aiReport ? 'Re-Generate AI Intelligence' : 'Generate AI Security Report'}
                      </button>

                      <div className="mt-4 flex items-center justify-center gap-2 py-2 border-t border-cyber-700/50">
                        <Save size={12} className="text-cyber-500" />
                        <span className="text-[10px] font-mono text-gray-500 uppercase tracking-tighter">Session Archive Synchronized</span>
                      </div>
                    </div>

                    <div className="bg-cyber-800 border border-cyber-700 rounded-lg p-6 max-h-[360px] overflow-y-auto custom-scrollbar">
                      <h3 className="text-md font-bold text-white mb-4 flex items-center gap-2">
                        <AlertTriangle className="text-yellow-500" size={18} /> Found Vectors
                        <span className="ml-auto text-[10px] font-mono text-gray-500">{batchSummaryStats.threats} items</span>
                      </h3>
                      <div className="space-y-2">
                        {session.results.filter(r => r.vulnerable).map((res) => {
                          const poc = findPocInCatalog(pocCatalogRef.current, res);
                          return (
                            <div key={res.pocId} onClick={() => poc && setSelectedResultPoc(poc)} className="bg-cyber-900/80 border-l-2 border-cyber-danger p-2 rounded cursor-pointer hover:bg-cyber-700 transition-colors group">
                              <div className="flex justify-between items-center gap-2">
                                <span className="text-gray-200 font-bold text-xs truncate">{poc?.name || res.pocId}</span>
                                <ChevronRight size={12} className="text-gray-600 group-hover:text-cyber-accent transition-colors shrink-0" />
                              </div>
                              {res.details ? (
                                <p className="mt-1 text-[10px] text-gray-500 line-clamp-2">{res.details}</p>
                              ) : null}
                            </div>
                          );
                        })}
                        {session.results.filter(r => r.vulnerable).length === 0 && (
                          <div className="text-center text-gray-500 py-4 text-xs font-mono italic">NO THREATS IDENTIFIED</div>
                        )}
                      </div>
                    </div>
                  </div>

                  {aiReportError && (
                    <div className="rounded-lg border border-red-500/40 bg-red-950/30 px-4 py-3 text-sm text-red-200">
                      AI 报告生成失败：{aiReportError}
                    </div>
                  )}

                  {session.aiReport && (
                    <div className="bg-cyber-800 border border-cyber-accent/30 rounded-lg p-6 flex flex-col relative shadow-2xl">
                      <div className="flex justify-between items-center mb-6 border-b border-cyber-700/50 pb-4 gap-3 flex-wrap">
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
                          <Download size={14} className="text-cyber-accent" /> EXPORT AI REPORT PDF
                        </button>
                      </div>
                      <div id="ai-report-content" className="prose prose-invert max-w-none text-sm text-gray-400 font-sans p-6 bg-black/40 rounded-xl border border-cyber-800 break-words pb-6 max-h-[480px] overflow-y-auto custom-scrollbar">
                        {session.aiReport.trim() ? (
                          <MarkdownRenderer content={session.aiReport} />
                        ) : (
                          <p className="text-gray-500 italic">AI 报告为空，请重新生成或检查 Profile 中的 AI 配置。</p>
                        )}
                      </div>
                    </div>
                  )}
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
