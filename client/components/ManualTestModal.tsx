import React, { useState, useEffect, useRef } from 'react';
import { POC, ConnectionParams, ParamType } from '../types';
import { X, Play, Terminal, AlertTriangle, ShieldCheck, ServerCrash, RotateCw, WifiOff, Cpu } from 'lucide-react';
import { checkBackendHealth, getBackendUrl, runPocPlugin, submitPocManualVerdict, ExecutionResult } from '../services/api';

interface ManualTestModalProps {
  poc: POC | null;
  isOpen: boolean;
  onClose: () => void;
  globalConnection: ConnectionParams;
  token: string | null;
}

const ManualTestModal: React.FC<ManualTestModalProps> = ({ poc, isOpen, onClose, globalConnection, token }) => {
  const [localParams, setLocalParams] = useState<Partial<ConnectionParams>>({});
  const prevIsOpen = useRef(false);
  const prevPocId = useRef<string | null>(null);

  const [isRunning, setIsRunning] = useState(false);
  const [isSubmittingVerdict, setIsSubmittingVerdict] = useState(false);
  const [consoleOutput, setConsoleOutput] = useState<string[]>([]);
  const [testResult, setTestResult] = useState<'idle' | 'success' | 'fail' | 'error' | 'manual'>('idle');
  const [pendingManualResult, setPendingManualResult] = useState<ExecutionResult | null>(null);
  const [operatorNote, setOperatorNote] = useState('');
  const [evidenceFile, setEvidenceFile] = useState('');
  const [backendOnline, setBackendOnline] = useState<boolean>(false);
  const scrollRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    // Initialize/Reset state only when modal opens or PoC changes
    if (isOpen && poc && (!prevIsOpen.current || prevPocId.current !== poc.id)) {
      const initial: Partial<ConnectionParams> = {};
      poc.requiredParams.forEach(p => {
        if (p === 'ip') initial.ip = globalConnection.ip;
        if (p === 'port') initial.port = globalConnection.port;
        if (p === 'bluetooth_mac') initial.bluetoothMac = globalConnection.bluetoothMac;
        if (p === 'can_interface') initial.canInterface = globalConnection.canInterface;
        if (p === 'url') initial.url = globalConnection.url;
        if (p === 'frequency') initial.frequency = globalConnection.frequency;
        if (p === 'interface') initial.interface = globalConnection.interface;
        if (p === 'usb_adb_serial') initial.usbAdbSerial = globalConnection.usbAdbSerial;
        if (p === 'usb_mount_point') initial.usbMountPoint = globalConnection.usbMountPoint;
      });
      setLocalParams(initial);
      setConsoleOutput([]);
      setTestResult('idle');
      setIsRunning(false);
      setIsSubmittingVerdict(false);
      setPendingManualResult(null);
      setOperatorNote('');
      setEvidenceFile('');

      // Check if backend is alive
      const currentUrl = getBackendUrl();
      checkBackendHealth().then(status => {
        setBackendOnline(status);
        if (!status) setConsoleOutput([
          `[-] Warning: Execution Engine is unreachable at ${currentUrl}`,
          "[-] Ensure 'python server.py' is running locally.",
          "[-] Check Global Config if you need to change IP/Port."
        ]);
        else setConsoleOutput([`[+] Execution Engine Online (${currentUrl})`]);
      });

    }
    
    prevIsOpen.current = isOpen;
    prevPocId.current = poc?.id || null;
  }, [isOpen, poc, globalConnection, token]);

  useEffect(() => {
    if (scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
    }
  }, [consoleOutput]);

  if (!isOpen || !poc) return null;

  const handleRun = async () => {
    if (!backendOnline) {
      setConsoleOutput(p => [...p, "[-] Error: Cannot execute. Backend server offline."]);
      return;
    }

    // Check missing params
    const missing = poc.requiredParams.filter(p => !localParams[paramFieldKey(p) as keyof ConnectionParams]);

    if (missing.length > 0) {
      setConsoleOutput(prev => [...prev, `[-] Error: Missing required arguments: ${missing.join(', ')}`]);
      return;
    }

    setIsRunning(true);
    setTestResult('idle');
    setPendingManualResult(null);
    setConsoleOutput(p => [...p, `[*] Initiating local vehicle runtime execution for ${poc.name}...`]);

    try {
      const result = await runPocPlugin(poc.pocFile, localParams as any, token);

      // Process Result
      if (result.success) {
        result.logs.forEach(l => setConsoleOutput(p => [...p, l]));
        if (result.requires_human_review || result.verification_status === 'pending_manual_review') {
          setTestResult('manual');
          setPendingManualResult(result);
          setConsoleOutput(p => [
            ...p,
            `[?] STATUS: Waiting for operator verdict.`,
            `[?] ${result.manual_review?.prompt || 'Observe the target and record the physical/business effect.'}`
          ]);
        } else if (result.vulnerable) {
          setTestResult('fail');
          setConsoleOutput(p => [...p, `[!] STATUS: Vulnerability Confirmed.`]);
        } else {
          setTestResult('success');
          setConsoleOutput(p => [...p, `[*] STATUS: Clean.`]);
        }
      } else {
        result.errors.forEach(e => setConsoleOutput(p => [...p, `[E] ${e}`]));
        setTestResult('error');
      }

    } catch (e) {
      setConsoleOutput(p => [...p, `[-] Critical Frontend Error: ${e}`]);
      setTestResult('error');
    }

    setIsRunning(false);
  };

  const handleManualVerdict = async (
    verdict: 'confirmed_vulnerable' | 'confirmed_not_vulnerable' | 'inconclusive' | 'needs_retest'
  ) => {
    if (!pendingManualResult) return;
    setIsSubmittingVerdict(true);
    const review = await submitPocManualVerdict({
      trace_id: pendingManualResult.trace_id,
      session_id: 'manual',
      poc_id: pendingManualResult.poc_id || poc.pocFile || poc.id,
      poc_name: poc.name,
      target_ip: (localParams as any).ip || (localParams as any).target_ip,
      target_mac: (localParams as any).targetMac,
      bluetooth_mac: (localParams as any).bluetoothMac,
      verdict,
      operator_note: operatorNote,
      evidence_file: evidenceFile,
    }, token);

    if (!review.success) {
      review.errors.forEach(e => setConsoleOutput(p => [...p, `[E] ${e}`]));
      setIsSubmittingVerdict(false);
      return;
    }

    setPendingManualResult(null);
    if (review.vulnerable === true) {
      setTestResult('fail');
      setConsoleOutput(p => [...p, `[!] MANUAL VERDICT: Vulnerability confirmed by operator.`]);
    } else if (review.vulnerable === false) {
      setTestResult('success');
      setConsoleOutput(p => [...p, `[*] MANUAL VERDICT: No observable exploit effect.`]);
    } else {
      setTestResult('error');
      setConsoleOutput(p => [...p, `[?] MANUAL VERDICT: ${review.verification_status || verdict}.`]);
    }
    setIsSubmittingVerdict(false);
  };

  const paramFieldKey = (param: ParamType): keyof ConnectionParams | ParamType => {
    if (param === 'bluetooth_mac') return 'bluetoothMac';
    if (param === 'can_interface') return 'canInterface';
    if (param === 'usb_adb_serial') return 'usbAdbSerial';
    if (param === 'usb_mount_point') return 'usbMountPoint';
    return param;
  };

  const getLabel = (p: ParamType) => {
    switch (p) {
      case 'bluetooth_mac': return 'Bluetooth MAC';
      case 'can_interface': return 'CAN Interface';
      case 'usb_adb_serial': return 'USB ADB Serial';
      case 'usb_mount_point': return 'USB Mount Point';
      default: return p.toUpperCase();
    }
  };

  return (
    <div className="fixed inset-0 z-[60] flex items-center justify-center bg-black/90 backdrop-blur-sm p-4 font-mono">
      <div className="bg-cyber-900 border border-cyber-500 w-full max-w-2xl rounded-lg shadow-[0_0_50px_rgba(59,130,246,0.2)] overflow-hidden flex flex-col max-h-[90vh]">
        {/* Header */}
        <div className="flex justify-between items-center p-4 border-b border-cyber-700 bg-cyber-800">
          <div className="flex items-center gap-2">
            <Terminal className="text-cyber-accent" />
            <h2 className="text-white font-bold">Real Execution: {poc.id}</h2>
          </div>
          <button onClick={onClose} className="text-gray-400 hover:text-white"><X size={20} /></button>
        </div>

        <div className="flex flex-col md:flex-row h-full overflow-hidden">
          {/* Left: Params Input */}
          <div className="w-full md:w-1/3 bg-cyber-800 p-4 border-r border-cyber-700 space-y-4 overflow-y-auto">
            {!backendOnline && (
              <div className="p-2 bg-red-900/50 border border-red-500 rounded text-xs text-red-300 flex items-center gap-2 mb-2">
                <WifiOff size={16} /> Server Offline
              </div>
            )}

            <div>
              <label className="text-gray-400 text-xs block mb-1">Execution Runtime</label>
              <div className="px-3 py-2 text-xs rounded border border-emerald-400 text-emerald-300 bg-emerald-500/10">
                <span className="inline-flex items-center gap-1"><Cpu size={12} /> Local Vehicle Workstation</span>
              </div>
              {poc.executionRequirements?.requires_edge && (
                <p className="text-[10px] text-amber-300 mt-2">
                  This PoC requires local capabilities: {poc.executionRequirements.required_capabilities.join(', ')}.
                </p>
              )}
            </div>

            <h3 className="text-cyber-400 text-xs uppercase font-bold mb-2">Configuration</h3>
            {poc.requiredParams.map(param => (
              <div key={param}>
                <label className="text-gray-400 text-xs block mb-1">{getLabel(param)}</label>
                <input
                  type="text"
                  className="w-full bg-cyber-900 border border-cyber-700 text-white p-2 text-xs rounded focus:border-cyber-accent outline-none"
                  // @ts-ignore
                  value={String(localParams[paramFieldKey(param) as keyof ConnectionParams] ?? '')}
                  onChange={(e) => {
                    const key = paramFieldKey(param);
                    setLocalParams(p => ({ ...p, [key]: e.target.value }));
                  }}
                />
              </div>
            ))}
            <div className="pt-4">
              <button
                onClick={handleRun}
                disabled={isRunning || !backendOnline}
                className={`w-full py-2 flex items-center justify-center gap-2 rounded font-bold text-sm transition-all ${isRunning || !backendOnline ? 'bg-gray-700 text-gray-500 cursor-not-allowed' : 'bg-cyber-danger text-white hover:bg-red-600 shadow-lg'
                  }`}
              >
                {isRunning ? <RotateCw className="animate-spin" size={14} /> : <Play size={14} />}
                {isRunning ? 'EXECUTING...' : 'RUN LOCALLY'}
              </button>
            </div>
          </div>

          {/* Right: Console Output */}
          <div className="flex-1 bg-black p-4 flex flex-col min-h-[300px]">
            <div className="flex-1 overflow-y-auto font-mono text-xs space-y-1 text-green-500" ref={scrollRef}>
              {consoleOutput.map((line, i) => (
                <div key={i} className={`${line.includes('Error') || line.includes('VULNERABLE') || line.includes('fail') ? 'text-red-500' :
                    line.includes('Online') ? 'text-cyber-accent' :
                      'text-green-500'
                  }`}>
                  {line.startsWith('[*]') ? '>' : ''} {line}
                </div>
              ))}
              {isRunning && <div className="animate-pulse text-cyber-accent">_ Executing local payload...</div>}
            </div>
            {testResult !== 'idle' && (
              <div className={`mt-2 p-2 border rounded flex items-center gap-2 ${testResult === 'fail' ? 'border-red-500 bg-red-900/20 text-red-500' : testResult === 'success' ? 'border-green-500 bg-green-900/20 text-green-500' : testResult === 'manual' ? 'border-amber-500 bg-amber-900/20 text-amber-300' : 'border-gray-500 text-gray-500'}`}>
                {testResult === 'fail' ? <AlertTriangle size={16} /> : testResult === 'success' ? <ShieldCheck size={16} /> : testResult === 'manual' ? <AlertTriangle size={16} /> : <ServerCrash size={16} />}
                <span className="font-bold uppercase">{testResult === 'fail' ? 'Vulnerability Confirmed' : testResult === 'success' ? 'Target Secure' : testResult === 'manual' ? 'Manual Verdict Required' : 'Execution Error'}</span>
              </div>
            )}
            {pendingManualResult && (
              <div className="mt-3 rounded border border-amber-500/50 bg-cyber-900 p-3 text-xs text-gray-200 space-y-3">
                <div className="font-bold text-amber-300">人工判定型 PoC</div>
                <div>{pendingManualResult.manual_review?.prompt || '该 PoC 已完成执行，但需要人工确认目标侧效果。'}</div>
                {pendingManualResult.manual_review?.required_observations?.length ? (
                  <ul className="list-disc pl-5 space-y-1 text-gray-300">
                    {pendingManualResult.manual_review.required_observations.map((item, idx) => (
                      <li key={idx}>{item}</li>
                    ))}
                  </ul>
                ) : null}
                <textarea
                  value={operatorNote}
                  onChange={(e) => setOperatorNote(e.target.value)}
                  placeholder="观察说明，例如：车门解锁、双闪闪烁、无可见响应、台架 ECU 返回异常帧..."
                  className="w-full min-h-16 rounded border border-cyber-700 bg-black p-2 text-gray-100 outline-none focus:border-amber-400"
                />
                <input
                  value={evidenceFile}
                  onChange={(e) => setEvidenceFile(e.target.value)}
                  placeholder="证据文件路径，可选，例如 lab/evidence/case_001_video.mp4"
                  className="w-full rounded border border-cyber-700 bg-black p-2 text-gray-100 outline-none focus:border-amber-400"
                />
                <div className="grid grid-cols-2 gap-2">
                  <button disabled={isSubmittingVerdict} onClick={() => handleManualVerdict('confirmed_vulnerable')} className="rounded bg-red-600 px-3 py-2 font-bold text-white disabled:opacity-50">
                    确认成功
                  </button>
                  <button disabled={isSubmittingVerdict} onClick={() => handleManualVerdict('confirmed_not_vulnerable')} className="rounded bg-emerald-600 px-3 py-2 font-bold text-white disabled:opacity-50">
                    确认失败
                  </button>
                  <button disabled={isSubmittingVerdict} onClick={() => handleManualVerdict('inconclusive')} className="rounded border border-gray-600 px-3 py-2 font-bold text-gray-200 disabled:opacity-50">
                    无法确认
                  </button>
                  <button disabled={isSubmittingVerdict} onClick={() => handleManualVerdict('needs_retest')} className="rounded border border-cyber-500 px-3 py-2 font-bold text-cyber-accent disabled:opacity-50">
                    需复测
                  </button>
                </div>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};

export default ManualTestModal;
