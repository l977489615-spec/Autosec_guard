import React, { useState, useEffect, useRef } from 'react';
import { POC, ConnectionParams, ParamType } from '../types';
import { X, Play, Terminal, AlertTriangle, ShieldCheck, ServerCrash, RotateCw, WifiOff, Cpu, Send } from 'lucide-react';
import { checkBackendHealth, createEdgeTask, getBackendUrl, getEdgeAgents, getEdgeRecommendations, runPocPlugin } from '../services/api';

interface ManualTestModalProps {
  poc: POC | null;
  isOpen: boolean;
  onClose: () => void;
  globalConnection: ConnectionParams;
  token: string | null;
}

const ManualTestModal: React.FC<ManualTestModalProps> = ({ poc, isOpen, onClose, globalConnection, token }) => {
  const [localParams, setLocalParams] = useState<Partial<ConnectionParams>>({});
  const [isRunning, setIsRunning] = useState(false);
  const [consoleOutput, setConsoleOutput] = useState<string[]>([]);
  const [testResult, setTestResult] = useState<'idle' | 'success' | 'fail' | 'error'>('idle');
  const [backendOnline, setBackendOnline] = useState<boolean>(false);
  const [executionPlane, setExecutionPlane] = useState<'cloud' | 'edge'>('cloud');
  const [edgeAgents, setEdgeAgents] = useState<any[]>([]);
  const [edgeRecommendations, setEdgeRecommendations] = useState<any[]>([]);
  const [selectedEdgeAgent, setSelectedEdgeAgent] = useState<string>('');
  const scrollRef = useRef<HTMLDivElement>(null);
  const supportedPlanes = poc?.supportedExecutionPlanes || ['cloud', 'edge'];
  const cloudAllowed = supportedPlanes.includes('cloud');
  const edgeAllowed = supportedPlanes.includes('edge');

  useEffect(() => {
    // Reset state when modal opens
    if (isOpen && poc) {
      const initial: Partial<ConnectionParams> = {};
      poc.requiredParams.forEach(p => {
        if (p === 'ip') initial.ip = globalConnection.ip;
        if (p === 'port') initial.port = globalConnection.port;
        if (p === 'bluetooth_mac') initial.bluetoothMac = globalConnection.bluetoothMac;
        if (p === 'can_interface') initial.canInterface = globalConnection.canInterface;
        if (p === 'url') initial.url = globalConnection.url;
        if (p === 'frequency') initial.frequency = globalConnection.frequency;
      });
      setLocalParams(initial);
      setConsoleOutput([]);
      setTestResult('idle');
      setIsRunning(false);
      setExecutionPlane(poc.recommendedExecutionPlane || (poc.executionRequirements?.requires_edge ? 'edge' : 'cloud'));
      setSelectedEdgeAgent('');
      setEdgeRecommendations([]);

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

      if (token) {
        getEdgeAgents(token)
          .then((data) => setEdgeAgents(data.agents || []))
          .catch(() => setEdgeAgents([]));
      }
    }
  }, [isOpen, poc, globalConnection, token]);

  useEffect(() => {
    if (scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
    }
  }, [consoleOutput]);

  if (!isOpen || !poc) return null;

  const buildEdgeParams = () => {
    const next: Record<string, any> = {};
    if (localParams.ip) next.target_ip = localParams.ip;
    if (localParams.port) next.port = localParams.port;
    if (localParams.bluetoothMac) next.bluetooth_mac = localParams.bluetoothMac;
    if (localParams.canInterface) next.can_interface = localParams.canInterface;
    if (localParams.url) next.url = localParams.url;
    if (localParams.frequency) next.rf_frequency = localParams.frequency;
    if (localParams.interface) next.interface = localParams.interface;
    return next;
  };

  const handleRecommendEdge = async () => {
    if (!token || !poc?.pocFile) return;
    try {
      const data = await getEdgeRecommendations(poc.pocFile, buildEdgeParams(), token);
      setEdgeRecommendations(data.recommendations || []);
      const best = (data.recommendations || []).find((item: any) => item.matches);
      setSelectedEdgeAgent(best?.agent?.agent_id || '');
      setConsoleOutput((prev) => [...prev, `[+] Edge recommendations loaded for ${poc.name}`]);
    } catch (e: any) {
      setConsoleOutput((prev) => [...prev, `[-] Edge recommendation failed: ${e?.message || e}`]);
    }
  };

  const handleRun = async () => {
    if (!backendOnline) {
      setConsoleOutput(p => [...p, "[-] Error: Cannot execute. Backend server offline."]);
      return;
    }

    // Check missing params
    const missing = poc.requiredParams.filter(p => {
      const key = p === 'bluetooth_mac' ? 'bluetoothMac' : p === 'can_interface' ? 'canInterface' : p;
      // @ts-ignore
      return !localParams[key];
    });

    if (missing.length > 0) {
      setConsoleOutput(prev => [...prev, `[-] Error: Missing required arguments: ${missing.join(', ')}`]);
      return;
    }

    setIsRunning(true);
    setTestResult('idle');
    setConsoleOutput(p => [...p, `[*] Initiating ${executionPlane === 'cloud' ? 'cloud' : 'edge'} execution for ${poc.name}...`]);

    try {
      if (executionPlane === 'edge') {
        if (!token) {
          throw new Error('JWT token missing for edge task creation.');
        }
        const payload: any = {
          filename: poc.pocFile,
          params: buildEdgeParams(),
          sync: true,
        };
        if (selectedEdgeAgent) {
          payload.agent_id = selectedEdgeAgent;
        }
        const taskResp = await createEdgeTask(payload, token);
        setConsoleOutput((p) => [
          ...p,
          `[+] Edge task: ${taskResp.task?.task_id}`,
          `[+] Agent: ${taskResp.selected_agent?.display_name || taskResp.task?.edge_agent_id || 'auto'}`,
        ]);

        const syncResult = taskResp.sync_result;
        if (syncResult) {
          // Display logs from actual execution
          if (Array.isArray(syncResult.logs)) {
            syncResult.logs.forEach((l: string) => setConsoleOutput(p => [...p, l]));
          }
          if (Array.isArray(syncResult.errors) && syncResult.errors.length > 0) {
            syncResult.errors.forEach((e: string) => setConsoleOutput(p => [...p, `[E] ${e}`]));
          }

          if (syncResult.vulnerable) {
            setTestResult('fail');
            setConsoleOutput(p => [...p, `[!] STATUS: Vulnerability Confirmed. Evidence: ${syncResult.evidence || 'N/A'}`]);
          } else if (syncResult.success) {
            setTestResult('success');
            setConsoleOutput(p => [...p, `[*] STATUS: Clean. (${syncResult.elapsed_seconds || 0}s)`]);
          } else {
            setTestResult('error');
            setConsoleOutput(p => [...p, `[-] Execution failed: ${syncResult.error || 'unknown error'}`]);
          }
        } else {
          // Fallback: async mode (no sync_result returned)
          setConsoleOutput(p => [...p, `[*] Task queued (async). Check Edge Control panel for results.`]);
          setTestResult('idle');
        }
        setIsRunning(false);
        return;
      }

      const result = await runPocPlugin(poc.pocFile, localParams as any, token);

      // Process Result
      if (result.success) {
        result.logs.forEach(l => setConsoleOutput(p => [...p, l]));
        if (result.vulnerable) {
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

  const getLabel = (p: ParamType) => {
    switch (p) {
      case 'bluetooth_mac': return 'Bluetooth MAC';
      case 'can_interface': return 'CAN Interface';
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
              <label className="text-gray-400 text-xs block mb-1">Execution Plane</label>
              <div className="grid grid-cols-2 gap-2">
                <button
                  onClick={() => cloudAllowed && setExecutionPlane('cloud')}
                  disabled={!cloudAllowed}
                  className={`px-3 py-2 text-xs rounded border ${executionPlane === 'cloud' ? 'border-cyber-accent text-cyber-accent bg-cyber-accent/10' : 'border-cyber-700 text-gray-400 bg-cyber-900'}`}
                >
                  <span className="inline-flex items-center gap-1"><Play size={12} /> Cloud</span>
                </button>
                <button
                  onClick={() => edgeAllowed && setExecutionPlane('edge')}
                  disabled={!edgeAllowed}
                  className={`px-3 py-2 text-xs rounded border ${executionPlane === 'edge' ? 'border-emerald-400 text-emerald-300 bg-emerald-500/10' : 'border-cyber-700 text-gray-400 bg-cyber-900'}`}
                >
                  <span className="inline-flex items-center gap-1"><Cpu size={12} /> Edge</span>
                </button>
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
                  value={localParams[param === 'bluetooth_mac' ? 'bluetoothMac' : param === 'can_interface' ? 'canInterface' : param] || ''}
                  onChange={(e) => {
                    const key = param === 'bluetooth_mac' ? 'bluetoothMac' : param === 'can_interface' ? 'canInterface' : param;
                    setLocalParams(p => ({ ...p, [key]: e.target.value }));
                  }}
                />
              </div>
            ))}
            {executionPlane === 'edge' && (
              <div className="space-y-2 pt-2 border-t border-cyber-700">
                <button
                  onClick={handleRecommendEdge}
                  disabled={!token}
                  className="w-full py-2 flex items-center justify-center gap-2 rounded text-xs font-bold border border-emerald-500/40 text-emerald-300 bg-emerald-500/10 disabled:opacity-50"
                >
                  <Send size={12} />
                  推荐边缘节点
                </button>
                <select
                  value={selectedEdgeAgent}
                  onChange={(e) => setSelectedEdgeAgent(e.target.value)}
                  className="w-full bg-cyber-900 border border-cyber-700 text-white p-2 text-xs rounded focus:border-cyber-accent outline-none"
                >
                  <option value="">自动选择匹配节点</option>
                  {edgeRecommendations.length === 0 && edgeAgents.length === 0 && (
                    <option value="" disabled>暂无已注册边缘节点</option>
                  )}
                  {edgeRecommendations.map((item) => (
                    <option key={item.agent.agent_id} value={item.agent.agent_id}>
                      {item.agent.display_name} [{item.agent.status}]
                    </option>
                  ))}
                  {edgeRecommendations.length === 0 && edgeAgents.map((agent) => (
                    <option key={agent.agent_id} value={agent.agent_id}>
                      {agent.display_name} [{agent.status}]
                    </option>
                  ))}
                </select>
              </div>
            )}
            <div className="pt-4">
              <button
                onClick={handleRun}
                disabled={isRunning || !backendOnline}
                className={`w-full py-2 flex items-center justify-center gap-2 rounded font-bold text-sm transition-all ${isRunning || !backendOnline ? 'bg-gray-700 text-gray-500 cursor-not-allowed' : 'bg-cyber-danger text-white hover:bg-red-600 shadow-lg'
                  }`}
              >
                {isRunning ? <RotateCw className="animate-spin" size={14} /> : <Play size={14} />}
                {isRunning ? 'EXECUTING...' : executionPlane === 'cloud' ? 'RUN IN CLOUD' : 'RUN ON EDGE'}
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
              {isRunning && <div className="animate-pulse text-cyber-accent">_ Executing remote payload...</div>}
            </div>
            {testResult !== 'idle' && (
              <div className={`mt-2 p-2 border rounded flex items-center gap-2 ${testResult === 'fail' ? 'border-red-500 bg-red-900/20 text-red-500' : testResult === 'success' ? 'border-green-500 bg-green-900/20 text-green-500' : 'border-gray-500 text-gray-500'}`}>
                {testResult === 'fail' ? <AlertTriangle size={16} /> : testResult === 'success' ? <ShieldCheck size={16} /> : <ServerCrash size={16} />}
                <span className="font-bold uppercase">{testResult === 'fail' ? 'Vulnerability Confirmed' : testResult === 'success' ? 'Target Secure' : 'Execution Error'}</span>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};

export default ManualTestModal;
