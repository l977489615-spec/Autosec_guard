import React, { useState, useEffect } from 'react';
import { Bot, Shield, Network, Cpu, FileText, Play, Loader, CheckCircle, XCircle, Key, Sliders, Download, RotateCcw, AlertTriangle, ShieldCheck, Zap } from 'lucide-react';
import { saveScanSession } from '../services/api';
import ScanLogs from './ScanLogs';
import { POC_DATABASE } from '../constants';
import { PhaseRecord, PlannerStep, Severity, SupervisorAdjustment, SupervisorEvent, SupervisorMetrics } from '../types';
import { Canvas } from '@react-three/fiber';
import { OrbitControls, Environment, ContactShadows } from '@react-three/drei';
import { CarModel } from './CarModel';
import ReactMarkdown from 'react-markdown';
import remarkGfm from 'remark-gfm';
import AttackGraph from './AttackGraph';
import { assessPhysicalImpact, generateAttackGraph, generateStructuredReport, simulateRemediation, getBackendUrl, setBackendUrl } from '../services/api';
import { AssessmentArtifacts } from '../types';

interface AgentPhase {
  name: string;
  label: string;
  icon: any;
  description: string;
}

const PHASES: AgentPhase[] = [
  { name: 'recon', label: '侦察 Agent', icon: Network, description: '端口扫描 + 拓扑分析 + 服务指纹' },
  { name: 'planner', label: '规划 Agent', icon: Sliders, description: '多级任务编排与攻击路径规划' },
  { name: 'decision', label: '决策 Agent', icon: Cpu, description: '自适应 PoC 筛选 + 认证策略生成' },
  { name: 'weaponize', label: '开采 Agent', icon: Zap, description: '零日漏洞 (0-day) 动态载荷生成' },
  { name: 'execute', label: '执行 Agent', icon: Shield, description: 'PoC 自动化执行 + 响应反馈闭环' },
  { name: 'reflector', label: '反思 Agent', icon: RotateCcw, description: '错误恢复与动态策略调整' },
  { name: 'assess', label: '评估 Agent', icon: FileText, description: 'ISO 21434 合规报告生成' },
];

interface PhaseResult {
  phase: string;
  status: 'idle' | 'running' | 'done' | 'error' | 'retrying' | 'skipped';
  output: string;
}

interface TopologyData {
  has_security_gateway: boolean;
  recommended_attack_vector: string;
  node_count: number;
  nodes: Array<{ ip: string; name: string; open_ports: number[]; is_behind_gateway: boolean }>;
}

interface AdaptiveContext {
  detected_services: string[];
  auth_contexts: Array<{ service: string; auth_type: string; recommended_strategy: string }>;
  ivi_load: { status: string; latency_ms: number; recommended_interval_ms: number };
  poc_filter_active: boolean;
  strategies: Record<string, string>;
}

interface AgentScanProps {
  token: string;
  onSessionComplete?: (session: any) => void;
  engineUrl?: string;
}

const diagnosePhaseFailure = ({
  backendUrl,
  status,
  errorMessage,
  payload,
}: {
  backendUrl: string;
  status?: number;
  errorMessage?: string;
  payload?: any;
}) => {
  const serverMessage = payload?.error || payload?.message || '';
  const combined = `${errorMessage || ''} ${serverMessage}`.trim();

  if (!status && /failed to fetch|networkerror|load failed|network request failed/i.test(combined)) {
    return [
      'Diagnosis: 后端地址错误或后端不可达',
      `Backend: ${backendUrl}`,
      'Action: 检查 Execution Engine URL，确认后端服务已启动且浏览器可访问。',
    ].join('\n');
  }

  if (status === 401 || status === 403) {
    return [
      'Diagnosis: Token 失效或权限不足',
      `HTTP Status: ${status}`,
      'Action: 重新登录，或确认当前账号具备访问该接口的权限。',
    ].join('\n');
  }

  if (/DASHSCOPE_API_KEY 未配置|AI 报告功能未启用|API key/i.test(combined)) {
    return [
      'Diagnosis: 模型 API Key 未配置',
      'Detail: 服务端未检测到 DASHSCOPE_API_KEY，Agent 无法调用模型。',
      'Action: 在 .env 中配置 DASHSCOPE_API_KEY 后重启后端。',
    ].join('\n');
  }

  if (/MCP Server 不可达|无法连接 MCP Server|Cannot connect to AutoSec API/i.test(combined)) {
    return [
      'Diagnosis: MCP Server 不可达',
      'Detail: Agent 工具注册或工具调用链路未能连通 MCP / AutoSec API。',
      'Action: 检查 MCP_SERVER 与 AUTOSEC_API 配置，确认相关服务已启动。',
    ].join('\n');
  }

  if (status && status >= 500) {
    return [
      'Diagnosis: 后端 500 异常',
      `HTTP Status: ${status}`,
      `Detail: ${serverMessage || combined || 'Internal Server Error'}`,
      'Action: 查看后端控制台日志，定位对应阶段的异常栈。',
    ].join('\n');
  }

  return [
    'Diagnosis: 未分类执行错误',
    `Detail: ${serverMessage || combined || 'Unknown error'}`,
    'Action: 查看控制台日志并核对当前阶段输入参数。',
  ].join('\n');
};

const diagnosePhaseOutput = (output: string) => {
  if (/DASHSCOPE_API_KEY 未配置|AI 报告功能未启用|API 错误|请求失败或配额耗尽/i.test(output)) {
    return {
      isError: true,
      output: [
        'Diagnosis: 模型 API 或模型调用失败',
        `Detail: ${output}`,
        'Action: 检查 DASHSCOPE_API_KEY、模型额度和外网连通性。',
      ].join('\n'),
    };
  }

  if (/MCP Server 不可达|无法连接 MCP Server|Cannot connect to AutoSec API/i.test(output)) {
    return {
      isError: true,
      output: [
        'Diagnosis: MCP / AutoSec API 调用失败',
        `Detail: ${output}`,
        'Action: 检查 MCP Server、AutoSec API 与端口配置。',
      ].join('\n'),
    };
  }

  return { isError: false, output };
};

const stringifyPhaseContext = (label: string, output: string, structured?: any) => {
  if (structured && Object.keys(structured).length > 0) {
    return `\n\n${label} 结果(JSON):\n${JSON.stringify(structured, null, 2)}`;
  }
  return `\n\n${label} 结果:\n${output}`;
};

const LOAD_COLOR: Record<string, string> = {
  normal: 'text-emerald-400',
  high: 'text-amber-400',
  critical: 'text-red-400',
  unknown: 'text-gray-400',
};

const buildIdlePhases = (): PhaseResult[] =>
  PHASES.map(p => ({ phase: p.name, status: 'idle', output: '' }));

const buildUiPhasesFromRecords = (records: PhaseRecord[] = [], previous?: PhaseResult[]): PhaseResult[] => {
  const prior = previous || buildIdlePhases();
  return PHASES.map((phase, index) => {
    const record = records.find(item => item.phase === phase.name);
    if (!record) return prior[index] || { phase: phase.name, status: 'idle', output: '' };
    return {
      phase: phase.name,
      status: (record.status as PhaseResult['status']) || 'idle',
      output: record.raw_output || record.error || prior[index]?.output || '',
    };
  });
};

const getResumablePhase = (records: PhaseRecord[] = []) => {
  for (const phase of PHASES) {
    const record = records.find(item => item.phase === phase.name);
    if (!record) return phase.name;
    if (record.status === 'error' || record.status === 'retrying' || record.status === 'pending') {
      return phase.name;
    }
  }
  return null;
};

const AgentScan: React.FC<AgentScanProps> = ({ token, onSessionComplete, engineUrl }) => {
  const [targetIp, setTargetIp] = useState('');
  const [targetName, setTargetName] = useState('IVI System');
  const [isFullMode, setIsFullMode] = useState(true);
  const [showAdvanced, setShowAdvanced] = useState(true);

  // 可选参数 — 控制 Agent 选择哪类 PoC
  const [canInterface, setCanInterface] = useState('PCAN_USBBUS1');
  const [bluetoothMac, setBluetoothMac] = useState('');
  const [wifiInterface, setWifiInterface] = useState('');
  const [rfFrequency, setRfFrequency] = useState('');

  const [topology, setTopology] = useState<TopologyData | null>(null);
  const [adaptiveCtx, setAdaptiveCtx] = useState<AdaptiveContext | null>(null);
  const [phases, setPhases] = useState<PhaseResult[]>(
    PHASES.map(p => ({ phase: p.name, status: 'idle', output: '' }))
  );
  const [finalReport, setFinalReport] = useState('');
  const [isRunning, setIsRunning] = useState(false);
  const [activeStep, setActiveStep] = useState<number>(-1);
  const [scanTime, setScanTime] = useState('');
  const [riskScore, setRiskScore] = useState(0);
  const [results, setResults] = useState<any[]>([]);
  const [logs, setLogs] = useState<any[]>([]);
  const [assessment, setAssessment] = useState<AssessmentArtifacts>({});
  const [phaseRecords, setPhaseRecords] = useState<PhaseRecord[]>([]);
  const [structuredState, setStructuredState] = useState<Record<string, any>>({});
  const [findings, setFindings] = useState<any[]>([]);

  const STORAGE_KEY = 'autosec_agent_scan_state';

  useEffect(() => {
    if (engineUrl) {
      setBackendUrl(engineUrl);
    }
  }, [engineUrl]);
  const resolveBackendUrl = () => (engineUrl ? engineUrl.replace(/\/$/, '') : getBackendUrl());

  // ── 从 localStorage 恢复状态 ──
  useEffect(() => {
    try {
      const saved = localStorage.getItem(STORAGE_KEY);
      if (saved) {
        const s = JSON.parse(saved);
        if (s.targetIp) setTargetIp(s.targetIp);
        if (s.targetName) setTargetName(s.targetName);
        const restoredPhaseRecords = Array.isArray(s.phaseRecords) ? s.phaseRecords : [];
        setPhaseRecords(restoredPhaseRecords);
        setStructuredState(s.structuredState || {});
        setFindings(Array.isArray(s.findings) ? s.findings : []);
        setPhases(
          Array.isArray(s.phases) && s.phases.length === PHASES.length
            ? s.phases
            : buildUiPhasesFromRecords(restoredPhaseRecords)
        );
        if (s.finalReport) setFinalReport(s.finalReport);
        if (s.topology) setTopology(s.topology);
        if (s.adaptiveCtx) setAdaptiveCtx(s.adaptiveCtx);
        if (s.scanTime) setScanTime(s.scanTime);
        if (s.canInterface) setCanInterface(s.canInterface);
        if (s.bluetoothMac) setBluetoothMac(s.bluetoothMac);
        if (s.wifiInterface) setWifiInterface(s.wifiInterface);
        if (s.rfFrequency) setRfFrequency(s.rfFrequency);
        setActiveStep(-1);
        if (s.riskScore) setRiskScore(s.riskScore);
        if (s.results) setResults(s.results);
        if (s.logs) setLogs(s.logs);
        if (s.assessment) setAssessment(s.assessment);
        if (typeof s.activeStep === 'number') setActiveStep(s.activeStep);
      }
    } catch { }
  }, []);

  // ── 保存状态到 localStorage ──
  const saveState = (override: Record<string, unknown> = {}) => {
    try {
      const current = {
        targetIp, targetName, phases, finalReport,
        topology, adaptiveCtx, scanTime, activeStep,
        canInterface, bluetoothMac, wifiInterface, rfFrequency,
        riskScore, results, logs,
        assessment,
        phaseRecords,
        structuredState,
        findings,
        ...override,
      };
      localStorage.setItem(STORAGE_KEY, JSON.stringify(current));
    } catch { }
  };

  const authHeaders = {
    'Content-Type': 'application/json',
    'Authorization': `Bearer ${token}`,
  };


  const fetchAdaptiveContext = async (ip: string, openPorts: number[] = []) => {
    try {
      const r = await fetch(`${resolveBackendUrl()}/api/adaptive-context`, {
        method: 'POST',
        headers: authHeaders,
        body: JSON.stringify({ target_ip: ip, open_ports: openPorts, reset: true }),
      });
      if (r.ok) setAdaptiveCtx(await r.json());
    } catch { }
  };

  // Calculate active zones for the 3D car model based on active step, results and logs
  const activeZones = React.useMemo(() => {
    if (activeStep < 0) return [];
    const currentPhase = PHASES[activeStep]?.name;
    const zones = new Set<string>();

    if (currentPhase === 'recon') zones.add('recon');

    // Display vulnerabilities that have been confirmed
    results.forEach(r => {
      const n = r.name.toLowerCase();
      if (n.includes('wifi') || n.includes('wireless') || n.includes('network') || n.includes('qnx')) zones.add('wireless');
      if (n.includes('bluetooth') || n.includes('bt') || n.includes('snoo')) zones.add('bluetooth');
      if (n.includes('can') || n.includes('uds') || n.includes('obd')) zones.add('canbus');
      if (n.includes('ssh') || n.includes('telnet') || n.includes('http') || n.includes('application') || n.includes('ivi')) zones.add('ivi');
      if (n.includes('gateway') || n.includes('advanced')) zones.add('advanced');
    });

    // Animate zones based on recent logs while executing to show "live hacking"
    if (currentPhase === 'execute') {
        const recentLogs = logs.slice(-8); // look at recent logs to flash zones
        recentLogs.forEach(l => {
           const msg = (l.message || '').toLowerCase();
           if (msg.includes('can') || msg.includes('uds')) zones.add('canbus');
           if (msg.includes('wifi') || msg.includes('wireless') || msg.includes('qnx')) zones.add('wireless');
           if (msg.includes('bluetooth') || msg.includes('bt')) zones.add('bluetooth');
           if (msg.includes('ssh') || msg.includes('http') || msg.includes('telnet') || msg.includes('adb')) zones.add('ivi');
           if (msg.includes('gateway') || msg.includes('route')) zones.add('advanced');
        });
    }

    return Array.from(zones);
  }, [activeStep, results, logs]);

  const fetchTopology = async (ip: string) => {
    try {
      const r = await fetch(`${resolveBackendUrl()}/api/topology`, {
        method: 'POST',
        headers: authHeaders,
        body: JSON.stringify({ target_ip: ip }),
      });
      if (r.ok) {
        const data = await r.json();
        setTopology(data);
        const ports = data.nodes?.[0]?.open_ports ?? [];
        await fetchAdaptiveContext(ip, ports);
      }
    } catch { }
  };

  const handleReset = () => {
    if (isRunning) return;
    if (!window.confirm('确定要重置所有设置、清除上次的检测结果和报告吗？')) return;
    setTargetIp('');
    setTargetName('IVI System');
    setIsFullMode(true);
    setCanInterface('PCAN_USBBUS1');
    setBluetoothMac('');
    setWifiInterface('');
    setRfFrequency('');
    setTopology(null);
    setAdaptiveCtx(null);
    setPhases(PHASES.map(p => ({ phase: p.name, status: 'idle', output: '' })));
    setFinalReport('');
    setActiveStep(-1);
    setScanTime('');
    setRiskScore(0);
    setResults([]);
    setLogs([]);
    setAssessment({});
    setPhaseRecords([]);
    setStructuredState({});
    setFindings([]);
    localStorage.removeItem(STORAGE_KEY);
  };

  const updatePhase = (idx: number, update: Partial<PhaseResult>) => {
    setPhases(prev => prev.map((p, i) => i === idx ? { ...p, ...update } : p));
  };

  const persistRunState = ({
    nextLogs,
    nextResults,
    nextFindings,
    nextPhaseRecords,
    nextStructured,
    nextAssessment,
    nextFinalReport,
    nextActiveStep,
    nextPhases,
  }: {
    nextLogs?: any[];
    nextResults?: any[];
    nextFindings?: any[];
    nextPhaseRecords?: PhaseRecord[];
    nextStructured?: Record<string, any>;
    nextAssessment?: AssessmentArtifacts;
    nextFinalReport?: string;
    nextActiveStep?: number;
    nextPhases?: PhaseResult[];
  }) => {
    saveState({
      logs: nextLogs ?? logs,
      results: nextResults ?? results,
      findings: nextFindings ?? findings,
      phaseRecords: nextPhaseRecords ?? phaseRecords,
      structuredState: nextStructured ?? structuredState,
      assessment: nextAssessment ?? assessment,
      finalReport: nextFinalReport ?? finalReport,
      activeStep: nextActiveStep ?? activeStep,
      phases: nextPhases ?? phases,
    });
  };

  const runAssessment = async (resumeFrom?: string) => {
    if (!targetIp.trim()) return;
    const now = new Date().toLocaleString('zh-CN', { hour12: false });
    setScanTime(now);
    setIsRunning(true);
    const isResume = Boolean(resumeFrom);
    const resetPhases = buildIdlePhases();
    const initialPhaseRecords = isResume ? [...phaseRecords] : [];
    const initialStructured = isResume ? { ...structuredState } : {};
    const initialFindings = isResume ? [...findings] : [];
    const initialResults = isResume ? [...results] : [];
    const initialLogs = isResume
      ? [...logs, { timestamp: new Date().toLocaleTimeString(), type: 'info', message: `[*] 从阶段 ${resumeFrom} 恢复执行任务: ${targetName}` }]
      : [
          { timestamp: new Date().toLocaleTimeString(), type: 'info', message: `[*] 启动自主渗透测试任务: ${targetName}` },
          { timestamp: new Date().toLocaleTimeString(), type: 'info', message: `[*] 目标向量: ${targetIp}` }
        ];

    if (!isResume) {
      setPhases(resetPhases);
      setTopology(null);
      setAdaptiveCtx(null);
      setFinalReport('');
      setActiveStep(-1);
      setRiskScore(0);
      setResults([]);
      setLogs([]);
      setAssessment({});
      setPhaseRecords([]);
      setStructuredState({});
      setFindings([]);
      saveState({
        phases: resetPhases,
        finalReport: '',
        topology: null,
        adaptiveCtx: null,
        activeStep: -1,
        scanTime: now,
        riskScore: 0,
        results: [],
        logs: [],
        assessment: {},
        phaseRecords: [],
        structuredState: {},
        findings: [],
      });
      await fetchTopology(targetIp);
    } else {
      persistRunState({
        nextLogs: initialLogs,
        nextResults: initialResults,
        nextFindings: initialFindings,
        nextPhaseRecords: initialPhaseRecords,
        nextStructured: initialStructured,
        nextActiveStep: activeStep,
      });
    }

    let currentFinalReport = isResume ? finalReport : '';
    let collectedLogs: any[] = initialLogs;
    let collectedResults: any[] = initialResults;
    let collectedFindings: any[] = initialFindings;
    let collectedPhaseRecords: PhaseRecord[] = initialPhaseRecords;
    let structuredPhases: Record<string, any> = initialStructured;

    try {
      if (isResume) {
        const activeBackendUrl = resolveBackendUrl();
        const r = await fetch(`${activeBackendUrl}/api/agent-scan`, {
          method: 'POST',
          headers: authHeaders,
          body: JSON.stringify({
            target_ip: targetIp,
            target_name: targetName,
            resume_from: resumeFrom,
            ...(canInterface && { can_interface: canInterface }),
            ...(bluetoothMac && { bluetooth_mac: bluetoothMac }),
            ...(wifiInterface && { wifi_interface: wifiInterface }),
            ...(rfFrequency && { frequency: rfFrequency }),
            state: {
              logs: collectedLogs,
              findings: collectedFindings,
              phase_records: collectedPhaseRecords,
              structured: structuredPhases,
            },
          }),
        });
        const data = await r.json();
        if (!r.ok) {
          throw new Error(diagnosePhaseFailure({
            backendUrl: activeBackendUrl,
            status: r.status,
            payload: data,
            errorMessage: data?.error || data?.message,
          }));
        }

        currentFinalReport = data?.phases?.assessment_report || currentFinalReport;
        collectedLogs = Array.isArray(data.logs) ? data.logs : collectedLogs;
        collectedFindings = Array.isArray(data.findings) ? data.findings : collectedFindings;
        collectedPhaseRecords = Array.isArray(data.phase_records) ? data.phase_records : collectedPhaseRecords;
        structuredPhases = data.structured || structuredPhases;
        if (collectedFindings.length > 0) {
          collectedResults = collectedFindings.map((f: any) => ({
            ...f,
            id: f.id || `vuln-${Date.now()}-${Math.random().toString(36).slice(2, 7)}`,
            timestamp: f.detectedAt || new Date().toISOString(),
          }));
        }

        setLogs(collectedLogs);
        setFindings(collectedFindings);
        setResults(collectedResults);
        setPhaseRecords(collectedPhaseRecords);
        setStructuredState(structuredPhases);
        setFinalReport(currentFinalReport);
        const nextPhases = buildUiPhasesFromRecords(collectedPhaseRecords, phases);
        setPhases(nextPhases);
        setActiveStep(PHASES.findIndex(phase => phase.name === 'assess'));
        persistRunState({
          nextLogs: collectedLogs,
          nextResults: collectedResults,
          nextFindings: collectedFindings,
          nextPhaseRecords: collectedPhaseRecords,
          nextStructured: structuredPhases,
          nextFinalReport: currentFinalReport,
          nextPhases,
          nextActiveStep: PHASES.findIndex(phase => phase.name === 'assess'),
        });
      } else {
      // 统一使用逐阶段顺序执行，让每个 Agent 的结果依次显现
      let prevContext = '';
      for (let i = 0; i < PHASES.length; i++) {
        setActiveStep(i);
        updatePhase(i, { status: 'running', output: '执行中...' });
        persistRunState({ nextActiveStep: i });

        try {
          const activeBackendUrl = resolveBackendUrl();
          const r = await fetch(`${activeBackendUrl}/api/agent-scan`, {
            method: 'POST',
            headers: authHeaders,
            body: JSON.stringify({
              target_ip: targetIp,
              target_name: targetName,
              phase: PHASES[i].name,
              context: prevContext,
              ...(canInterface && { can_interface: canInterface }),
              ...(bluetoothMac && { bluetooth_mac: bluetoothMac }),
              ...(wifiInterface && { wifi_interface: wifiInterface }),
              ...(rfFrequency && { frequency: rfFrequency }),
              state: {
                logs: collectedLogs,
                findings: collectedFindings,
                phase_records: collectedPhaseRecords,
                structured: structuredPhases,
              },
            }),
          });
          const data = await r.json();
          const rawOutput = data.result || data.error || data.message || JSON.stringify(data);
          const diagnosed = diagnosePhaseOutput(String(rawOutput));
          const phaseStatus = r.ok && !diagnosed.isError ? 'done' : 'error';
          const output = r.ok
            ? diagnosed.output
            : diagnosePhaseFailure({
                backendUrl: activeBackendUrl,
                status: r.status,
                payload: data,
                errorMessage: rawOutput,
              });
          updatePhase(i, { status: phaseStatus, output });

          // 集成后端返回的所有详细日志 (工具调用、PoC 详情及 Agent 步骤)
          if (data.logs && Array.isArray(data.logs)) {
            collectedLogs.push(...data.logs);
            setLogs([...collectedLogs]);
            persistRunState({ nextLogs: [...collectedLogs] });
          }

          if (data.phase_records && Array.isArray(data.phase_records)) {
            data.phase_records.forEach((record: any) => {
              const idx = collectedPhaseRecords.findIndex((item) => item.phase === record.phase);
              if (idx >= 0) collectedPhaseRecords[idx] = record;
              else collectedPhaseRecords.push(record);
            });
            setPhaseRecords([...collectedPhaseRecords]);
          }

          if (data.structured_result) {
            structuredPhases[PHASES[i].name] = data.structured_result;
            setStructuredState({ ...structuredPhases });
          }

          // 集成结构化漏洞发现
          if (data.findings && Array.isArray(data.findings)) {
            data.findings.forEach((f: any) => {
              if (!collectedFindings.find(existing => existing.name === f.name)) {
                collectedFindings.push(f);
              }
            });
            data.findings.forEach((f: any) => {
              if (!collectedResults.find(r => r.name === f.name)) {
                collectedResults.push({
                  ...f,
                  id: `vuln-${Date.now()}-${Math.random().toString(36).substr(2, 5)}`,
                  timestamp: new Date().toISOString()
                });
              }
            });
            setResults([...collectedResults]);
            setFindings([...collectedFindings]);
          }

          prevContext += stringifyPhaseContext(PHASES[i].label, output, data.structured_result);
          if (i === PHASES.length - 1 && phaseStatus === 'done') {
            currentFinalReport = output;
            setFinalReport(output);
          }
          persistRunState({
            nextLogs: [...collectedLogs],
            nextResults: [...collectedResults],
            nextFindings: [...collectedFindings],
            nextPhaseRecords: [...collectedPhaseRecords],
            nextStructured: { ...structuredPhases },
            nextFinalReport: currentFinalReport,
          });
        } catch (e: any) {
          const errorMessage = diagnosePhaseFailure({
            backendUrl: resolveBackendUrl(),
            errorMessage: e?.message,
          });
          updatePhase(i, { status: 'error', output: errorMessage });
          const errorLog = {
            timestamp: new Date().toLocaleTimeString(),
            type: 'error',
            message: `[!] ${PHASES[i].label} 执行异常: ${errorMessage}`
          };
          collectedLogs.push(errorLog);
          setLogs([...collectedLogs]);
          persistRunState({ nextLogs: [...collectedLogs] });
        }
      }
      }
    } finally {
      setIsRunning(false);

      let calculatedRisk = 0;

      // 1. 累加逻辑：遍历所有结构化发现，根据 POC_DATABASE 中的生命等级折算分数 (与 Scan Engine 一致)
      collectedResults.forEach(res => {
        const poc = POC_DATABASE.find(p => p.name === res.name);
        if (poc) {
          const score = poc.severity === Severity.CRITICAL ? 10 : poc.severity === Severity.HIGH ? 7 : 3;
          calculatedRisk += score;
        } else {
          // 如果找不到匹配的 POC，默认给个保底分
          calculatedRisk += 5;
        }
      });

      // 2. AI 报告增强逻辑：如果 AI 报告明确提到了更高等级的风险，进行提升
      if (currentFinalReport) {
        const hasCritical = /高危|Critical|严重/i.test(currentFinalReport);
        const hasHigh = /中危|High|较高/i.test(currentFinalReport);

        if (hasCritical && calculatedRisk < 90) calculatedRisk = Math.max(calculatedRisk, 95);
        else if (hasHigh && calculatedRisk < 60) calculatedRisk = Math.max(calculatedRisk, 75);

        const noVulnerabilities = /未发现任何漏洞|无漏洞|No vulnerabilities|未发现.{1,5}漏洞|0个漏洞|0 vulnerabilities|None found|Secure/i.test(currentFinalReport);
        // 仅在 AI 报告确认安全且确实无工具发现时置 0
        if (noVulnerabilities && collectedResults.length === 0) {
          calculatedRisk = 0;
        }
      }

      calculatedRisk = Math.min(calculatedRisk, 100);
      setRiskScore(calculatedRisk);

      const sessionBase = {
        targetName: targetName,
        connection: {
          ip: targetIp,
          bluetoothMac: bluetoothMac,
          canInterface: canInterface,
          interface: wifiInterface,
          port: '', url: '', frequency: ''
        },
        results: collectedResults,
        riskScore: calculatedRisk,
      };

      let artifacts: AssessmentArtifacts = {};
      try {
        const [attackGraph, physicalImpact, remediationPlan, structuredReport] = await Promise.all([
          generateAttackGraph(sessionBase, token),
          assessPhysicalImpact(sessionBase, token),
          simulateRemediation(sessionBase, token),
          generateStructuredReport(sessionBase, token),
        ]);
        artifacts = { attackGraph, physicalImpact, remediationPlan, structuredReport };
        setAssessment(artifacts);
      } catch (e: any) {
        collectedLogs.push({
          timestamp: new Date().toLocaleTimeString(),
          type: 'warning',
          message: `[!] 攻击路径与整改模拟生成失败: ${e.message}`,
        });
      }

      const sessionObj = {
        id: `SCAN-AGENT-${Date.now().toString().slice(-6)}`,
        targetName: targetName,
        connection: {
          ip: targetIp,
          bluetoothMac: bluetoothMac,
          canInterface: canInterface,
          interface: wifiInterface,
          port: '', url: '', frequency: ''
        },
        isConnected: true,
        startTime: now,
        endTime: new Date().toISOString(),
        status: 'completed',
        mode: 'agent',
        logs: collectedLogs,
        results: collectedResults,
        riskScore: calculatedRisk,
        aiReport: currentFinalReport,
        assessment: artifacts,
        findings: collectedFindings,
        phase_records: collectedPhaseRecords,
        structured: structuredPhases,
      };
      saveScanSession(sessionObj, token);
      onSessionComplete?.(sessionObj);

      // 完成后保存所有状态到 localStorage
      setPhaseRecords(collectedPhaseRecords);
      setStructuredState(structuredPhases);
      setFindings(collectedFindings);
      persistRunState({
        nextActiveStep: 3,
        nextAssessment: artifacts,
        nextLogs: collectedLogs,
        nextResults: collectedResults,
        nextFindings: collectedFindings,
        nextPhaseRecords: collectedPhaseRecords,
        nextStructured: structuredPhases,
        nextFinalReport: currentFinalReport,
      });
    }
  };

  const runFullAssessment = async () => runAssessment();
  const resumeAssessment = async () => {
    const resumeFrom = getResumablePhase(phaseRecords);
    if (!resumeFrom || isRunning) return;
    await runAssessment(resumeFrom);
  };

  // ── PDF 导出 ──
  const exportToPdf = () => {
    const now = scanTime || new Date().toLocaleString('zh-CN', { hour12: false });
    const reportHtml = finalReport
      // markdown bold
      .replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>')
      // markdown headers
      .replace(/^### (.+)$/gm, '<h3>$1</h3>')
      .replace(/^## (.+)$/gm, '<h2>$1</h2>')
      .replace(/^# (.+)$/gm, '<h1>$1</h1>')
      // markdown list items
      .replace(/^[-*] (.+)$/gm, '<li>$1</li>')
      // line breaks
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
        <span><span class="label">扫描目标：</span>${targetName}&#8203;(${targetIp})</span>
        <span><span class="label">扫描时间：</span>${now}</span>
        <span><span class="label">报告类型：</span>Agent 自主渗透测试报告</span>
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

    const win = window.open('', '_blank', 'width=900,height=700');
    if (win) {
      win.document.write(html);
      win.document.close();
    }
  };

  const statusIcon = (status: PhaseResult['status']) => {
    switch (status) {
      case 'running': return <Loader className="w-4 h-4 animate-spin text-cyan-400" />;
      case 'done': return <CheckCircle className="w-4 h-4 text-emerald-400" />;
      case 'error': return <XCircle className="w-4 h-4 text-red-400" />;
      default: return <div className="w-4 h-4 rounded-full border border-gray-600" />;
    }
  };

  const attackVectorColor = (v?: string) => {
    if (!v) return 'text-gray-400';
    if (v === 'direct') return 'text-emerald-400';
    if (v === 'lateral_wifi') return 'text-amber-400';
    return 'text-purple-400';
  };

  const handleAutoDiscovery = async () => {
    try {
      const activeBackendUrl = resolveBackendUrl();
      const resp = await fetch(`${activeBackendUrl}/api/auto_discovery`);
      const data = await resp.json();
      if (data.status === 'success') {
        const { wifi, can, bluetooth_mac, target_ip } = data.interfaces;
        if (target_ip) setTargetIp(target_ip);
        if (can) setCanInterface(can);
        if (wifi) setWifiInterface(wifi);
        if (bluetooth_mac) setBluetoothMac(bluetooth_mac);
        setShowAdvanced(true);
      }
    } catch (e: any) {
      console.error(`Auto discovery failed at ${resolveBackendUrl()}:`, e);
    }
  };

  const resumablePhase = getResumablePhase(phaseRecords);
  const plannerSteps: PlannerStep[] = Array.isArray(structuredState?.planner?.steps) ? structuredState.planner.steps : [];
  const plannerSummary = structuredState?.planner?.strategy_summary || '';
  const plannerGuardrails: string[] = Array.isArray(structuredState?.planner?.guardrails) ? structuredState.planner.guardrails : [];
  const supervisorEvents: SupervisorEvent[] = Array.isArray(structuredState?.supervisor?.events) ? structuredState.supervisor.events : [];
  const supervisorMetrics = (structuredState?.supervisor?.metrics || {}) as Partial<SupervisorMetrics>;
  const supervisorAdjustments: SupervisorAdjustment[] = Array.isArray(structuredState?.supervisor?.adjustments) ? structuredState.supervisor.adjustments : [];
  const hasSupervisorData = supervisorEvents.length > 0 || supervisorAdjustments.length > 0 || Boolean(supervisorMetrics.total_events);

  return (
    <div className="flex flex-col gap-4 h-full overflow-y-auto p-4">

      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center gap-3 pb-3 border-b border-cyan-900/40">
        <div className="flex items-center gap-3">
          <Bot className="w-6 h-6 text-cyan-400 shrink-0" />
          <div>
            <h2 className="text-lg font-bold text-cyan-300">多 Agent 自主渗透测试</h2>
            <p className="text-xs text-gray-400">针对 IVI 测试场景 · 服务感知自适应 + MCP + Qwen (千问) Function Calling</p>
          </div>
        </div>
        <div className="flex-1" />
        <div className="flex gap-2 self-end sm:self-auto">
          {resumablePhase && (
            <button
              onClick={resumeAssessment}
              disabled={isRunning || !targetIp.trim()}
              className="flex items-center gap-2 bg-emerald-950/50 border border-emerald-700 hover:border-emerald-500 hover:text-emerald-300 text-emerald-400 disabled:opacity-50 disabled:cursor-not-allowed rounded px-3 py-1.5 text-xs font-semibold transition-colors"
              title={`从 ${resumablePhase} 阶段继续执行`}
            >
              <Play className="w-3.5 h-3.5" />
              继续执行
            </button>
          )}
          <button
            onClick={handleAutoDiscovery}
            disabled={isRunning}
            className="flex items-center gap-2 bg-black/40 border border-yellow-600/50 hover:border-yellow-500 hover:text-yellow-400 text-yellow-500/80 shadow-[0_0_10px_rgba(234,179,8,0.1)] disabled:opacity-50 disabled:cursor-not-allowed rounded px-3 py-1.5 text-xs font-semibold transition-all"
            title="一键探测本地网络接口并填充配置 (Zero-Config Discovery)"
          >
            <Zap className="w-3.5 h-3.5" />
            极速介入
          </button>
          <button
            onClick={handleReset}
            disabled={isRunning}
            className="flex items-center gap-2 bg-black/40 border border-gray-600 hover:border-red-500 hover:text-red-400 text-gray-400 disabled:opacity-50 disabled:cursor-not-allowed rounded px-3 py-1.5 text-xs font-semibold transition-colors"
          >
            <RotateCcw className="w-3.5 h-3.5" />
            重置设定与结果
          </button>
        </div>
      </div>

      {/* Config Row */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 mt-2">
        <div>
          <label className="text-xs text-gray-400 mb-1 block">目标 IP (IVI / ECU)</label>
          <input
            type="text"
            placeholder="192.168.100.1"
            value={targetIp}
            onChange={e => setTargetIp(e.target.value)}
            className="w-full bg-black/40 border border-cyan-900/50 text-cyan-300 rounded px-3 py-2 text-sm focus:outline-none focus:border-cyan-500"
          />
        </div>
        <div>
          <label className="text-xs text-gray-400 mb-1 block">目标名称</label>
          <input
            type="text"
            placeholder="车型 / IVI 系统名称"
            value={targetName}
            onChange={e => setTargetName(e.target.value)}
            className="w-full bg-black/40 border border-cyan-900/50 text-cyan-300 rounded px-3 py-2 text-sm focus:outline-none focus:border-cyan-500"
          />
        </div>
        <div className="flex flex-col">
          <label className="text-xs text-gray-400 mb-1 block">模式</label>
          <select
            value={isFullMode ? 'full' : 'step'}
            onChange={e => setIsFullMode(e.target.value === 'full')}
            className="w-full bg-black/40 border border-cyan-900/50 text-cyan-300 rounded px-3 py-2 text-sm focus:outline-none h-[38px]"
          >
            <option value="full">全量自动</option>
            <option value="step">步进调试</option>
          </select>
        </div>
        <div className="flex flex-col justify-end">
          <div className="flex gap-2">
            <button
              onClick={runFullAssessment}
              disabled={isRunning || !targetIp.trim()}
              className="flex-1 flex items-center justify-center gap-2 bg-cyan-600 hover:bg-cyan-500 disabled:bg-gray-700 disabled:text-gray-500 text-white rounded px-4 py-2 text-sm font-semibold transition-colors h-[38px]"
            >
              {isRunning ? <Loader className="w-4 h-4 animate-spin" /> : <Play className="w-4 h-4" />}
              {isRunning ? '运行中...' : '启动评估'}
            </button>
            {resumablePhase && (
              <button
                onClick={resumeAssessment}
                disabled={isRunning || !targetIp.trim()}
                className="flex items-center justify-center gap-2 bg-emerald-700/20 hover:bg-emerald-700/30 disabled:bg-gray-700 disabled:text-gray-500 text-emerald-300 border border-emerald-700 rounded px-3 py-2 text-sm font-semibold transition-colors h-[38px]"
                title={`从 ${resumablePhase} 阶段继续执行`}
              >
                <RotateCcw className="w-4 h-4" />
                继续
              </button>
            )}
          </div>
        </div>
      </div>

      {/* Connection Parameters — Collapsible but prominent */}
      <div className="border border-cyan-900/30 rounded-lg bg-black/20 mt-2">
        <button
          onClick={() => setShowAdvanced(v => !v)}
          className="w-full flex items-center justify-between px-4 py-3 hover:bg-cyan-950/20 transition-colors"
        >
          <div className="flex items-center gap-2">
            <Sliders className="w-4 h-4 text-cyan-500" />
            <span className="text-xs font-bold text-cyan-400 uppercase tracking-wider">连接参数设定 (可选多向量)</span>
          </div>
          <span className="text-xs text-gray-500">{showAdvanced ? '▲ 收起' : '▼ 展开设定'}</span>
        </button>
        {showAdvanced && (
          <div className="p-4 pt-2 grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 bg-black/5 border-t border-cyan-900/20">
            <div>
              <label className="text-[10px] text-gray-500 uppercase font-bold mb-1 block">蓝牙 MAC</label>
              <input
                type="text"
                placeholder="AA:BB:CC:..."
                value={bluetoothMac}
                onChange={e => setBluetoothMac(e.target.value)}
                className="w-full bg-black/40 border border-cyan-900/40 text-cyan-300 rounded px-3 py-1.5 text-xs focus:outline-none focus:border-cyan-500"
              />
            </div>
            <div>
              <label className="text-[10px] text-gray-500 uppercase font-bold mb-1 block">CAN 接口</label>
              <input
                type="text"
                placeholder="PCAN_USBBUS1"
                value={canInterface}
                onChange={e => setCanInterface(e.target.value)}
                className="w-full bg-black/40 border border-cyan-900/40 text-cyan-300 rounded px-3 py-1.5 text-xs focus:outline-none focus:border-cyan-500"
              />
            </div>
            <div>
              <label className="text-[10px] text-gray-500 uppercase font-bold mb-1 block">WiFi 接口</label>
              <input
                type="text"
                placeholder="wlan0mon / en0"
                value={wifiInterface}
                onChange={e => setWifiInterface(e.target.value)}
                className="w-full bg-black/40 border border-cyan-900/40 text-cyan-300 rounded px-3 py-1.5 text-xs focus:outline-none focus:border-cyan-500"
              />
            </div>
            <div>
              <label className="text-[10px] text-gray-500 uppercase font-bold mb-1 block">RF 频率 (Hz)</label>
              <input
                type="text"
                placeholder="433.92MHz / 315MHz"
                value={rfFrequency}
                onChange={e => setRfFrequency(e.target.value)}
                className="w-full bg-black/40 border border-cyan-900/40 text-cyan-300 rounded px-3 py-1.5 text-xs focus:outline-none focus:border-cyan-500"
              />
            </div>
          </div>
        )}
      </div>

      {/* ========================================================= */}
      {/* 3D Digital Twin GUI (Phase 1 Hackathon Upgrade) */}
      {/* ========================================================= */}
      <div className="bg-black/30 border border-cyan-900/40 rounded-lg p-0 relative h-72 overflow-hidden mt-2 flex items-center justify-center shrink-0 shadow-[inset_0_0_20px_rgba(0,255,255,0.05)]">
        <div className="absolute top-3 left-4 z-10 flex items-center gap-2 bg-black/50 px-3 py-1.5 rounded-full border border-cyan-900/50 backdrop-blur-md">
          <Shield className="w-4 h-4 text-cyan-400" />
          <span className="text-xs font-bold text-cyan-300 tracking-widest uppercase">
            DIGITAL TWIN SANDBOX // TARGET: {targetName}
          </span>
          {activeZones.length > 0 && (
             <span className="ml-2 w-2 h-2 rounded-full bg-red-500 animate-pulse"></span>
          )}
        </div>
        
        <Canvas camera={{ position: [3, 2, 5], fov: 45 }} className="w-full h-full">
          <ambientLight intensity={0.5} />
          <pointLight position={[10, 10, 10]} intensity={1} />
          <OrbitControls 
            enableZoom={false} 
            enablePan={false}
            autoRotate={activeStep < 0}
            autoRotateSpeed={1}
            maxPolarAngle={Math.PI / 2 - 0.1} // don't go below ground
          />
          <Environment preset="night" />
          <CarModel activeZones={activeZones} />
          <ContactShadows resolution={512} scale={10} blur={2} opacity={0.6} far={10} color="#0eb5c2" />
        </Canvas>
      </div>

      {/* Context Cards Row */}
      <div className="grid grid-cols-2 gap-3">

        {/* Adaptive Context Card */}
        <div className="bg-black/30 border border-cyan-900/40 rounded-lg p-3">
          <div className="flex items-center gap-2 mb-2">
            <Sliders className="w-4 h-4 text-cyan-400" />
            <span className="text-xs font-semibold text-cyan-300">自适应上下文</span>
            {adaptiveCtx && (
              <span className={`text-xs ml-auto px-2 py-0.5 rounded-full font-bold bg-black/40 border border-current ${LOAD_COLOR[adaptiveCtx.ivi_load?.status || 'unknown']}`}>
                IVI 负载: {adaptiveCtx.ivi_load?.status ?? '--'}
              </span>
            )}
          </div>
          {adaptiveCtx ? (
            <div className="space-y-1.5 text-xs">
              <div className="flex justify-between">
                <span className="text-gray-500">检测到服务</span>
                <span className="text-cyan-400 font-mono text-right">
                  {adaptiveCtx.detected_services.length > 0
                    ? adaptiveCtx.detected_services.join(', ')
                    : '无'}
                </span>
              </div>
              <div className="flex justify-between">
                <span className="text-gray-500">服务匹配过滤</span>
                <span className={adaptiveCtx.poc_filter_active ? 'text-emerald-400' : 'text-gray-400'}>
                  {adaptiveCtx.poc_filter_active ? '✓ 已激活' : '全量模式'}
                </span>
              </div>
              <div className="flex justify-between">
                <span className="text-gray-500">响应延迟</span>
                <span className={LOAD_COLOR[adaptiveCtx.ivi_load?.status || 'unknown']}>
                  {adaptiveCtx.ivi_load?.latency_ms != null ? `${adaptiveCtx.ivi_load.latency_ms.toFixed(0)} ms` : '--'}
                </span>
              </div>
              <div className="flex justify-between">
                <span className="text-gray-500">推荐扫描间隔</span>
                <span className="text-purple-400">
                  {((adaptiveCtx.ivi_load?.recommended_interval_ms ?? 500) / 1000).toFixed(1)} s
                </span>
              </div>
              {adaptiveCtx.auth_contexts?.length > 0 && (
                <div className="mt-1.5 pt-1.5 border-t border-cyan-900/30">
                  <div className="flex items-center gap-1 text-gray-500 mb-1">
                    <Key className="w-3 h-3" />
                    <span>认证策略</span>
                  </div>
                  {adaptiveCtx.auth_contexts.map((ctx, i) => (
                    <div key={i} className="flex justify-between mt-0.5 text-xs">
                      <span className="text-gray-600 capitalize">{ctx.service}</span>
                      <span className="text-amber-400 truncate max-w-[60%] text-right">{ctx.recommended_strategy}</span>
                    </div>
                  ))}
                </div>
              )}
            </div>
          ) : (
            <p className="text-xs text-gray-500">启动评估后将自动探测：<br />服务指纹 · 认证机制 · IVI 系统负载</p>
          )}
        </div>

        {/* Topology Card */}
        <div className="bg-black/30 border border-cyan-900/40 rounded-lg p-3">
          <div className="flex items-center gap-2 mb-2">
            <Network className="w-4 h-4 text-purple-400" />
            <span className="text-xs font-semibold text-purple-300">网络拓扑</span>
          </div>
          {topology ? (
            <div className="space-y-1 text-xs">
              <div className="flex justify-between">
                <span className="text-gray-500">安全网关 SEC-GW</span>
                <span className={topology.has_security_gateway ? 'text-red-400' : 'text-emerald-400'}>
                  {topology.has_security_gateway ? '✓ 检测到' : '未检测到'}
                </span>
              </div>
              <div className="flex justify-between">
                <span className="text-gray-500">推荐攻击向量</span>
                <span className={attackVectorColor(topology.recommended_attack_vector)}>
                  {topology.recommended_attack_vector}
                </span>
              </div>
              <div className="flex justify-between">
                <span className="text-gray-500">发现节点</span>
                <span className="text-cyan-400">{topology.node_count} 个</span>
              </div>
              {topology.nodes?.slice(0, 2).map((n, i) => (
                <div key={i} className="flex justify-between text-gray-600 text-xs">
                  <span>{n.ip}</span>
                  <span>{n.open_ports?.slice(0, 4).join(', ')}</span>
                </div>
              ))}
            </div>
          ) : (
            <p className="text-xs text-gray-500">启动评估后自动分析网络拓扑结构...</p>
          )}
        </div>
      </div>

      {/* Agent Pipeline */}
      <div className="grid grid-cols-5 gap-2">
        {PHASES.map((phase, i) => {
          const r = phases[i];
          const PhaseIcon: any = phase.icon;
          const isActive = activeStep === i;
          return (
            <div
              key={phase.name}
              className={`bg-black/30 border rounded-lg p-3 transition-all ${isActive ? 'border-cyan-500 shadow-[0_0_12px_rgba(0,200,255,0.2)]' :
                r.status === 'done' ? 'border-emerald-800/60' :
                  r.status === 'error' ? 'border-red-800/60' :
                    'border-cyan-900/40'
                }`}
            >
              <div className="flex items-center justify-between mb-2">
                <div className="flex items-center gap-2">
                  <PhaseIcon className={`w-4 h-4 ${isActive ? 'text-cyan-400' : r.status === 'done' ? 'text-emerald-400' : r.status === 'error' ? 'text-red-400' : 'text-gray-500'}`} />
                  <span className="text-xs font-semibold text-gray-300">{phase.label}</span>
                </div>
                {statusIcon(r.status)}
              </div>
              <p className="text-xs text-gray-500">{phase.description}</p>
              {r.output && r.status !== 'idle' && (
                <div className="mt-2 p-2 bg-black/40 rounded text-xs text-gray-300 max-h-24 overflow-y-auto whitespace-pre-wrap">
                  {r.output.slice(0, 400)}{r.output.length > 400 ? '...' : ''}
                </div>
              )}
            </div>
          );
        })}
      </div>

      {(plannerSteps.length > 0 || hasSupervisorData) && (
        <div className={`grid grid-cols-1 gap-4 ${hasSupervisorData ? 'xl:grid-cols-2' : ''}`}>
          <div className="bg-black/30 border border-cyan-900/40 rounded-lg p-4">
            <div className="flex items-center gap-2 mb-3">
              <Cpu className="w-4 h-4 text-cyan-400" />
              <span className="text-xs font-bold text-cyan-300 uppercase tracking-widest">Planner Blueprint</span>
            </div>
            {plannerSummary ? (
              <p className="text-sm text-gray-300 mb-4 leading-relaxed">{plannerSummary}</p>
            ) : (
              <p className="text-xs text-gray-500 mb-4">尚未生成执行纲要。</p>
            )}
            {plannerSteps.length > 0 && (
              <div className="space-y-2">
                {plannerSteps.map((step) => (
                  <div key={`${step.step}-${step.title}`} className="bg-black/40 border border-cyan-900/30 rounded p-3">
                    <div className="flex items-center justify-between gap-3 mb-1">
                      <div className="text-sm font-semibold text-white">
                        {step.step}. {step.title}
                      </div>
                      {Array.isArray(step.depends_on) && step.depends_on.length > 0 ? (
                        <span className="text-[10px] text-gray-400 font-mono">depends_on: {step.depends_on.join(', ')}</span>
                      ) : null}
                    </div>
                    <div className="text-xs text-gray-300">目标: {step.objective || '未提供'}</div>
                    <div className="text-xs text-cyan-300 mt-1">成功标准: {step.success_criteria || '未提供'}</div>
                  </div>
                ))}
              </div>
            )}
            {plannerGuardrails.length > 0 && (
              <div className="mt-4 pt-3 border-t border-cyan-900/30">
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

          {hasSupervisorData ? (
            <div className="bg-black/30 border border-amber-900/40 rounded-lg p-4">
              <div className="flex items-center gap-2 mb-3">
                <AlertTriangle className="w-4 h-4 text-amber-400" />
                <span className="text-xs font-bold text-amber-300 uppercase tracking-widest">Supervisor Events</span>
              </div>
              {(supervisorMetrics.total_events || supervisorAdjustments.length > 0) && (
                <div className="grid grid-cols-2 gap-2 mb-4">
                  <div className="bg-black/40 border border-amber-900/30 rounded p-2">
                    <div className="text-[10px] text-gray-500 uppercase">Events</div>
                    <div className="text-lg font-mono text-amber-300">{supervisorMetrics.total_events || 0}</div>
                  </div>
                  <div className="bg-black/40 border border-amber-900/30 rounded p-2">
                    <div className="text-[10px] text-gray-500 uppercase">Pruned Steps</div>
                    <div className="text-lg font-mono text-red-300">{supervisorMetrics.pruned_steps || 0}</div>
                  </div>
                  <div className="bg-black/40 border border-amber-900/30 rounded p-2">
                    <div className="text-[10px] text-gray-500 uppercase">No Progress</div>
                    <div className="text-lg font-mono text-amber-300">{supervisorMetrics.no_progress_events || 0}</div>
                  </div>
                  <div className="bg-black/40 border border-amber-900/30 rounded p-2">
                    <div className="text-[10px] text-gray-500 uppercase">Execution Errors</div>
                    <div className="text-lg font-mono text-red-300">{supervisorMetrics.execution_errors || 0}</div>
                  </div>
                </div>
              )}
              {supervisorAdjustments.length > 0 && (
                <div className="mb-4 pt-3 border-t border-amber-900/30">
                  <div className="text-[11px] font-bold text-gray-400 uppercase tracking-wider mb-2">Automatic Adjustments</div>
                  <div className="space-y-2 max-h-36 overflow-y-auto pr-1">
                    {supervisorAdjustments.map((adjustment, index) => (
                      <div key={`${adjustment.type}-${adjustment.timestamp || index}`} className="bg-black/40 border border-amber-900/30 rounded p-2">
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
                <div className="space-y-2 max-h-80 overflow-y-auto pr-1">
                  {supervisorEvents.map((event, index) => (
                    <div key={`${event.scope}-${event.timestamp || index}`} className="bg-black/40 border border-amber-900/30 rounded p-3">
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
              ) : null}
            </div>
          ) : (
            <div className="bg-black/20 border border-amber-900/20 rounded-lg px-4 py-2 flex items-center gap-2">
              <AlertTriangle className="w-3.5 h-3.5 text-amber-500/80" />
              <span className="text-[11px] font-bold text-amber-300 uppercase tracking-widest">Supervisor</span>
              <span className="text-xs text-gray-500">当前未触发监督事件</span>
            </div>
          )}
        </div>
      )}

      {/* Results & Console Row */}
      <div className="grid grid-cols-3 gap-4 h-[400px]">
        {/* Console - occupy 2/3 */}
        <div className="col-span-2 h-full">
          <ScanLogs
            logs={logs}
            onClearLogs={() => {
              setLogs([]);
              saveState({ logs: [] });
            }}
          />
        </div>

        {/* Results Info - occupy 1/3 */}
        <div className="flex flex-col gap-3 h-full">
          {/* Risk Score */}
          <div className="bg-black/30 border border-cyan-900/40 rounded-lg p-4 flex flex-col items-center justify-center shrink-0">
            <div className="flex items-center gap-2 mb-2 w-full">
              <ShieldCheck className="w-4 h-4 text-cyan-400" />
              <span className="text-xs font-bold text-gray-400 uppercase tracking-widest">Risk Score</span>
            </div>
            <div className="text-4xl font-mono font-bold text-cyan-400">
              {riskScore} <span className="text-sm text-gray-600">/ 100</span>
            </div>
            <div className={`mt-2 text-[10px] uppercase font-bold px-3 py-1 rounded bg-black/40 border ${riskScore >= 75 ? 'border-red-500/50 text-red-400' :
              riskScore >= 40 ? 'border-orange-500/50 text-orange-400' :
                'border-emerald-500/50 text-emerald-400'
              }`}>
              {riskScore >= 75 ? 'Critical Threat' : riskScore >= 40 ? 'Medium Risk' : 'System Secure'}
            </div>
          </div>

          {/* Vulnerabilities List */}
          <div className="bg-black/30 border border-cyan-900/40 rounded-lg p-4 flex-1 flex flex-col min-h-0">
            <div className="flex items-center gap-2 mb-3">
              <AlertTriangle className="w-4 h-4 text-amber-400" />
              <span className="text-xs font-bold text-gray-400 uppercase tracking-widest">Found Vectors ({results.length})</span>
            </div>
            <div className="flex-1 overflow-y-auto space-y-2 pr-1 custom-scrollbar">
              {results.length > 0 ? (
                results.map((res, idx) => (
                  <div key={res.id || idx} className="bg-black/40 border-l-2 border-red-500 p-2 rounded hover:bg-black/60 transition-colors">
                    <div className="text-xs font-bold text-gray-200">{res.name}</div>
                    <div className="text-[10px] text-gray-500 truncate">{res.description}</div>
                  </div>
                ))
              ) : (
                <div className="h-full flex flex-col items-center justify-center text-gray-600 italic text-[10px]">
                  No vulnerabilities detected yet
                </div>
              )}
            </div>
          </div>
        </div>
      </div>

      {(assessment.attackGraph || assessment.physicalImpact || assessment.remediationPlan) && (
        <AttackGraph
          graph={assessment.attackGraph}
          physicalImpact={assessment.physicalImpact}
          remediationPlan={assessment.remediationPlan}
        />
      )}

      {/* Final Report */}
      {finalReport && (
        <div className="bg-black/30 border border-emerald-800/50 rounded-lg p-4">
          <div className="flex items-center gap-2 mb-3">
            <FileText className="w-4 h-4 text-emerald-400" />
            <span className="text-sm font-bold text-emerald-300">AI 自主安全评估报告</span>
            {scanTime && (
              <span className="ml-auto text-xs text-gray-500">扫描时间: {scanTime}</span>
            )}
            <button
              onClick={exportToPdf}
              className="flex items-center gap-1.5 bg-emerald-700/40 hover:bg-emerald-600/50 border border-emerald-700/50 text-emerald-300 rounded px-3 py-1 text-xs font-semibold transition-colors"
            >
              <Download className="w-3.5 h-3.5" />
              导出 PDF
            </button>
          </div>
          <div className="text-sm text-gray-300 leading-relaxed max-h-96 overflow-y-auto mt-4 custom-scrollbar">
            <ReactMarkdown 
              remarkPlugins={[remarkGfm]}
              components={{
                table: ({node, ...props}) => <table className="w-full text-left border-collapse my-4" {...props} />,
                thead: ({node, ...props}) => <thead className="bg-cyan-900/30 text-cyan-300" {...props} />,
                th: ({node, ...props}) => <th className="border border-cyan-900/60 px-4 py-2 font-semibold" {...props} />,
                td: ({node, ...props}) => <td className="border border-cyan-900/40 px-4 py-2" {...props} />,
                h1: ({node, ...props}) => <h1 className="text-xl font-bold text-emerald-400 mt-6 mb-3" {...props} />,
                h2: ({node, ...props}) => <h2 className="text-lg font-bold text-cyan-300 mt-5 border-l-4 border-cyan-500 pl-2 mb-2" {...props} />,
                h3: ({node, ...props}) => <h3 className="text-md font-bold text-cyan-400 mt-4 mb-2" {...props} />,
                ul: ({node, ...props}) => <ul className="list-disc list-inside my-2 space-y-1" {...props} />,
                li: ({node, ...props}) => <li className="ml-4" {...props} />,
                p: ({node, ...props}) => <p className="my-2" {...props} />
              }}
            >
              {finalReport}
            </ReactMarkdown>
          </div>
        </div>
      )}
    </div>
  );
};

export default AgentScan;
