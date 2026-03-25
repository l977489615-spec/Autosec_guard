import React, { useState, useEffect } from 'react';
import { Bot, Shield, Network, Cpu, FileText, Play, Loader, CheckCircle, XCircle, Key, Sliders, Download, RotateCcw, AlertTriangle, ShieldCheck } from 'lucide-react';
import { saveScanSession } from '../services/api';
import ScanLogs from './ScanLogs';
import { POC_DATABASE } from '../constants';
import { Severity } from '../types';

const BACKEND_URL = 'http://localhost:5002';

interface AgentPhase {
  name: string;
  label: string;
  icon: React.ElementType;
  description: string;
}

const PHASES: AgentPhase[] = [
  { name: 'recon', label: '侦察 Agent', icon: Network, description: '端口扫描 + 拓扑分析 + 服务指纹' },
  { name: 'decision', label: '决策 Agent', icon: Cpu, description: '自适应 PoC 筛选 + 认证策略规划' },
  { name: 'execute', label: '执行 Agent', icon: Shield, description: 'PoC 自动化执行 + 响应反馈闭环' },
  { name: 'assess', label: '评估 Agent', icon: FileText, description: 'ISO 21434 合规报告生成' },
];

interface PhaseResult {
  phase: string;
  status: 'idle' | 'running' | 'done' | 'error';
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
}

const LOAD_COLOR: Record<string, string> = {
  normal: 'text-emerald-400',
  high: 'text-amber-400',
  critical: 'text-red-400',
  unknown: 'text-gray-400',
};

const AgentScan: React.FC<AgentScanProps> = ({ token }) => {
  const [targetIp, setTargetIp] = useState('');
  const [targetName, setTargetName] = useState('IVI System');
  const [isFullMode, setIsFullMode] = useState(true);
  const [showAdvanced, setShowAdvanced] = useState(true);

  // 可选参数 — 控制 Agent 选择哪类 PoC
  const [canInterface, setCanInterface] = useState('');
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

  const STORAGE_KEY = 'autosec_agent_scan_state';

  // ── 从 localStorage 恢复状态 ──
  useEffect(() => {
    try {
      const saved = localStorage.getItem(STORAGE_KEY);
      if (saved) {
        const s = JSON.parse(saved);
        if (s.targetIp) setTargetIp(s.targetIp);
        if (s.targetName) setTargetName(s.targetName);
        if (s.phases) setPhases(s.phases);
        if (s.finalReport) setFinalReport(s.finalReport);
        if (s.topology) setTopology(s.topology);
        if (s.adaptiveCtx) setAdaptiveCtx(s.adaptiveCtx);
        if (s.scanTime) setScanTime(s.scanTime);
        if (s.canInterface) setCanInterface(s.canInterface);
        if (s.bluetoothMac) setBluetoothMac(s.bluetoothMac);
        if (s.wifiInterface) setWifiInterface(s.wifiInterface);
        if (s.rfFrequency) setRfFrequency(s.rfFrequency);
        if (typeof s.activeStep === 'number') setActiveStep(s.activeStep);
        if (s.riskScore) setRiskScore(s.riskScore);
        if (s.results) setResults(s.results);
        if (s.logs) setLogs(s.logs);
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
      const r = await fetch(`${BACKEND_URL}/api/adaptive-context`, {
        method: 'POST',
        headers: authHeaders,
        body: JSON.stringify({ target_ip: ip, open_ports: openPorts, reset: true }),
      });
      if (r.ok) setAdaptiveCtx(await r.json());
    } catch { }
  };

  const fetchTopology = async (ip: string) => {
    try {
      const r = await fetch(`${BACKEND_URL}/api/topology`, {
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
    setCanInterface('');
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
    localStorage.removeItem(STORAGE_KEY);
  };

  const updatePhase = (idx: number, update: Partial<PhaseResult>) => {
    setPhases(prev => prev.map((p, i) => i === idx ? { ...p, ...update } : p));
  };

  const runFullAssessment = async () => {
    if (!targetIp.trim()) return;
    const now = new Date().toLocaleString('zh-CN', { hour12: false });
    setScanTime(now);
    setIsRunning(true);
    const resetPhases = PHASES.map(p => ({ phase: p.name, status: 'idle' as const, output: '' }));
    setPhases(resetPhases);
    setTopology(null);
    setAdaptiveCtx(null);
    setFinalReport('');
    setActiveStep(-1);
    setRiskScore(0);
    setResults([]);
    setLogs([]);
    saveState({
      phases: resetPhases, finalReport: '', topology: null,
      adaptiveCtx: null, activeStep: -1, scanTime: now,
      riskScore: 0, results: [], logs: []
    });

    await fetchTopology(targetIp);

    let currentFinalReport = '';
    const collectedLogs: any[] = [
      { timestamp: new Date().toLocaleTimeString(), type: 'info', message: `[*] 启动自主渗透测试任务: ${targetName}` },
      { timestamp: new Date().toLocaleTimeString(), type: 'info', message: `[*] 目标向量: ${targetIp}` }
    ];
    const collectedResults: any[] = [];

    try {
      // 统一使用逐阶段顺序执行，让每个 Agent 的结果依次显现
      let prevContext = '';
      for (let i = 0; i < PHASES.length; i++) {
        setActiveStep(i);
        updatePhase(i, { status: 'running', output: '执行中...' });
        saveState({ activeStep: i });

        try {
          const r = await fetch(`${BACKEND_URL}/api/agent-scan`, {
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
            }),
          });
          const data = await r.json();
          const output = data.result || data.error || JSON.stringify(data);
          updatePhase(i, { status: r.ok ? 'done' : 'error', output });

          // 集成后端返回的所有详细日志 (工具调用、PoC 详情及 Agent 步骤)
          if (data.logs && Array.isArray(data.logs)) {
            collectedLogs.push(...data.logs);
            setLogs([...collectedLogs]);
          }

          // 集成结构化漏洞发现
          if (data.findings && Array.isArray(data.findings)) {
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
          }

          prevContext += `\n\n${PHASES[i].label} 结果:\n${output}`;
          if (i === PHASES.length - 1) {
            currentFinalReport = output;
            setFinalReport(output);
          }
        } catch (e: any) {
          updatePhase(i, { status: 'error', output: e.message });
          const errorLog = {
            timestamp: new Date().toLocaleTimeString(),
            type: 'error',
            message: `[!] ${PHASES[i].label} 执行异常: ${e.message}`
          };
          collectedLogs.push(errorLog);
          setLogs([...collectedLogs]);
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
        aiReport: currentFinalReport
      };
      saveScanSession(sessionObj, token);

      // 完成后保存所有状态到 localStorage
      saveState({ activeStep: 3 });
    }
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
        <button
          onClick={handleReset}
          disabled={isRunning}
          className="flex items-center gap-2 bg-black/40 border border-gray-600 hover:border-red-500 hover:text-red-400 text-gray-400 disabled:opacity-50 disabled:cursor-not-allowed rounded px-3 py-1.5 text-xs font-semibold transition-colors w-fit self-end sm:self-auto"
        >
          <RotateCcw className="w-3.5 h-3.5" />
          重置设定与结果
        </button>
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
          <button
            onClick={runFullAssessment}
            disabled={isRunning || !targetIp.trim()}
            className="w-full flex items-center justify-center gap-2 bg-cyan-600 hover:bg-cyan-500 disabled:bg-gray-700 disabled:text-gray-500 text-white rounded px-4 py-2 text-sm font-semibold transition-colors h-[38px]"
          >
            {isRunning ? <Loader className="w-4 h-4 animate-spin" /> : <Play className="w-4 h-4" />}
            {isRunning ? '运行中...' : '启动评估'}
          </button>
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
                placeholder="can0 / vcan0"
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
      <div className="grid grid-cols-4 gap-2">
        {PHASES.map((phase, i) => {
          const r = phases[i];
          const PhaseIcon = phase.icon;
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
                  <PhaseIcon className={`w-4 h-4 ${isActive ? 'text-cyan-400' :
                    r.status === 'done' ? 'text-emerald-400' :
                      r.status === 'error' ? 'text-red-400' : 'text-gray-500'
                    }`} />
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
          <div className="text-sm text-gray-300 whitespace-pre-wrap leading-relaxed max-h-96 overflow-y-auto">
            {finalReport}
          </div>
        </div>
      )}
    </div>
  );
};

export default AgentScan;
