import React, { useEffect, useMemo, useState } from 'react';
import { Cpu, RadioTower, RefreshCw, Send, Server, Usb, Wifi, Bluetooth, Signal, CheckCircle2, AlertTriangle } from 'lucide-react';
import { createEdgeTask, generateEnrollmentToken, getEdgeAgents, getEdgeRecommendations, getEdgeTasks, listPocs } from '../services/api';
import { EdgeAgentRecord, EdgeRecommendationItem, EdgeRequirementSummary, EdgeTaskRecord } from '../types';

interface EdgeManagerProps {
  token: string | null;
  currentUser: any;
  onUnauthorized?: () => void;
}

const capabilityIcons: Record<string, React.ReactNode> = {
  usb: <Usb size={14} />,
  can: <RadioTower size={14} />,
  wifi: <Wifi size={14} />,
  bluetooth: <Bluetooth size={14} />,
  sdr: <Signal size={14} />,
  pcan: <RadioTower size={14} className="text-emerald-400" />,
};

const EdgeManager: React.FC<EdgeManagerProps> = ({ token, currentUser, onUnauthorized }) => {
  const [agents, setAgents] = useState<EdgeAgentRecord[]>([]);
  const [tasks, setTasks] = useState<EdgeTaskRecord[]>([]);
  const [pocs, setPocs] = useState<any[]>([]);
  const [loading, setLoading] = useState(false);
  const [message, setMessage] = useState<string>('');
  const [error, setError] = useState<string>('');
  const [selectedFilename, setSelectedFilename] = useState<string>('');
  const [selectedAgentId, setSelectedAgentId] = useState<string>('');
  const [requirements, setRequirements] = useState<EdgeRequirementSummary | null>(null);
  const [recommendations, setRecommendations] = useState<EdgeRecommendationItem[]>([]);
  const [expandedTaskId, setExpandedTaskId] = useState<string | null>(null);
  const [tokenLabel, setTokenLabel] = useState('');
  const [tokenTtlHours, setTokenTtlHours] = useState('24');
  const [installCommand, setInstallCommand] = useState('');
  const [params, setParams] = useState({
    target_ip: '',
    bluetooth_mac: '',
    can_interface: '',
    can_bitrate: '',
    interface: '',
    rf_frequency: '',
    url: '',
    target_mac: '',
    custom_json: '',
  });

  const selectedPoc = useMemo(
    () => pocs.find((item) => item.filename === selectedFilename),
    [pocs, selectedFilename]
  );

  const refreshData = async () => {
    if (!token) return;
    setLoading(true);
    setError('');
    try {
      const results = await Promise.allSettled([
        getEdgeTasks(token),
        listPocs(),
        currentUser?.role === 'admin' ? getEdgeAgents(token) : Promise.resolve({ agents: [] }),
      ]);

      const [taskResp, pocResp, agentResp] = results;

      if (taskResp.status === 'fulfilled') {
        setTasks(taskResp.value.tasks || []);
      } else {
        setTasks([]);
      }

      if (pocResp.status === 'fulfilled') {
        setPocs(pocResp.value.pocs || []);
        if (!selectedFilename && pocResp.value.pocs?.length) {
          setSelectedFilename(pocResp.value.pocs[0].filename);
        }
      } else {
        setPocs([]);
      }

      if (agentResp.status === 'fulfilled') {
        setAgents(agentResp.value.agents || []);
      } else {
        setAgents([]);
      }

      const failures = results
        .map((entry, index) => ({ entry, name: ['edge tasks', 'poc list', 'edge agents'][index] }))
        .filter((entry) => entry.entry.status === 'rejected')
        .map((entry: any) => `${entry.name}: ${entry.entry.reason?.message || 'unknown error'}`);

      if (failures.length > 0) {
        setError(failures.join(' | '));
      }
    } catch (err: any) {
      if (String(err?.message || '').includes('401')) {
        onUnauthorized?.();
      }
      setError(err?.message || 'Failed to refresh edge data.');
    } finally {
      setLoading(false);
    }
  };

  const startTransitionRefresh = () => {
    let count = 0;
    const max = 8; // ~15-16 seconds total
    const timer = window.setInterval(() => {
      count++;
      refreshData();
      if (count >= max) {
        window.clearInterval(timer);
      }
    }, 2000);
  };

  useEffect(() => {
    refreshData();
  }, [token, currentUser?.role]);


  const buildParams = () => {
    const next: Record<string, any> = {};
    Object.entries(params).forEach(([key, value]) => {
      if (key === 'custom_json') return;
      if (value.trim()) {
        next[key] = value.trim();
      }
    });
    if (params.custom_json.trim()) {
      const parsed = JSON.parse(params.custom_json);
      if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
        Object.assign(next, parsed);
      }
    }
    return next;
  };

  const handleRecommend = async () => {
    if (!token || !selectedFilename) return;
    setLoading(true);
    setError('');
    setMessage('');
    try {
      const payload = buildParams();
      const data = await getEdgeRecommendations(selectedFilename, payload, token);
      setRequirements(data.requirements || null);
      setRecommendations(data.recommendations || []);
      if (!selectedAgentId) {
        const best = (data.recommendations || []).find((item: EdgeRecommendationItem) => item.matches);
        setSelectedAgentId(best?.agent?.agent_id || '');
      }
      setMessage('Edge capability matching completed.');
    } catch (err: any) {
      if (String(err?.message || '').includes('401')) {
        onUnauthorized?.();
      }
      setError(err?.message || 'Failed to calculate edge recommendations.');
    } finally {
      setLoading(false);
    }
  };

  const handleCreateTask = async () => {
    if (!token || !selectedFilename) return;
    setLoading(true);
    setError('');
    setMessage('');
    try {
      const payload: {
        filename: string;
        params: Record<string, any>;
        agent_id?: string;
      } = {
        filename: selectedFilename,
        params: buildParams(),
      };
      if (selectedAgentId) {
        payload.agent_id = selectedAgentId;
      }
      const data = await createEdgeTask(payload, token);
      setMessage(`Edge task queued on ${data.selected_agent?.display_name || data.task?.edge_agent_id || 'agent'}.`);
      await refreshData();
      startTransitionRefresh();
    } catch (err: any) {
      if (String(err?.message || '').includes('401')) {
        onUnauthorized?.();
      }
      setError(err?.message || 'Failed to create edge task.');
    } finally {
      setLoading(false);
    }
  };

  const handleGenerateInstallCommand = async () => {
    if (!token) return;
    setLoading(true);
    setError('');
    setMessage('');
    try {
      const ttl = Number.parseInt(tokenTtlHours, 10);
      const data = await generateEnrollmentToken(tokenLabel.trim(), Number.isFinite(ttl) ? ttl : 24, token);
      setInstallCommand(data.install_command || '');
      setMessage('已生成一次性边缘部署命令。令牌首次注册成功后即失效。');
      await refreshData();
    } catch (err: any) {
      if (String(err?.message || '').includes('401')) {
        onUnauthorized?.();
      }
      setError(err?.message || 'Failed to generate edge install command.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="p-6 space-y-6 overflow-y-auto h-full">
      <div className="flex flex-col xl:flex-row xl:items-center xl:justify-between gap-4">
        <div>
          <h2 className="text-2xl font-bold text-white flex items-center gap-3">
            <Server className="text-cyber-accent" />
            Edge Control Plane
          </h2>
          <p className="text-sm text-gray-400 mt-2">
            为 USB、PCAN、蓝牙、Wi-Fi monitor、SDR 等现场能力分配合适的边缘节点。
          </p>
        </div>
        <button
          onClick={refreshData}
          disabled={loading}
          className="inline-flex items-center gap-2 px-4 py-2 rounded-lg border border-cyber-600 bg-cyber-800 hover:bg-cyber-700 text-white disabled:opacity-60"
        >
          <RefreshCw size={16} className={loading ? 'animate-spin' : ''} />
          刷新状态
        </button>
      </div>

      {(message || error) && (
        <div className={`rounded-lg border px-4 py-3 text-sm ${error ? 'border-red-500/40 bg-red-500/10 text-red-200' : 'border-emerald-500/40 bg-emerald-500/10 text-emerald-200'}`}>
          {error || message}
        </div>
      )}

      <div className="grid grid-cols-1 xl:grid-cols-3 gap-6">
        <div className="xl:col-span-1 bg-cyber-800 border border-cyber-700 rounded-xl p-5 space-y-4">
          <div className="space-y-3 rounded-lg border border-cyber-700 bg-cyber-900/40 p-4">
            <div className="text-white font-semibold">边缘端自助安装</div>
            <div className="text-xs text-gray-400">
              在云端生成一次性部署命令。用户在本地执行后，只会下载最小 edge runtime 并完成注册，不需要访问 `.env`。
            </div>
            <div className="space-y-2">
              <label className="text-xs uppercase tracking-wider text-gray-500">节点标签</label>
              <input
                value={tokenLabel}
                onChange={(e) => setTokenLabel(e.target.value)}
                placeholder={`${currentUser?.username || 'user'} edge node`}
                className="w-full bg-cyber-900 border border-cyber-700 rounded-lg px-3 py-2 text-sm text-white"
              />
            </div>
            <div className="space-y-2">
              <label className="text-xs uppercase tracking-wider text-gray-500">有效期（小时）</label>
              <input
                value={tokenTtlHours}
                onChange={(e) => setTokenTtlHours(e.target.value)}
                className="w-full bg-cyber-900 border border-cyber-700 rounded-lg px-3 py-2 text-sm text-white"
              />
            </div>
            <button
              onClick={handleGenerateInstallCommand}
              disabled={loading || !token}
              className="w-full inline-flex items-center justify-center gap-2 px-4 py-2 rounded-lg bg-cyber-accent/20 border border-cyber-accent/40 text-cyber-accent hover:bg-cyber-accent/25 disabled:opacity-60"
            >
              <Server size={16} />
              生成部署命令
            </button>
            {installCommand && (
              <div className="space-y-2">
                <label className="text-xs uppercase tracking-wider text-gray-500">安装命令</label>
                <textarea
                  readOnly
                  value={installCommand}
                  rows={4}
                  className="w-full bg-cyber-950 border border-cyber-700 rounded-lg px-3 py-2 text-xs text-emerald-300 font-mono"
                />
              </div>
            )}
          </div>

          <div className="flex items-center gap-2 text-white font-semibold">
            <Cpu size={18} className="text-cyber-accent" />
            任务编排
          </div>

          <div className="space-y-2">
            <label className="text-xs uppercase tracking-wider text-gray-500">PoC 模块</label>
            <select
              value={selectedFilename}
              onChange={(e) => setSelectedFilename(e.target.value)}
              className="w-full bg-cyber-900 border border-cyber-700 rounded-lg px-3 py-2 text-sm text-white"
            >
              {pocs.map((poc) => (
                <option key={poc.filename} value={poc.filename}>
                  {poc.poc_name || poc.filename}
                </option>
              ))}
            </select>
            {selectedPoc && (
              <div className="text-xs text-gray-400">
                <div>{selectedPoc.filename}</div>
                <div>Severity: {selectedPoc.severity || 'Unknown'} | Protocol: {selectedPoc.protocol || 'Unknown'}</div>
              </div>
            )}
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            {[
              ['target_ip', 'TARGET IP'],
              ['bluetooth_mac', 'BLUETOOTH MAC'],
              ['can_interface', 'CAN INTERFACE'],
              ['interface', 'WI-FI INTERFACE'],
              ['rf_frequency', 'RF FREQUENCY'],
              ['url', 'TARGET URL'],
              ['target_mac', 'TARGET MAC'],
              ['can_bitrate', 'CAN BITRATE'],
            ].map(([key, label]) => (
              <div key={key} className="space-y-2">
                <label className="text-xs uppercase tracking-wider text-gray-500">{label}</label>
                <input
                  value={(params as any)[key]}
                  onChange={(e) => setParams((prev) => ({ ...prev, [key]: e.target.value }))}
                  placeholder={
                    key === 'can_interface' ? 'PCAN_USBBUS1' : 
                    key === 'can_bitrate' ? '500000' : 
                    ''
                  }
                  className="w-full bg-cyber-900 border border-cyber-700 rounded-lg px-3 py-2 text-sm text-white"
                />
              </div>
            ))}
          </div>

          <div className="space-y-2">
            <label className="text-xs uppercase tracking-wider text-gray-500">额外参数 JSON</label>
            <textarea
              value={params.custom_json}
              onChange={(e) => setParams((prev) => ({ ...prev, custom_json: e.target.value }))}
              rows={5}
              placeholder='{"arbitration_id":"0x123","data":"11223344"}'
              className="w-full bg-cyber-900 border border-cyber-700 rounded-lg px-3 py-2 text-sm text-white font-mono"
            />
          </div>

          <div className="space-y-2">
            <label className="text-xs uppercase tracking-wider text-gray-500">指定边缘节点</label>
            <select
              value={selectedAgentId}
              onChange={(e) => setSelectedAgentId(e.target.value)}
              className="w-full bg-cyber-900 border border-cyber-700 rounded-lg px-3 py-2 text-sm text-white"
            >
              <option value="">自动选择匹配节点</option>
              {recommendations.length === 0 && agents.length === 0 && (
                <option value="" disabled>暂无已注册边缘节点</option>
              )}
              {recommendations.map((item) => (
                <option key={item.agent.agent_id} value={item.agent.agent_id}>
                  {item.agent.display_name} [{item.agent.status}]
                </option>
              ))}
              {recommendations.length === 0 && agents.map((agent) => (
                <option key={agent.agent_id} value={agent.agent_id}>
                  {agent.display_name} [{agent.status}]
                </option>
              ))}
            </select>
          </div>

          <div className="flex flex-col md:flex-row gap-3">
            <button
              onClick={handleRecommend}
              disabled={loading || !selectedFilename}
              className="flex-1 inline-flex items-center justify-center gap-2 px-4 py-2 rounded-lg bg-cyber-accent/20 border border-cyber-accent/40 text-cyber-accent hover:bg-cyber-accent/25 disabled:opacity-60"
            >
              <CheckCircle2 size={16} />
              推荐节点
            </button>
            <button
              onClick={handleCreateTask}
              disabled={loading || !selectedFilename}
              className="flex-1 inline-flex items-center justify-center gap-2 px-4 py-2 rounded-lg bg-emerald-500/20 border border-emerald-500/40 text-emerald-300 hover:bg-emerald-500/25 disabled:opacity-60"
            >
              <Send size={16} />
              创建任务
            </button>
          </div>
        </div>

        <div className="xl:col-span-2 space-y-6">
          <div className="bg-cyber-800 border border-cyber-700 rounded-xl p-5">
            <div className="flex items-center gap-2 text-white font-semibold mb-4">
              <RadioTower size={18} className="text-cyber-accent" />
              能力匹配
            </div>
            <div className="flex flex-wrap gap-2 mb-4">
              {(requirements?.required_capabilities || []).length > 0 ? (
                requirements?.required_capabilities.map((item) => (
                  <span key={item} className="inline-flex items-center gap-1 rounded-full border border-cyber-accent/40 bg-cyber-accent/10 px-3 py-1 text-xs text-cyber-accent">
                    {capabilityIcons[item] || null}
                    {item}
                  </span>
                ))
              ) : (
                <span className="text-sm text-gray-500">先点击“推荐节点”查看当前 PoC 的本地能力要求。</span>
              )}
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
              {recommendations.map((item) => (
                <div key={item.agent.agent_id} className={`rounded-lg border p-4 ${item.matches ? 'border-emerald-500/40 bg-emerald-500/10' : 'border-cyber-700 bg-cyber-900/60'}`}>
                  <div className="flex items-start justify-between gap-3">
                    <div>
                      <div className="text-white font-semibold">{item.agent.display_name}</div>
                      <div className="text-xs text-gray-400">{item.agent.site_name || item.agent.agent_id}</div>
                    </div>
                    <span className={`text-xs px-2 py-1 rounded-full ${item.agent.status === 'online' ? 'bg-emerald-500/20 text-emerald-300' : item.agent.status === 'busy' ? 'bg-amber-500/20 text-amber-300' : 'bg-gray-500/20 text-gray-300'}`}>
                      {item.agent.status}
                    </span>
                  </div>

                  <div className="flex flex-wrap gap-2 mt-3">
                    {Object.entries(item.agent.capability_flags || {}).filter(([, enabled]) => Boolean(enabled)).map(([name]) => (
                      <span key={name} className="inline-flex items-center gap-1 text-xs rounded-full border border-cyber-600 px-2 py-1 text-gray-300">
                        {capabilityIcons[name] || null}
                        {name}
                      </span>
                    ))}
                  </div>

                  {!item.matches && item.missing_capabilities.length > 0 && (
                    <div className="mt-3 text-xs text-amber-300 flex items-center gap-2">
                      <AlertTriangle size={14} />
                      Missing: {item.missing_capabilities.join(', ')}
                    </div>
                  )}
                </div>
              ))}
            </div>
          </div>

          {currentUser?.role === 'admin' && (
            <div className="bg-cyber-800 border border-cyber-700 rounded-xl p-5">
              <div className="flex items-center gap-2 text-white font-semibold mb-4">
                <Server size={18} className="text-cyber-accent" />
                已注册边缘节点
              </div>
              <div className="overflow-x-auto">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="text-left text-gray-500 border-b border-cyber-700">
                      <th className="pb-3">节点</th>
                      <th className="pb-3">状态</th>
                      <th className="pb-3">能力</th>
                      <th className="pb-3">Last Seen</th>
                    </tr>
                  </thead>
                  <tbody>
                    {agents.map((agent) => (
                      <tr key={agent.agent_id} className="border-b border-cyber-800">
                        <td className="py-3">
                          <div className="text-white">{agent.display_name}</div>
                          <div className="text-xs text-gray-500">{agent.site_name || agent.agent_id}</div>
                        </td>
                        <td className="py-3 text-gray-300">{agent.status}</td>
                        <td className="py-3">
                            {Object.entries(agent.capability_flags || {}).filter(([, enabled]) => Boolean(enabled)).map(([name]) => (
                              <span key={name} className="inline-flex items-center gap-1 rounded-full bg-cyber-900 border border-cyber-700 px-2 py-1 text-xs text-gray-300">
                                {capabilityIcons[name] || null}
                                {name}
                              </span>
                            ))}
                          
                          {/* Hardware Insights Section */}
                          {agent.capabilities && Object.keys(agent.capabilities).length > 0 && (
                            <div className="mt-3 space-y-2">
                              <details className="group">
                                <summary className="text-[10px] uppercase tracking-tighter text-cyber-accent cursor-pointer hover:text-white transition-colors flex items-center gap-1">
                                  <span>Hardware Insights</span>
                                  <Signal size={10} className="group-open:rotate-180 transition-transform" />
                                </summary>
                                <div className="mt-2 p-3 bg-cyber-950/80 rounded-lg border border-cyber-700/50 text-[11px] font-mono whitespace-pre-wrap max-h-48 overflow-y-auto text-gray-400">
                                  {agent.capabilities.usb?.lsusb && (
                                    <div className="mb-2">
                                      <div className="text-emerald-400/80 mb-1 flex items-center gap-1 border-b border-cyber-700/30 pb-0.5">
                                        <Usb size={10} /> USB Devices
                                      </div>
                                      {agent.capabilities.usb.lsusb}
                                    </div>
                                  )}
                                  {agent.capabilities.socketcan?.interfaces && (
                                    <div className="mb-2">
                                      <div className="text-cyber-accent mb-1 flex items-center gap-1 border-b border-cyber-700/30 pb-0.5">
                                        <RadioTower size={10} /> CAN Interfaces
                                      </div>
                                      {agent.capabilities.socketcan.interfaces}
                                    </div>
                                  )}
                                  {agent.capabilities.pcan_chardev?.present && (
                                    <div className="mb-2">
                                      <div className="text-emerald-400 mb-1 flex items-center gap-1 border-b border-cyber-700/30 pb-0.5">
                                        <RadioTower size={10} /> PEAK Drivers
                                      </div>
                                      {agent.capabilities.pcan_chardev.devices?.join('\n') || 'Found pcan chardev'}
                                      {agent.capabilities.pcan_chardev.proc_pcan && (
                                        <div className="mt-1 opacity-70 italic">{agent.capabilities.pcan_chardev.proc_pcan}</div>
                                      )}
                                    </div>
                                  )}
                                  {agent.capabilities.host_tools && (
                                    <div className="opacity-60 text-[9px]">
                                      Available host tools: {Object.entries(agent.capabilities.host_tools).filter(([,v]) => v).map(([k]) => k).join(', ')}
                                    </div>
                                  )}
                                </div>
                              </details>
                            </div>
                          )}
                        </td>
                        <td className="py-3 text-xs text-gray-500">{agent.last_seen_at || '-'}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          <div className="bg-cyber-800 border border-cyber-700 rounded-xl p-5">
            <div className="flex items-center gap-2 text-white font-semibold mb-4">
              <Send size={18} className="text-cyber-accent" />
              边缘任务队列
            </div>
            <div className="space-y-3">
              {tasks.length === 0 && (
                <div className="text-sm text-gray-500">暂无边缘任务。</div>
              )}
              {tasks.map((task) => (
                <div key={task.task_id} className="rounded-lg border border-cyber-700 bg-cyber-900/60 p-4">
                  <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-3">
                    <div>
                      <div className="text-white font-medium">{task.poc_filename}</div>
                      <div className="text-xs text-gray-500">{task.task_id} · {task.edge_agent_id || 'pending assignment'}</div>
                    </div>
                    <span className={`text-xs px-2 py-1 rounded-full self-start ${task.status === 'completed' ? 'bg-emerald-500/20 text-emerald-300' : task.status === 'failed' ? 'bg-red-500/20 text-red-300' : task.status === 'running' ? 'bg-amber-500/20 text-amber-300' : 'bg-cyber-700 text-gray-300'}`}>
                      {task.status}
                    </span>
                  </div>
                  <div className="mt-3 text-xs text-gray-400 break-all">
                    Params: {JSON.stringify(task.params || {})}
                  </div>
                  <div className="mt-3">
                    <button
                      onClick={() => setExpandedTaskId((prev) => prev === task.task_id ? null : task.task_id)}
                      className="text-xs text-cyber-accent hover:text-white transition-colors"
                    >
                      {expandedTaskId === task.task_id ? '隐藏详情' : '查看详情'}
                    </button>
                  </div>
                  {task.result && (
                    <div className="mt-3 grid grid-cols-1 md:grid-cols-4 gap-3 text-xs">
                      <div className="rounded bg-cyber-950/70 p-3">
                        <div className="text-gray-500 uppercase">Success</div>
                        <div className="text-white mt-1">{String(Boolean(task.result.success))}</div>
                      </div>
                      <div className="rounded bg-cyber-950/70 p-3">
                        <div className="text-gray-500 uppercase">Vulnerable</div>
                        <div className="text-white mt-1">{String(Boolean(task.result.vulnerable))}</div>
                      </div>
                      <div className="rounded bg-cyber-950/70 p-3">
                        <div className="text-gray-500 uppercase">Evidence</div>
                        <div className="text-white mt-1">{task.result.evidence || '-'}</div>
                      </div>
                      <div className="rounded bg-cyber-950/70 p-3">
                        <div className="text-gray-500 uppercase">Elapsed</div>
                        <div className="text-white mt-1">{task.result.elapsed_seconds || 0}s</div>
                      </div>
                    </div>
                  )}
                  {expandedTaskId === task.task_id && (
                    <div className="mt-4 space-y-3 text-xs">
                      <div className="rounded bg-cyber-950/70 p-3">
                        <div className="text-gray-500 uppercase mb-2">Logs</div>
                        <pre className="whitespace-pre-wrap break-words text-gray-300">
                          {Array.isArray(task.result?.logs) && task.result.logs.length > 0 ? task.result.logs.join('\n') : 'No logs'}
                        </pre>
                      </div>
                      <div className="rounded bg-cyber-950/70 p-3">
                        <div className="text-gray-500 uppercase mb-2">Errors</div>
                        <pre className="whitespace-pre-wrap break-words text-gray-300">
                          {Array.isArray(task.result?.errors) && task.result.errors.length > 0 ? task.result.errors.join('\n') : 'No errors'}
                        </pre>
                      </div>
                      <div className="rounded bg-cyber-950/70 p-3">
                        <div className="text-gray-500 uppercase mb-2">Plugin Results</div>
                        <pre className="whitespace-pre-wrap break-words text-gray-300">
                          {JSON.stringify(task.result?.plugin_results || {}, null, 2)}
                        </pre>
                      </div>
                      <div className="rounded bg-cyber-950/70 p-3">
                        <div className="text-gray-500 uppercase mb-2">Security Profile</div>
                        <pre className="whitespace-pre-wrap break-words text-gray-300">
                          {JSON.stringify(task.result?.security_profile || {}, null, 2)}
                        </pre>
                      </div>
                    </div>
                  )}
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default EdgeManager;
