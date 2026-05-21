import React, { useEffect, useMemo, useState } from 'react';
import {
  AlertTriangle,
  Bluetooth,
  CheckCircle2,
  Cpu,
  HardDrive,
  Play,
  RadioTower,
  RefreshCw,
  Server,
  Signal,
  Usb,
  Wifi,
} from 'lucide-react';
import { getLocalCapabilities, listPocs, runPocPlugin } from '../services/api';
import { LocalCapabilityFlags } from '../types';

interface LocalRuntimeProps {
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

const capabilityLabels: Record<string, string> = {
  usb: 'USB / Mount',
  can: 'CAN / SocketCAN',
  pcan: 'PCAN',
  wifi: 'Wi-Fi Interface',
  bluetooth: 'Bluetooth',
  sdr: 'SDR / RF',
  lsusb: 'lsusb',
  iw: 'iw',
  bluetoothctl: 'bluetoothctl',
  hackrf: 'HackRF / RTL-SDR',
};

const LocalRuntime: React.FC<LocalRuntimeProps> = ({ token, currentUser, onUnauthorized }) => {
  const [pocs, setPocs] = useState<any[]>([]);
  const [capabilityPayload, setCapabilityPayload] = useState<any>(null);
  const [loading, setLoading] = useState(false);
  const [message, setMessage] = useState('');
  const [error, setError] = useState('');
  const [selectedFilename, setSelectedFilename] = useState('');
  const [runResult, setRunResult] = useState<any>(null);
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

  const capabilityFlags = (capabilityPayload?.capability_flags || {}) as LocalCapabilityFlags;
  const rawCapabilities = capabilityPayload?.capabilities || {};

  const refreshData = async () => {
    if (!token) return;
    setLoading(true);
    setError('');
    try {
      const [capabilityResp, pocResp] = await Promise.all([
        getLocalCapabilities(token),
        listPocs(),
      ]);
      setCapabilityPayload(capabilityResp);
      setPocs(pocResp.pocs || []);
      if (!selectedFilename && pocResp.pocs?.length) {
        setSelectedFilename(pocResp.pocs[0].filename);
      }
      setMessage('本机硬件能力已刷新。');
    } catch (err: any) {
      if (String(err?.message || '').includes('401')) {
        onUnauthorized?.();
      }
      setError(err?.message || 'Failed to refresh local runtime data.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    refreshData();
  }, [token, currentUser?.role]);

  const buildParams = () => {
    const next: Record<string, any> = {};
    Object.entries(params).forEach(([key, value]) => {
      if (key === 'custom_json') return;
      if (value.trim()) next[key] = value.trim();
    });
    if (params.custom_json.trim()) {
      const parsed = JSON.parse(params.custom_json);
      if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
        Object.assign(next, parsed);
      }
    }
    return next;
  };

  const handleRunLocalPoc = async () => {
    if (!token || !selectedFilename) return;
    setLoading(true);
    setError('');
    setMessage('');
    setRunResult(null);
    try {
      const data = await runPocPlugin(selectedFilename, buildParams(), token);
      setRunResult(data);
      setMessage(data?.vulnerable ? '本机验证完成：发现可验证风险。' : '本机验证完成。');
    } catch (err: any) {
      if (String(err?.message || '').includes('401')) {
        onUnauthorized?.();
      }
      setError(err?.message || 'Failed to run local PoC.');
    } finally {
      setLoading(false);
    }
  };

  const capabilityRows = Object.entries(capabilityLabels);

  return (
    <div className="p-6 space-y-6 overflow-y-auto h-full">
      <div className="flex flex-col xl:flex-row xl:items-center xl:justify-between gap-4">
        <div>
          <h2 className="text-2xl font-bold text-white flex items-center gap-3">
            <Server className="text-cyber-accent" />
            Local Vehicle Runtime
          </h2>
          <p className="text-sm text-gray-400 mt-2">
            本机即为车端检测工作站，直接使用本机 USB、PCAN、蓝牙、Wi-Fi monitor、SDR 和车载以太网能力执行 PoC。
          </p>
        </div>
        <button
          onClick={refreshData}
          disabled={loading}
          className="inline-flex items-center gap-2 px-4 py-2 rounded-lg border border-cyber-600 bg-cyber-800 hover:bg-cyber-700 text-white disabled:opacity-60"
        >
          <RefreshCw size={16} className={loading ? 'animate-spin' : ''} />
          刷新本机能力
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
            <div className="text-white font-semibold flex items-center gap-2">
              <HardDrive size={16} className="text-cyber-accent" />
              本机运行时
            </div>
            <div className="text-xs text-gray-400">
              当前产品模式为本地车端检测，不需要注册远端边缘节点，也不需要云端下发任务。
            </div>
            <div className="text-xs text-gray-400">
              Host: <span className="text-white">{capabilityPayload?.host || '--'}</span>
            </div>
            <div className="text-xs text-gray-400">
              Operator: <span className="text-white">{capabilityPayload?.operator || currentUser?.username || '--'}</span>
            </div>
          </div>

          <div className="space-y-3">
            <div className="text-white font-semibold">本机 PoC 快速验证</div>
            <select
              value={selectedFilename}
              onChange={(event) => setSelectedFilename(event.target.value)}
              className="w-full bg-cyber-900 border border-cyber-700 rounded-lg px-3 py-2 text-sm text-white"
            >
              {pocs.map((poc) => (
                <option key={poc.filename} value={poc.filename}>
                  {poc.name || poc.filename}
                </option>
              ))}
            </select>
            {selectedPoc && (
              <div className="text-xs text-gray-400 border border-cyber-700 rounded-lg p-3 bg-cyber-900/40">
                <div className="text-white">{selectedPoc.filename}</div>
                <div>Severity: {selectedPoc.severity || '--'} · Protocol: {selectedPoc.protocol || '--'}</div>
              </div>
            )}
            {[
              ['target_ip', 'Target IP'],
              ['bluetooth_mac', 'Bluetooth MAC'],
              ['can_interface', 'CAN Interface'],
              ['interface', 'Wi-Fi Interface'],
              ['rf_frequency', 'RF Frequency'],
              ['url', 'URL'],
              ['custom_json', 'Extra JSON Params'],
            ].map(([key, label]) => (
              <div key={key} className="space-y-1">
                <label className="text-xs uppercase tracking-wider text-gray-500">{label}</label>
                <input
                  value={(params as any)[key]}
                  onChange={(event) => setParams((prev) => ({ ...prev, [key]: event.target.value }))}
                  className="w-full bg-cyber-900 border border-cyber-700 rounded-lg px-3 py-2 text-sm text-white"
                />
              </div>
            ))}
            <button
              onClick={handleRunLocalPoc}
              disabled={loading || !selectedFilename}
              className="w-full inline-flex items-center justify-center gap-2 px-4 py-2 rounded-lg bg-cyber-accent text-black font-bold disabled:opacity-60"
            >
              <Play size={16} />
              本机执行 PoC
            </button>
          </div>
        </div>

        <div className="xl:col-span-2 space-y-6">
          <div className="bg-cyber-800 border border-cyber-700 rounded-xl p-5">
            <div className="flex items-center justify-between mb-4">
              <div>
                <h3 className="text-lg font-bold text-white">硬件能力检测</h3>
                <p className="text-xs text-gray-500 mt-1">
                  能力来自本机探测，扫描 CAN、蓝牙、Wi-Fi Monitor、SDR、USB 类 PoC 前应先确认对应能力可用。
                </p>
              </div>
              <Cpu className="text-cyber-accent" />
            </div>
            <div className="grid grid-cols-2 md:grid-cols-3 gap-3">
              {capabilityRows.map(([key, label]) => {
                const enabled = Boolean((capabilityFlags as any)[key]);
                return (
                  <div key={key} className={`rounded-lg border p-3 ${enabled ? 'border-emerald-500/40 bg-emerald-500/10' : 'border-cyber-700 bg-cyber-900/40'}`}>
                    <div className="flex items-center gap-2 text-sm">
                      <span className={enabled ? 'text-emerald-300' : 'text-gray-500'}>
                        {capabilityIcons[key] || <CheckCircle2 size={14} />}
                      </span>
                      <span className="text-white">{label}</span>
                    </div>
                    <div className={`mt-2 text-xs font-mono ${enabled ? 'text-emerald-300' : 'text-gray-500'}`}>
                      {enabled ? 'available' : 'not detected'}
                    </div>
                  </div>
                );
              })}
            </div>
          </div>

          <div className="bg-cyber-800 border border-cyber-700 rounded-xl p-5">
            <h3 className="text-lg font-bold text-white mb-3">探测原始摘要</h3>
            {!capabilityPayload ? (
              <div className="text-sm text-gray-500">暂无本机能力数据。</div>
            ) : (
              <pre className="max-h-72 overflow-auto text-xs bg-black/50 border border-cyber-700 rounded-lg p-4 text-gray-300">
                {JSON.stringify(rawCapabilities, null, 2)}
              </pre>
            )}
          </div>

          {runResult && (
            <div className={`rounded-xl border p-5 ${runResult.vulnerable ? 'border-red-500/40 bg-red-500/10' : 'border-cyber-700 bg-cyber-800'}`}>
              <div className="flex items-center gap-2 mb-3">
                {runResult.vulnerable ? <AlertTriangle className="text-red-400" /> : <CheckCircle2 className="text-emerald-300" />}
                <h3 className="text-lg font-bold text-white">本机执行结果</h3>
              </div>
              <div className="text-sm text-gray-300 mb-3">
                Success: {String(runResult.success)} · Vulnerable: {String(runResult.vulnerable)} · Elapsed: {runResult.elapsed_seconds || 0}s
              </div>
              {runResult.evidence && <div className="text-sm text-gray-200 mb-3">Evidence: {runResult.evidence}</div>}
              <pre className="max-h-72 overflow-auto text-xs bg-black/50 border border-cyber-700 rounded-lg p-4 text-gray-300">
                {JSON.stringify(runResult, null, 2)}
              </pre>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default LocalRuntime;
