import React, { useRef, useState } from 'react';
import { AlertTriangle, Check, Clipboard, FileKey2, LogOut, RefreshCw, ShieldCheck, Upload } from 'lucide-react';
import { activateOfflineLicense, getLicenseStatus, LicenseStatus } from '../services/api';

interface LicenseActivationProps {
  status: LicenseStatus;
  onActivated: (status: LicenseStatus) => void;
  onLogout: () => void;
}

const STATE_LABELS: Record<string, string> = {
  missing: '尚未安装许可证',
  expired: '许可证已到期',
  wrong_device: '许可证与本机不匹配',
  invalid_signature: '许可证签名无效',
  invalid_format: '许可证格式无效',
  invalid_claims: '许可证声明无效',
  clock_rollback: '检测到系统时间回拨',
  configuration_error: '授权公钥未配置',
  not_yet_valid: '许可证尚未生效',
};

const LicenseActivation: React.FC<LicenseActivationProps> = ({ status, onActivated, onLogout }) => {
  const [licenseText, setLicenseText] = useState('');
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const [copied, setCopied] = useState(false);
  const fileRef = useRef<HTMLInputElement>(null);

  const activate = async () => {
    if (!licenseText.trim()) {
      setError('请选择许可证文件，或粘贴许可证内容。');
      return;
    }
    setBusy(true);
    setError('');
    try {
      onActivated(await activateOfflineLicense(licenseText));
    } catch (err: any) {
      setError(err?.message || '许可证激活失败。');
    } finally {
      setBusy(false);
    }
  };

  const refresh = async () => {
    setBusy(true);
    setError('');
    try {
      onActivated(await getLicenseStatus());
    } catch (err: any) {
      setError(err?.message || '刷新许可证状态失败。');
    } finally {
      setBusy(false);
    }
  };

  const readFile = async (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    if (!file) return;
    try {
      setLicenseText(await file.text());
      setError('');
    } catch {
      setError('无法读取许可证文件。');
    }
  };

  const copyMachineCode = async () => {
    await navigator.clipboard.writeText(status.machine_code);
    setCopied(true);
    window.setTimeout(() => setCopied(false), 1600);
  };

  return (
    <main className="auth-shell min-h-screen overflow-auto px-5 py-10 text-slate-100">
      <div className="auth-aurora auth-aurora-a" />
      <div className="auth-grid" />
      <div className="relative z-10 mx-auto flex min-h-[calc(100vh-5rem)] max-w-3xl items-center justify-center">
        <section className="surface-panel w-full p-7 sm:p-9">
          <div className="flex items-start justify-between gap-5">
            <div className="flex items-center gap-4">
              <div className="brand-mark !h-12 !w-12 !rounded-xl"><FileKey2 size={24} /></div>
              <div>
                <p className="font-mono text-[10px] uppercase tracking-[0.2em] text-cyan-300/60">Offline workstation license</p>
                <h1 className="mt-1 text-2xl font-semibold text-white">激活智驭安盾工作站</h1>
              </div>
            </div>
            <button onClick={onLogout} className="secondary-action flex items-center gap-2 px-3 py-2 text-xs"><LogOut size={14} />退出</button>
          </div>

          <div className="mt-7 flex items-start gap-3 rounded-xl border border-amber-400/20 bg-amber-400/[0.06] p-4 text-amber-100">
            <AlertTriangle className="mt-0.5 shrink-0" size={18} />
            <div>
              <div className="text-sm font-medium">{STATE_LABELS[status.state] || status.message || '许可证不可用'}</div>
              <p className="mt-1 text-xs leading-5 text-amber-100/60">扫描与 PoC 执行当前处于受限状态。已有数据不会被删除。</p>
            </div>
          </div>

          <div className="mt-7">
            <label className="field-label">本机设备码</label>
            <div className="mt-2 flex gap-2">
              <code className="control-input min-w-0 flex-1 overflow-x-auto rounded-xl px-4 py-3 font-mono text-xs text-cyan-200">{status.machine_code}</code>
              <button onClick={copyMachineCode} className="secondary-action flex shrink-0 items-center gap-2 px-4 text-xs">
                {copied ? <Check size={15} /> : <Clipboard size={15} />}{copied ? '已复制' : '复制'}
              </button>
            </div>
            <p className="mt-2 text-xs leading-5 text-slate-500">将设备码发送给供应商。供应商签发 1 个月或 3 个月许可证后，将文件导入下方。</p>
          </div>

          <div className="mt-6">
            <div className="flex items-center justify-between">
              <label className="field-label">许可证内容</label>
              <input ref={fileRef} type="file" accept=".autosec,.json,application/json" onChange={readFile} className="hidden" />
              <button onClick={() => fileRef.current?.click()} className="secondary-action flex items-center gap-2 px-3 py-2 text-xs"><Upload size={14} />选择文件</button>
            </div>
            <textarea
              value={licenseText}
              onChange={(event) => setLicenseText(event.target.value)}
              rows={7}
              spellCheck={false}
              className="control-input mt-2 w-full resize-y rounded-xl p-4 font-mono text-xs text-slate-300"
              placeholder="粘贴 license.autosec 的完整 JSON 内容"
            />
          </div>

          {error && <div className="mt-4 rounded-xl border border-rose-400/20 bg-rose-400/[0.06] p-3 text-sm text-rose-200">{error}</div>}

          <div className="mt-6 grid gap-3 sm:grid-cols-[1fr_auto]">
            <button onClick={activate} disabled={busy} className="primary-action flex items-center justify-center gap-2 py-3 disabled:opacity-50">
              {busy ? <RefreshCw className="animate-spin" size={16} /> : <ShieldCheck size={17} />}
              验证并激活许可证
            </button>
            <button onClick={refresh} disabled={busy} className="secondary-action flex items-center justify-center gap-2 px-5 py-3 disabled:opacity-50">
              <RefreshCw size={15} />刷新状态
            </button>
          </div>

          {status.license_id && (
            <div className="mt-6 border-t border-white/[0.07] pt-5 text-xs text-slate-500">
              当前许可证：{status.license_id} · {status.customer || '未知客户'} · 到期时间 {status.expires_at || '-'}
            </div>
          )}
        </section>
      </div>
    </main>
  );
};

export default LicenseActivation;
