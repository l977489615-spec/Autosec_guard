import React, { useEffect, useMemo, useState } from 'react';
import {
  Activity, AlertTriangle, CheckCircle2, Cpu, Eye, EyeOff, KeyRound,
  Save, ShieldCheck, Sparkles, UserRound,
} from 'lucide-react';
import {
  AI_CONFIG_PLACEHOLDERS,
  buildAiConfigPayload,
  defaultAiSettings,
  testCurrentAiConfig,
  updateCurrentProfile,
} from '../services/api';

interface ProfileProps {
  currentUser: any;
  token: string | null;
  onUpdateSuccess: (newUser: any) => void;
}

const inputClass = 'control-input w-full rounded-xl px-4 py-3 text-sm text-white placeholder:text-slate-600';

const Profile: React.FC<ProfileProps> = ({ currentUser, token, onUpdateSuccess }) => {
  const initialAiSettings = useMemo(
    () => ({ ...defaultAiSettings(), ...(currentUser.ai_config || {}) }),
    [currentUser],
  );
  const [newUsername, setNewUsername] = useState(currentUser.username);
  const [newPassword, setNewPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [aiSettings, setAiSettings] = useState(initialAiSettings);
  const [loading, setLoading] = useState(false);
  const [testing, setTesting] = useState(false);
  const [showApiKey, setShowApiKey] = useState(false);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');

  useEffect(() => {
    setNewUsername(currentUser.username);
    setAiSettings(initialAiSettings);
  }, [currentUser, initialAiSettings]);

  const aiSettingsChanged = JSON.stringify(aiSettings) !== JSON.stringify(initialAiSettings);
  const hasChanges = Boolean(newPassword || newUsername !== currentUser.username || aiSettingsChanged);

  const handleUpdate = async (event: React.FormEvent) => {
    event.preventDefault();
    setError('');
    setSuccess('');
    if (newPassword && newPassword.length < 8) {
      setError('新密码至少需要 8 个字符。');
      return;
    }
    if (newPassword !== confirmPassword) {
      setError('两次输入的新密码不一致。');
      return;
    }
    if (!token || !hasChanges) return;

    setLoading(true);
    try {
      const data = await updateCurrentProfile(token, {
        new_username: newUsername !== currentUser.username ? newUsername.trim() : undefined,
        new_password: newPassword || undefined,
        ai_config: buildAiConfigPayload(aiSettings, { includeApiKey: Boolean(aiSettings.apiKey?.trim()) }),
      });
      setSuccess('设置已安全保存。');
      setNewPassword('');
      setConfirmPassword('');
      if (data.user) onUpdateSuccess(data.user);
    } catch (err: any) {
      setError(err?.message || '保存失败，请稍后重试。');
    } finally {
      setLoading(false);
    }
  };

  const handleTestConfig = async () => {
    if (!token) return;
    setTesting(true);
    setError('');
    setSuccess('');
    try {
      const data = await testCurrentAiConfig(
        token,
        buildAiConfigPayload(aiSettings, { includeApiKey: Boolean(aiSettings.apiKey?.trim()) }),
      );
      if (!data.success) throw new Error(data.message || 'AI 连接测试失败。');
      setSuccess(`AI 连接正常，已验证模型 ${data.model || '当前模型'}。`);
    } catch (err: any) {
      setError(err?.message || 'AI 连接测试失败。');
    } finally {
      setTesting(false);
    }
  };

  return (
    <div className="console-page min-h-full overflow-y-auto px-5 py-8 md:px-10 md:py-10">
      <form onSubmit={handleUpdate} className="relative z-10 mx-auto max-w-6xl space-y-6">
        <header className="flex flex-col gap-5 border-b border-white/10 pb-7 md:flex-row md:items-end md:justify-between">
          <div>
            <div className="section-kicker"><ShieldCheck size={14} /> 身份与运行时密钥</div>
            <h2 className="mt-3 text-3xl font-semibold tracking-tight text-white md:text-4xl">个人设置</h2>
            <p className="mt-2 max-w-2xl text-sm leading-6 text-slate-400">
              管理本机工作站身份、登录密码与用户级 AI 连接。敏感密钥只在服务端加密保存。
            </p>
          </div>
          <div className="inline-flex w-fit items-center gap-3 rounded-full border border-cyan-300/15 bg-cyan-300/[0.06] px-4 py-2 text-xs text-cyan-100">
            <span className="status-orb" />
            <span className="font-mono">{currentUser.username}</span>
            <span className="text-cyan-300/40">/</span>
            <span>{currentUser.role === 'admin' ? '管理员' : '操作员'}</span>
          </div>
        </header>

        {(error || success) && (
          <div
            role="status"
            className={`flex items-start gap-3 rounded-xl border px-4 py-3 text-sm ${
              error
                ? 'border-rose-400/30 bg-rose-500/10 text-rose-200'
                : 'border-emerald-400/25 bg-emerald-400/10 text-emerald-100'
            }`}
          >
            {error ? <AlertTriangle size={18} /> : <CheckCircle2 size={18} />}
            <span>{error || success}</span>
          </div>
        )}

        <div className="grid gap-6 lg:grid-cols-[0.78fr_1.22fr]">
          <section className="surface-panel p-6 md:p-7">
            <div className="flex items-center gap-3">
              <div className="icon-well"><UserRound size={20} /></div>
              <div>
                <h3 className="font-semibold text-white">账号安全</h3>
                <p className="mt-0.5 text-xs text-slate-500">更新标识与登录凭据</p>
              </div>
            </div>

            <div className="mt-7 space-y-6">
              <label className="field-label">
                用户名
                <input
                  type="text"
                  required
                  minLength={3}
                  maxLength={64}
                  autoComplete="username"
                  value={newUsername}
                  onChange={(event) => setNewUsername(event.target.value)}
                  className={inputClass}
                />
              </label>

              <div className="h-px bg-white/[0.07]" />
              <div>
                <div className="flex items-center justify-between">
                  <span className="text-sm font-medium text-slate-200">修改密码</span>
                  <span className="text-[11px] text-slate-500">可选 · 至少 8 位</span>
                </div>
                <div className="mt-3 space-y-3">
                  <label className="field-label">
                    新密码
                    <input
                      type="password"
                      minLength={8}
                      autoComplete="new-password"
                      value={newPassword}
                      onChange={(event) => setNewPassword(event.target.value)}
                      className={inputClass}
                      placeholder="输入新密码"
                    />
                  </label>
                  <label className="field-label">
                    确认新密码
                    <input
                      type="password"
                      minLength={8}
                      autoComplete="new-password"
                      value={confirmPassword}
                      onChange={(event) => setConfirmPassword(event.target.value)}
                      className={inputClass}
                      placeholder="再次输入新密码"
                    />
                  </label>
                </div>
              </div>
            </div>
          </section>

          <section className="surface-panel overflow-hidden">
            <div className="border-b border-white/[0.07] px-6 py-5 md:px-7">
              <div className="flex items-center gap-3">
                <div className="icon-well"><Sparkles size={20} /></div>
                <div>
                  <h3 className="font-semibold text-white">AI 运行时</h3>
                  <p className="mt-0.5 text-xs text-slate-500">兼容 OpenAI 协议的模型服务</p>
                </div>
                <span className={`ml-auto rounded-full border px-2.5 py-1 text-[10px] font-medium ${
                  aiSettings.apiKeyConfigured
                    ? 'border-emerald-400/20 bg-emerald-400/10 text-emerald-300'
                    : 'border-amber-400/20 bg-amber-400/10 text-amber-200'
                }`}>
                  {aiSettings.apiKeyConfigured ? '密钥已配置' : '等待配置'}
                </span>
              </div>
            </div>

            <div className="space-y-5 px-6 py-6 md:px-7">
              <label className="field-label">
                API Base URL
                <input
                  type="url"
                  value={aiSettings.baseUrl}
                  placeholder={AI_CONFIG_PLACEHOLDERS.baseUrl}
                  onChange={(event) => setAiSettings((prev) => ({ ...prev, baseUrl: event.target.value }))}
                  className={inputClass}
                />
              </label>

              <label className="field-label">
                API Key
                <div className="relative">
                  <input
                    type={showApiKey ? 'text' : 'password'}
                    value={aiSettings.apiKey}
                    autoComplete="off"
                    placeholder={aiSettings.apiKeyConfigured ? '已加密保存；留空表示继续使用' : '输入 API Key'}
                    onChange={(event) => setAiSettings((prev) => ({ ...prev, apiKey: event.target.value }))}
                    className={`${inputClass} pr-12 font-mono`}
                  />
                  <button
                    type="button"
                    aria-label={showApiKey ? '隐藏 API Key' : '显示 API Key'}
                    onClick={() => setShowApiKey((value) => !value)}
                    className="absolute inset-y-0 right-0 grid w-12 place-items-center text-slate-500 transition hover:text-cyan-200"
                  >
                    {showApiKey ? <EyeOff size={17} /> : <Eye size={17} />}
                  </button>
                </div>
              </label>

              <div className="grid gap-3 md:grid-cols-3">
                {([
                  ['reportModel', '报告模型', AI_CONFIG_PLACEHOLDERS.reportModel],
                  ['fastModel', '快速模型', AI_CONFIG_PLACEHOLDERS.fastModel],
                  ['strongModel', '推理模型', AI_CONFIG_PLACEHOLDERS.strongModel],
                ] as const).map(([key, label, placeholder]) => (
                  <label key={key} className="field-label">
                    {label}
                    <input
                      type="text"
                      value={aiSettings[key]}
                      placeholder={placeholder}
                      onChange={(event) => setAiSettings((prev) => ({ ...prev, [key]: event.target.value }))}
                      className={inputClass}
                    />
                  </label>
                ))}
              </div>

              <div className="flex gap-3 rounded-xl border border-cyan-300/10 bg-cyan-300/[0.035] p-4 text-xs leading-5 text-slate-400">
                <KeyRound size={17} className="mt-0.5 shrink-0 text-cyan-300" />
                <p>测试会优先使用快速模型，并自动复用服务端已保存的密钥；浏览器不会取回密钥明文。</p>
              </div>
            </div>
          </section>
        </div>

        <div className="flex flex-col-reverse gap-3 border-t border-white/10 pt-5 sm:flex-row sm:items-center sm:justify-between">
          <div className="flex items-center gap-2 text-xs text-slate-500">
            <Cpu size={14} /> 配置仅作用于当前用户与本机执行面
          </div>
          <div className="flex gap-3">
            <button
              type="button"
              onClick={handleTestConfig}
              disabled={loading || testing}
              className="secondary-action flex items-center gap-2 px-4 py-2.5"
            >
              <Activity size={16} className={testing ? 'animate-pulse' : ''} />
              {testing ? '正在验证…' : '测试 AI 连接'}
            </button>
            <button
              type="submit"
              disabled={loading || testing || !hasChanges}
              className="primary-action flex items-center gap-2 px-5 py-2.5"
            >
              <Save size={16} />
              {loading ? '正在保存…' : '保存设置'}
            </button>
          </div>
        </div>
      </form>
    </div>
  );
};

export default Profile;
