import React, { useEffect, useState } from 'react';
import {
  AlertTriangle, ArrowRight, CheckCircle2, Eye, EyeOff,
  KeyRound, LockKeyhole, Network, RefreshCw, ScanLine, Shield, UserRound,
} from 'lucide-react';
import { AuthStatus, getAuthStatus, submitAuth } from '../services/api';

interface AuthPageProps {
  onLogin: (user: any) => void;
}

type AuthView = 'loading' | 'initialize' | 'cli_pending' | 'login' | 'register';

const AuthPage: React.FC<AuthPageProps> = ({ onLogin }) => {
  const [authStatus, setAuthStatus] = useState<AuthStatus | null>(null);
  const [view, setView] = useState<AuthView>('loading');
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [bootstrapToken, setBootstrapToken] = useState('');
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  const [loading, setLoading] = useState(false);

  const refreshAuthStatus = async () => {
    try {
      const status = await getAuthStatus();
      setAuthStatus(status);
      if (status.bootstrap_required && !status.web_bootstrap_allowed) setView('cli_pending');
      else if (status.bootstrap_required) setView('initialize');
      else setView('login');
    } catch (err: any) {
      setError(err?.message || '无法连接本机安全引擎。');
      setView('login');
    }
  };

  useEffect(() => { refreshAuthStatus(); }, []);

  const selectView = (next: 'login' | 'register') => {
    if (next === 'register' && !authStatus?.registration_allowed) {
      setError('当前部署仅允许管理员创建账号；请从本机地址访问，或联系管理员开放注册。');
      return;
    }
    setView(next);
    setError('');
    setSuccess('');
    setPassword('');
    setConfirmPassword('');
  };

  const handleSubmit = async (event: React.FormEvent) => {
    event.preventDefault();
    setError('');
    setSuccess('');
    const isRegistration = view === 'initialize' || view === 'register';
    if (isRegistration && password !== confirmPassword) {
      setError('两次输入的密码不一致。');
      return;
    }

    setLoading(true);
    try {
      const payload: Record<string, string> = { username: username.trim(), password };
      if (view === 'initialize' && authStatus?.bootstrap_token_required) payload.bootstrap_token = bootstrapToken;
      const data = await submitAuth(isRegistration ? 'register' : 'login', payload);
      if (!isRegistration) {
        onLogin(data.user);
        return;
      }
      setSuccess(view === 'initialize' ? '系统初始化完成，请登录管理员账号。' : '账号创建成功，请登录。');
      setPassword('');
      setConfirmPassword('');
      setBootstrapToken('');
      await refreshAuthStatus();
      setView('login');
    } catch (err: any) {
      const trace = err?.traceId ? `（追踪号 ${err.traceId}）` : '';
      setError(`${err?.message || '认证请求失败。'}${trace}`);
    } finally {
      setLoading(false);
    }
  };

  const isRegistration = view === 'initialize' || view === 'register';
  const submitLabel = loading
    ? '正在处理…'
    : view === 'initialize'
      ? '创建管理员并初始化'
      : view === 'register'
        ? '创建账号'
        : '进入安全工作站';

  return (
    <main className="auth-shell min-h-screen overflow-hidden text-slate-100">
      <div className="auth-aurora auth-aurora-a" />
      <div className="auth-aurora auth-aurora-b" />
      <div className="auth-grid" />

      <div className="relative z-10 mx-auto grid min-h-screen w-full max-w-[1440px] lg:grid-cols-[1.12fr_0.88fr]">
        <section className="hidden min-h-screen flex-col justify-between border-r border-white/[0.06] px-14 py-12 lg:flex xl:px-20">
          <div className="flex items-center gap-3">
            <div className="brand-mark"><Shield size={25} /></div>
            <div>
              <div className="text-sm font-semibold tracking-[0.18em] text-white">智驭安盾</div>
              <div className="mt-0.5 text-[10px] tracking-[0.2em] text-cyan-200/45">AUTOSEC GUARD / EDGE</div>
            </div>
          </div>

          <div className="max-w-2xl pb-8">
            <div className="section-kicker"><ScanLine size={14} /> ICV 边缘漏洞扫描工作站</div>
            <h1 className="mt-6 text-5xl font-semibold leading-[1.12] tracking-[-0.035em] text-white xl:text-6xl">
              一车一检，<br /><span className="text-cyan-300">全攻击面</span>就地扫透。
            </h1>
            <p className="mt-6 max-w-xl text-base leading-7 text-slate-400">
              内置 317 个车端专用 PoC，覆盖侦察、车载网络、CAN/UDS、无线与应用层。Global / Manual / Agent 三种扫描模式，在车旁工控机直接执行，不依赖云端调度；破坏性检测须审批放行，结果自动归档为可复核证据。
            </p>

            <div className="mt-11 grid max-w-xl grid-cols-3 border-y border-white/[0.08] py-5">
              {[
                [ScanLine, '317 车端 PoC', '6 大攻击面'],
                [Network, '边缘就地执行', 'CAN·网络·无线'],
                [Shield, '扫描可控可审', '审批·留证·报告'],
              ].map(([Icon, label, sub]) => {
                const FeatureIcon = Icon as typeof Network;
                return (
                  <div key={String(label)} className="border-r border-white/[0.07] px-4 first:pl-0 last:border-0">
                    <FeatureIcon size={18} className="text-cyan-300/80" />
                    <div className="mt-3 text-xs font-medium text-slate-200">{String(label)}</div>
                    <div className="mt-1 font-mono text-[10px] text-slate-600">{String(sub)}</div>
                  </div>
                );
              })}
            </div>
          </div>

          <div className="flex items-center gap-2 text-[11px] text-slate-600">
            <span className="status-orb" /> 本机安全引擎 · 加密连接 · v3.0
          </div>
        </section>

        <section className="flex min-h-screen items-center justify-center px-5 py-10 sm:px-10 lg:px-14">
          <div className="w-full max-w-md animate-auth-enter">
            <div className="mb-9 flex items-center gap-3 lg:hidden">
              <div className="brand-mark"><Shield size={23} /></div>
              <div className="font-semibold tracking-[0.16em]">智驭安盾</div>
            </div>

            <div className="mb-7">
              <p className="font-mono text-[11px] uppercase tracking-[0.22em] text-cyan-300/60">
                {view === 'initialize' ? 'First run initialization' : 'Secure operator access'}
              </p>
              <h2 className="mt-3 text-3xl font-semibold tracking-tight text-white">
                {view === 'initialize' ? '初始化工作站' : view === 'register' ? '创建操作员账号' : '欢迎回来'}
              </h2>
              <p className="mt-2 text-sm leading-6 text-slate-500">
                {view === 'initialize'
                  ? '创建首位管理员，完成本机安全边界初始化。'
                  : view === 'register'
                    ? '新账号默认使用普通操作员权限。'
                    : '使用工作站账号继续访问扫描与证据。'}
              </p>
            </div>

            {view === 'loading' ? (
              <div className="surface-panel grid min-h-64 place-items-center">
                <div className="text-center text-sm text-slate-500">
                  <RefreshCw className="mx-auto mb-3 animate-spin text-cyan-300" size={22} />
                  正在验证本机状态…
                </div>
              </div>
            ) : view === 'cli_pending' ? (
              <div className="surface-panel p-6">
                <div className="flex items-center gap-3 text-amber-200">
                  <AlertTriangle size={20} /><strong>等待管理员初始化</strong>
                </div>
                <p className="mt-4 text-sm leading-6 text-slate-400">当前使用企业 CLI 初始化策略，请在服务器执行：</p>
                <pre className="mt-4 overflow-x-auto rounded-xl border border-white/10 bg-black/30 p-4 font-mono text-xs text-cyan-200">{`cd server\nFLASK_APP=server.py flask create-admin --username admin`}</pre>
                <button type="button" onClick={refreshAuthStatus} className="secondary-action mt-5 w-full py-3">刷新状态</button>
              </div>
            ) : (
              <div className="surface-panel p-6 sm:p-7">
                {view !== 'initialize' && (
                  <div className="mb-7 grid grid-cols-2 rounded-xl border border-white/[0.08] bg-black/20 p-1">
                    <button
                      type="button"
                      onClick={() => selectView('login')}
                      className={`auth-tab ${view === 'login' ? 'auth-tab-active' : ''}`}
                    >登录</button>
                    <button
                      type="button"
                      onClick={() => selectView('register')}
                      aria-disabled={!authStatus?.registration_allowed}
                      title={authStatus?.registration_allowed ? '创建普通操作员账号' : '仅本机或管理员开放注册'}
                      className={`auth-tab ${view === 'register' ? 'auth-tab-active' : ''} ${!authStatus?.registration_allowed ? 'opacity-50' : ''}`}
                    >注册账号</button>
                  </div>
                )}

                <form onSubmit={handleSubmit} className="space-y-5">
                  <label className="field-label">
                    {view === 'initialize' ? '管理员用户名' : '用户名'}
                    <div className="relative">
                      <UserRound className="pointer-events-none absolute left-4 top-1/2 -translate-y-1/2 text-slate-600" size={17} />
                      <input
                        autoFocus
                        type="text"
                        required
                        minLength={3}
                        maxLength={64}
                        autoComplete="username"
                        value={username}
                        onChange={(event) => setUsername(event.target.value)}
                        className="control-input w-full rounded-xl py-3.5 pl-11 pr-4 text-sm text-white"
                        placeholder="输入用户名"
                      />
                    </div>
                  </label>

                  <label className="field-label">
                    密码
                    <div className="relative">
                      <LockKeyhole className="pointer-events-none absolute left-4 top-1/2 -translate-y-1/2 text-slate-600" size={17} />
                      <input
                        type={showPassword ? 'text' : 'password'}
                        required
                        minLength={12}
                        autoComplete={isRegistration ? 'new-password' : 'current-password'}
                        value={password}
                        onChange={(event) => setPassword(event.target.value)}
                        className="control-input w-full rounded-xl py-3.5 pl-11 pr-12 text-sm text-white"
                        placeholder="至少 12 个字符"
                      />
                      <button
                        type="button"
                        aria-label={showPassword ? '隐藏密码' : '显示密码'}
                        onClick={() => setShowPassword((value) => !value)}
                        className="absolute inset-y-0 right-0 grid w-12 place-items-center text-slate-600 transition hover:text-cyan-200"
                      >{showPassword ? <EyeOff size={17} /> : <Eye size={17} />}</button>
                    </div>
                  </label>

                  {isRegistration && (
                    <label className="field-label">
                      确认密码
                      <input
                        type={showPassword ? 'text' : 'password'}
                        required
                        minLength={12}
                        autoComplete="new-password"
                        value={confirmPassword}
                        onChange={(event) => setConfirmPassword(event.target.value)}
                        className="control-input w-full rounded-xl px-4 py-3.5 text-sm text-white"
                        placeholder="再次输入密码"
                      />
                    </label>
                  )}

                  {view === 'initialize' && authStatus?.bootstrap_token_required && (
                    <label className="field-label">
                      初始化令牌
                      <div className="relative">
                        <KeyRound className="pointer-events-none absolute left-4 top-1/2 -translate-y-1/2 text-slate-600" size={17} />
                        <input
                          type="password"
                          required
                          value={bootstrapToken}
                          onChange={(event) => setBootstrapToken(event.target.value)}
                          className="control-input w-full rounded-xl py-3.5 pl-11 pr-4 font-mono text-sm text-white"
                          placeholder="AUTOSEC_BOOTSTRAP_TOKEN"
                        />
                      </div>
                    </label>
                  )}

                  {(error || success) && (
                    <div className={`flex items-start gap-2.5 rounded-xl border px-4 py-3 text-sm ${
                      error ? 'border-rose-400/30 bg-rose-500/10 text-rose-200' : 'border-emerald-400/25 bg-emerald-400/10 text-emerald-100'
                    }`}>
                      {error ? <AlertTriangle size={17} /> : <CheckCircle2 size={17} />}
                      <span>{error || success}</span>
                    </div>
                  )}

                  <button type="submit" disabled={loading} className="primary-action group flex w-full items-center justify-center gap-2 py-3.5">
                    {submitLabel}
                    <ArrowRight size={17} className="transition-transform group-hover:translate-x-1" />
                  </button>
                </form>
              </div>
            )}

            <p className="mt-6 text-center text-[11px] leading-5 text-slate-600">
              登录即表示仅在已授权的目标与测试范围内使用本系统
            </p>
          </div>
        </section>
      </div>
    </main>
  );
};

export default AuthPage;
