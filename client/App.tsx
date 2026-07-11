import React, { lazy, Suspense, useEffect, useState } from 'react';
import { LayoutDashboard, Radio, Database, Shield, Github, History, User, AlertTriangle, ServerCrash, Cpu } from 'lucide-react';
import AuthPage from './components/AuthPage';
import { ScanSession } from './types';
import { fetchCurrentProfile, getBackendHealth, getBackendUrl, logoutCurrentSession, setUnauthorizedHandler } from './services/api';
import { sanitizeUserForStorage } from './utils/security';

const Dashboard = lazy(() => import('./components/Dashboard'));
const Scanner = lazy(() => import('./components/Scanner'));
const PocDatabase = lazy(() => import('./components/PocDatabase'));
const ScanHistory = lazy(() => import('./components/ScanHistory'));
const Profile = lazy(() => import('./components/Profile'));
const UserManagement = lazy(() => import('./components/UserManagement'));
const LocalRuntime = lazy(() => import('./components/LocalRuntime'));

const ViewLoading = () => (
  <div className="h-full flex items-center justify-center text-sm text-cyan-300" role="status" aria-live="polite">
    <div className="flex items-center gap-3 rounded-lg border border-cyan-900/60 bg-cyber-800/80 px-5 py-3">
      <span className="h-2.5 w-2.5 animate-pulse rounded-full bg-cyber-accent" />
      正在加载工作区…
    </div>
  </div>
);

enum View {
  DASHBOARD = 'dashboard',
  SCANNER = 'scanner',
  DATABASE = 'database',
  HISTORY = 'history',
  EDGE = 'edge',
  PROFILE = 'profile',
  USER_MANAGEMENT = 'user_management'
}

type ScannerMode = 'SELECTION' | 'GLOBAL' | 'MANUAL' | 'AGENT';
const APP_UI_STATE_STORAGE_KEY = 'autosec_app_ui_state';
const SCANNER_SESSION_STORAGE_KEY = 'autosec_scanner_session_state';
const VIEW_PATHS: Record<View, string> = {
  [View.DASHBOARD]: '/overview',
  [View.SCANNER]: '/scans/new',
  [View.DATABASE]: '/pocs',
  [View.HISTORY]: '/sessions',
  [View.EDGE]: '/capabilities',
  [View.PROFILE]: '/settings/profile',
  [View.USER_MANAGEMENT]: '/settings/users',
};

const readViewFromPath = (): View | undefined => {
  if (typeof window === 'undefined') return undefined;
  const entry = Object.entries(VIEW_PATHS).find(([, path]) => window.location.pathname === path);
  return entry?.[0] as View | undefined;
};

const buildDefaultScannerSession = (): ScanSession => ({
  id: 'SESSION-INIT',
  targetName: '',
  connection: {
    ip: '',
    port: '5555',
    bluetoothMac: '',
    canInterface: '',
    url: 'https://',
    frequency: '',
    interface: '',
    usbAdbSerial: '',
    usbMountPoint: '',
  },
  isConnected: false,
  startTime: '',
  status: 'idle',
  mode: 'batch',
  logs: [],
  results: [],
  riskScore: 0,
  aiReport: null
});

const isValidView = (value: string | null): value is View => (
  Boolean(value) && Object.values(View).includes(value as View)
);

const isValidScannerMode = (value: string | null): value is ScannerMode => (
  value === 'SELECTION' || value === 'GLOBAL' || value === 'MANUAL' || value === 'AGENT'
);

const inferScannerModeFromSession = (session?: ScanSession | null): ScannerMode => {
  if (!session) return 'SELECTION';
  if (session.mode === 'agent') return 'AGENT';
  if (session.mode === 'manual') return 'MANUAL';
  if (session.mode === 'batch') return 'GLOBAL';
  return 'SELECTION';
};

const readStoredUiState = (): { currentView?: View; scannerMode?: ScannerMode } => {
  if (typeof window === 'undefined') return {};
  try {
    const raw = window.localStorage.getItem(APP_UI_STATE_STORAGE_KEY);
    if (!raw) return {};
    const parsed = JSON.parse(raw);
    const currentView = isValidView(parsed?.currentView) ? parsed.currentView : undefined;
    const scannerMode = isValidScannerMode(parsed?.scannerMode) ? parsed.scannerMode : undefined;
    return { currentView, scannerMode };
  } catch {
    return {};
  }
};

const readStoredScannerSession = (): ScanSession | null => {
  if (typeof window === 'undefined') return null;
  try {
    const raw = window.sessionStorage.getItem(SCANNER_SESSION_STORAGE_KEY);
    if (!raw) return null;
    const parsed = JSON.parse(raw);
    const fallback = buildDefaultScannerSession();
    const restoredStatus = parsed?.status === 'completed' || parsed?.status === 'failed' ? parsed.status : 'idle';
    return {
      ...fallback,
      ...parsed,
      connection: {
        ...fallback.connection,
        ...(parsed?.connection || {}),
      },
      isConnected: restoredStatus === 'idle' ? false : Boolean(parsed?.isConnected),
      status: restoredStatus,
      logs: Array.isArray(parsed?.logs) ? parsed.logs : fallback.logs,
      results: Array.isArray(parsed?.results) ? parsed.results : fallback.results,
    } as ScanSession;
  } catch {
    return null;
  }
};

const compactScannerSessionForStorage = (session: ScanSession): ScanSession => ({
  ...session,
  logs: Array.isArray(session.logs) ? session.logs.slice(-1000) : [],
  results: Array.isArray(session.results) ? session.results : [],
  aiReport: typeof session.aiReport === 'string' ? session.aiReport.slice(0, 20000) : session.aiReport,
});

const App: React.FC = () => {
  const storedUiState = readStoredUiState();
  const storedScannerSession = readStoredScannerSession();
  const initialScannerMode = storedUiState.scannerMode || inferScannerModeFromSession(storedScannerSession);
  const initialView = readViewFromPath() || storedUiState.currentView || (initialScannerMode !== 'SELECTION' ? View.SCANNER : View.DASHBOARD);
  const [currentView, setCurrentView] = useState<View>(initialView);

  // The browser session is held only in an HttpOnly cookie.
  const [token, setToken] = useState<string | null>(null);
  const [user, setUser] = useState<any>(null);
  const [authLoading, setAuthLoading] = useState(true);

  // Lifted state for history so it persists
  const [scanHistory, setScanHistory] = useState<ScanSession[]>([]);

  // Persistent Scanner State
  const [scannerMode, setScannerMode] = useState<ScannerMode>(initialScannerMode);
  const [engineUrl, setEngineUrl] = useState(getBackendUrl());
  const [engineStatus, setEngineStatus] = useState<'unknown' | 'online' | 'offline'>('unknown');
  const [globalBackendHealth, setGlobalBackendHealth] = useState<{
    url: string;
    ok: boolean;
    database?: string;
    ai_reports_enabled?: boolean;
    warnings?: string[];
    error?: string;
  }>({
    url: getBackendUrl(),
    ok: false,
  });
  const [scannerSession, setScannerSession] = useState<ScanSession>(storedScannerSession || buildDefaultScannerSession());

  const handleLogin = (userData: any) => {
    const safeUser = sanitizeUserForStorage(userData);
    setToken('cookie-session');
    setUser(safeUser);
  };

  const clearLocalSession = () => {
    localStorage.removeItem(APP_UI_STATE_STORAGE_KEY);
    sessionStorage.removeItem(SCANNER_SESSION_STORAGE_KEY);
    sessionStorage.removeItem('autosec_agent_scan_state');
    setToken(null);
    setUser(null);
    setCurrentView(View.DASHBOARD);
    setScannerMode('SELECTION');
    setScannerSession(buildDefaultScannerSession());
  };

  const handleLogout = async () => {
    try { await logoutCurrentSession(); } catch { /* local cleanup still wins */ }
    clearLocalSession();
  };

  // 全局 401 处理： token 过期或失效自动登出
  const handleUnauthorized = () => {
    clearLocalSession();
  };

  const addToHistory = (session: ScanSession) => {
    setScanHistory(prev => [...prev, session]);
  };

  const handleResumeAgentSession = (session: ScanSession) => {
    const phaseRecords = session.phase_records || [];
    const allPhases = ['recon', 'planner', 'decision', 'weaponize', 'execute', 'reflector', 'assess'];
    const phases = allPhases.map((phase) => {
      const record = phaseRecords.find(item => item.phase === phase);
      return {
        phase,
        status: (record?.status || 'idle') as 'idle' | 'running' | 'done' | 'error' | 'retrying' | 'skipped',
        output: record?.raw_output || record?.error || '',
      };
    });

    sessionStorage.setItem('autosec_agent_scan_state', JSON.stringify({
      restoreRunState: true,
      targetIp: session.connection.ip || '',
      targetName: session.targetName || 'IVI System',
      phases,
      finalReport: session.aiReport || '',
      topology: null,
      adaptiveCtx: null,
      scanTime: session.startTime ? new Date(session.startTime).toLocaleString('zh-CN', { hour12: false }) : '',
      activeStep: -1,
      canInterface: session.connection.canInterface || '',
      bluetoothMac: session.connection.bluetoothMac || '',
      wifiInterface: session.connection.interface || '',
      rfFrequency: session.connection.frequency || '',
      enableWeaponize: session.agentDraft?.enableWeaponize ?? true,
      riskScore: session.riskScore || 0,
      results: session.results || [],
      logs: session.logs || [],
      assessment: session.assessment || {},
      phaseRecords,
      structuredState: session.structured || {},
      findings: session.findings || [],
    }));
    setScannerMode('AGENT');
    setCurrentView(View.SCANNER);
  };

  useEffect(() => {
    let cancelled = false;

    const refreshHealth = async () => {
      const health = await getBackendHealth(engineUrl);
      if (cancelled) return;
      setGlobalBackendHealth({
        url: health.url,
        ok: health.ok,
        database: health.database,
        ai_reports_enabled: health.ai_reports_enabled,
        warnings: health.warnings,
        error: health.error,
      });
      setEngineStatus(health.ok ? 'online' : 'offline');
    };

    refreshHealth();
    const intervalId = window.setInterval(refreshHealth, 30_000);
    return () => {
      cancelled = true;
      window.clearInterval(intervalId);
    };
  }, [engineUrl]);

  useEffect(() => {
    setUnauthorizedHandler(handleUnauthorized);
  }, []);

  useEffect(() => {
    const handlePopState = () => setCurrentView(readViewFromPath() || View.DASHBOARD);
    window.addEventListener('popstate', handlePopState);
    return () => window.removeEventListener('popstate', handlePopState);
  }, []);

  useEffect(() => {
    const nextPath = VIEW_PATHS[currentView];
    if (window.location.pathname !== nextPath) window.history.pushState({}, '', nextPath);
  }, [currentView]);

  useEffect(() => {
    if (typeof window === 'undefined') return;
    try {
      window.localStorage.setItem(APP_UI_STATE_STORAGE_KEY, JSON.stringify({
        currentView,
        scannerMode,
      }));
    } catch {
      // ignore storage failures
    }
  }, [currentView, scannerMode]);

  useEffect(() => {
    if (typeof window === 'undefined') return;
    try {
      window.sessionStorage.setItem(
        SCANNER_SESSION_STORAGE_KEY,
        JSON.stringify(compactScannerSessionForStorage(scannerSession))
      );
    } catch {
      // ignore storage failures
    }
  }, [scannerSession]);

  useEffect(() => {
    let cancelled = false;

    const refreshProfile = async () => {
      try {
        const latestUser = await fetchCurrentProfile();
        if (cancelled || !latestUser) return;
        const safeUser = sanitizeUserForStorage(latestUser);
        setUser(safeUser);
        setToken('cookie-session');
      } catch (error: any) {
        if (cancelled) return;
        setToken(null);
        setUser(null);
      } finally {
        if (!cancelled) setAuthLoading(false);
      }
    };

    refreshProfile();
    return () => {
      cancelled = true;
    };
  }, []);

  if (authLoading) {
    return <ViewLoading />;
  }

  if (!token || !user) {
    return <AuthPage onLogin={handleLogin} />;
  }

  return (
    <div className="flex h-screen w-full bg-cyber-900 text-slate-200 overflow-hidden font-sans">
      {/* Sidebar */}
      <aside className="app-sidebar w-20 lg:w-64 flex-shrink-0 flex flex-col transition-all duration-300">
        <div className="h-[72px] flex items-center justify-center lg:justify-start lg:px-5 border-b border-white/[0.07]">
          <div className="brand-mark !h-10 !w-10 !rounded-xl"><Shield className="w-5 h-5" /></div>
          <div className="hidden lg:block ml-3">
            <span className="block font-semibold text-base tracking-[0.12em] text-white">智驭<span className="text-cyber-accent">安盾</span></span>
            <span className="mt-0.5 block font-mono text-[8px] tracking-[0.18em] text-slate-600">EDGE SECURITY</span>
          </div>
        </div>

        <nav className="flex-1 py-6 space-y-2 px-2">
          <button
            onClick={() => setCurrentView(View.DASHBOARD)}
            className={`nav-control ${currentView === View.DASHBOARD ? 'nav-control-active' : ''}`}
          >
            <LayoutDashboard size={20} />
            <span className="hidden lg:block ml-3 font-medium">态势概览</span>
          </button>

          <button
            onClick={() => setCurrentView(View.SCANNER)}
            className={`nav-control ${currentView === View.SCANNER ? 'nav-control-active' : ''}`}
          >
            <Radio size={20} />
            <span className="hidden lg:block ml-3 font-medium">创建扫描</span>
          </button>


          <button
            onClick={() => setCurrentView(View.DATABASE)}
            className={`nav-control ${currentView === View.DATABASE ? 'nav-control-active' : ''}`}
          >
            <Database size={20} />
            <span className="hidden lg:block ml-3 font-medium">PoC 目录</span>
          </button>

          <button
            onClick={() => setCurrentView(View.HISTORY)}
            className={`nav-control ${currentView === View.HISTORY ? 'nav-control-active' : ''}`}
          >
            <History size={20} />
            <span className="hidden lg:block ml-3 font-medium">历史记录</span>
          </button>

          <button
            onClick={() => setCurrentView(View.EDGE)}
            className={`nav-control ${currentView === View.EDGE ? 'nav-control-active' : ''}`}
          >
            <Cpu size={20} />
            <span className="hidden lg:block ml-3 font-medium">本机能力</span>
          </button>


          <button
            onClick={() => setCurrentView(View.PROFILE)}
            className={`nav-control mt-auto ${currentView === View.PROFILE ? 'nav-control-active' : ''}`}
          >
            <User size={20} />
            <span className="hidden lg:block ml-3 font-medium">个人设置</span>
          </button>

          {user.role === 'admin' && (
            <button
              onClick={() => setCurrentView(View.USER_MANAGEMENT)}
              className={`nav-control ${currentView === View.USER_MANAGEMENT ? 'nav-control-active' : ''}`}
            >
              <Shield size={20} />
              <span className="hidden lg:block ml-3 font-medium">系统管理</span>
            </button>
          )}

        </nav>

        <div className="p-3 lg:p-4 border-t border-white/[0.07] space-y-3">
          {/* Current User Info & Logout */}
          <div
            className="hidden lg:flex items-center justify-between text-xs border border-white/[0.06] bg-white/[0.025] p-3 rounded-xl cursor-pointer hover:border-cyan-300/15 transition-colors"
            onClick={() => setCurrentView(View.PROFILE)}
          >
            <div>
              <span className="block text-gray-500">OPERATOR</span>
              <span className="font-bold text-cyber-accent truncate w-24 block" title={user.username}>@{user.username}</span>
            </div>
            <div>
              <span className="block text-gray-500">ROLE</span>
              <span className={`font-mono ${user.role === 'admin' ? 'text-cyber-danger' : 'text-green-500'}`}>{user.role.toUpperCase()}</span>
            </div>
          </div>

          <button
            onClick={handleLogout}
            className="w-full flex items-center justify-center p-2.5 rounded-xl bg-rose-500/[0.05] text-rose-300/70 hover:bg-rose-500/10 hover:text-rose-200 transition-colors text-xs font-medium border border-rose-400/10"
          >
            退出登录
          </button>

          <div className="flex justify-center text-gray-500 text-xs mt-2">
            <Github size={14} className="mr-2" />
            <span className="hidden lg:block">v3.0 边缘工作站</span>
          </div>
        </div>
      </aside>

      {/* Main Content */}
      <main className="flex-1 flex flex-col overflow-hidden relative">
        {/* Header */}
        <header className="h-[72px] bg-[#0A1C30]/88 backdrop-blur-xl border-b border-cyan-100/10 flex items-center justify-between px-6 lg:px-8 z-10 shadow-[0_10px_35px_rgba(0,5,15,.16)]">
          <h1 className="text-base font-semibold text-white tracking-wide">
            {currentView === View.DASHBOARD && '安全态势概览'}
            {currentView === View.SCANNER && '创建与执行扫描'}
            {currentView === View.DATABASE && 'PoC 运行时目录'}
            {currentView === View.HISTORY && '扫描历史记录'}
            {currentView === View.EDGE && '本机能力与连接'}
            {currentView === View.PROFILE && '个人与 AI 设置'}
            {currentView === View.USER_MANAGEMENT && '用户与权限'}
          </h1>
          <div className="flex items-center gap-4">
            <div className="flex items-center gap-2">
              <span className={`w-2 h-2 rounded-full animate-pulse ${globalBackendHealth.ok ? 'bg-green-500' : 'bg-red-500'}`}></span>
              <span className={`text-xs font-mono ${globalBackendHealth.ok ? 'text-green-500' : 'text-red-400'}`}>
                {globalBackendHealth.ok ? '本机引擎在线' : '本机引擎离线'}
              </span>
            </div>
          </div>
        </header>

        <div className={`px-6 lg:px-8 py-2 border-b text-[10px] font-mono flex items-center gap-3 ${globalBackendHealth.ok ? 'bg-cyan-300/[0.035] border-white/[0.06] text-cyan-200/70' : 'bg-red-950/20 border-red-900/40 text-red-300'}`}>
          {globalBackendHealth.ok ? <Shield className="w-3.5 h-3.5" /> : <ServerCrash className="w-3.5 h-3.5" />}
          <span>执行面：本机</span>
          {globalBackendHealth.database && <span>DB: {globalBackendHealth.database}</span>}
          <span>AI: {globalBackendHealth.ai_reports_enabled ? 'user-configured' : 'unavailable'}</span>
          {!globalBackendHealth.ok && globalBackendHealth.error && (
            <span className="flex items-center gap-1"><AlertTriangle className="w-3.5 h-3.5" />{globalBackendHealth.error}</span>
          )}
          {globalBackendHealth.ok && globalBackendHealth.warnings && globalBackendHealth.warnings.length > 0 && (
            <span className="truncate">Warnings: {globalBackendHealth.warnings.join(' | ')}</span>
          )}
        </div>

        {/* View Container */}
        <div className="console-page flex-1 overflow-auto relative">
          <Suspense fallback={<ViewLoading />}>
          <div className="relative z-10 h-full">
            {currentView === View.DASHBOARD && <Dashboard token={token} />}
            {currentView === View.SCANNER && (
              <Scanner
                onAddToHistory={addToHistory}
                mode={scannerMode}
                setMode={setScannerMode}
                session={scannerSession}
                setSession={setScannerSession}
                engineUrl={engineUrl}
                setEngineUrl={setEngineUrl}
                engineStatus={engineStatus}
                setEngineStatus={setEngineStatus}
                token={token}
                currentUser={user}
              />
            )}
            {currentView === View.DATABASE && <PocDatabase token={token} />}
            {currentView === View.HISTORY && (
              <ScanHistory
                localHistory={scanHistory}
                currentUser={user}
                token={token}
                onUnauthorized={handleUnauthorized}
                onResumeSession={handleResumeAgentSession}
              />
            )}
            {currentView === View.EDGE && (
              <LocalRuntime
                token={token}
                currentUser={user}
                onUnauthorized={handleUnauthorized}
              />
            )}


            {currentView === View.PROFILE && (
              <Profile
                currentUser={user}
                token={token}
                onUpdateSuccess={(newUser) => {
                  const safeUser = sanitizeUserForStorage(newUser);
                  setUser(safeUser);
                }}
              />
            )}
            {currentView === View.USER_MANAGEMENT && user.role === 'admin' && (
              <UserManagement token={token} onUnauthorized={handleUnauthorized} />
            )}
          </div>
          </Suspense>
        </div>
      </main>
    </div>
  );
};

export default App;
