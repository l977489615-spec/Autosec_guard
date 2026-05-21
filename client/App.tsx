import React, { useEffect, useState } from 'react';
import { LayoutDashboard, Radio, Database, Shield, Github, History, User, AlertTriangle, ServerCrash, Cpu } from 'lucide-react';
import Dashboard from './components/Dashboard';
import Scanner from './components/Scanner';
import PocDatabase from './components/PocDatabase';
import ScanHistory from './components/ScanHistory';
import AuthPage from './components/AuthPage';
import Profile from './components/Profile';
import UserManagement from './components/UserManagement';
import AgentScan from './components/AgentScan';
import LocalRuntime from './components/LocalRuntime';
import { ScanSession } from './types';
import { fetchCurrentProfile, getBackendHealth, getBackendUrl } from './services/api';

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

const App: React.FC = () => {
  const [currentView, setCurrentView] = useState<View>(View.DASHBOARD);

  // 检查 JWT token 是否过期
  const isTokenValid = (t: string | null): boolean => {
    if (!t) return false;
    try {
      const payload = JSON.parse(atob(t.split('.')[1]));
      return payload.exp * 1000 > Date.now();
    } catch {
      return false;
    }
  };

  const storedToken = localStorage.getItem('autosec_token');
  const storedUser = localStorage.getItem('autosec_user');

  // Auth State
  const [token, setToken] = useState<string | null>(
    isTokenValid(storedToken) ? storedToken : null
  );
  const [user, setUser] = useState<any>(
    isTokenValid(storedToken) && storedUser ? JSON.parse(storedUser) : null
  );

  // token 无效时清除 localStorage
  if (!isTokenValid(storedToken) && storedToken) {
    localStorage.removeItem('autosec_token');
    localStorage.removeItem('autosec_user');
  }

  // Lifted state for history so it persists
  const [scanHistory, setScanHistory] = useState<ScanSession[]>([]);

  // Persistent Scanner State
  const [scannerMode, setScannerMode] = useState<ScannerMode>('SELECTION');
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
  const [scannerSession, setScannerSession] = useState<ScanSession>({
    id: 'SESSION-INIT',
    targetName: '',
    connection: {
      ip: '',
      port: '5555',
      bluetoothMac: '',
      canInterface: 'PCAN_USBBUS1',
      url: 'https://',
      frequency: '',
      interface: ''
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

  const handleLogin = (newToken: string, userData: any) => {
    localStorage.setItem('autosec_token', newToken);
    localStorage.setItem('autosec_user', JSON.stringify(userData));
    setToken(newToken);
    setUser(userData);
  };

  const handleLogout = () => {
    localStorage.removeItem('autosec_token');
    localStorage.removeItem('autosec_user');
    setToken(null);
    setUser(null);
    setCurrentView(View.DASHBOARD);
  };

  // 全局 401 处理： token 过期或失效自动登出
  const handleUnauthorized = () => {
    handleLogout();
  };

  const addToHistory = (session: ScanSession) => {
    setScanHistory(prev => [...prev, session]);
  };

  const handleResumeAgentSession = (session: ScanSession) => {
    const phaseRecords = session.phase_records || [];
    const phases = ['recon', 'decision', 'weaponize', 'execute', 'assess'].map((phase) => {
      const record = phaseRecords.find(item => item.phase === phase);
      return {
        phase,
        status: (record?.status || 'idle') as 'idle' | 'running' | 'done' | 'error' | 'retrying' | 'skipped',
        output: record?.raw_output || record?.error || '',
      };
    });

    localStorage.setItem('autosec_agent_scan_state', JSON.stringify({
      targetIp: session.connection.ip || '',
      targetName: session.targetName || 'IVI System',
      phases,
      finalReport: session.aiReport || '',
      topology: null,
      adaptiveCtx: null,
      scanTime: session.startTime ? new Date(session.startTime).toLocaleString('zh-CN', { hour12: false }) : '',
      activeStep: -1,
      canInterface: session.connection.canInterface || 'PCAN_USBBUS1',
      bluetoothMac: session.connection.bluetoothMac || '',
      wifiInterface: session.connection.interface || '',
      rfFrequency: session.connection.frequency || '',
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
    return () => {
      cancelled = true;
    };
  }, [engineUrl]);

  useEffect(() => {
    let cancelled = false;

    const refreshProfile = async () => {
      if (!token) return;
      try {
        const latestUser = await fetchCurrentProfile(token);
        if (cancelled || !latestUser) return;
        setUser(latestUser);
        localStorage.setItem('autosec_user', JSON.stringify(latestUser));
      } catch (error: any) {
        if (cancelled) return;
        if (/401|403|Could not verify|Invalid token/i.test(String(error?.message || ''))) {
          handleUnauthorized();
        }
      }
    };

    refreshProfile();
    return () => {
      cancelled = true;
    };
  }, [token]);

  if (!token || !user) {
    return <AuthPage onLogin={handleLogin} />;
  }

  return (
    <div className="flex h-screen w-full bg-cyber-900 text-gray-200 overflow-hidden font-sans">
      {/* Sidebar */}
      <aside className="w-20 lg:w-64 flex-shrink-0 bg-cyber-800 border-r border-cyber-700 flex flex-col transition-all duration-300">
        <div className="h-16 flex items-center justify-center lg:justify-start lg:px-6 border-b border-cyber-700">
          <Shield className="w-8 h-8 text-cyber-accent" />
          <span className="hidden lg:block ml-3 font-bold text-lg tracking-wider text-white">智驭<span className="text-cyber-accent">安盾</span></span>
        </div>

        <nav className="flex-1 py-6 space-y-2 px-2">
          <button
            onClick={() => setCurrentView(View.DASHBOARD)}
            className={`w-full flex items-center p-3 rounded-lg transition-colors ${currentView === View.DASHBOARD ? 'bg-cyber-700 text-cyber-accent border-l-4 border-cyber-accent' : 'text-gray-400 hover:bg-cyber-700 hover:text-white'}`}
          >
            <LayoutDashboard size={20} />
            <span className="hidden lg:block ml-3 font-medium">Dashboard</span>
          </button>

          <button
            onClick={() => setCurrentView(View.SCANNER)}
            className={`w-full flex items-center p-3 rounded-lg transition-colors ${currentView === View.SCANNER ? 'bg-cyber-700 text-cyber-accent border-l-4 border-cyber-accent' : 'text-gray-400 hover:bg-cyber-700 hover:text-white'}`}
          >
            <Radio size={20} />
            <span className="hidden lg:block ml-3 font-medium">Scan Engine</span>
          </button>


          <button
            onClick={() => setCurrentView(View.DATABASE)}
            className={`w-full flex items-center p-3 rounded-lg transition-colors ${currentView === View.DATABASE ? 'bg-cyber-700 text-cyber-accent border-l-4 border-cyber-accent' : 'text-gray-400 hover:bg-cyber-700 hover:text-white'}`}
          >
            <Database size={20} />
            <span className="hidden lg:block ml-3 font-medium">POC Database</span>
          </button>

          <button
            onClick={() => setCurrentView(View.HISTORY)}
            className={`w-full flex items-center p-3 rounded-lg transition-colors ${currentView === View.HISTORY ? 'bg-cyber-700 text-cyber-accent border-l-4 border-cyber-accent' : 'text-gray-400 hover:bg-cyber-700 hover:text-white'}`}
          >
            <History size={20} />
            <span className="hidden lg:block ml-3 font-medium">Scan History</span>
          </button>

          <button
            onClick={() => setCurrentView(View.EDGE)}
            className={`w-full flex items-center p-3 rounded-lg transition-colors ${currentView === View.EDGE ? 'bg-cyber-700 text-cyber-accent border-l-4 border-cyber-accent' : 'text-gray-400 hover:bg-cyber-700 hover:text-white'}`}
          >
            <Cpu size={20} />
            <span className="hidden lg:block ml-3 font-medium">Local Runtime</span>
          </button>


          <button
            onClick={() => setCurrentView(View.PROFILE)}
            className={`w-full flex items-center p-3 rounded-lg transition-colors mt-auto ${currentView === View.PROFILE ? 'bg-cyber-700 text-cyber-accent border-l-4 border-cyber-accent' : 'text-gray-400 hover:bg-cyber-700 hover:text-white'}`}
          >
            <User size={20} />
            <span className="hidden lg:block ml-3 font-medium">Profile Settings</span>
          </button>

          {user.role === 'admin' && (
            <button
              onClick={() => setCurrentView(View.USER_MANAGEMENT)}
              className={`w-full flex items-center p-3 rounded-lg transition-colors ${currentView === View.USER_MANAGEMENT ? 'bg-cyber-700 text-red-500 border-l-4 border-red-500' : 'text-gray-400 hover:bg-cyber-700 hover:text-white'}`}
            >
              <Shield size={20} />
              <span className="hidden lg:block ml-3 font-medium">System Admin</span>
            </button>
          )}

        </nav>

        <div className="p-4 border-t border-cyber-700 space-y-4">
          {/* Current User Info & Logout */}
          <div
            className="hidden lg:flex items-center justify-between text-xs bg-black/40 p-2 rounded cursor-pointer hover:bg-black/60 transition-colors"
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
            className="w-full flex items-center justify-center p-2 rounded bg-red-900/20 text-red-500 hover:bg-red-900/40 hover:text-red-400 transition-colors text-xs font-bold font-mono tracking-wider border border-red-900/50"
          >
            TERMINATE SESSION
          </button>

          <div className="flex justify-center text-gray-500 text-xs mt-2">
            <Github size={14} className="mr-2" />
            <span className="hidden lg:block">v2.5.0 (Prototype)</span>
          </div>
        </div>
      </aside>

      {/* Main Content */}
      <main className="flex-1 flex flex-col overflow-hidden relative">
        {/* Header */}
        <header className="h-16 bg-cyber-800/50 backdrop-blur-md border-b border-cyber-700 flex items-center justify-between px-6 z-10">
          <h1 className="text-lg font-semibold text-white uppercase tracking-wide">
            {currentView === View.DASHBOARD && 'Operational Overview'}
            {currentView === View.SCANNER && 'Vulnerability Scanner'}
            {currentView === View.DATABASE && 'Threat Intelligence Database'}
            {currentView === View.HISTORY && 'Scan Records & Audit'}
            {currentView === View.EDGE && 'Local Vehicle Runtime'}
            {currentView === View.PROFILE && 'User Profile & Settings'}
            {currentView === View.USER_MANAGEMENT && 'System Operators'}
          </h1>
          <div className="flex items-center gap-4">
            <div className="flex items-center gap-2">
              <span className={`w-2 h-2 rounded-full animate-pulse ${globalBackendHealth.ok ? 'bg-green-500' : 'bg-red-500'}`}></span>
              <span className={`text-xs font-mono ${globalBackendHealth.ok ? 'text-green-500' : 'text-red-400'}`}>
                {globalBackendHealth.ok ? 'SYSTEM ONLINE' : 'BACKEND OFFLINE'}
              </span>
            </div>
          </div>
        </header>

        <div className={`px-6 py-2 border-b text-xs font-mono flex items-center gap-3 ${globalBackendHealth.ok ? 'bg-cyan-950/20 border-cyan-900/40 text-cyan-300' : 'bg-red-950/20 border-red-900/40 text-red-300'}`}>
          {globalBackendHealth.ok ? <Shield className="w-3.5 h-3.5" /> : <ServerCrash className="w-3.5 h-3.5" />}
          <span>Local Engine: {globalBackendHealth.url}</span>
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
        <div className="flex-1 overflow-auto bg-gradient-to-br from-cyber-900 to-black relative">
          {/* Ambient Background Glow */}
          <div className="absolute top-0 left-0 w-full h-full overflow-hidden pointer-events-none z-0">
            <div className="absolute top-[-10%] left-[-10%] w-[40%] h-[40%] bg-cyber-500/5 rounded-full blur-[120px]"></div>
            <div className="absolute bottom-[-10%] right-[-10%] w-[30%] h-[30%] bg-cyber-danger/5 rounded-full blur-[100px]"></div>
          </div>

          <div className="relative z-10 h-full">
            {currentView === View.DASHBOARD && <Dashboard />}
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
            {currentView === View.DATABASE && <PocDatabase />}
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
                  setUser(newUser);
                  localStorage.setItem('autosec_user', JSON.stringify(newUser));
                }}
              />
            )}
            {currentView === View.USER_MANAGEMENT && user.role === 'admin' && (
              <UserManagement token={token} onUnauthorized={handleUnauthorized} />
            )}
          </div>
        </div>
      </main>
    </div>
  );
};

export default App;
