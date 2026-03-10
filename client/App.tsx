import React, { useState } from 'react';
import { LayoutDashboard, Radio, Database, Shield, Github, History, User } from 'lucide-react';
import Dashboard from './components/Dashboard';
import Scanner from './components/Scanner';
import PocDatabase from './components/PocDatabase';
import ScanHistory from './components/ScanHistory';
import AuthPage from './components/AuthPage';
import Profile from './components/Profile';
import UserManagement from './components/UserManagement';
import { ScanSession } from './types';

enum View {
  DASHBOARD = 'dashboard',
  SCANNER = 'scanner',
  DATABASE = 'database',
  HISTORY = 'history',
  PROFILE = 'profile',
  USER_MANAGEMENT = 'user_management'
}

const App: React.FC = () => {
  const [currentView, setCurrentView] = useState<View>(View.DASHBOARD);

  // Auth State
  const [token, setToken] = useState<string | null>(localStorage.getItem('autosec_token'));
  const [user, setUser] = useState<any>(localStorage.getItem('autosec_user') ? JSON.parse(localStorage.getItem('autosec_user') as string) : null);

  // Lifted state for history so it persists
  const [scanHistory, setScanHistory] = useState<ScanSession[]>([]);

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

  const addToHistory = (session: ScanSession) => {
    setScanHistory(prev => [...prev, session]);
  };

  if (!token || !user) {
    return <AuthPage onLogin={handleLogin} />;
  }

  return (
    <div className="flex h-screen w-full bg-cyber-900 text-gray-200 overflow-hidden font-sans">
      {/* Sidebar */}
      <aside className="w-20 lg:w-64 flex-shrink-0 bg-cyber-800 border-r border-cyber-700 flex flex-col transition-all duration-300">
        <div className="h-16 flex items-center justify-center lg:justify-start lg:px-6 border-b border-cyber-700">
          <Shield className="w-8 h-8 text-cyber-accent" />
          <span className="hidden lg:block ml-3 font-bold text-lg tracking-wider text-white">AutoSec<span className="text-cyber-accent">Guard</span></span>
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

          {user.role === 'admin' && (
            <button
              onClick={() => setCurrentView(View.USER_MANAGEMENT)}
              className={`w-full flex items-center p-3 rounded-lg transition-colors ${currentView === View.USER_MANAGEMENT ? 'bg-cyber-700 text-red-500 border-l-4 border-red-500' : 'text-gray-400 hover:bg-cyber-700 hover:text-white'}`}
            >
              <Shield size={20} />
              <span className="hidden lg:block ml-3 font-medium">System Admin</span>
            </button>
          )}

          <button
            onClick={() => setCurrentView(View.PROFILE)}
            className={`w-full flex items-center p-3 rounded-lg transition-colors mt-auto ${currentView === View.PROFILE ? 'bg-cyber-700 text-cyber-accent border-l-4 border-cyber-accent' : 'text-gray-400 hover:bg-cyber-700 hover:text-white'}`}
          >
            <User size={20} />
            <span className="hidden lg:block ml-3 font-medium">Profile Settings</span>
          </button>
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
            {currentView === View.PROFILE && 'User Profile & Settings'}
            {currentView === View.USER_MANAGEMENT && 'System Operators'}
          </h1>
          <div className="flex items-center gap-4">
            <div className="flex items-center gap-2">
              <span className="w-2 h-2 bg-green-500 rounded-full animate-pulse"></span>
              <span className="text-xs text-green-500 font-mono">SYSTEM ONLINE</span>
            </div>
          </div>
        </header>

        {/* View Container */}
        <div className="flex-1 overflow-auto bg-gradient-to-br from-cyber-900 to-black relative">
          {/* Ambient Background Glow */}
          <div className="absolute top-0 left-0 w-full h-full overflow-hidden pointer-events-none z-0">
            <div className="absolute top-[-10%] left-[-10%] w-[40%] h-[40%] bg-cyber-500/5 rounded-full blur-[120px]"></div>
            <div className="absolute bottom-[-10%] right-[-10%] w-[30%] h-[30%] bg-cyber-danger/5 rounded-full blur-[100px]"></div>
          </div>

          <div className="relative z-10 h-full">
            {currentView === View.DASHBOARD && <Dashboard />}
            {currentView === View.SCANNER && <Scanner onAddToHistory={addToHistory} />}
            {currentView === View.DATABASE && <PocDatabase />}
            {currentView === View.HISTORY && <ScanHistory history={scanHistory} currentUser={user} token={token} />}
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
              <UserManagement token={token} />
            )}
          </div>
        </div>
      </main>
    </div>
  );
};

export default App;