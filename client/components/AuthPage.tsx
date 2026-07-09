import React, { useEffect, useState } from 'react';
import { Shield, Lock, User, Terminal, ArrowRight, Zap, KeyRound, AlertTriangle } from 'lucide-react';
import { AuthStatus, getAuthStatus, getBackendUrl } from '../services/api';

interface AuthPageProps {
	onLogin: (token: string, user: any) => void;
}

type AuthView = 'loading' | 'initialize' | 'cli_pending' | 'login' | 'register';

const AuthPage: React.FC<AuthPageProps> = ({ onLogin }) => {
	const [authStatus, setAuthStatus] = useState<AuthStatus | null>(null);
	const [view, setView] = useState<AuthView>('loading');
	const [username, setUsername] = useState('');
	const [password, setPassword] = useState('');
	const [bootstrapToken, setBootstrapToken] = useState('');
	const [error, setError] = useState('');
	const [success, setSuccess] = useState('');
	const [loading, setLoading] = useState(false);

	const refreshAuthStatus = async () => {
		try {
			const status = await getAuthStatus();
			setAuthStatus(status);
			if (status.bootstrap_required && !status.web_bootstrap_allowed) {
				setView('cli_pending');
			} else if (status.bootstrap_required && status.web_bootstrap_allowed) {
				setView('initialize');
			} else {
				setView('login');
			}
		} catch (err: any) {
			setError(err.message || `无法连接后端 ${getBackendUrl()}`);
			setView('login');
		}
	};

	useEffect(() => {
		refreshAuthStatus();
	}, []);

	const handleSubmit = async (e: React.FormEvent) => {
		e.preventDefault();
		setError('');
		setSuccess('');
		setLoading(true);

		const isInit = view === 'initialize';
		const isRegister = view === 'register';
		const endpoint = isInit || isRegister ? '/api/register' : '/api/login';
		const backendUrl = getBackendUrl();
		const url = `${backendUrl}${endpoint}`;

		try {
			const body: Record<string, string> = { username, password };
			if (isInit && authStatus?.bootstrap_token_required) {
				body.bootstrap_token = bootstrapToken;
			}

			const response = await fetch(url, {
				method: 'POST',
				headers: { 'Content-Type': 'application/json' },
				body: JSON.stringify(body),
			});

			const data = await response.json();

			if (!response.ok) {
				throw new Error(data.message || 'Authentication failed');
			}

			if (isInit || isRegister) {
				setSuccess(isInit ? '系统初始化完成，请使用管理员账号登录。' : '注册成功，请登录。');
				setPassword('');
				setBootstrapToken('');
				await refreshAuthStatus();
				setView('login');
			} else {
				onLogin(data.token, data.user);
			}
		} catch (err: any) {
			setError(err.message || `Failed to reach backend at ${backendUrl}`);
		} finally {
			setLoading(false);
		}
	};

	const showRegisterTab = authStatus?.open_registration && !authStatus?.bootstrap_required;

	const titleForView = () => {
		switch (view) {
			case 'initialize': return '系统初始化';
			case 'cli_pending': return '等待管理员配置';
			case 'register': return '注册账号';
			default: return '登录';
		}
	};

	const submitLabel = () => {
		if (loading) return 'Processing';
		if (view === 'initialize') return '创建管理员并初始化';
		if (view === 'register') return 'Create Profile';
		return 'Initialize Uplink';
	};

	return (
		<div className="min-h-screen bg-cyber-900 flex items-center justify-center relative overflow-hidden font-sans">
			<div className="absolute inset-0 pointer-events-none grid-background opacity-20" />
			<div className="absolute -top-[20%] -left-[10%] w-[50%] h-[50%] bg-cyber-500/10 rounded-full blur-[120px]" />
			<div className="absolute -bottom-[20%] -right-[10%] w-[50%] h-[50%] bg-cyber-accent/10 rounded-full blur-[120px]" />

			<div className="w-full max-w-md relative z-10 p-8">
				<div className="text-center mb-10">
					<div className="flex justify-center mb-4 relative">
						<div className="absolute inset-0 bg-cyber-accent blur-xl opacity-20 animate-pulse rounded-full" />
						<Shield className="w-16 h-16 text-cyber-accent relative z-10" />
					</div>
					<h1 className="text-3xl font-bold text-white tracking-widest uppercase">
						智驭<span className="text-cyber-accent">安盾</span>
					</h1>
					<p className="text-cyber-400 text-sm mt-2 flex items-center justify-center gap-2 font-mono">
						<Terminal size={14} /> Edge-side ICV Vulnerability Workstation
					</p>
				</div>

				<div className="bg-cyber-800/80 backdrop-blur-xl border border-cyber-700 p-8 rounded-xl shadow-2xl relative overflow-hidden group hover:border-cyber-accent/50 transition-colors duration-500">
					<div className="absolute top-0 left-0 w-full h-1 bg-gradient-to-r from-transparent via-cyber-accent to-transparent opacity-50"></div>

					{view === 'loading' ? (
						<div className="flex flex-col items-center justify-center py-12 gap-4 text-gray-400">
							<div className="w-8 h-8 border-2 border-cyber-accent/30 border-t-cyber-accent rounded-full animate-spin" />
							<span className="text-sm font-mono">正在检查系统状态…</span>
						</div>
					) : view === 'cli_pending' ? (
						<div className="space-y-5">
							<div className="flex items-center gap-3 text-amber-400">
								<AlertTriangle size={22} />
								<h2 className="text-lg font-bold">需要 CLI 初始化管理员</h2>
							</div>
							<p className="text-sm text-gray-300 leading-relaxed">
								当前部署模式为 <code className="text-cyber-accent">cli_only</code>，禁止通过 Web 创建首管理员。
								请在服务器上执行：
							</p>
							<pre className="text-xs bg-black/60 border border-cyber-700 rounded-lg p-4 text-cyan-300 overflow-x-auto font-mono">
{`cd server
FLASK_APP=server.py flask create-admin --username admin`}
							</pre>
							<p className="text-xs text-gray-500">
								创建完成后刷新此页面即可登录。
							</p>
							<button
								type="button"
								onClick={() => { setError(''); refreshAuthStatus(); }}
								className="w-full border border-cyber-700 hover:border-cyber-accent text-gray-300 py-3 rounded font-mono text-sm"
							>
								刷新状态
							</button>
						</div>
					) : (
						<>
							<div className="flex justify-between items-center mb-6 border-b border-cyber-700 pb-4">
								{view === 'initialize' ? (
									<div className="flex items-center gap-2 text-cyber-accent">
										<Zap size={18} />
										<span className="text-lg font-bold uppercase tracking-wider">系统初始化</span>
									</div>
								) : (
									<>
										<button
											type="button"
											className={`text-lg font-bold uppercase tracking-wider transition-colors ${view === 'login' ? 'text-cyber-accent' : 'text-gray-500 hover:text-gray-300'}`}
											onClick={() => { setView('login'); setError(''); setSuccess(''); }}
										>
											登录
										</button>
										{showRegisterTab && (
											<button
												type="button"
												className={`text-lg font-bold uppercase tracking-wider transition-colors ${view === 'register' ? 'text-cyber-accent' : 'text-gray-500 hover:text-gray-300'}`}
												onClick={() => { setView('register'); setError(''); setSuccess(''); }}
											>
												注册
											</button>
										)}
									</>
								)}
							</div>

							{view === 'initialize' && (
								<div className="mb-6 rounded-lg border border-amber-600/40 bg-amber-900/20 px-4 py-3 text-xs text-amber-200/90 leading-relaxed">
									首次启动须创建<strong>管理员账号</strong>。初始化完成后，开放注册默认关闭，后续账号由管理员在后台创建。
								</div>
							)}

							<form onSubmit={handleSubmit} className="space-y-6">
								<div>
									<label className="block text-xs font-mono text-gray-400 uppercase mb-2">
										{view === 'initialize' ? '管理员用户名' : 'Identifier'}
									</label>
									<div className="relative">
										<div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
											<User size={18} className="text-cyber-500" />
										</div>
										<input
											type="text"
											required
											value={username}
											onChange={(e) => setUsername(e.target.value)}
											className="w-full bg-cyber-900 border border-cyber-700 text-white pl-10 pr-4 py-3 rounded focus:outline-none focus:border-cyber-accent focus:ring-1 focus:ring-cyber-accent transition-all font-mono"
											placeholder="username"
										/>
									</div>
								</div>

								<div>
									<label className="block text-xs font-mono text-gray-400 uppercase mb-2">Passkey</label>
									<div className="relative">
										<div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
											<Lock size={18} className="text-cyber-500" />
										</div>
										<input
											type="password"
											required
											minLength={8}
											value={password}
											onChange={(e) => setPassword(e.target.value)}
											className="w-full bg-cyber-900 border border-cyber-700 text-white pl-10 pr-4 py-3 rounded focus:outline-none focus:border-cyber-accent focus:ring-1 focus:ring-cyber-accent transition-all font-mono tracking-widest"
											placeholder="••••••••"
										/>
									</div>
								</div>

								{view === 'initialize' && authStatus?.bootstrap_token_required && (
									<div>
										<label className="block text-xs font-mono text-gray-400 uppercase mb-2">Bootstrap Token</label>
										<div className="relative">
											<div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
												<KeyRound size={18} className="text-cyber-500" />
											</div>
											<input
												type="password"
												required
												value={bootstrapToken}
												onChange={(e) => setBootstrapToken(e.target.value)}
												className="w-full bg-cyber-900 border border-cyber-700 text-white pl-10 pr-4 py-3 rounded focus:outline-none focus:border-cyber-accent font-mono"
												placeholder="AUTOSEC_BOOTSTRAP_TOKEN"
											/>
										</div>
									</div>
								)}

								{error && (
									<div className="p-3 rounded text-sm font-mono border bg-red-900/20 text-red-400 border-red-500/50">
										{error}
									</div>
								)}
								{success && (
									<div className="p-3 rounded text-sm font-mono border bg-green-900/20 text-green-400 border-green-500/50">
										{success}
									</div>
								)}

								<button
									type="submit"
									disabled={loading}
									className="w-full bg-cyber-700 hover:bg-cyber-accent text-white hover:text-black py-4 rounded font-bold uppercase tracking-widest flex justify-center items-center gap-2 transition-all group disabled:opacity-50 disabled:cursor-not-allowed"
								>
									{loading ? (
										<span className="flex items-center gap-2">
											Processing
											<div className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin"></div>
										</span>
									) : (
										<>
											{submitLabel()}
											<ArrowRight size={18} className="group-hover:translate-x-1 transition-transform" />
										</>
									)}
								</button>
							</form>
						</>
					)}
				</div>

				<div className="text-center mt-8 text-xs font-mono text-cyber-600">
					<p>UNAUTHORIZED ACCESS STRICTLY PROHIBITED</p>
					<p className="mt-1">{titleForView()} · SECURE CONNECTION REQUIRED</p>
				</div>
			</div>
		</div>
	);
};

export default AuthPage;
