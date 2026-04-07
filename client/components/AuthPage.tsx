import React, { useState } from 'react';
import { Shield, Lock, User, Terminal, ArrowRight, Zap } from 'lucide-react';
import { getBackendUrl } from '../services/api';

interface AuthPageProps {
	onLogin: (token: string, user: any) => void;
}

const AuthPage: React.FC<AuthPageProps> = ({ onLogin }) => {
	const [isLogin, setIsLogin] = useState(true);
	const [username, setUsername] = useState('');
	const [password, setPassword] = useState('');
	const [error, setError] = useState('');
	const [loading, setLoading] = useState(false);

	const handleSubmit = async (e: React.FormEvent) => {
		e.preventDefault();
		setError('');
		setLoading(true);

		const endpoint = isLogin ? '/api/login' : '/api/register';
		const backendUrl = getBackendUrl();
		const url = `${backendUrl}${endpoint}`;

		try {
			const response = await fetch(url, {
				method: 'POST',
				headers: {
					'Content-Type': 'application/json',
				},
				body: JSON.stringify({ username, password }),
			});

			const data = await response.json();

			if (!response.ok) {
				throw new Error(data.message || 'Authentication failed');
			}

			if (isLogin) {
				onLogin(data.token, data.user);
			} else {
				// Auto-switch to login mode on successful registration
				setIsLogin(true);
				setError('Registration successful. Please log in.'); // Using error state for success message temporarily
			}
		} catch (err: any) {
			setError(err.message || `Failed to reach backend at ${backendUrl}`);
		} finally {
			setLoading(false);
		}
	};

	return (
		<div className="min-h-screen bg-cyber-900 flex items-center justify-center relative overflow-hidden font-sans">
			{/* Ambient Cyber Background */}
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
						<Terminal size={14} /> ICV Vulnerability Platform
					</p>
				</div>

				<div className="bg-cyber-800/80 backdrop-blur-xl border border-cyber-700 p-8 rounded-xl shadow-2xl relative overflow-hidden group hover:border-cyber-accent/50 transition-colors duration-500">
					{/* Glitch Line Decoration */}
					<div className="absolute top-0 left-0 w-full h-1 bg-gradient-to-r from-transparent via-cyber-accent to-transparent opacity-50"></div>

					<div className="flex justify-between items-center mb-8 border-b border-cyber-700 pb-4">
						<button
							className={`text-lg font-bold uppercase tracking-wider transition-colors ${isLogin ? 'text-cyber-accent' : 'text-gray-500 hover:text-gray-300'}`}
							onClick={() => { setIsLogin(true); setError(''); }}
						>
							Authenticate
						</button>
						<button
							className={`text-lg font-bold uppercase tracking-wider transition-colors ${!isLogin ? 'text-cyber-accent' : 'text-gray-500 hover:text-gray-300'}`}
							onClick={() => { setIsLogin(false); setError(''); }}
						>
							Register
						</button>
					</div>

					<form onSubmit={handleSubmit} className="space-y-6">
						<div>
							<label className="block text-xs font-mono text-gray-400 uppercase mb-2">Identifier</label>
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
									value={password}
									onChange={(e) => setPassword(e.target.value)}
									className="w-full bg-cyber-900 border border-cyber-700 text-white pl-10 pr-4 py-3 rounded focus:outline-none focus:border-cyber-accent focus:ring-1 focus:ring-cyber-accent transition-all font-mono tracking-widest"
									placeholder="••••••••"
								/>
							</div>
						</div>

						{error && (
							<div className={`p-3 rounded text-sm font-mono border ${error.includes('successful') ? 'bg-green-900/20 text-green-400 border-green-500/50' : 'bg-red-900/20 text-red-400 border-red-500/50'}`}>
								{error}
							</div>
						)}

						<button
							type="submit"
							disabled={loading}
							className="w-full bg-cyber-700 hover:bg-cyber-accent text-white hover:text-black py-4 rounded font-bold uppercase tracking-widest flex justify-center items-center gap-2 transition-all group disabled:opacity-50 disabled:cursor-not-allowed"
						>
							{loading ? (
								<span className="flex items-center gap-2">Processing <div className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin"></div></span>
							) : (
								<>
									{isLogin ? 'Initialize Uplink' : 'Create Profile'}
									<ArrowRight size={18} className="group-hover:translate-x-1 transition-transform" />
								</>
							)}
						</button>
					</form>
				</div>

				<div className="text-center mt-8 text-xs font-mono text-cyber-600">
					<p>UNAUTHORIZED ACCESS STRICTLY PROHIBITED</p>
					<p className="mt-1">SECURE CONNECTION REQUIRED</p>
				</div>
			</div>
		</div>
	);
};

export default AuthPage;
