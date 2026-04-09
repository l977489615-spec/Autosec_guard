import React, { useEffect, useState } from 'react';
import { User, Key, Save, AlertTriangle, CheckCircle, Activity, Eye, EyeOff } from 'lucide-react';
import { defaultAiSettings, getBackendUrl } from '../services/api';

interface ProfileProps {
	currentUser: any;
	token: string | null;
	onUpdateSuccess: (newUser: any) => void;
}

const Profile: React.FC<ProfileProps> = ({ currentUser, token, onUpdateSuccess }) => {
	const [newUsername, setNewUsername] = useState(currentUser.username);
	const [newPassword, setNewPassword] = useState('');
	const [confirmPassword, setConfirmPassword] = useState('');
	const [aiSettings, setAiSettings] = useState(() => ({ ...defaultAiSettings(), ...(currentUser.ai_config || {}) }));

	const [loading, setLoading] = useState(false);
	const [testing, setTesting] = useState(false);
	const [showApiKey, setShowApiKey] = useState(false);
	const [error, setError] = useState('');
	const [success, setSuccess] = useState('');
	const aiSettingsChanged = JSON.stringify(aiSettings) !== JSON.stringify({ ...defaultAiSettings(), ...(currentUser.ai_config || {}) });

	useEffect(() => {
		setNewUsername(currentUser.username);
		setAiSettings({ ...defaultAiSettings(), ...(currentUser.ai_config || {}) });
	}, [currentUser]);

	const handleUpdate = async (e: React.FormEvent) => {
		e.preventDefault();
		setError('');
		setSuccess('');

		if (newPassword && newPassword !== confirmPassword) {
			setError("New passwords do not match.");
			return;
		}

		if (!token) return;

		setLoading(true);
		try {
			const res = await fetch(`${getBackendUrl()}/api/profile`, {
				method: 'PUT',
				headers: {
					'Content-Type': 'application/json',
					'Authorization': `Bearer ${token}`
				},
				body: JSON.stringify({
					new_username: newUsername !== currentUser.username ? newUsername : undefined,
					new_password: newPassword ? newPassword : undefined,
					ai_config: aiSettings,
				})
			});

			const data = await res.json();

			if (!res.ok) {
				throw new Error(data.message || 'Failed to update profile');
			}

			setSuccess(data.message);
			setNewPassword('');
			setConfirmPassword('');

			if (data.user) {
				onUpdateSuccess(data.user);
			}

		} catch (err: any) {
			setError(err.message);
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
			const res = await fetch(`${getBackendUrl()}/api/test-ai-config`, {
				method: 'POST',
				headers: {
					'Content-Type': 'application/json',
					'Authorization': `Bearer ${token}`
				},
				body: JSON.stringify({ ai_config: aiSettings })
			});

			const data = await res.json();
			if (!res.ok || !data.success) {
				throw new Error(data.message || 'AI Configuration test failed');
			}

			setSuccess(data.message);
		} catch (err: any) {
			setError(err.message);
		} finally {
			setTesting(false);
		}
	};

	return (
		<div className="p-6 min-h-full w-full flex flex-col items-center justify-start md:justify-center relative overflow-y-auto overflow-x-hidden pt-12 pb-20">
			{/* Background elements */}
			<div className="absolute top-0 left-0 w-full h-full pointer-events-none">
				<div className="absolute -top-[20%] -right-[10%] w-[50%] h-[50%] bg-cyber-accent/5 rounded-full blur-[120px]"></div>
				<div className="absolute -bottom-[20%] -left-[10%] w-[50%] h-[50%] bg-cyber-danger/5 rounded-full blur-[120px]"></div>
			</div>

			<div className="w-full max-w-md bg-cyber-800/80 backdrop-blur-md border border-cyber-700 p-8 rounded-xl shadow-2xl relative z-10">
				<div className="flex flex-col items-center mb-8">
					<div className="w-16 h-16 bg-cyber-900 border border-cyber-accent rounded-full flex items-center justify-center text-cyber-accent mb-4">
						<User size={32} />
					</div>
					<h2 className="text-2xl font-bold text-white tracking-widest">USER PROFILE</h2>
					<div className="text-sm font-mono text-gray-400 mt-2 flex items-center gap-2">
						ROLE: <span className={`px-2 py-0.5 rounded text-xs ${currentUser.role === 'admin' ? 'bg-red-900/30 text-cyber-danger border border-red-900' : 'bg-green-900/30 text-green-500 border border-green-900'}`}>{currentUser.role.toUpperCase()}</span>
					</div>
				</div>

				{error && (
					<div className="bg-red-900/20 border border-red-500/50 text-red-400 p-3 rounded mb-6 text-sm flex items-center gap-2">
						<AlertTriangle size={16} />
						{error}
					</div>
				)}
				{success && (
					<div className="bg-green-900/20 border border-green-500/50 text-green-400 p-3 rounded mb-6 text-sm flex items-center gap-2">
						<CheckCircle size={16} />
						{success}
					</div>
				)}

				<form onSubmit={handleUpdate} className="space-y-6">
					<div>
						<label className="block text-xs font-mono text-gray-500 mb-2">IDENTIFIER / USERNAME</label>
						<div className="relative">
							<div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
								<User size={16} className="text-gray-500" />
							</div>
							<input
								type="text"
								value={newUsername}
								onChange={(e) => setNewUsername(e.target.value)}
								className="w-full bg-cyber-900 border border-cyber-700 rounded-lg pl-10 pr-4 py-3 text-white focus:outline-none focus:border-cyber-accent transition-colors"
								required
							/>
						</div>
					</div>

					<div className="pt-4 border-t border-cyber-700">
						<label className="block text-xs font-mono text-gray-500 mb-2">UPDATE PASSKEY (Optionally)</label>
						<div className="space-y-4">
							<div className="relative">
								<div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
									<Key size={16} className="text-gray-500" />
								</div>
								<input
									type="password"
									value={newPassword}
									placeholder="New Passkey"
									onChange={(e) => setNewPassword(e.target.value)}
									className="w-full bg-cyber-900 border border-cyber-700 rounded-lg pl-10 pr-4 py-3 text-white focus:outline-none focus:border-cyber-accent transition-colors"
								/>
							</div>
							<div className="relative">
								<div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
									<Key size={16} className="text-gray-500" />
								</div>
								<input
									type="password"
									value={confirmPassword}
									placeholder="Confirm New Passkey"
									onChange={(e) => setConfirmPassword(e.target.value)}
									className="w-full bg-cyber-900 border border-cyber-700 rounded-lg pl-10 pr-4 py-3 text-white focus:outline-none focus:border-cyber-accent transition-colors"
								/>
							</div>
						</div>
					</div>

					<div className="pt-4 border-t border-cyber-700 space-y-4">
						<label className="block text-xs font-mono text-gray-500">AI RUNTIME CONFIG (USER-SUPPLIED)</label>
						<div className="text-xs text-gray-400">
							模型配置按当前用户维度加密保存在后端，并在本次请求中透传给 AI 调用链。请仅填写你本人可授权使用的 Key。
						</div>
						<div className="text-[11px] text-gray-500">
							推荐填写：Base URL 使用 `https://dashscope.aliyuncs.com/compatible-mode/v1`，Report model=`qwen-max`，Fast model=`qwen-plus`，Strong model=`qwen-max`。
						</div>
						<div className="space-y-3">
							<input
								type="text"
								value={aiSettings.baseUrl}
								placeholder={defaultAiSettings().baseUrl}
								onChange={(e) => setAiSettings((prev) => ({ ...prev, baseUrl: e.target.value }))}
								className="w-full bg-cyber-900 border border-cyber-700 rounded-lg px-4 py-3 text-white focus:outline-none focus:border-cyber-accent transition-colors"
							/>
							<div className="relative">
								<input
									type={showApiKey ? 'text' : 'password'}
									value={aiSettings.apiKey}
									placeholder="API Key"
									onChange={(e) => setAiSettings((prev) => ({ ...prev, apiKey: e.target.value }))}
									className="w-full bg-cyber-900 border border-cyber-700 rounded-lg pl-4 pr-12 py-3 text-white focus:outline-none focus:border-cyber-accent transition-colors font-mono"
								/>
								<button
									type="button"
									onClick={() => setShowApiKey(!showApiKey)}
									className="absolute inset-y-0 right-0 pr-3 flex items-center text-gray-500 hover:text-cyber-accent transition-colors"
								>
									{showApiKey ? <EyeOff size={18} /> : <Eye size={18} />}
								</button>
							</div>
							<div className="grid grid-cols-1 md:grid-cols-3 gap-3">
								<input
									type="text"
									value={aiSettings.reportModel}
									placeholder="Report model"
									onChange={(e) => setAiSettings((prev) => ({ ...prev, reportModel: e.target.value }))}
									className="w-full bg-cyber-900 border border-cyber-700 rounded-lg px-4 py-3 text-white focus:outline-none focus:border-cyber-accent transition-colors"
								/>
								<input
									type="text"
									value={aiSettings.fastModel}
									placeholder="Fast model"
									onChange={(e) => setAiSettings((prev) => ({ ...prev, fastModel: e.target.value }))}
									className="w-full bg-cyber-900 border border-cyber-700 rounded-lg px-4 py-3 text-white focus:outline-none focus:border-cyber-accent transition-colors"
								/>
								<input
									type="text"
									value={aiSettings.strongModel}
									placeholder="Strong model"
									onChange={(e) => setAiSettings((prev) => ({ ...prev, strongModel: e.target.value }))}
									className="w-full bg-cyber-900 border border-cyber-700 rounded-lg px-4 py-3 text-white focus:outline-none focus:border-cyber-accent transition-colors"
								/>
							</div>
						</div>
					</div>

					<div className="flex gap-4">
						<button
							type="button"
							onClick={handleTestConfig}
							disabled={loading || testing}
							className={`flex-1 flex items-center justify-center gap-2 py-3 rounded-lg font-bold tracking-wider transition-all
								${loading || testing
									? 'bg-cyber-700 text-gray-500 cursor-not-allowed'
									: 'bg-cyber-900 border border-cyber-accent text-cyber-accent hover:bg-cyber-accent/10 shadow-[0_0_10px_rgba(34,211,238,0.2)]'}`}
						>
							<Activity size={18} />
							{testing ? 'TESTING...' : 'TEST AI CONFIG'}
						</button>

						<button
							type="submit"
							disabled={loading || testing || (!newPassword && newUsername === currentUser.username && !aiSettingsChanged)}
							className={`flex-1 flex items-center justify-center gap-2 py-3 rounded-lg font-bold tracking-wider transition-all
								${loading || testing || (!newPassword && newUsername === currentUser.username && !aiSettingsChanged)
									? 'bg-cyber-700 text-gray-500 cursor-not-allowed'
									: 'bg-cyber-accent text-cyber-900 hover:bg-cyan-300 shadow-[0_0_15px_rgba(34,211,238,0.4)]'}`}
						>
							<Save size={18} />
							{loading ? 'PROCESSING...' : 'SAVE CHANGES'}
						</button>
					</div>
				</form>
			</div>
		</div>
	);
};

export default Profile;
