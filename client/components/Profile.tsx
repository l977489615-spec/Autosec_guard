import React, { useState } from 'react';
import { User, Key, Save, AlertTriangle, CheckCircle } from 'lucide-react';
import { getBackendUrl } from '../services/api';

interface ProfileProps {
	currentUser: any;
	token: string | null;
	onUpdateSuccess: (newUser: any) => void;
}

const Profile: React.FC<ProfileProps> = ({ currentUser, token, onUpdateSuccess }) => {
	const [newUsername, setNewUsername] = useState(currentUser.username);
	const [newPassword, setNewPassword] = useState('');
	const [confirmPassword, setConfirmPassword] = useState('');

	const [loading, setLoading] = useState(false);
	const [error, setError] = useState('');
	const [success, setSuccess] = useState('');

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
					new_password: newPassword ? newPassword : undefined
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

	return (
		<div className="p-6 h-full flex flex-col items-center justify-center relative overflow-hidden">
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

					<button
						type="submit"
						disabled={loading || (!newPassword && newUsername === currentUser.username)}
						className={`w-full flex items-center justify-center gap-2 py-3 rounded-lg font-bold tracking-wider transition-all
                  ${loading || (!newPassword && newUsername === currentUser.username)
								? 'bg-cyber-700 text-gray-500 cursor-not-allowed'
								: 'bg-cyber-accent text-cyber-900 hover:bg-cyan-300 shadow-[0_0_15px_rgba(34,211,238,0.4)]'}`}
					>
						<Save size={18} />
						{loading ? 'PROCESSING...' : 'SAVE CHANGES'}
					</button>
				</form>
			</div>
		</div>
	);
};

export default Profile;
