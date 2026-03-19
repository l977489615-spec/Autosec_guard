import React, { useState, useEffect } from 'react';
import { Users, Shield, Trash2, Edit2, Plus, AlertTriangle, Key } from 'lucide-react';
import { getBackendUrl } from '../services/api';

interface UserData {
	id: number;
	username: string;
	role: string;
	created_at: string;
}

interface UserManagementProps {
	token: string | null;
	onUnauthorized?: () => void;
}

const UserManagement: React.FC<UserManagementProps> = ({ token, onUnauthorized }) => {

	const [users, setUsers] = useState<UserData[]>([]);
	const [loading, setLoading] = useState(true);
	const [error, setError] = useState('');

	// Modal State
	const [isModalOpen, setIsModalOpen] = useState(false);
	const [isEditing, setIsEditing] = useState(false);
	const [currentUserId, setCurrentUserId] = useState<number | null>(null);

	// Delete Modal State
	const [isDeleteModalOpen, setIsDeleteModalOpen] = useState(false);
	const [userToDelete, setUserToDelete] = useState<{ id: number, username: string } | null>(null);

	// Form State
	const [username, setUsername] = useState('');
	const [password, setPassword] = useState('');
	const [role, setRole] = useState('user');
	const [formError, setFormError] = useState('');

	const fetchUsers = async () => {
		if (!token) return;
		try {
			const res = await fetch(`${getBackendUrl()}/api/admin/users`, {
				headers: { 'Authorization': `Bearer ${token}` }
			});
			if (res.status === 401 || res.status === 403) {
				onUnauthorized?.();
				return;
			}
			if (!res.ok) throw new Error('Failed to fetch users');
			const data = await res.json();
			setUsers(data.users);
		} catch (err: any) {
			setError(err.message);
		} finally {
			setLoading(false);
		}
	};

	useEffect(() => {
		fetchUsers();
	}, [token]);

	const handleOpenModal = (user?: UserData) => {
		setFormError('');
		if (user) {
			setIsEditing(true);
			setCurrentUserId(user.id);
			setUsername(user.username);
			setRole(user.role);
			setPassword(''); // Don't show existing hash
		} else {
			setIsEditing(false);
			setCurrentUserId(null);
			setUsername('');
			setPassword('');
			setRole('user');
		}
		setIsModalOpen(true);
	};

	const handleCloseModal = () => {
		setIsModalOpen(false);
	};

	const handleSubmit = async (e: React.FormEvent) => {
		e.preventDefault();
		if (!token) return;

		const url = isEditing
			? `${getBackendUrl()}/api/admin/users/${currentUserId}`
			: `${getBackendUrl()}/api/admin/users`;

		const method = isEditing ? 'PUT' : 'POST';

		// Only send password if it's new/changed
		const body: any = { username, role };
		if (password) body.password = password;

		try {
			const res = await fetch(url, {
				method,
				headers: {
					'Content-Type': 'application/json',
					'Authorization': `Bearer ${token}`
				},
				body: JSON.stringify(body)
			});
			const data = await res.json();
			if (!res.ok) throw new Error(data.message);

			await fetchUsers();
			handleCloseModal();
		} catch (err: any) {
			setFormError(err.message);
		}
	};

	const handleDeleteClick = (id: number, username: string) => {
		setUserToDelete({ id, username });
		setIsDeleteModalOpen(true);
	};

	const executeDelete = async () => {
		if (!userToDelete || !token) return;

		try {
			const res = await fetch(`${getBackendUrl()}/api/admin/users/${userToDelete.id}`, {
				method: 'DELETE',
				headers: { 'Authorization': `Bearer ${token}` }
			});
			const data = await res.json();
			if (!res.ok) throw new Error(data.message);

			await fetchUsers();
			setIsDeleteModalOpen(false);
			setUserToDelete(null);
		} catch (err: any) {
			alert(`Error deleting user: ${err.message}`);
		}
	};

	return (
		<div className="p-6 h-full flex flex-col relative z-10 overflow-hidden">
			<div className="flex justify-between items-center mb-6">
				<div>
					<h2 className="text-2xl font-bold text-white tracking-widest flex items-center gap-3">
						<Users className="text-cyber-accent" />
						SYSTEM OPERATORS
					</h2>
					<p className="text-gray-400 text-sm mt-1">Manage platform access, roles, and identity</p>
				</div>

				<button
					onClick={() => handleOpenModal()}
					className="bg-cyber-accent text-cyber-900 px-4 py-2 rounded font-bold hover:bg-cyan-300 transition-colors flex items-center gap-2"
				>
					<Plus size={18} /> Add Operator
				</button>
			</div>

			{error ? (
				<div className="bg-red-900/20 border border-red-500/50 text-red-500 p-4 rounded-lg flex items-center mb-6">
					<AlertTriangle className="mr-3 flex-shrink-0" />
					<p>{error}</p>
				</div>
			) : loading ? (
				<div className="flex-1 flex items-center justify-center">
					<div className="text-cyber-accent animate-pulse font-mono tracking-widest">LOADING DIRECTORY...</div>
				</div>
			) : (
				<div className="bg-cyber-900/50 rounded-lg border border-cyber-700 overflow-hidden flex-1 overflow-y-auto">
					<table className="w-full text-left text-sm">
						<thead className="bg-cyber-800 text-gray-400 sticky top-0 z-10 font-mono">
							<tr>
								<th className="p-4 border-b border-cyber-700">ID</th>
								<th className="p-4 border-b border-cyber-700">IDENTIFIER</th>
								<th className="p-4 border-b border-cyber-700">ROLE</th>
								<th className="p-4 border-b border-cyber-700">CREATED</th>
								<th className="p-4 border-b border-cyber-700 text-right">ACTIONS</th>
							</tr>
						</thead>
						<tbody>
							{users.map((u) => (
								<tr key={u.id} className="border-b border-cyber-800/50 hover:bg-cyber-800/30 transition-colors group">
									<td className="p-4 text-gray-500 font-mono">#{u.id.toString().padStart(4, '0')}</td>
									<td className="p-4 font-bold text-gray-300">@{u.username}</td>
									<td className="p-4">
										<span className={`px-2 py-1 rounded text-xs flex items-center gap-1 w-fit
                      ${u.role === 'admin' ? 'bg-red-900/30 text-cyber-danger border border-red-900' : 'bg-green-900/30 text-green-500 border border-green-900'}`}>
											{u.role === 'admin' && <Shield size={12} />}
											{u.role.toUpperCase()}
										</span>
									</td>
									<td className="p-4 text-gray-500">
										{new Date(u.created_at).toLocaleString()}
									</td>
									<td className="p-4 text-right opacity-50 group-hover:opacity-100 transition-opacity">
										<button
											onClick={() => handleOpenModal(u)}
											className="p-2 text-cyber-accent hover:bg-cyber-accent/20 rounded mr-2"
											title="Edit User"
										>
											<Edit2 size={16} />
										</button>
										<button
											onClick={() => handleDeleteClick(u.id, u.username)}
											className="p-2 text-red-500 hover:bg-red-500/20 rounded"
											title="Delete User"
										>
											<Trash2 size={16} />
										</button>
									</td>
								</tr>
							))}
						</tbody>
					</table>
				</div>
			)}

			{/* Add/Edit Modal */}
			{isModalOpen && (
				<div className="fixed inset-0 bg-black/80 flex items-center justify-center z-50 p-4">
					<div className="bg-cyber-900 border border-cyber-700 rounded-lg w-full max-w-md shadow-2xl relative overflow-hidden">
						<div className="absolute top-0 left-0 w-full h-1 bg-gradient-to-r from-transparent via-cyber-accent to-transparent"></div>

						<div className="p-6 border-b border-cyber-800 flex justify-between items-center">
							<h3 className="text-xl font-bold text-white tracking-widest">{isEditing ? 'EDIT OPERATOR' : 'ADD OPERATOR'}</h3>
							<button onClick={handleCloseModal} className="text-gray-500 hover:text-white">&times;</button>
						</div>

						<form onSubmit={handleSubmit} className="p-6 space-y-4">
							{formError && (
								<div className="p-3 bg-red-900/30 border border-red-500/50 text-red-400 text-sm rounded">
									{formError}
								</div>
							)}

							<div>
								<label className="block text-xs font-mono text-gray-500 mb-1">IDENTIFIER (Username)</label>
								<div className="relative">
									<div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
										<Users size={16} className="text-gray-500" />
									</div>
									<input
										type="text"
										value={username}
										onChange={e => setUsername(e.target.value)}
										required
										className="w-full bg-cyber-900 border border-cyber-700 text-white pl-10 pr-4 py-3 rounded focus:outline-none focus:border-cyber-accent focus:ring-1 focus:ring-cyber-accent transition-all font-mono"
									/>
								</div>
							</div>

							<div>
								<label className="block text-xs font-mono text-gray-500 mb-1">
									PASSKEY {isEditing && '(Leave blank to keep current)'}
								</label>
								<div className="relative">
									<div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
										<Key size={16} className="text-gray-500" />
									</div>
									<input
										type="password"
										value={password}
										placeholder={isEditing ? "••••••••" : ""}
										onChange={e => setPassword(e.target.value)}
										required={!isEditing}
										className="w-full bg-cyber-900 border border-cyber-700 text-white pl-10 pr-4 py-3 rounded focus:outline-none focus:border-cyber-accent focus:ring-1 focus:ring-cyber-accent transition-all font-mono tracking-widest"
									/>
								</div>
							</div>

							<div>
								<label className="block text-xs font-mono text-gray-500 mb-1">CLEARANCE LEVEL (Role)</label>
								<div className="flex gap-4">
									<label className="flex items-center gap-2 cursor-pointer">
										<input
											type="radio"
											name="role"
											value="user"
											checked={role === 'user'}
											onChange={() => setRole('user')}
											className="text-cyber-accent bg-cyber-900 border-cyber-700"
										/>
										<span className="text-gray-300">Standard User</span>
									</label>
									<label className="flex items-center gap-2 cursor-pointer">
										<input
											type="radio"
											name="role"
											value="admin"
											checked={role === 'admin'}
											onChange={() => setRole('admin')}
											className="text-cyber-danger bg-cyber-900 border-cyber-700"
										/>
										<span className="text-red-400">Administrator</span>
									</label>
								</div>
							</div>

							<div className="pt-4 flex justify-end gap-3 border-t border-cyber-800 mt-6">
								<button
									type="button"
									onClick={handleCloseModal}
									className="px-4 py-2 rounded text-gray-400 hover:text-white transition-colors"
								>
									CANCEL
								</button>
								<button
									type="submit"
									className="px-4 py-2 bg-cyber-accent text-cyber-900 rounded font-bold hover:bg-cyan-300 shadow-[0_0_10px_rgba(34,211,238,0.3)]"
								>
									{isEditing ? 'COMMIT CHANGES' : 'AUTHORIZE'}
								</button>
							</div>
						</form>
					</div>
				</div>
			)}

			{/* Delete Confirmation Modal */}
			{isDeleteModalOpen && userToDelete && (
				<div className="fixed inset-0 bg-black/80 flex items-center justify-center z-50 p-4">
					<div className="bg-cyber-900 border border-red-900 rounded-lg w-full max-w-md shadow-2xl relative overflow-hidden">
						<div className="absolute top-0 left-0 w-full h-1 bg-gradient-to-r from-transparent via-red-500 to-transparent"></div>

						<div className="p-6 border-b border-cyber-800 flex items-center gap-3">
							<AlertTriangle className="text-red-500" size={24} />
							<h3 className="text-xl font-bold text-white tracking-widest">CONFIRM REMOVAL</h3>
						</div>

						<div className="p-6">
							<p className="text-gray-300 font-mono text-sm leading-relaxed">
								WARNING: Deleting operator <span className="text-white font-bold">@{userToDelete.username}</span> will also permanently erase all of their scan history.
							</p>
							<p className="text-red-400 font-mono text-sm mt-4 font-bold">
								This action cannot be undone. Proceed?
							</p>

							<div className="pt-6 flex justify-end gap-3 mt-2">
								<button
									onClick={() => setIsDeleteModalOpen(false)}
									className="px-4 py-2 rounded text-gray-400 hover:text-white transition-colors uppercase font-bold text-sm"
								>
									Cancel
								</button>
								<button
									onClick={executeDelete}
									className="px-4 py-2 bg-red-900/50 text-red-500 border border-red-900 rounded font-bold hover:bg-red-500 hover:text-white transition-colors uppercase text-sm tracking-wider shadow-[0_0_15px_rgba(239,68,68,0.2)]"
								>
									Execute Removal
								</button>
							</div>
						</div>
					</div>
				</div>
			)}
		</div>
	);
};

export default UserManagement;
