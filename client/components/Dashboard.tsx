import React from 'react';
import { ResponsiveContainer, BarChart, Bar, XAxis, YAxis, Tooltip, CartesianGrid, PieChart, Pie, Cell } from 'recharts';
import { POC_DATABASE } from '../constants';
import { Severity, Category } from '../types';
import { Activity, Shield, AlertTriangle, Zap } from 'lucide-react';

const Dashboard: React.FC = () => {
  const totalPocs = POC_DATABASE.length;

  const severityData = [
    { name: 'Critical', value: POC_DATABASE.filter(p => p.severity === Severity.CRITICAL).length, color: '#ff3366' },
    { name: 'High', value: POC_DATABASE.filter(p => p.severity === Severity.HIGH).length, color: '#fb923c' },
    { name: 'Medium', value: POC_DATABASE.filter(p => p.severity === Severity.MEDIUM).length, color: '#facc15' },
    { name: 'Low', value: POC_DATABASE.filter(p => p.severity === Severity.LOW).length, color: '#60a5fa' },
  ];

  const categoryData = Object.values(Category).map(cat => ({
    name: cat.split(' ')[0],
    count: POC_DATABASE.filter(p => p.category === cat).length
  }));

  // Count PoCs with pocFile (integrated from Pocs/ directory)
  const integratedPocs = POC_DATABASE.filter(p => p.pocFile).length;
  const criticalCount = severityData[0].value;
  const wirelessCount = POC_DATABASE.filter(p => p.category === Category.WIRELESS).length;

  return (
    <div className="p-6 space-y-6 overflow-y-auto h-full">
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        <div className="bg-cyber-800 border border-cyber-700 p-4 rounded-lg flex items-center gap-4">
          <div className="p-3 bg-blue-500/20 rounded-full text-blue-400"><Shield size={24} /></div>
          <div>
            <p className="text-gray-400 text-sm uppercase">Total Modules</p>
            <p className="text-2xl font-bold text-white">{totalPocs}</p>
          </div>
        </div>
        <div className="bg-cyber-800 border border-cyber-700 p-4 rounded-lg flex items-center gap-4">
          <div className="p-3 bg-red-500/20 rounded-full text-red-400"><AlertTriangle size={24} /></div>
          <div>
            <p className="text-gray-400 text-sm uppercase">Critical CVEs</p>
            <p className="text-2xl font-bold text-white">{criticalCount}</p>
          </div>
        </div>
        <div className="bg-cyber-800 border border-cyber-700 p-4 rounded-lg flex items-center gap-4">
          <div className="p-3 bg-green-500/20 rounded-full text-green-400"><Activity size={24} /></div>
          <div>
            <p className="text-gray-400 text-sm uppercase">System Status</p>
            <p className="text-2xl font-bold text-white">READY</p>
          </div>
        </div>
        <div className="bg-cyber-800 border border-cyber-700 p-4 rounded-lg flex items-center gap-4">
          <div className="p-3 bg-yellow-500/20 rounded-full text-yellow-400"><Zap size={24} /></div>
          <div>
            <p className="text-gray-400 text-sm uppercase">Active Scanners</p>
            <p className="text-2xl font-bold text-white">{integratedPocs}</p>
          </div>
        </div>
      </div>

      {/* Summary Bar */}
      <div className="bg-cyber-800 border border-cyber-700 p-4 rounded-lg">
        <div className="flex flex-wrap gap-6 text-sm">
          <div className="flex items-center gap-2">
            <span className="w-2 h-2 bg-indigo-500 rounded-full"></span>
            <span className="text-gray-400">Recon: <span className="text-white font-bold">{POC_DATABASE.filter(p => p.category === Category.RECON).length}</span></span>
          </div>
          <div className="flex items-center gap-2">
            <span className="w-2 h-2 bg-blue-500 rounded-full"></span>
            <span className="text-gray-400">Network: <span className="text-white font-bold">{POC_DATABASE.filter(p => p.category === Category.NETWORK).length}</span></span>
          </div>
          <div className="flex items-center gap-2">
            <span className="w-2 h-2 bg-green-500 rounded-full"></span>
            <span className="text-gray-400">CANBus: <span className="text-white font-bold">{POC_DATABASE.filter(p => p.category === Category.CANBUS).length}</span></span>
          </div>
          <div className="flex items-center gap-2">
            <span className="w-2 h-2 bg-cyan-500 rounded-full"></span>
            <span className="text-gray-400">Wireless: <span className="text-white font-bold">{POC_DATABASE.filter(p => p.category === Category.WIRELESS).length}</span></span>
          </div>
          <div className="flex items-center gap-2">
            <span className="w-2 h-2 bg-purple-500 rounded-full"></span>
            <span className="text-gray-400">App: <span className="text-white font-bold">{POC_DATABASE.filter(p => p.category === Category.APPLICATION).length}</span></span>
          </div>
          <div className="flex items-center gap-2">
            <span className="w-2 h-2 bg-red-500 rounded-full"></span>
            <span className="text-gray-400">Advanced: <span className="text-white font-bold">{POC_DATABASE.filter(p => p.category === Category.ADVANCED).length}</span></span>
          </div>
          <div className="flex items-center gap-2 ml-auto">
            <span className="w-2 h-2 bg-cyber-accent rounded-full animate-pulse"></span>
            <span className="text-gray-400">Integrated: <span className="text-white font-bold">{integratedPocs}/{totalPocs}</span></span>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 h-96">
        <div className="bg-cyber-800 border border-cyber-700 p-6 rounded-lg flex flex-col">
          <h3 className="text-lg font-bold text-white mb-4">Vulnerability Coverage by Severity</h3>
          <div className="flex-1 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={severityData}
                  cx="50%"
                  cy="50%"
                  innerRadius={60}
                  outerRadius={100}
                  paddingAngle={5}
                  dataKey="value"
                >
                  {severityData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={entry.color} stroke="none" />
                  ))}
                </Pie>
                <Tooltip
                  contentStyle={{ backgroundColor: '#0b1628', borderColor: '#15253e', color: '#fff' }}
                />
              </PieChart>
            </ResponsiveContainer>
          </div>
          <div className="flex justify-center gap-4 mt-2">
            {severityData.map(d => (
              <div key={d.name} className="flex items-center gap-2">
                <div className="w-3 h-3 rounded-full" style={{ backgroundColor: d.color }}></div>
                <span className="text-xs text-gray-400">{d.name} ({d.value})</span>
              </div>
            ))}
          </div>
        </div>

        <div className="bg-cyber-800 border border-cyber-700 p-6 rounded-lg flex flex-col">
          <h3 className="text-lg font-bold text-white mb-4">Module Distribution by Category</h3>
          <div className="flex-1 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={categoryData}>
                <CartesianGrid strokeDasharray="3 3" stroke="#15253e" />
                <XAxis dataKey="name" stroke="#6b7280" fontSize={12} />
                <YAxis stroke="#6b7280" fontSize={12} />
                <Tooltip
                  contentStyle={{ backgroundColor: '#0b1628', borderColor: '#15253e', color: '#fff' }}
                  cursor={{ fill: '#15253e' }}
                />
                <Bar dataKey="count" fill="#3b82f6" radius={[4, 4, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>
    </div>
  );
};

export default Dashboard;