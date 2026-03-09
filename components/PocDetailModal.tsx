import React from 'react';
import { POC, Severity } from '../types';
import { X, Terminal, Shield, AlertTriangle, CheckCircle, Bug, Play } from 'lucide-react';

interface PocDetailModalProps {
  poc: POC | null;
  isOpen: boolean;
  onClose: () => void;
  onRunTest?: (poc: POC) => void; // Optional callback for "Test" action
}

const PocDetailModal: React.FC<PocDetailModalProps> = ({ poc, isOpen, onClose, onRunTest }) => {
  if (!isOpen || !poc) return null;

  const getSeverityColor = (sev: Severity) => {
    switch(sev) {
      case Severity.CRITICAL: return 'text-red-500 bg-red-500/10 border-red-500';
      case Severity.HIGH: return 'text-orange-500 bg-orange-500/10 border-orange-500';
      case Severity.MEDIUM: return 'text-yellow-500 bg-yellow-500/10 border-yellow-500';
      default: return 'text-blue-400 bg-blue-400/10 border-blue-400';
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-sm p-4">
      <div className="bg-cyber-800 border border-cyber-700 w-full max-w-4xl max-h-[90vh] rounded-xl shadow-2xl overflow-hidden flex flex-col">
        {/* Header */}
        <div className="flex justify-between items-start p-6 border-b border-cyber-700 bg-cyber-900/50">
          <div>
            <div className="flex items-center gap-3 mb-2">
              <span className={`px-2 py-1 rounded text-xs font-bold border ${getSeverityColor(poc.severity)}`}>
                {poc.severity}
              </span>
              <span className="text-gray-500 font-mono text-sm">{poc.id}</span>
              {poc.cveId && <span className="text-cyber-accent font-mono text-sm bg-cyber-accent/10 px-2 py-0.5 rounded">{poc.cveId}</span>}
            </div>
            <h2 className="text-2xl font-bold text-white">{poc.name}</h2>
          </div>
          <button onClick={onClose} className="text-gray-400 hover:text-white hover:bg-cyber-700 p-2 rounded-full transition-colors">
            <X size={24} />
          </button>
        </div>

        {/* Scrollable Content */}
        <div className="flex-1 overflow-y-auto p-6 space-y-6">
          {/* Description */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <div className="space-y-4">
               <div>
                 <h3 className="text-sm font-bold text-cyber-400 uppercase tracking-wider mb-2 flex items-center gap-2">
                   <Bug size={16} /> Vulnerability Description
                 </h3>
                 <p className="text-gray-300 text-sm leading-relaxed">{poc.description}</p>
               </div>
               
               <div>
                 <h3 className="text-sm font-bold text-cyber-danger uppercase tracking-wider mb-2 flex items-center gap-2">
                   <AlertTriangle size={16} /> Business Impact
                 </h3>
                 <p className="text-gray-300 text-sm leading-relaxed">{poc.impact}</p>
               </div>
            </div>

            <div className="space-y-4">
              <div>
                 <h3 className="text-sm font-bold text-cyber-success uppercase tracking-wider mb-2 flex items-center gap-2">
                   <Shield size={16} /> Remediation Strategy
                 </h3>
                 <div className="bg-cyber-900/50 p-3 rounded border border-cyber-700 text-gray-300 text-sm">
                   {poc.remediation}
                 </div>
               </div>
               
               <div>
                 <h3 className="text-sm font-bold text-gray-400 uppercase tracking-wider mb-2">Category</h3>
                 <span className="inline-block bg-cyber-700 text-white px-3 py-1 rounded-full text-xs">
                   {poc.category}
                 </span>
               </div>
            </div>
          </div>

          {/* Code Snippet */}
          <div>
            <h3 className="text-sm font-bold text-cyber-accent uppercase tracking-wider mb-2 flex items-center gap-2">
              <Terminal size={16} /> Exploit POC Script (Prototype)
            </h3>
            <div className="bg-[#0d1117] border border-gray-700 rounded-lg p-4 font-mono text-sm text-gray-300 overflow-x-auto shadow-inner relative group">
              <div className="absolute top-2 right-2 opacity-0 group-hover:opacity-100 transition-opacity">
                <span className="text-xs text-gray-500">python/bash</span>
              </div>
              <pre className="whitespace-pre-wrap"><code>{poc.codeSnippet}</code></pre>
            </div>
            <p className="text-xs text-gray-600 mt-2 italic">
              * This script is a proof-of-concept for verification purposes only. Ensure authorization before executing on target vehicle.
            </p>
          </div>
        </div>

        {/* Footer */}
        <div className="p-4 border-t border-cyber-700 bg-cyber-900/50 flex justify-end gap-4">
          <button 
            onClick={onClose}
            className="px-4 py-2 text-gray-400 hover:text-white transition-colors text-sm"
          >
            Close Details
          </button>
          {onRunTest && (
            <button 
                onClick={() => onRunTest(poc)}
                className="px-6 py-2 bg-cyber-danger hover:bg-red-600 text-white rounded font-bold shadow-[0_0_15px_rgba(255,51,102,0.3)] flex items-center gap-2 transition-all"
            >
                <Play size={16} fill="currentColor" />
                CONFIGURE & ATTACK
            </button>
          )}
        </div>
      </div>
    </div>
  );
};

export default PocDetailModal;