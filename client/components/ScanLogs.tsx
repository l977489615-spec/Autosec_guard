import React, { useEffect, useRef } from 'react';
import { ScanLog } from '../types';

interface ScanLogsProps {
  logs: ScanLog[];
}

const ScanLogs: React.FC<ScanLogsProps> = ({ logs }) => {
  const scrollRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
    }
  }, [logs]);

  return (
    <div className="bg-cyber-900 border border-cyber-700 rounded-lg p-4 h-96 flex flex-col font-mono text-sm shadow-[0_0_15px_rgba(59,130,246,0.1)]">
      <div className="flex justify-between items-center mb-2 border-b border-cyber-700 pb-2">
        <span className="text-cyber-400 font-bold uppercase tracking-widest">System Console</span>
        <div className="flex gap-2">
          <div className="w-3 h-3 rounded-full bg-red-500"></div>
          <div className="w-3 h-3 rounded-full bg-yellow-500"></div>
          <div className="w-3 h-3 rounded-full bg-green-500"></div>
        </div>
      </div>
      <div ref={scrollRef} className="flex-1 overflow-y-auto scroller space-y-1 p-2">
        {logs.length === 0 && <span className="text-gray-600 italic">Waiting for scan to initiate...</span>}
        {logs.map((log, idx) => (
          <div key={idx} className="flex gap-3">
            <span className="text-gray-500 shrink-0">[{log.timestamp}]</span>
            <span className={`${log.type === 'error' ? 'text-cyber-danger' :
                log.type === 'success' ? 'text-cyber-success' :
                  log.type === 'warning' ? 'text-cyber-warning' :
                    log.type === 'terminal' ? 'text-green-400 opacity-80 text-[11px]' : 'text-cyan-300'
              }`}>
              {log.type === 'success' && '✓ '}
              {log.type === 'error' && '✗ '}
              {log.type === 'warning' && '! '}
              {log.type === 'terminal' && '  '}
              {log.message}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
};

export default ScanLogs;