import React, { useEffect, useRef } from 'react';
import { ScanLog } from '../types';
import { Download, Trash2 } from 'lucide-react';

interface ScanLogsProps {
  logs: ScanLog[];
  onClearLogs?: () => void;
}

const ScanLogs: React.FC<ScanLogsProps> = ({ logs, onClearLogs }) => {
  const scrollRef = useRef<HTMLDivElement>(null);
  const visibleLogs = logs.slice(-500);

  useEffect(() => {
    if (scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
    }
  }, [logs]);

  const exportLogs = () => {
    const text = logs
      .map(l => `[${l.timestamp}] [${l.type.toUpperCase()}] ${l.message}`)
      .join('\n');
    const blob = new Blob([text], { type: 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `autosec_scan_log_${new Date().toISOString().slice(0, 10)}.log`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="bg-cyber-900 border border-cyber-700 rounded-lg p-4 h-96 flex flex-col font-mono text-sm shadow-[0_0_15px_rgba(59,130,246,0.1)]">
      <div className="flex justify-between items-center mb-2 border-b border-cyber-700 pb-2">
        <span className="text-cyber-400 font-bold uppercase tracking-widest">System Console</span>
        <div className="flex gap-3 items-center">
          <span className="text-gray-500 text-[10px]">{logs.length} lines</span>
          <button
            onClick={exportLogs}
            disabled={logs.length === 0}
            className="text-gray-400 hover:text-cyan-300 disabled:opacity-30 transition-colors"
            title="导出日志"
          >
            <Download size={14} />
          </button>
          {onClearLogs && (
            <button
              onClick={onClearLogs}
              disabled={logs.length === 0}
              className="text-gray-400 hover:text-red-400 disabled:opacity-30 transition-colors"
              title="清空日志"
            >
              <Trash2 size={14} />
            </button>
          )}
          <div className="flex gap-1.5 ml-1">
            <div className="w-2.5 h-2.5 rounded-full bg-red-500"></div>
            <div className="w-2.5 h-2.5 rounded-full bg-yellow-500"></div>
            <div className="w-2.5 h-2.5 rounded-full bg-green-500"></div>
          </div>
        </div>
      </div>
      <div ref={scrollRef} className="flex-1 overflow-y-auto scroller space-y-1 p-2">
        {logs.length === 0 && <span className="text-gray-600 italic">Waiting for scan to initiate...</span>}
        {logs.length > visibleLogs.length && (
          <div className="text-gray-500 italic">
            Showing latest {visibleLogs.length} lines. Export logs for the retained buffer.
          </div>
        )}
        {visibleLogs.map((log, idx) => (
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
