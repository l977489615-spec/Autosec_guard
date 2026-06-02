import React from 'react';
import { AlertTriangle } from 'lucide-react';

type Props = { children: React.ReactNode };
type State = { hasError: boolean; message: string };

export class AgentScanErrorBoundary extends React.Component<Props, State> {
  state: State = { hasError: false, message: '' };

  static getDerivedStateFromError(error: Error): State {
    return { hasError: true, message: error?.message || 'Unknown render error' };
  }

  componentDidCatch(error: Error, info: React.ErrorInfo) {
    console.error('[AgentScan] render error:', error, info.componentStack);
  }

  render() {
    if (!this.state.hasError) return this.props.children;
    return (
      <div className="flex h-full min-h-[320px] flex-col items-center justify-center gap-4 p-8 text-center">
        <AlertTriangle className="h-10 w-10 text-amber-400" />
        <h3 className="text-lg font-semibold text-cyan-300">Agent Scan 界面加载失败</h3>
        <p className="max-w-lg text-sm text-gray-400">
          {this.state.message}
        </p>
        <button
          type="button"
          onClick={() => {
            try { localStorage.removeItem('autosec_agent_scan_state'); } catch { /* ignore */ }
            this.setState({ hasError: false, message: '' });
            window.location.reload();
          }}
          className="rounded border border-cyan-700 px-4 py-2 text-sm text-cyan-300 hover:bg-cyan-950/50"
        >
          清除缓存并刷新
        </button>
      </div>
    );
  }
}
