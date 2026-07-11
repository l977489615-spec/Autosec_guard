import React from 'react';
import { AlertTriangle } from 'lucide-react';

type Props = { children: React.ReactNode; resetKey?: string };
type State = { hasError: boolean; message: string };

export class AgentScanErrorBoundary extends React.Component<Props, State> {
  state: State = { hasError: false, message: '' };

  static getDerivedStateFromError(error: Error): State {
    return { hasError: true, message: error?.message || 'Unknown render error' };
  }

  componentDidCatch(error: Error, info: React.ErrorInfo) {
    console.error('[AgentScan] render error:', error, info.componentStack);
  }

  componentDidUpdate(previousProps: Props) {
    if (this.state.hasError && previousProps.resetKey !== this.props.resetKey) {
      this.setState({ hasError: false, message: '' });
    }
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
            try { sessionStorage.removeItem('autosec_agent_scan_state'); } catch { /* ignore */ }
            this.setState({ hasError: false, message: '' });
            this.setState({ hasError: false, message: '' });
          }}
          className="rounded border border-cyan-700 px-4 py-2 text-sm text-cyan-300 hover:bg-cyan-950/50"
        >
          清除本页运行缓存并重试
        </button>
      </div>
    );
  }
}
