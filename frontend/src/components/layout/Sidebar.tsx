import { useState } from "react";
import { Play, Pause, RotateCcw, ChevronLeft, ChevronRight, Activity, Zap, FileText } from "lucide-react";

interface SidebarProps {
  onRunFlow: () => void;
  onPauseFlow: () => void;
  onResetFlow: () => void;
  flowState: 'idle' | 'running' | 'paused' | 'complete';
  metrics: {
    handshakeLatency: number;
    tokenSize: number;
    sessions: number;
  };
  logs: Array<{
    timestamp: Date;
    type: 'handshake' | 'auth' | 'token' | 'access' | 'error';
    message: string;
    status: 'success' | 'error' | 'info';
  }>;
}

export function Sidebar({ onRunFlow, onPauseFlow, onResetFlow, flowState, metrics, logs }: SidebarProps) {
  const [collapsed, setCollapsed] = useState(false);

  if (collapsed) {
    return (
      <aside className="w-[60px] flex-shrink-0 border-r border-glass-border bg-bg-secondary flex flex-col items-center py-4 gap-6 transition-all duration-300">
        <button onClick={() => setCollapsed(false)} className="p-2 hover:bg-glass-bg rounded-full text-text-secondary hover:text-accent-blue shadow-glow-blue transition-colors">
          <ChevronRight className="w-5 h-5" />
        </button>
        <button onClick={onRunFlow} className="p-2 text-accent-blue hover:scale-110 transition-transform">
          <Play className="w-5 h-5 fill-current" />
        </button>
        <button className="p-2 text-text-secondary hover:text-accent-blue transition-colors"><Activity className="w-5 h-5" /></button>
        <button className="p-2 text-text-secondary hover:text-accent-blue transition-colors"><FileText className="w-5 h-5" /></button>
      </aside>
    );
  }

  return (
    <aside className="w-[320px] flex-shrink-0 border-r border-glass-border bg-bg-secondary flex flex-col h-[calc(100vh-100px)] overflow-hidden transition-all duration-300 relative">
      <button 
        onClick={() => setCollapsed(true)} 
        className="absolute top-4 right-4 p-1 hover:bg-glass-bg rounded text-text-secondary hover:text-accent-blue transition-colors z-10"
      >
        <ChevronLeft className="w-5 h-5" />
      </button>

      <div className="flex-1 overflow-y-auto p-4 flex flex-col gap-8 custom-scrollbar">
        {/* Flow Control */}
        <section>
          <h3 className="text-xs font-bold text-text-tertiary mb-3 tracking-wider">FLOW CONTROL</h3>
          <div className="flex flex-col gap-2">
            <button 
              onClick={flowState === 'running' ? onPauseFlow : onRunFlow}
              className={`flex items-center justify-center gap-2 py-3 rounded-xl font-semibold transition-all duration-normal text-text-primary ${
                flowState === 'running' 
                ? 'bg-accent-purple/20 border border-accent-purple shadow-glow-purple group' 
                : 'bg-gradient-to-br from-accent-blue to-cyan-600 shadow-[0_4px_20px_rgba(0,212,255,0.3)] hover:-translate-y-0.5 hover:shadow-[0_6px_30px_rgba(0,212,255,0.5)]'
              }`}
            >
              {flowState === 'running' ? <Pause className="w-5 h-5" /> : <Play className="w-5 h-5 fill-current" />}
              {flowState === 'running' ? 'Pause Flow' : 'Run Flow'}
            </button>
            <button 
              onClick={onResetFlow}
              className="flex items-center justify-center gap-2 py-2 rounded-lg font-medium text-text-secondary hover:text-text-primary hover:bg-glass-bg transition-colors border border-transparent hover:border-glass-border"
            >
              <RotateCcw className="w-4 h-4" />
              Reset
            </button>
          </div>
        </section>

        {/* Configuration */}
        <section>
          <h3 className="text-xs font-bold text-text-tertiary mb-3 tracking-wider">CONFIGURATION</h3>
          <div className="space-y-3 bg-bg-tertiary p-3 rounded-lg border border-glass-border text-sm">
            <div className="flex justify-between items-center text-text-secondary">
              <span>Expected Identity</span>
              <span className="text-text-primary font-mono text-xs">api.example.com</span>
            </div>
            <div className="flex justify-between items-center text-text-secondary">
              <span>Session Policy</span>
              <span className="text-text-primary font-mono text-xs">channel-bound</span>
            </div>
            <div className="flex justify-between items-center text-text-secondary">
              <span>Enable PKCE</span>
              <span className="text-success">✓</span>
            </div>
          </div>
        </section>

        {/* Live Metrics */}
        <section>
          <h3 className="text-xs font-bold text-text-tertiary mb-3 tracking-wider">LIVE METRICS</h3>
          <div className="space-y-3">
            <MetricCard label="Handshake Status" value="Verified" status="success" />
            <MetricCard label="Token Size" value={`${metrics.tokenSize}KB`} trend="up" status="warning" />
            <MetricCard label="Active Sessions" value={metrics.sessions} />
          </div>
        </section>

        {/* Activity Log */}
        <section className="flex-1 flex flex-col min-h-0">
          <h3 className="text-xs font-bold text-text-tertiary mb-3 tracking-wider">ACTIVITY LOG</h3>
          <div className="flex-1 flex flex-col gap-2 overflow-y-auto pr-1">
            {logs.map((log, i) => (
              <div 
                key={i} 
                className={`text-xs font-mono p-2 border-l-2 bg-glass-bg animate-in slide-in-from-left-2 
                  ${log.status === 'success' ? 'border-success' : log.status === 'error' ? 'border-error' : 'border-info'}`
                }
              >
                <div className="text-text-secondary break-words">
                  {log.message}
                </div>
              </div>
            ))}
          </div>
        </section>
      </div>
    </aside>
  );
}

function MetricCard({ label, value, trend, status = 'info' }: { label: string, value: string|number, trend?: 'up'|'down', status?: 'success'|'warning'|'error'|'info' }) {
  const statusColor = {
    success: 'text-success',
    warning: 'text-warning',
    error: 'text-error',
    info: 'text-info'
  }[status];

  return (
    <div className="metric-card hover:-translate-y-0.5">
      <div className="text-xs text-text-tertiary mb-1 uppercase tracking-wider">{label}</div>
      <div className="flex items-end justify-between">
        <div className="metric-value">{value}</div>
        {trend && (
          <div className={`text-xs ${trend === 'up' ? 'text-error' : 'text-success'} font-bold`}>
            {trend === 'up' ? '↑' : '↓'}
          </div>
        )}
      </div>
      <div className="mt-2 h-1 w-full bg-glass-bg rounded overflow-hidden">
        <div 
          className="h-full bg-current opacity-50" 
          style={{ width: `${Math.random() * 40 + 30}%`, color: `var(--${status})` }} 
        />
      </div>
    </div>
  );
}
