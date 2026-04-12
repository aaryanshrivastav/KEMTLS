interface StatusBarProps {
  connectionStatus: 'connected' | 'disconnected' | 'connecting';
  currentMode: string;
  sessionId?: string;
}

export function StatusBar({ connectionStatus, currentMode, sessionId }: StatusBarProps) {
  return (
    <footer className="h-[40px] flex items-center gap-6 px-6 bg-bg-secondary border-t border-glass-border font-mono text-sm z-50">
      <div className="flex items-center gap-2">
        <div className={`w-2 h-2 rounded-full ${
          connectionStatus === 'connected' ? 'bg-success shadow-[0_0_10px_var(--success)]' : 
          connectionStatus === 'connecting' ? 'bg-warning shadow-[0_0_10px_var(--warning)] animate-pulse' : 
          'bg-error shadow-[0_0_10px_var(--error)]'
        }`} />
        <span className="text-text-primary capitalize">{connectionStatus}</span>
      </div>
      
      <div className="text-text-tertiary">|</div>
      
      <div className="text-text-secondary">
        Mode: <span className="text-text-primary uppercase">{currentMode}</span>
      </div>

      {sessionId && (
        <>
          <div className="text-text-tertiary">|</div>
          <div className="text-text-secondary">
            Session: <span className="text-accent-blue">{sessionId}</span>
          </div>
        </>
      )}

      <div className="flex-1" />
    </footer>
  );
}
