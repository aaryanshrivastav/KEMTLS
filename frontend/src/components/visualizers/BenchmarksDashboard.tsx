export function BenchmarksDashboard() {
  return (
    <div className="h-full flex flex-col items-center pt-8 overflow-y-auto w-full max-w-4xl mx-auto">
      <h2 className="text-xl font-display font-medium text-text-primary mb-8 tracking-wider">PERFORMANCE COMPARISON</h2>
      <p className="text-sm text-text-secondary mb-12">Baseline (Full PQ Handshake) vs PDK (Pre-Distributed Keys)</p>
      
      <div className="w-full space-y-8">
        <BenchmarkItem 
          title="Handshake Effort"
          baseline={{ label: "Level 3.2", value: 3.2, max: 4.0 }}
          pdk={{ label: "Level 2.1", value: 2.1, max: 4.0 }}
          improvement="34%"
          improvementLabel="Reduction"
        />

        <BenchmarkItem 
          title="ServerHello Size"
          baseline={{ label: "2.8 KB", value: 2.8, max: 3.5 }}
          pdk={{ label: "1.2 KB", value: 1.2, max: 3.5 }}
          improvement="57%"
          improvementLabel="Reduction"
        />

        <BenchmarkItem 
          title="Token Size (PQ-Signed vs Standard)"
          baseline={{ label: "Standard 0.3 KB", value: 0.3, max: 8.0 }}
          pdk={{ label: "PQ-Signed 7.8 KB", value: 7.8, max: 8.0, color: "var(--warning)" }}
          improvement="2500%"
          improvementLabel="Increase"
          invertColors={true}
        />
      </div>

      <div className="mt-12 flex gap-4">
        <button className="px-6 py-2 bg-glass-bg border border-glass-border rounded-lg text-text-primary hover:bg-glass-border transition-colors">
          Show Details
        </button>
        <button className="px-6 py-2 bg-accent-blue/10 border border-accent-blue/50 text-accent-blue rounded-lg hover:bg-accent-blue/20 transition-colors">
          Export CSV
        </button>
      </div>
    </div>
  );
}

interface BenchmarkItemProps {
  title: string;
  baseline: { label: string, value: number, max: number };
  pdk: { label: string, value: number, max: number, color?: string };
  improvement: string;
  improvementLabel: string;
  invertColors?: boolean;
}

function BenchmarkItem({ title, baseline, pdk, improvement, improvementLabel, invertColors }: BenchmarkItemProps) {
  const baselinePct = (baseline.value / baseline.max) * 100;
  const pdkPct = (pdk.value / pdk.max) * 100;

  const pdkColor = pdk.color || 'var(--accent-blue)';
  
  return (
    <div className="grid grid-cols-3 gap-8 items-center bg-bg-secondary border border-glass-border p-6 rounded-xl relative group overflow-hidden hover:border-accent-blue/50 transition-colors">
      <div className="col-span-2 space-y-4">
        <h3 className="font-semibold text-text-primary tracking-wide text-sm">{title}</h3>
        
        <div className="space-y-3">
          <div className="space-y-1">
            <div className="flex justify-between text-xs">
              <span className="text-text-secondary">Baseline</span>
              <span className="font-mono text-text-primary">{baseline.label}</span>
            </div>
            <div className="h-4 bg-bg-tertiary rounded-sm overflow-hidden">
              <div 
                className="h-full bg-text-tertiary transition-all duration-slower ease-out" 
                style={{ width: `${baselinePct}%` }} 
              />
            </div>
          </div>
          
          <div className="space-y-1">
            <div className="flex justify-between text-xs">
              <span className="text-accent-blue font-bold">PDK</span>
              <span className="font-mono text-text-primary">{pdk.label}</span>
            </div>
            <div className="h-4 bg-bg-tertiary rounded-sm overflow-hidden">
              <div 
                className="h-full transition-all duration-slower ease-out" 
                style={{ width: `${pdkPct}%`, backgroundColor: pdkColor }} 
              />
            </div>
          </div>
        </div>
      </div>
      
      <div className="col-span-1 border-l border-glass-border pl-8 flex flex-col justify-center gap-1 opacity-50 group-hover:opacity-100 transition-opacity">
        <div className="text-xs text-text-secondary uppercase">{improvementLabel}</div>
        <div className={`text-3xl font-display font-bold ${invertColors ? 'text-warning' : 'text-success'}`}>{improvement}</div>
      </div>
    </div>
  );
}
