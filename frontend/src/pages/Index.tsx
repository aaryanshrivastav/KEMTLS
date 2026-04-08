import { useState, useEffect, useRef, useCallback, useMemo } from 'react';
import { io, Socket } from 'socket.io-client';
import { CyberCursor } from '../components/CyberCursor';
import { GridBackground } from '../components/GridBackground';
import { useThreatPopups, THREATS } from '../components/ThreatPopup';
import { ProtocolActivity } from '../components/ProtocolActivity';
import { LoginPlatformPanel } from '../components/LoginPlatformPanel';

/* ──────────────────────────────────────────
   Types
   ────────────────────────────────────────── */
interface FlowStep {
  id: string;
  label: string;
  detail: string;
  explanation: string;
  status: 'idle' | 'running' | 'done' | 'error';
  data?: Record<string, string>;
  durationMs?: number;
}

interface LogEntry {
  ts: number;
  level: 'info' | 'ok' | 'warn' | 'err' | 'data';
  msg: string;
}

type FlowState = 'idle' | 'running' | 'paused' | 'done';
type RunMode = 'full' | 'step';

const SOCKET_URL = 'http://localhost:5002';
const BACKEND_STEP_IDS = ['hello', 'server', 'derive', 'finished', 'authorize', 'account_auth', 'consent', 'token_exchange', 'session_bind', 'resource_access'] as const;

/* ──────────────────────────────────────────
   Step definitions with explanations for click-and-resume
   ────────────────────────────────────────── */
const INITIAL_STEPS: FlowStep[] = [
  {
    id: 'hello', label: 'CLIENT HELLO',
    detail: 'ML-KEM-768 key share + cipher suites',
    explanation: 'The client generates an ML-KEM-768 key pair and sends the public key to the server along with supported cipher suites. This uses lattice-based cryptography that is resistant to quantum attacks via Shor\'s algorithm.',
    status: 'idle',
  },
  {
    id: 'server', label: 'SERVER HELLO',
    detail: 'ML-KEM-768 ciphertext + ML-DSA-65 cert chain',
    explanation: 'The server encapsulates a shared secret using the client\'s ML-KEM public key and sends the ciphertext back alongside its ML-DSA-65 signed certificate chain. The post-quantum signature prevents certificate forgery even by quantum adversaries.',
    status: 'idle',
  },
  {
    id: 'derive', label: 'KEY SCHEDULE',
    detail: 'HKDF-SHA256 → client_key, server_key, exporter',
    explanation: 'Both parties derive symmetric keys using HKDF-SHA256 from the shared KEM secret, bound to the full handshake transcript. This transcript binding means any MITM modification is detectable — the derived keys will differ.',
    status: 'idle',
  },
  {
    id: 'finished', label: 'FINISHED',
    detail: 'Handshake MAC verified on both sides',
    explanation: 'Both sides exchange Finished messages containing HMAC over the handshake transcript. Fresh nonces ensure uniqueness — replaying a captured handshake will fail MAC verification because the nonce won\'t match.',
    status: 'idle',
  },
  {
    id: 'authorize', label: 'OIDC AUTHORIZE',
    detail: 'GET /authorize → redirect to identity provider',
    explanation: 'The client initiates the OpenID Connect authorization code flow over the now quantum-secure KEMTLS channel. The user is redirected to the identity provider (e.g. Google) with PKCE (S256) to prevent authorization code interception.',
    status: 'idle',
  },
  {
    id: 'account_auth', label: 'ACCOUNT AUTH',
    detail: 'User selects account + authenticates at IdP',
    explanation: 'The user authenticates at the identity provider by selecting their account and completing any required authentication (password, MFA). This happens entirely at the IdP — the relying party never sees credentials.',
    status: 'idle',
  },
  {
    id: 'consent', label: 'CONSENT + CODE',
    detail: 'User grants consent → auth code issued',
    explanation: 'The identity provider presents the requested permissions (name, email, profile). When the user consents, an authorization code is issued and the user is redirected back to the relying party with the code and state parameter.',
    status: 'idle',
  },
  {
    id: 'token_exchange', label: 'TOKEN EXCHANGE',
    detail: 'POST /token → PQ-signed ID + Access + Refresh',
    explanation: 'The client exchanges the authorization code for tokens. The auth server signs all tokens with ML-DSA-65, a post-quantum digital signature algorithm. The PKCE verifier ensures only the legitimate client can complete this exchange.',
    status: 'idle',
  },
  {
    id: 'session_bind', label: 'SESSION BIND',
    detail: 'cnf.kbh = SHA256(exporter || session_id)',
    explanation: 'The token is cryptographically bound to this specific KEMTLS channel using the TLS Exporter. The binding hash is embedded in the cnf claim of the access token. Even if tokens are stolen, they cannot be used from a different connection because the binding verification will fail.',
    status: 'idle',
  },
  {
    id: 'resource_access', label: 'RESOURCE ACCESS',
    detail: 'GET /resource with Bearer token over KEMTLS',
    explanation: 'The client calls the protected resource endpoint with the issued access token. The resource server verifies the token binding against the active KEMTLS session before granting access.',
    status: 'idle',
  },
];

const PLACEHOLDER_LOGS: LogEntry[] = [];

function makePlaceholderData(stepId: string): Record<string, string> {
  const data: Record<string, Record<string, string>> = {
    hello: { kem_pk_size: '1184 bytes', cipher_suite: 'ML-KEM-768 + ML-DSA-65', pkce: 'S256' },
    server: { ct_size: '1088 bytes', cert_alg: 'ML-DSA-65', cert_chain: '2 certs' },
    derive: { client_key: 'a1b2...f0e9 (32B)', server_key: 'c3d4...78ab (32B)', exporter: 'ZjRhY2Mx...OGM (32B)' },
    finished: { handshake_mac: 'HMAC-SHA256 ✓', replay_nonce: '0x7a3f...e1c0', latency: '2.1 ms' },
    authorize: { redirect_uri: 'https://accounts.google.com/o/oauth2/v2/auth', state: 'rng_state_439f', scope: 'openid profile email', pkce: 'S256' },
    account_auth: { provider: 'Google', method: 'session + MFA', account: 'user@gmail.com', status: 'authenticated' },
    consent: { permissions: 'name, email, profile picture', code: 'a8f3k2x9m1b7...', state_verified: 'true' },
    token_exchange: { alg: 'ML-DSA-65', id_token_size: '7.8 KB', sig_size: '3293 bytes', refresh_bound: 'true' },
    session_bind: { session_id: 'kemtls-001', binding_hash: 'ZjRhY2MxODM...', binding_alg: 'HKDF-SHA256', exporter_label: 'kemtls-session-v1' },
    resource_access: { resource: '/api/userinfo', auth: 'Bearer token', result: '200 OK – Access Granted' },
  };
  return data[stepId] || {};
}

/* Phase groupings for vertical flow layout */
const PHASES = [
  { label: 'PQ TRANSPORT', color: 'var(--cyan)', stepIds: ['hello', 'server', 'derive', 'finished'] },
  { label: 'OIDC LOGIN', color: 'var(--magenta)', stepIds: ['authorize', 'account_auth', 'consent'] },
  { label: 'TOKEN SECURITY', color: 'var(--violet)', stepIds: ['token_exchange', 'session_bind'] },
  { label: 'PLATFORM', color: 'var(--lime)', stepIds: ['resource_access'] },
];

/* ──────────────────────────────────────────
   Component
   ────────────────────────────────────────── */
export default function Index() {
  const [runMode, setRunMode] = useState<RunMode>('full');
  const [flowState, setFlowState] = useState<FlowState>('idle');
  const [steps, setSteps] = useState<FlowStep[]>(INITIAL_STEPS);
  const [logs, setLogs] = useState<LogEntry[]>(PLACEHOLDER_LOGS);
  const [elapsed, setElapsed] = useState(0);
  const [selectedStep, setSelectedStep] = useState<string | null>(null);
  const [terminalOpen, setTerminalOpen] = useState(false);
  const [terminalWidth, setTerminalWidth] = useState(380);
  const [detailsOpen, setDetailsOpen] = useState(true);
  const [waitingForClick, setWaitingForClick] = useState(false);
  const [currentStepIdx, setCurrentStepIdx] = useState(-1);
  const [isBackendConnected, setIsBackendConnected] = useState(false);
  const [currentRunId, setCurrentRunId] = useState<string | null>(null);
  const timerRef = useRef<ReturnType<typeof setInterval>>();
  const logBoxRef = useRef<HTMLDivElement>(null);
  const socketRef = useRef<Socket | null>(null);
  const currentRunIdRef = useRef<string | null>(null);
  const fullFlowRunIdRef = useRef(0);
  const isDraggingRef = useRef(false);
  const scrollContainerRef = useRef<HTMLDivElement>(null);
  const { activeThreat, triggerThreat, dismissThreat } = useThreatPopups();
  const triggerThreatRef = useRef(triggerThreat);

  const stepIndexById = useRef<Record<string, number>>({});

  useEffect(() => {
    currentRunIdRef.current = currentRunId;
  }, [currentRunId]);

  useEffect(() => {
    triggerThreatRef.current = triggerThreat;
  }, [triggerThreat]);

  useEffect(() => {
    const mapping: Record<string, number> = {};
    INITIAL_STEPS.forEach((step, idx) => {
      mapping[step.id] = idx;
    });
    stepIndexById.current = mapping;
  }, []);

  // Scroll logs to bottom
  useEffect(() => {
    if (logBoxRef.current) logBoxRef.current.scrollTop = logBoxRef.current.scrollHeight;
  }, [logs]);

  // Timer for elapsed
  useEffect(() => {
    if (flowState === 'running') {
      timerRef.current = setInterval(() => setElapsed(e => e + 100), 100);
    } else {
      clearInterval(timerRef.current);
    }
    return () => clearInterval(timerRef.current);
  }, [flowState]);

  const addLog = useCallback((level: LogEntry['level'], msg: string) => {
    setLogs(prev => [...prev, { ts: Date.now(), level, msg }]);
  }, []);

  const resetUiState = useCallback(() => {
    dismissThreat();
    setFlowState('idle');
    setWaitingForClick(false);
    setCurrentStepIdx(-1);
    setSelectedStep(null);
    setSteps(INITIAL_STEPS);
    setLogs([]);
    setElapsed(0);
    scrollContainerRef.current?.scrollTo({ top: 0, behavior: 'auto' });
  }, [dismissThreat]);

  const applySnapshot = useCallback((snapshot: {
    hasActiveRun: boolean;
    runId?: string;
    status?: 'idle' | 'running' | 'paused' | 'done' | 'error';
    stepIndex?: number;
    currentStepId?: string | null;
    nextStepId?: string | null;
  }) => {
    if (!snapshot.hasActiveRun) {
      setCurrentRunId(null);
      resetUiState();
      return;
    }

    const runId = snapshot.runId || null;
    if (runId) setCurrentRunId(runId);

    const stepIndex = typeof snapshot.stepIndex === 'number' ? snapshot.stepIndex : 0;
    const status = snapshot.status || 'idle';

    setSteps(prev => prev.map((step, idx) => {
      const isBackendStep = BACKEND_STEP_IDS.includes(step.id as (typeof BACKEND_STEP_IDS)[number]);
      if (!isBackendStep) return step;

      if (idx < stepIndex) {
        return { ...step, status: 'done' };
      }

      if (status === 'running' && idx === stepIndex) {
        return { ...step, status: 'running' };
      }

      return { ...step, status: 'idle' };
    }));

    if (status === 'paused') {
      const nextId = snapshot.nextStepId || null;
      if (nextId) {
        const nextIdx = stepIndexById.current[nextId];
        if (nextIdx !== undefined) {
          setCurrentStepIdx(nextIdx - 1);
          setSelectedStep(INITIAL_STEPS[Math.max(nextIdx - 1, 0)]?.id || null);
        }
      }
      setWaitingForClick(true);
      setFlowState('paused');
      return;
    }

    if (status === 'running') {
      setCurrentStepIdx(stepIndex);
      setSelectedStep(snapshot.currentStepId || INITIAL_STEPS[stepIndex]?.id || null);
      setWaitingForClick(false);
      setFlowState('running');
      return;
    }

    if (status === 'done') {
      setWaitingForClick(false);
      setFlowState('done');
      return;
    }

    if (status === 'error') {
      setWaitingForClick(false);
      setFlowState('idle');
      return;
    }
  }, [resetUiState]);

  // Step-by-step backend connection (Socket.IO)
  useEffect(() => {
    const socket = io(SOCKET_URL, {
      transports: ['websocket', 'polling'],
      upgrade: true,
      rememberUpgrade: true,
      reconnection: true,
      reconnectionAttempts: 5,
      reconnectionDelay: 1000,
    });

    socketRef.current = socket;

    socket.on('connect', () => {
      setIsBackendConnected(true);
      socket.emit('get_step_flow_state');
    });

    socket.on('disconnect', () => {
      setIsBackendConnected(false);
    });

    socket.on('connected', () => {
      // backend ready
    });

    socket.on('log', (data: { message: string; level: 'info' | 'success' | 'error' | 'warning'; timestamp: number }) => {
      const levelMap: Record<string, LogEntry['level']> = {
        info: 'info',
        success: 'ok',
        error: 'err',
        warning: 'warn',
      };
      addLog(levelMap[data.level] || 'info', data.message);
    });

    socket.on('step_flow_started', (data: { runId?: string }) => {
      if (data.runId) setCurrentRunId(data.runId);
      dismissThreat();
      setFlowState('running');
      setElapsed(0);
      setLogs([]);
      setSelectedStep(null);
      setCurrentStepIdx(-1);
      setWaitingForClick(false);
      setSteps(INITIAL_STEPS.map(s => ({ ...s, status: 'idle', data: undefined, durationMs: undefined })));
    });

    socket.on('handshake_step_start', (data: { stepId: string; runId?: string }) => {
      if (currentRunIdRef.current && data.runId && data.runId !== currentRunIdRef.current) return;
      const idx = stepIndexById.current[data.stepId];
      if (idx === undefined) return;

      setCurrentStepIdx(idx);
      setSelectedStep(data.stepId);
      setFlowState('running');
      setSteps(prev => prev.map((s, i) => {
        if (i === idx) return { ...s, status: 'running' };
        return s;
      }));
      triggerThreatRef.current(data.stepId);
    });

    socket.on('handshake_step_complete', (data: { stepId: string; durationMs: number; data: Record<string, string>; isFinal: boolean; runId?: string }) => {
      if (currentRunIdRef.current && data.runId && data.runId !== currentRunIdRef.current) return;
      const idx = stepIndexById.current[data.stepId];
      if (idx === undefined) return;

      setSteps(prev => prev.map((s, i) => {
        if (i === idx) {
          return {
            ...s,
            status: 'done',
            data: data.data,
            durationMs: data.durationMs,
          };
        }
        return s;
      }));

      if (data.isFinal) {
        setWaitingForClick(false);
        setFlowState('done');
      }
    });

    socket.on('step_flow_paused', (data: { nextStepId: string; runId?: string }) => {
      if (currentRunIdRef.current && data.runId && data.runId !== currentRunIdRef.current) return;
      const nextIdx = stepIndexById.current[data.nextStepId];
      if (nextIdx === undefined) return;

      // Interactive steps (account_auth, consent): the backend paused AT the step
      // (step_start was emitted but step_complete was not). Keep the step as "running".
      const INTERACTIVE_STEPS = ['account_auth', 'consent'];
      const isInteractive = INTERACTIVE_STEPS.includes(data.nextStepId);

      if (isInteractive) {
        // Step is already 'running' from handshake_step_start — keep it that way.
        setCurrentStepIdx(nextIdx);
        setSelectedStep(data.nextStepId);
      } else {
        setCurrentStepIdx(nextIdx - 1);
      }

      setFlowState('paused');
      setWaitingForClick(true);
      if (isInteractive) {
        addLog('info', `  ⏸ Awaiting user action on ${data.nextStepId.replace('_', ' ')}`);
      } else {
        addLog('info', `  ⏸ Paused — click step ${nextIdx + 1} to continue`);
      }
    });

    socket.on('step_flow_complete', (data: { runId?: string }) => {
      if (currentRunIdRef.current && data.runId && data.runId !== currentRunIdRef.current) return;
      setWaitingForClick(false);
      setFlowState('done');
      addLog('ok', '');
      addLog('ok', '═══════════════════════════════════════');
      addLog('ok', '  ✓ KEMTLS + OIDC CONTRACT FLOW COMPLETE');
      addLog('ok', '═══════════════════════════════════════');
    });

    socket.on('step_flow_error', (data: { message: string; error?: string; runId?: string }) => {
      if (currentRunIdRef.current && data.runId && data.runId !== currentRunIdRef.current) return;
      setFlowState('paused');
      setWaitingForClick(true);
      addLog('err', `${data.message}${data.error ? `: ${data.error}` : ''}`);
      socket.emit('get_step_flow_state');
    });

    socket.on('step_flow_reset', () => {
      setCurrentRunId(null);
      resetUiState();
    });

    socket.on('step_flow_state', (data: {
      hasActiveRun: boolean;
      runId?: string;
      status?: 'idle' | 'running' | 'paused' | 'done' | 'error';
      stepIndex?: number;
      currentStepId?: string | null;
      nextStepId?: string | null;
    }) => {
      applySnapshot(data);
    });

    return () => {
      socket.disconnect();
    };
  }, [addLog, applySnapshot, resetUiState, dismissThreat]);

  /* ────── Terminal resize drag handler ────── */
  const handleTerminalDragStart = useCallback((e: React.MouseEvent) => {
    e.preventDefault();
    isDraggingRef.current = true;
    const startX = e.clientX;
    const startW = terminalWidth;

    const onMove = (ev: MouseEvent) => {
      if (!isDraggingRef.current) return;
      const delta = startX - ev.clientX;
      const newW = Math.max(260, Math.min(window.innerWidth * 0.7, startW + delta));
      setTerminalWidth(newW);
    };

    const onUp = () => {
      isDraggingRef.current = false;
      document.removeEventListener('mousemove', onMove);
      document.removeEventListener('mouseup', onUp);
      document.body.style.cursor = '';
      document.body.style.userSelect = '';
    };

    document.body.style.cursor = 'col-resize';
    document.body.style.userSelect = 'none';
    document.addEventListener('mousemove', onMove);
    document.addEventListener('mouseup', onUp);
  }, [terminalWidth]);

  /* ────── Run Full Flow (real backend auto mode) ────── */
  const runFullFlow = useCallback(() => {
    if (flowState === 'running' || flowState === 'paused') return;
    if (!isBackendConnected || !socketRef.current) {
      addLog('err', 'Backend step-flow server is not connected (expected at http://localhost:5002).');
      return;
    }

    fullFlowRunIdRef.current += 1;
    socketRef.current.emit('start_step_flow', { mode: 'baseline', autoAdvance: true });
  }, [flowState, addLog, isBackendConnected]);

  /* ────── Run Step-by-Step (with attacks, pauses) ────── */
  const runStepFlow = useCallback(() => {
    if (flowState === 'running' || flowState === 'paused') return;
    if (!isBackendConnected || !socketRef.current) {
      addLog('err', 'Backend step-flow server is not connected (expected at http://localhost:5002).');
      return;
    }

    socketRef.current.emit('start_step_flow', { mode: 'baseline', autoAdvance: false });
  }, [flowState, addLog, isBackendConnected]);

  /* ────── Handle node click (for step mode resume) ────── */
  const advanceStepFlow = useCallback((stepId?: string) => {
    if (runMode !== 'step' || !waitingForClick) return;

    const nextIdx = currentStepIdx + 1;
    if (nextIdx >= INITIAL_STEPS.length) return;

    const expectedNextStepId = INITIAL_STEPS[nextIdx].id;
    if (stepId && expectedNextStepId !== stepId) return;
    if (!BACKEND_STEP_IDS.includes(expectedNextStepId as (typeof BACKEND_STEP_IDS)[number])) return;

    socketRef.current?.emit('continue_step_flow', { runId: currentRunId });
  }, [runMode, waitingForClick, currentStepIdx, currentRunId]);

  /* ────── Advance from login panel (no step ID validation needed) ────── */
  const advanceFromLoginPanel = useCallback(() => {
    if (runMode !== 'step' || !waitingForClick || flowState !== 'paused') return;
    socketRef.current?.emit('continue_step_flow', { runId: currentRunId });
  }, [runMode, waitingForClick, flowState, currentRunId]);

  const handleNodeClick = useCallback((stepId: string) => {
    advanceStepFlow(stepId);
    setSelectedStep(stepId);
  }, [advanceStepFlow]);

  useEffect(() => {
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.code !== 'Space') return;

      const target = event.target as HTMLElement | null;
      const tag = target?.tagName?.toLowerCase();
      const isTypingTarget = tag === 'input' || tag === 'textarea' || target?.isContentEditable;
      if (isTypingTarget) return;

      if (runMode === 'step' && waitingForClick && flowState === 'paused') {
        event.preventDefault();
        advanceStepFlow();
      }
    };

    window.addEventListener('keydown', onKeyDown);
    return () => window.removeEventListener('keydown', onKeyDown);
  }, [runMode, waitingForClick, flowState, advanceStepFlow]);

  const startFlow = useCallback(() => {
    if (runMode === 'full') {
      runFullFlow();
    } else {
      runStepFlow();
    }
  }, [runMode, runFullFlow, runStepFlow]);

  const resetFlow = useCallback(() => {
    // Cancel any in-flight full-flow async loop immediately.
    fullFlowRunIdRef.current += 1;

    // Always reset backend state if a run is active, regardless of UI mode.
    if (socketRef.current && currentRunId) {
      socketRef.current?.emit('reset_step_flow', { runId: currentRunId });
    }
    setCurrentRunId(null);
    resetUiState();
  }, [currentRunId, resetUiState]);

  // Active step for explanation panel
  const activeStepObj = steps.find(s => s.id === (selectedStep || ''));
  const activeThreatInfo = selectedStep ? THREATS.find(t => t.stepId === selectedStep) : null;

  return (
    <div className="fixed inset-0 flex flex-col overflow-hidden" style={{ background: 'var(--void)' }}>
      <CyberCursor />
      <GridBackground />


      {/* ═══ TOP BAR ═══ */}
      <header className="relative z-20 h-14 flex items-center px-5 gap-4" style={{
        background: 'linear-gradient(90deg, rgba(0,229,255,0.04), transparent 40%, transparent 60%, rgba(255,0,229,0.04))',
        borderBottom: '1px solid rgba(0, 229, 255, 0.1)',
      }}>
        {/* Logo */}
        <div className="flex items-center gap-3 mr-4" data-hover>
          <div className="relative w-9 h-9">
            <div className="absolute inset-0 rounded-lg" style={{
              border: '1.5px solid var(--cyan)',
              boxShadow: 'var(--glow-cyan)',
              animation: 'hex-rotate 8s linear infinite',
            }} />
            <div className="absolute inset-0 flex items-center justify-center font-display text-sm font-bold neon-text">H</div>
          </div>
          <div>
            <div className="font-display text-sm font-bold neon-text tracking-widest">HelloWorld</div>
            <div className="text-[10px] tracking-[0.3em]" style={{ color: 'var(--text-dim)' }}>PQ-OIDC DASHBOARD</div>
          </div>
        </div>

        {/* Run Mode Toggle */}
        <div className="flex rounded-lg overflow-hidden" style={{ border: '1px solid rgba(0,229,255,0.15)' }}>
          {([
            { key: 'full' as const, label: 'FULL FLOW' },
            { key: 'step' as const, label: 'STEP BY STEP' },
          ]).map(m => (
            <button
              key={m.key}
              onClick={() => {
                if (flowState === 'idle') {
                  dismissThreat();
                  setRunMode(m.key);
                }
              }}
              data-hover
              className="px-4 py-1.5 text-xs font-display font-semibold tracking-wider transition-all duration-200"
              style={{
                background: runMode === m.key ? 'rgba(0,229,255,0.15)' : 'transparent',
                color: runMode === m.key ? 'var(--cyan)' : 'var(--text-mid)',
                borderRight: '1px solid rgba(0,229,255,0.1)',
                textShadow: runMode === m.key ? '0 0 8px rgba(0,229,255,0.5)' : 'none',
                opacity: flowState !== 'idle' && runMode !== m.key ? 0.3 : 1,
              }}
            >
              {m.label}
            </button>
          ))}
        </div>

        {/* Action buttons */}
        <div className="flex gap-2 ml-4">
          {/* In step mode, flow starts from login panel — hide START, show status only */}
          {runMode === 'full' && (
            <button
              onClick={startFlow}
              disabled={flowState === 'running' || flowState === 'paused'}
              data-hover
              className="px-5 py-1.5 font-display font-bold text-xs tracking-wider rounded-lg transition-all duration-300"
              style={{
                background: flowState === 'running' || flowState === 'paused'
                  ? 'rgba(255,171,0,0.1)'
                  : 'linear-gradient(135deg, rgba(0,229,255,0.2), rgba(255,0,229,0.15))',
                border: `1px solid ${flowState === 'running' || flowState === 'paused' ? 'var(--amber)' : 'var(--cyan)'}`,
                color: flowState === 'running' || flowState === 'paused' ? 'var(--amber)' : 'var(--cyan)',
                boxShadow: flowState === 'running' || flowState === 'paused' ? 'var(--glow-amber)' : 'var(--glow-cyan)',
                opacity: flowState === 'running' || flowState === 'paused' ? 0.6 : 1,
              }}
            >
              {flowState === 'running' ? '◉ RUNNING...' : flowState === 'paused' ? '⏸ PAUSED' : flowState === 'done' ? '▶ RUN AGAIN' : '▶ START'}
            </button>
          )}
          {runMode === 'step' && flowState !== 'idle' && (
            <div className="flex items-center gap-2 px-4 py-1.5 rounded-lg" style={{
              background: flowState === 'running' ? 'rgba(255,171,0,0.08)' : flowState === 'paused' ? 'rgba(160,120,200,0.08)' : flowState === 'done' ? 'rgba(78,201,160,0.08)' : 'transparent',
              border: `1px solid ${flowState === 'running' ? 'var(--amber)' : flowState === 'paused' ? 'var(--magenta)' : flowState === 'done' ? 'var(--lime)' : 'rgba(0,229,255,0.15)'}`,
            }}>
              <div className="w-2 h-2 rounded-full" style={{
                background: flowState === 'running' ? 'var(--amber)' : flowState === 'paused' ? 'var(--magenta)' : 'var(--lime)',
                animation: flowState !== 'done' ? 'pulse-glow 1s ease infinite' : 'none',
              }} />
              <span className="font-display text-xs tracking-wider" style={{
                color: flowState === 'running' ? 'var(--amber)' : flowState === 'paused' ? 'var(--magenta)' : 'var(--lime)',
              }}>
                {flowState === 'running' ? 'RUNNING' : flowState === 'paused' ? 'PAUSED' : 'COMPLETE'}
              </span>
            </div>
          )}
          <button
            onClick={resetFlow}
            data-hover
            className="px-3 py-1.5 font-display font-semibold text-xs tracking-wider rounded-lg transition-all duration-200"
            style={{
              background: 'transparent',
              border: '1px solid rgba(0,229,255,0.15)',
              color: 'var(--text-mid)',
            }}
          >
            ↺
          </button>
        </div>

        <div className="flex-1" />

        {/* Status */}
        <div className="flex items-center gap-3 text-xs font-code">
          <div className="flex items-center gap-2">
            <div className="w-2 h-2 rounded-full" style={{
              background: flowState === 'running' ? 'var(--amber)' : flowState === 'paused' ? 'var(--magenta)' : flowState === 'done' ? 'var(--lime)' : 'var(--cyan)',
              boxShadow: flowState === 'running' ? 'var(--glow-amber)' : flowState === 'paused' ? 'var(--glow-magenta)' : flowState === 'done' ? 'var(--glow-lime)' : 'var(--glow-cyan)',
              animation: flowState === 'running' ? 'pulse-glow 1s ease infinite' : flowState === 'paused' ? 'pulse-glow 2s ease infinite' : 'none',
            }} />
            <span style={{ color: 'var(--text-mid)' }}>
              {flowState === 'idle' ? 'READY' : flowState === 'running' ? 'RUNNING' : flowState === 'paused' ? 'PAUSED' : 'COMPLETE'}
            </span>
          </div>
          <span style={{ color: 'var(--text-dim)' }}>|</span>
          <span style={{ color: 'var(--text-mid)' }}>{(elapsed / 1000).toFixed(1)}s</span>
        </div>

        {/* Terminal toggle */}
        {runMode === 'step' && (
          <button
            onClick={() => setDetailsOpen(!detailsOpen)}
            data-hover
            className="ml-3 px-3 py-1.5 text-xs font-display font-semibold tracking-wider rounded-lg transition-all duration-200"
            style={{
              background: detailsOpen ? 'rgba(0,229,255,0.1)' : 'transparent',
              border: `1px solid ${detailsOpen ? 'var(--cyan)' : 'rgba(0,229,255,0.15)'}`,
              color: detailsOpen ? 'var(--cyan)' : 'var(--text-dim)',
            }}
          >
            {detailsOpen ? '✕ DETAILS' : 'ⓘ DETAILS'}
          </button>
        )}

        <button
          onClick={() => setTerminalOpen(!terminalOpen)}
          data-hover
          className="ml-3 px-3 py-1.5 text-xs font-display font-semibold tracking-wider rounded-lg transition-all duration-200"
          style={{
            background: terminalOpen ? 'rgba(0,229,255,0.1)' : 'transparent',
            border: `1px solid ${terminalOpen ? 'var(--cyan)' : 'rgba(0,229,255,0.15)'}`,
            color: terminalOpen ? 'var(--cyan)' : 'var(--text-dim)',
          }}
        >
          {terminalOpen ? '✕ TERMINAL' : '⟩_ TERMINAL'}
        </button>
      </header>

      {/* ═══ MAIN CONTENT ═══ */}
      <div className="flex-1 flex overflow-hidden relative z-10">
        {/* ─── LEFT: Login Platform Panel (step mode only) ─── */}
        {runMode === 'step' && (
          <div className="flex-shrink-0 overflow-hidden" style={{ width: '25%', minWidth: '280px', maxWidth: '360px' }}>
            <LoginPlatformPanel
              steps={steps}
              currentStepIdx={currentStepIdx}
              flowState={flowState}
              onLoginClick={runStepFlow}
              onAccountSelect={advanceFromLoginPanel}
              onConsentGrant={advanceFromLoginPanel}
            />
          </div>
        )}

        {/* ─── CENTER: Vertical Flow + Protocol Activity (inline) ─── */}
        <div className="flex-1 flex flex-col overflow-hidden">
          {/* Scrollable flow area */}
          <div ref={scrollContainerRef} className="flex-1 overflow-y-auto overflow-x-hidden">
            <VerticalFlowVisualizer
              steps={steps}
              selectedStep={selectedStep}
              flowState={flowState}
              runMode={runMode}
              waitingForClick={waitingForClick}
              currentStepIdx={currentStepIdx}
              onNodeClick={handleNodeClick}
              activeThreat={activeThreat}
              onDismissThreat={dismissThreat}
              scrollContainerRef={scrollContainerRef}
            />
          </div>

          {/* Protocol Activity — now inline at the bottom, adjusts with panels */}
          <ProtocolActivity currentStepId={selectedStep} flowState={flowState === 'paused' ? 'running' : flowState} />
        </div>

        {/* ─── RIGHT: Step Explanation (in step mode when step selected & done) ─── */}
        {runMode === 'step' && detailsOpen && activeStepObj && activeStepObj.status === 'done' && (flowState === 'paused' || flowState === 'done') && (
          <div className="w-[380px] flex-shrink-0 flex flex-col overflow-y-auto" style={{
            borderLeft: '1px solid rgba(0,229,255,0.08)',
            background: 'rgba(6, 13, 31, 0.85)',
            animation: 'slideInRight 0.3s ease',
          }}>
            <StepExplanation step={activeStepObj} threat={activeThreatInfo || undefined} />
          </div>
        )}

        {/* ─── RIGHT: Resizable Terminal ─── */}
        {terminalOpen && (
          <div
            className="flex-shrink-0 flex flex-col overflow-hidden relative"
            style={{
              width: `${terminalWidth}px`,
              borderLeft: '1px solid rgba(0,229,255,0.08)',
              background: 'rgba(2, 6, 20, 0.92)',
            }}
          >
            {/* Drag handle — left edge */}
            <div
              onMouseDown={handleTerminalDragStart}
              style={{
                position: 'absolute',
                left: 0,
                top: 0,
                bottom: 0,
                width: '6px',
                cursor: 'col-resize',
                zIndex: 10,
                background: 'transparent',
              }}
              onMouseEnter={(e) => { (e.target as HTMLElement).style.background = 'rgba(0,229,255,0.15)'; }}
              onMouseLeave={(e) => { if (!isDraggingRef.current) (e.target as HTMLElement).style.background = 'transparent'; }}
            />

            <div className="px-4 py-3 flex items-center gap-2 flex-shrink-0" style={{ borderBottom: '1px solid rgba(0,229,255,0.06)' }}>
              <div className="w-2 h-2 rounded-full" style={{ background: 'var(--lime)', boxShadow: '0 0 6px var(--lime)' }} />
              <span className="text-[10px] font-display tracking-[0.3em]" style={{ color: 'var(--text-dim)' }}>
                TERMINAL OUTPUT
              </span>
              <div className="flex-1" />
              <span className="text-[9px] font-code" style={{ color: 'var(--text-dim)', opacity: 0.5 }}>
                ← drag to resize
              </span>
            </div>
            <div ref={logBoxRef} className="flex-1 overflow-y-auto p-3 font-code leading-relaxed" style={{ fontSize: Math.max(12, Math.min(24, terminalWidth / 26)) + 'px' }}>
              {logs.length === 0 && (
                <div style={{ color: 'var(--text-dim)' }}>
                  <span className="neon-text">{'>'}</span> Waiting for flow execution...
                  <span className="inline-block w-2 h-4 ml-1" style={{
                    background: 'var(--cyan)',
                    animation: 'pulse-glow 1s ease infinite',
                  }} />
                </div>
              )}
              {logs.map((log, i) => (
                <div key={i} className="mb-0.5" style={{
                  color: log.level === 'ok' ? 'var(--lime)' :
                         log.level === 'err' ? 'var(--red)' :
                         log.level === 'warn' ? 'var(--amber)' :
                         log.level === 'data' ? 'var(--text-mid)' : 'var(--cyan)',
                  textShadow: log.level === 'ok' ? '0 0 4px rgba(57,255,20,0.3)' :
                              log.level === 'err' ? '0 0 4px rgba(255,23,68,0.3)' : 'none',
                }}>
                  {log.msg}
                </div>
              ))}
              {(flowState === 'running' || flowState === 'paused') && (
                <div className="mt-1 flex items-center gap-1">
                  <span className="neon-text">{'>'}</span>
                  <span className="inline-block w-2 h-4" style={{
                    background: flowState === 'paused' ? 'var(--magenta)' : 'var(--cyan)',
                    animation: 'pulse-glow 0.8s ease infinite',
                  }} />
                </div>
              )}
            </div>
          </div>
        )}
      </div>

      {/* ═══ STATUS BAR ═══ */}
      <footer className="relative z-20 h-8 flex items-center px-5 gap-6 text-[10px] font-code" style={{
        background: 'rgba(6,13,31,0.9)',
        borderTop: '1px solid rgba(0,229,255,0.08)',
      }}>
        <div className="flex items-center gap-2">
          <div className="w-1.5 h-1.5 rounded-full" style={{ background: 'var(--lime)', boxShadow: '0 0 4px var(--lime)' }} />
          <span style={{ color: 'var(--text-mid)' }}>{isBackendConnected ? 'CONNECTED' : 'DISCONNECTED'}</span>
        </div>
        <span style={{ color: 'var(--text-dim)' }}>│</span>
        <span style={{ color: 'var(--text-mid)' }}>MODE: <span className="neon-text">{runMode === 'full' ? 'FULL FLOW' : 'STEP-BY-STEP'}</span></span>
        <span style={{ color: 'var(--text-dim)' }}>│</span>
        <span style={{ color: 'var(--text-mid)' }}>CRYPTO: <span style={{ color: 'var(--lime)' }}>ML-KEM-768 + ML-DSA-65</span></span>
        {waitingForClick && (
          <>
            <span style={{ color: 'var(--text-dim)' }}>│</span>
            <span style={{ color: 'var(--magenta)', animation: 'pulse-glow 1.5s ease infinite' }}>
              PRESS SPACE OR CLICK NEXT STEP TO CONTINUE
            </span>
          </>
        )}
        <div className="flex-1" />
        <span style={{ color: 'var(--text-dim)' }}>HelloWorld v1.0 │ {new Date().toLocaleTimeString()}</span>
      </footer>
    </div>
  );
}

/* ══════════════════════════════════════════
   VERTICAL FLOW VISUALIZER
   Phases stacked vertically with BIGGER clickable nodes
   ══════════════════════════════════════════ */
function VerticalFlowVisualizer({ steps, selectedStep, flowState, runMode, waitingForClick, currentStepIdx, onNodeClick, activeThreat, onDismissThreat, scrollContainerRef }: {
  steps: FlowStep[];
  selectedStep: string | null;
  flowState: FlowState;
  runMode: RunMode;
  waitingForClick: boolean;
  currentStepIdx: number;
  onNodeClick: (stepId: string) => void;
  activeThreat: import('../components/ThreatPopup').ThreatInfo | null;
  onDismissThreat: () => void;
  scrollContainerRef: React.RefObject<HTMLDivElement | null>;
}) {
  const stepIndexMap = useMemo(() => {
    const map: Record<string, number> = {};
    INITIAL_STEPS.forEach((s, i) => {
      map[s.id] = i;
    });
    return map;
  }, []);
  const phaseRefs = useRef<(HTMLDivElement | null)[]>([]);
  const lastScrolledPhaseRef = useRef(-1);

  // Auto-scroll when a phase completes AND its threat is dismissed
  // i.e. when currentStepIdx reaches the first step of the NEXT phase
  useEffect(() => {
    PHASES.forEach((phase, pi) => {
      if (pi < PHASES.length - 1) {
        const nextPhaseFirstStepId = PHASES[pi + 1].stepIds[0];
        const nextPhaseFirstStepIdx = stepIndexMap[nextPhaseFirstStepId];

        // If we've reached or passed the first step of the next phase, we should scroll to it
        if (currentStepIdx >= nextPhaseFirstStepIdx && pi > lastScrolledPhaseRef.current) {
          lastScrolledPhaseRef.current = pi;
          const nextEl = phaseRefs.current[pi + 1];
          if (nextEl && scrollContainerRef.current) {
            setTimeout(() => {
              nextEl.scrollIntoView({ behavior: 'smooth', block: 'center' });
            }, 300);
          }
        }
      }
    });
  }, [currentStepIdx, scrollContainerRef, stepIndexMap]);

  // Reset scroll tracking on flow restart
  useEffect(() => {
    if (flowState === 'idle') {
      lastScrolledPhaseRef.current = -1;
    }
  }, [flowState]);

  return (
    <div className="flex flex-col items-center py-8 px-8 gap-0 min-h-full justify-center">
      {/* Idle hero */}
      {flowState === 'idle' && (
        <div className="text-center mb-8" style={{ animation: 'float 4s ease-in-out infinite' }}>
          <div className="font-display text-4xl font-bold tracking-widest mb-3" style={{
            background: 'linear-gradient(135deg, var(--cyan), var(--magenta))',
            WebkitBackgroundClip: 'text',
            WebkitTextFillColor: 'transparent',
            filter: 'drop-shadow(0 0 24px rgba(0,229,255,0.35))',
          }}>
            PQ-OIDC
          </div>
          <div className="text-sm font-code" style={{ color: 'var(--text-mid)' }}>
            Post-Quantum OpenID Connect over KEMTLS
          </div>
          <div className="mt-3 text-xs font-display tracking-widest" style={{ color: 'var(--text-dim)', animation: 'pulse-glow 2s ease infinite' }}>
            {runMode === 'full' ? 'PRESS START TO RUN FULL FLOW' : 'PRESS START FOR STEP-BY-STEP WALKTHROUGH'}
          </div>
        </div>
      )}

      {/* Done hero */}
      {flowState === 'done' && (
        <div className="text-center mb-6" style={{ animation: 'float 4s ease-in-out infinite' }}>
          <div className="font-display text-3xl font-bold tracking-widest neon-text-lime mb-2">
            ✓ FLOW COMPLETE
          </div>
          <div className="text-sm font-code" style={{ color: 'var(--text-mid)' }}>
            All 10 protocol steps executed successfully
          </div>
          <div className="flex gap-6 mt-4 justify-center">
            <StatChip label="HANDSHAKE" value="2.1ms" color="var(--cyan)" />
            <StatChip label="TOKEN SIZE" value="7.8KB" color="var(--magenta)" />
            <StatChip label="SIG SIZE" value="3293B" color="var(--violet)" />
            <StatChip label="TOTAL" value={`${(steps.reduce((a, s) => a + (s.durationMs || 0), 0) / 1000).toFixed(1)}s`} color="var(--lime)" />
          </div>
        </div>
      )}

      {/* Vertical phase layout */}
      {PHASES.map((phase, pi) => {
        const phaseSteps = steps.filter(s => phase.stepIds.includes(s.id));
        const phaseActive = phaseSteps.some(s => s.status !== 'idle');
        const phaseDone = phaseSteps.every(s => s.status === 'done');

        return (
          <div key={pi} ref={el => { phaseRefs.current[pi] = el; }} className="flex flex-col items-center w-full max-w-4xl">
            {/* Phase label */}
            <div className="text-xs font-display tracking-[0.3em] font-bold mb-3 transition-all duration-500" style={{
              color: phaseDone ? 'var(--lime)' : phase.color,
              textShadow: phaseActive ? `0 0 10px ${phase.color}` : 'none',
              opacity: phaseActive || flowState === 'idle' ? 1 : 0.35,
              fontSize: '13px',
            }}>
              {phaseDone ? `✓ ${phase.label}` : phase.label}
            </div>

            {/* Step nodes in a row */}
            <div className="flex items-start justify-center gap-12 w-full mb-2">
              {phaseSteps.map((step, si) => {
                const globalIdx = stepIndexMap[step.id];
                const isSelected = selectedStep === step.id;
                const isActive = step.status === 'running';
                const isDone = step.status === 'done';
                const isNextClickable = runMode === 'step' && waitingForClick && globalIdx === currentStepIdx + 1;

                const hasThreat = runMode === 'step' && activeThreat?.stepId === step.id;

                // Height of the node icon for centering the connector
                const nodeSize = isSelected ? 80 : 68;
                const connectorTop = nodeSize / 2;

                return (
                  <div key={step.id} className="flex items-start relative">
                    {/* Node */}
                    <button
                      onClick={() => onNodeClick(step.id)}
                      data-hover
                      className="relative flex flex-col items-center justify-start transition-all duration-400 group"
                      style={{ outline: 'none' }}
                    >
                      <div
                        className="relative flex items-center justify-center transition-all duration-500"
                        style={{
                          width: `${nodeSize}px`,
                          height: `${nodeSize}px`,
                        }}
                      >
                        {/* Glow ring */}
                        <div className="absolute inset-0 rounded-xl transition-all duration-500" style={{
                          border: `2px solid ${
                            isNextClickable ? 'var(--magenta)'
                            : isDone ? 'var(--lime)'
                            : isActive ? 'var(--amber)'
                            : isSelected ? phase.color
                            : 'rgba(92,168,212,0.12)'
                          }`,
                          boxShadow: isNextClickable ? '0 0 16px rgba(160,120,200,0.3), 0 0 30px rgba(160,120,200,0.1)'
                            : isDone ? '0 0 12px rgba(78,201,160,0.25), 0 0 24px rgba(78,201,160,0.08)'
                            : isActive ? '0 0 12px rgba(212,165,92,0.25), 0 0 24px rgba(212,165,92,0.08)'
                            : isSelected ? `0 0 10px color-mix(in srgb, ${phase.color} 30%, transparent)`
                            : 'none',
                          background: isDone ? 'rgba(78,201,160,0.06)'
                            : isActive ? 'rgba(212,165,92,0.06)'
                            : isNextClickable ? 'rgba(160,120,200,0.06)'
                            : 'rgba(92,168,212,0.02)',
                          animation: isActive ? 'glow-breathe 2s ease infinite'
                            : isNextClickable ? 'glow-breathe 1.5s ease infinite'
                            : 'none',
                          transform: isSelected ? 'scale(1.04)' : 'scale(1)',
                        }} />

                        {/* Inner label */}
                        <div className="relative z-10 font-display font-bold" style={{
                          fontSize: '16px',
                          color: isDone ? 'var(--lime)'
                            : isActive ? 'var(--amber)'
                            : isNextClickable ? 'var(--magenta)'
                            : 'var(--text-mid)',
                        }}>
                          {isDone ? '✓' : isActive ? '◉' : globalIdx + 1}
                        </div>

                        {/* Shimmer on active */}
                        {isActive && (
                          <div className="absolute inset-0 rounded-xl overflow-hidden">
                            <div className="absolute inset-0" style={{
                              background: 'linear-gradient(90deg, transparent 30%, rgba(212,165,92,0.1) 50%, transparent 70%)',
                              animation: 'shimmer 2s ease-in-out infinite',
                            }} />
                          </div>
                        )}

                        {/* Click indicator pulse */}
                        {isNextClickable && (
                          <div className="absolute inset-0 rounded-xl" style={{
                            border: '2px solid var(--magenta)',
                            animation: 'pulse-glow 1s ease infinite',
                            opacity: 0.4,
                          }} />
                        )}
                      </div>

                      {/* Step label */}
                      <div className="mt-2 font-display font-semibold text-center leading-tight transition-all duration-300" style={{
                        fontSize: '11px',
                        letterSpacing: '0.08em',
                        color: isDone ? 'var(--lime)'
                          : isActive ? 'var(--amber)'
                          : isNextClickable ? 'var(--magenta)'
                          : isSelected ? 'var(--text-glow)'
                          : 'var(--text-mid)',
                        maxWidth: '100px',
                      }}>
                        {step.label}
                      </div>

                      {/* Detail text */}
                      <div className="mt-1 font-code text-center leading-tight" style={{
                        fontSize: '9px',
                        color: 'var(--text-dim)',
                        maxWidth: '120px',
                        opacity: isSelected || isDone || isActive ? 0.7 : 0.35,
                      }}>
                        {step.detail.length > 30 ? step.detail.slice(0, 30) + '…' : step.detail}
                      </div>

                      {/* Duration badge */}
                      {step.durationMs && (
                        <div className="font-code mt-0.5" style={{ fontSize: '10px', color: 'var(--lime)' }}>
                          {step.durationMs}ms
                        </div>
                      )}
                    </button>

                    {/* Threat tooltip — Left for all except the first ('hello') node */}
                    {hasThreat && activeThreat && (() => {
                      // Keep tooltip in view: prefer right side for earlier nodes and
                      // left side only when we are far enough into the flow.
                      const showOnLeft = globalIdx >= 3;
                      const arrowColor = activeThreat.severity === 'critical' ? 'rgba(212,92,110,0.5)' : activeThreat.severity === 'high' ? 'rgba(212,140,92,0.5)' : 'rgba(212,165,92,0.5)';

                      return (
                        <div style={{
                          position: 'absolute',
                          top: `${connectorTop}px`,
                          ...(showOnLeft
                            ? { right: '100%', marginRight: '16px' }
                            : { left: '100%', marginLeft: '16px' }),
                          transform: 'translateY(-50%)',
                          width: 'min(320px, calc(100vw - 40px))',
                          zIndex: 50,
                          animation: showOnLeft ? 'slideInLeft 0.3s ease' : 'slideInRight 0.3s ease',
                          pointerEvents: 'auto',
                        }}>
                          <div style={{
                            position: 'absolute',
                            top: '50%',
                            transform: 'translateY(-50%)',
                            width: 0,
                            height: 0,
                            ...(showOnLeft
                              ? {
                                  right: '-8px',
                                  borderTop: '8px solid transparent',
                                  borderBottom: '8px solid transparent',
                                  borderLeft: `8px solid ${arrowColor}`,
                                }
                              : {
                                  left: '-8px',
                                  borderTop: '8px solid transparent',
                                  borderBottom: '8px solid transparent',
                                  borderRight: `8px solid ${arrowColor}`,
                                }),
                          }} />
                          <InlineThreatTooltip threat={activeThreat} onClose={onDismissThreat} />
                        </div>
                      );
                    })()}

                    {/* Horizontal connector — centered at node icon midpoint */}
                    {si < phaseSteps.length - 1 && (
                      <div style={{
                        position: 'absolute',
                        top: `${connectorTop}px`,
                        left: '100%',
                        transform: 'translateY(-50%)',
                        width: '40px',
                        height: '2px',
                        marginLeft: '4px',
                        borderRadius: '1px',
                        background: isDone
                          ? `linear-gradient(90deg, var(--lime), ${phase.color})`
                          : isActive
                          ? 'rgba(212,165,92,0.4)'
                          : 'rgba(92,168,212,0.12)',
                        boxShadow: isDone
                          ? `0 0 6px ${phase.color}`
                          : 'none',
                        transition: 'all 0.5s',
                        overflow: 'hidden',
                      }}>
                        {isActive && (
                          <div className="absolute inset-y-0 w-8 animate-[shimmer_1s_linear_infinite]" style={{
                            background: 'linear-gradient(90deg, transparent, rgba(255,255,255,0.3), transparent)',
                          }} />
                        )}
                      </div>
                    )}
                  </div>
                );
              })}
            </div>

            {/* Vertical connector to next phase */}
            {pi < PHASES.length - 1 && (
              <div className="flex flex-col items-center my-3">
                <div className="transition-all duration-500" style={{
                  width: '2px',
                  height: '40px',
                  borderRadius: '1px',
                  background: phaseDone
                    ? `linear-gradient(180deg, ${phase.color}, ${PHASES[pi + 1].color})`
                    : 'rgba(92,168,212,0.1)',
                  boxShadow: phaseDone
                    ? `0 0 8px color-mix(in srgb, ${PHASES[pi + 1].color} 30%, transparent)`
                    : 'none',
                }} />
                <div className="w-0 h-0" style={{
                  borderLeft: '6px solid transparent',
                  borderRight: '6px solid transparent',
                  borderTop: `8px solid ${phaseDone ? PHASES[pi + 1].color : 'rgba(92,168,212,0.1)'}`,
                  filter: phaseDone ? `drop-shadow(0 0 4px ${PHASES[pi + 1].color})` : 'none',
                  transition: 'all 0.5s',
                }} />
              </div>
            )}
          </div>
        );
      })}

      {/* Running indicator */}
      {flowState === 'running' && (
        <div className="mt-4 text-center">
          <div className="font-display text-base tracking-widest" style={{
            color: 'var(--amber)',
            textShadow: '0 0 10px rgba(255,171,0,0.5)',
            animation: 'pulse-glow 1.5s ease infinite',
          }}>
            EXECUTING FLOW...
          </div>
        </div>
      )}

      {/* Paused indicator */}
      {flowState === 'paused' && (
        <div className="mt-4 text-center">
          <div className="font-display text-base tracking-widest" style={{
            color: 'var(--magenta)',
            textShadow: '0 0 10px rgba(255,0,229,0.5)',
            animation: 'pulse-glow 2s ease infinite',
          }}>
            ⏸ PAUSED — CLICK THE NEXT STEP TO CONTINUE
          </div>
        </div>
      )}

      {/* Small bottom spacer */}
      <div className="h-4" />
    </div>
  );
}

/* ══════════════════════════════════════════
   INLINE THREAT TOOLTIP
   Compact threat bubble attached to the active node
   ══════════════════════════════════════════ */
function InlineThreatTooltip({ threat, onClose }: { threat: import('../components/ThreatPopup').ThreatInfo; onClose: () => void }) {
  const [phase, setPhase] = useState<'threat' | 'blocking' | 'blocked'>('threat');

  useEffect(() => {
    setPhase('threat');
    const t1 = setTimeout(() => setPhase('blocking'), 2000);
    const t2 = setTimeout(() => setPhase('blocked'), 3200);
    return () => { clearTimeout(t1); clearTimeout(t2); };
  }, [threat.id]);

  const severityColor = {
    critical: '#d45c6e',
    high: '#d4885c',
    medium: '#d4a55c',
  }[threat.severity];

  return (
    <div style={{
      borderRadius: '10px',
      background: 'linear-gradient(135deg, rgba(255, 23, 68, 0.06), rgba(10, 4, 8, 0.95))',
      border: `1px solid ${severityColor}50`,
      boxShadow: `0 0 16px ${severityColor}25, 0 4px 20px rgba(0,0,0,0.4)`,
      backdropFilter: 'blur(16px)',
      overflow: 'hidden',
    }}>
      {/* Animated top bar */}
      <div style={{
        height: '2px',
        background: phase === 'blocked'
          ? 'linear-gradient(90deg, var(--lime), var(--teal))'
          : `linear-gradient(90deg, transparent, ${severityColor}, transparent)`,
        backgroundSize: '200% 100%',
        animation: phase !== 'blocked' ? 'border-run 1.5s linear infinite' : 'none',
        transition: 'background 0.5s ease',
      }} />

      {/* Header */}
      <div style={{
        padding: '10px 12px 8px',
        display: 'flex',
        alignItems: 'center',
        gap: '8px',
        borderBottom: `1px solid ${severityColor}15`,
      }}>
        <div style={{ fontSize: '14px', flexShrink: 0 }}>
          {phase === 'blocked' ? '🛡️' : '⚠️'}
        </div>
        <div style={{ flex: 1, minWidth: 0 }}>
          <div className="font-display" style={{
            fontSize: '8px',
            letterSpacing: '0.2em',
            color: phase === 'blocked' ? 'var(--lime)' : severityColor,
            transition: 'color 0.4s',
          }}>
            {phase === 'blocked' ? '✓ THREAT NEUTRALIZED' : '⚡ THREAT DETECTED'}
          </div>
          <div className="font-display" style={{
            fontSize: '12px',
            fontWeight: 700,
            color: 'var(--text-glow)',
            letterSpacing: '0.05em',
          }}>
            {threat.title}
          </div>
        </div>
        <div className="font-display" style={{
          fontSize: '8px',
          fontWeight: 700,
          padding: '2px 6px',
          borderRadius: '3px',
          background: `${severityColor}20`,
          border: `1px solid ${severityColor}40`,
          color: severityColor,
          letterSpacing: '0.1em',
          flexShrink: 0,
        }}>
          {threat.severity.toUpperCase()}
        </div>
        <button
          onClick={(e) => { e.stopPropagation(); onClose(); }}
          data-hover
          style={{
            width: '24px',
            height: '24px',
            borderRadius: '5px',
            background: `${severityColor}15`,
            border: `1px solid ${severityColor}40`,
            color: severityColor,
            fontSize: '12px',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            flexShrink: 0,
            lineHeight: 1,
            cursor: 'pointer',
          }}
        >
          ✕
        </button>
      </div>

      {/* Body */}
      <div style={{ padding: '8px 12px 10px' }}>
        <div className="font-body" style={{
          fontSize: '11px',
          color: 'var(--text-bright)',
          lineHeight: 1.4,
          marginBottom: '8px',
        }}>
          {threat.description}
        </div>

        <div style={{
          padding: '8px 10px',
          borderRadius: '6px',
          background: phase === 'blocked' ? 'rgba(57,255,20,0.06)' : 'rgba(0,229,255,0.03)',
          border: `1px solid ${phase === 'blocked' ? 'rgba(57,255,20,0.25)' : 'rgba(0,229,255,0.1)'}`,
          transition: 'all 0.4s ease',
        }}>
          <div className="font-display" style={{
            fontSize: '8px',
            letterSpacing: '0.15em',
            color: phase === 'blocked' ? 'var(--lime)' : 'var(--cyan)',
            marginBottom: '3px',
            transition: 'color 0.4s',
          }}>
            {phase === 'blocked' ? '✓ BLOCKED BY' : 'PROTOCOL DEFENSE'}
          </div>
          <div className="font-body" style={{
            fontSize: '11px',
            color: phase === 'blocked' ? 'var(--lime)' : 'var(--text-bright)',
            lineHeight: 1.4,
            transition: 'color 0.4s',
            textShadow: phase === 'blocked' ? '0 0 4px rgba(57,255,20,0.2)' : 'none',
          }}>
            {threat.mitigation}
          </div>
        </div>

        {phase === 'blocking' && (
          <div style={{ marginTop: '8px' }}>
            <div style={{
              height: '2px',
              borderRadius: '1px',
              background: 'rgba(0,229,255,0.1)',
              overflow: 'hidden',
            }}>
              <div style={{
                height: '100%',
                background: 'linear-gradient(90deg, var(--cyan), var(--lime))',
                animation: 'progress-fill 1.2s ease forwards',
                boxShadow: '0 0 8px var(--lime)',
              }} />
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

/* ══════════════════════════════════════════
   STEP EXPLANATION PANEL (step-by-step mode)
   Shown on the right when paused at a step
   ══════════════════════════════════════════ */
function StepExplanation({ step, threat }: { step: FlowStep; threat?: { title: string; description: string; mitigation: string; severity: string } }) {
  return (
    <div className="p-5 flex flex-col gap-4">
      {/* Step header */}
      <div>
        <div className="text-[10px] font-display tracking-[0.3em] mb-1" style={{ color: 'var(--lime)' }}>
          ✓ STEP COMPLETE
        </div>
        <div className="font-display text-xl font-bold tracking-wider" style={{
          color: 'var(--text-glow)',
          textShadow: '0 0 10px rgba(0,229,255,0.35)',
        }}>
          {step.label}
        </div>
        <div className="text-sm font-code mt-1" style={{ color: 'var(--text-mid)' }}>
          {step.detail}
        </div>
      </div>

      {/* How it works */}
      <div style={{
        padding: '14px 16px',
        borderRadius: '10px',
        background: 'rgba(0, 229, 255, 0.05)',
        border: '1px solid rgba(0, 229, 255, 0.15)',
      }}>
        <div className="font-display text-[10px] tracking-[0.2em] mb-2" style={{ color: 'var(--cyan)' }}>
          ⚙ HOW IT WORKS
        </div>
        <div className="font-body text-[13px] leading-relaxed" style={{ color: 'var(--text-bright)' }}>
          {step.explanation}
        </div>
      </div>

      {/* Data inspector */}
      {step.data && (
        <div>
          <div className="font-display text-[10px] tracking-[0.2em] mb-2" style={{ color: 'var(--cyan)' }}>
            📊 DATA CAPTURED
          </div>
          <div className="flex flex-col gap-2">
            {Object.entries(step.data).map(([key, val]) => (
              <div key={key} className="rounded-lg p-3 transition-all duration-200" style={{
                background: 'rgba(0,229,255,0.04)',
                border: '1px solid rgba(0,229,255,0.08)',
              }}>
                <div className="text-[9px] font-display tracking-wider uppercase mb-0.5" style={{ color: 'var(--text-dim)' }}>
                  {key}
                </div>
                <div className="text-[12px] font-code break-all" style={{ color: 'var(--text-bright)' }}>
                  {val}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Active threat for this step */}
      {threat && (
        <div style={{
          padding: '14px 16px',
          borderRadius: '10px',
          background: 'rgba(255, 23, 68, 0.06)',
          border: '1px solid rgba(255, 23, 68, 0.25)',
        }}>
          <div className="font-display text-[10px] tracking-[0.2em] mb-2" style={{ color: 'var(--red)' }}>
            ⚠ THREAT AT THIS STEP
          </div>
          <div className="font-display text-sm font-bold mb-1" style={{ color: 'var(--red)', textShadow: '0 0 6px rgba(255,23,68,0.35)' }}>
            {threat.title}
          </div>
          <div className="font-body text-[12px] leading-relaxed mb-3" style={{ color: 'var(--text-bright)' }}>
            {threat.description}
          </div>

          <div style={{
            padding: '10px 12px',
            borderRadius: '8px',
            background: 'rgba(57, 255, 20, 0.06)',
            border: '1px solid rgba(57, 255, 20, 0.25)',
          }}>
            <div className="font-display text-[10px] tracking-[0.2em] mb-1" style={{ color: 'var(--lime)' }}>
              🛡️ BLOCKED BY
            </div>
            <div className="font-body text-[12px] leading-relaxed" style={{ color: 'var(--lime)' }}>
              {threat.mitigation}
            </div>
          </div>
        </div>
      )}

      {/* Continue prompt */}
      <div className="text-center mt-2 font-display text-xs tracking-widest" style={{
        color: 'var(--magenta)',
        animation: 'pulse-glow 2s ease infinite',
      }}>
        CLICK NEXT STEP NODE TO CONTINUE →
      </div>
    </div>
  );
}

/* ══════════════════════════════════════════
   STAT CHIP (completion summary)
   ══════════════════════════════════════════ */
function StatChip({ label, value, color }: { label: string; value: string; color: string }) {
  return (
    <div className="text-center px-5 py-3 rounded-lg transition-all duration-200" style={{
      background: `${color}0a`,
      border: `1px solid ${color}35`,
    }}>
      <div className="text-[9px] font-display tracking-widest mb-1" style={{ color: `${color}90` }}>{label}</div>
      <div className="text-base font-display font-bold" style={{ color, textShadow: `0 0 10px ${color}` }}>{value}</div>
    </div>
  );
}
