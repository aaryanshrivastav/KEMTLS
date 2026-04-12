import { useState, useEffect, useCallback } from 'react';

/* ═══════════════════════════════════════════
   THREAT DEFINITIONS — mapped to flow step IDs
   ═══════════════════════════════════════════ */
export interface ThreatInfo {
  id: string;
  stepId: string;
  title: string;
  description: string;
  mitigation: string;
  severity: 'critical' | 'high' | 'medium';
  icon: string;
}

export const THREATS: ThreatInfo[] = [
  {
    id: 'harvest-now',
    stepId: 'hello',
    title: 'HARVEST NOW, DECRYPT LATER',
    description: 'Adversary records TLS traffic today to decrypt with future quantum computers.',
    mitigation: 'ML-KEM-768 key exchange ensures quantum-resistant forward secrecy from the very first handshake message.',
    severity: 'critical',
    icon: '🔓',
  },
  {
    id: 'cert-forge',
    stepId: 'server',
    title: 'CERTIFICATE FORGERY',
    description: 'Quantum adversary forges RSA/ECDSA server certificates using Shor\'s algorithm.',
    mitigation: 'ML-DSA-65 post-quantum digital signatures on the certificate chain prevent quantum forgery attacks.',
    severity: 'critical',
    icon: '📜',
  },
  {
    id: 'mitm',
    stepId: 'derive',
    title: 'MAN-IN-THE-MIDDLE',
    description: 'Attacker intercepts handshake to inject their own keys and eavesdrop on all traffic.',
    mitigation: 'HKDF-SHA256 key schedule binds shared secrets to handshake transcript — any tampering is detected.',
    severity: 'high',
    icon: '👁️',
  },
  {
    id: 'replay',
    stepId: 'finished',
    title: 'REPLAY ATTACK',
    description: 'Attacker captures and replays valid handshake messages to hijack sessions.',
    mitigation: 'Handshake MAC with fresh nonces ensures each session is unique and replay attempts fail verification.',
    severity: 'high',
    icon: '🔄',
  },
  {
    id: 'redirect-hijack',
    stepId: 'authorize',
    title: 'REDIRECT HIJACKING',
    description: 'Attacker intercepts the OIDC authorize redirect to capture the authorization code before the legitimate client.',
    mitigation: 'PKCE (S256) code challenge ensures only the client that initiated the flow can exchange the authorization code.',
    severity: 'critical',
    icon: '🔀',
  },
  {
    id: 'credential-phish',
    stepId: 'account_auth',
    title: 'CREDENTIAL PHISHING',
    description: 'Fake login page harvests user credentials by impersonating the identity provider.',
    mitigation: 'Authentication happens at the real IdP over the PQ-secure KEMTLS channel — the relying party never sees user credentials.',
    severity: 'high',
    icon: '🎣',
  },
  {
    id: 'auth-code-intercept',
    stepId: 'consent',
    title: 'AUTHORIZATION CODE THEFT',
    description: 'Attacker intercepts the authorization code during the redirect back to the relying party.',
    mitigation: 'PKCE verifier + state parameter validation ensure the code can only be used by the original requestor over the same session.',
    severity: 'high',
    icon: '📋',
  },
  {
    id: 'token-theft',
    stepId: 'token_exchange',
    title: 'TOKEN INTERCEPTION',
    description: 'Attacker intercepts OIDC tokens during exchange to impersonate the user.',
    mitigation: 'PQ-signed tokens (ML-DSA-65) + PKCE code verifier ensure only the legitimate client can exchange tokens.',
    severity: 'critical',
    icon: '🎫',
  },
  {
    id: 'session-hijack',
    stepId: 'session_bind',
    title: 'SESSION HIJACKING',
    description: 'Attacker steals session credentials and uses them from a different TLS connection.',
    mitigation: 'Session binding (cnf.kbh = SHA256(tls-exporter || session_id)) cryptographically ties tokens to this specific KEMTLS channel.',
    severity: 'high',
    icon: '🔗',
  },
  {
    id: 'token-misuse',
    stepId: 'resource_access',
    title: 'STOLEN TOKEN MISUSE',
    description: 'Attacker uses an exfiltrated access token from a different device/connection.',
    mitigation: 'Session-bound tokens are tied to the KEMTLS channel. The resource server verifies the binding claim against the active session, preventing token reuse from different connections.',
    severity: 'medium',
    icon: '🛡️',
  },
  {
    id: 'refresh-replay',
    stepId: 'refresh_token',
    title: 'REFRESH TOKEN REPLAY',
    description: 'Attacker reuses a stolen or previously used refresh token to mint new access tokens.',
    mitigation: 'Refresh token rotation with reuse detection invalidates stale tokens and revokes the family on replay attempts.',
    severity: 'high',
    icon: '♻️',
  },
];

/* ═══════════════════════════════════════════
   THREAT POPUP COMPONENT
   Now on the LEFT side, with manual X dismiss
   ═══════════════════════════════════════════ */
interface ThreatPopupProps {
  threat: ThreatInfo | null;
  onClose: () => void;
}

export function ThreatPopup({ threat, onClose }: ThreatPopupProps) {
  const [phase, setPhase] = useState<'enter' | 'threat' | 'blocking' | 'blocked'>('enter');
  const [glitchText, setGlitchText] = useState(false);

  useEffect(() => {
    if (!threat) {
      setPhase('enter');
      return;
    }

    setPhase('enter');
    setGlitchText(true);

    const timers: ReturnType<typeof setTimeout>[] = [];
    timers.push(setTimeout(() => { setPhase('threat'); setGlitchText(false); }, 300));
    timers.push(setTimeout(() => setPhase('blocking'), 2200));
    timers.push(setTimeout(() => setPhase('blocked'), 3400));
    // NO auto-dismiss — user must click X

    return () => timers.forEach(clearTimeout);
  }, [threat]);

  if (!threat) return null;

  const severityColor = {
    critical: '#ff1744',
    high: '#ff6d00',
    medium: '#ffab00',
  }[threat.severity];

  const severityGlow = {
    critical: '0 0 20px rgba(255, 23, 68, 0.4), 0 0 60px rgba(255, 23, 68, 0.15)',
    high: '0 0 20px rgba(255, 109, 0, 0.4), 0 0 60px rgba(255, 109, 0, 0.15)',
    medium: '0 0 20px rgba(255, 171, 0, 0.4), 0 0 60px rgba(255, 171, 0, 0.15)',
  }[threat.severity];

  return (
    <div
      className="fixed z-50"
      style={{
        top: '80px',
        left: '24px',
        width: '380px',
        opacity: phase === 'enter' ? 0 : 1,
        transform: phase === 'enter'
          ? 'translateX(-100px) scale(0.9)'
          : 'translateX(0) scale(1)',
        transition: 'opacity 0.4s ease, transform 0.4s ease',
      }}
    >
      {/* Threat card */}
      <div
        style={{
          background: 'linear-gradient(135deg, rgba(255, 23, 68, 0.08), rgba(20, 6, 10, 0.95))',
          border: `1px solid ${severityColor}60`,
          borderRadius: '12px',
          boxShadow: severityGlow,
          backdropFilter: 'blur(20px)',
          overflow: 'hidden',
          position: 'relative',
        }}
      >
        {/* Scanline effect */}
        <div
          style={{
            position: 'absolute',
            inset: 0,
            background: 'repeating-linear-gradient(0deg, transparent, transparent 2px, rgba(255,23,68,0.02) 2px, rgba(255,23,68,0.02) 4px)',
            pointerEvents: 'none',
            zIndex: 1,
          }}
        />

        {/* Animated top bar */}
        <div
          style={{
            height: '3px',
            background: phase === 'blocked'
              ? 'linear-gradient(90deg, var(--lime), var(--teal))'
              : `linear-gradient(90deg, transparent, ${severityColor}, transparent)`,
            backgroundSize: '200% 100%',
            animation: phase !== 'blocked' ? 'border-run 1.5s linear infinite' : 'none',
            transition: 'background 0.5s ease',
          }}
        />

        {/* Header */}
        <div
          style={{
            padding: '14px 16px 10px',
            display: 'flex',
            alignItems: 'center',
            gap: '10px',
            borderBottom: `1px solid ${severityColor}20`,
          }}
        >
          <div
            style={{
              width: '36px',
              height: '36px',
              borderRadius: '8px',
              background: `${severityColor}15`,
              border: `1px solid ${severityColor}40`,
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              fontSize: '18px',
              animation: phase === 'threat' ? 'pulse-glow 0.8s ease infinite' : 'none',
              boxShadow: phase === 'blocked' ? '0 0 10px rgba(57,255,20,0.3)' : `0 0 10px ${severityColor}30`,
              transition: 'box-shadow 0.5s ease',
            }}
          >
            {phase === 'blocked' ? '🛡️' : '⚠️'}
          </div>

          <div style={{ flex: 1, minWidth: 0 }}>
            <div
              className="font-display"
              style={{
                fontSize: '9px',
                letterSpacing: '0.25em',
                color: phase === 'blocked' ? 'var(--lime)' : severityColor,
                marginBottom: '2px',
                textShadow: phase === 'blocked' ? '0 0 6px rgba(57,255,20,0.4)' : `0 0 6px ${severityColor}60`,
                transition: 'color 0.5s, text-shadow 0.5s',
              }}
            >
              {phase === 'blocked' ? '✓ THREAT NEUTRALIZED' : '⚡ THREAT DETECTED'}
            </div>
            <div
              className="font-display"
              style={{
                fontSize: '13px',
                fontWeight: 700,
                color: glitchText ? severityColor : 'var(--text-glow)',
                letterSpacing: '0.1em',
                transition: 'color 0.3s',
              }}
            >
              {threat.title}
            </div>
          </div>

          {/* Severity badge */}
          <div
            className="font-display"
            style={{
              fontSize: '9px',
              fontWeight: 700,
              padding: '3px 8px',
              borderRadius: '4px',
              background: `${severityColor}20`,
              border: `1px solid ${severityColor}40`,
              color: severityColor,
              letterSpacing: '0.15em',
            }}
          >
            {threat.severity.toUpperCase()}
          </div>

          {/* X close button */}
          <button
            onClick={onClose}
            data-hover
            style={{
              width: '28px',
              height: '28px',
              borderRadius: '6px',
              background: 'rgba(255, 23, 68, 0.1)',
              border: '1px solid rgba(255, 23, 68, 0.3)',
              color: severityColor,
              fontSize: '14px',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              transition: 'all 0.2s',
              flexShrink: 0,
              pointerEvents: 'auto',
              lineHeight: 1,
            }}
            onMouseEnter={(e) => {
              (e.target as HTMLElement).style.background = 'rgba(255, 23, 68, 0.3)';
              (e.target as HTMLElement).style.borderColor = severityColor;
            }}
            onMouseLeave={(e) => {
              (e.target as HTMLElement).style.background = 'rgba(255, 23, 68, 0.1)';
              (e.target as HTMLElement).style.borderColor = 'rgba(255, 23, 68, 0.3)';
            }}
          >
            ✕
          </button>
        </div>

        {/* Body */}
        <div style={{ padding: '12px 16px', position: 'relative', zIndex: 2 }}>
          {/* Attack description */}
          <div
            style={{
              marginBottom: '12px',
              padding: '10px 12px',
              borderRadius: '8px',
              background: `${severityColor}08`,
              border: `1px solid ${severityColor}15`,
            }}
          >
            <div
              className="font-display"
              style={{
                fontSize: '9px',
                letterSpacing: '0.2em',
                color: severityColor,
                marginBottom: '4px',
                opacity: 0.8,
              }}
            >
              ATTACK VECTOR
            </div>
            <div
              className="font-body"
              style={{ fontSize: '12px', color: 'var(--text-bright)', lineHeight: 1.5 }}
            >
              {threat.description}
            </div>
          </div>

          {/* Mitigation */}
          <div
            style={{
              padding: '10px 12px',
              borderRadius: '8px',
              background: phase === 'blocking' || phase === 'blocked'
                ? 'rgba(57, 255, 20, 0.06)'
                : 'rgba(0, 229, 255, 0.03)',
              border: `1px solid ${
                phase === 'blocked' ? 'rgba(57, 255, 20, 0.3)'
                : phase === 'blocking' ? 'rgba(57, 255, 20, 0.15)'
                : 'rgba(0, 229, 255, 0.1)'
              }`,
              transition: 'all 0.5s ease',
            }}
          >
            <div
              className="font-display"
              style={{
                fontSize: '9px',
                letterSpacing: '0.2em',
                color: phase === 'blocked' ? 'var(--lime)' : 'var(--cyan)',
                marginBottom: '4px',
                transition: 'color 0.5s',
              }}
            >
              {phase === 'blocked' ? '✓ BLOCKED BY' : 'PROTOCOL DEFENSE'}
            </div>
            <div
              className="font-body"
              style={{
                fontSize: '12px',
                color: phase === 'blocked' ? 'var(--lime)' : 'var(--text-bright)',
                lineHeight: 1.5,
                transition: 'color 0.5s',
                textShadow: phase === 'blocked' ? '0 0 4px rgba(57,255,20,0.2)' : 'none',
              }}
            >
              {threat.mitigation}
            </div>
          </div>

          {/* Progress bar */}
          {(phase === 'blocking') && (
            <div style={{ marginTop: '10px' }}>
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
    </div>
  );
}

/* ═══════════════════════════════════════════
   HOOK: manage threat queue
   ═══════════════════════════════════════════ */
export function useThreatPopups() {
  const [activeThreat, setActiveThreat] = useState<ThreatInfo | null>(null);

  const triggerThreat = useCallback((stepId: string) => {
    const threat = THREATS.find(t => t.stepId === stepId);
    if (!threat) return;

    // Always sync popup to the current step threat immediately.
    setActiveThreat(prev => (prev?.id === threat.id ? prev : threat));
  }, []);

  const dismissThreat = useCallback(() => {
    setActiveThreat(null);
  }, []);

  return { activeThreat, triggerThreat, dismissThreat };
}
