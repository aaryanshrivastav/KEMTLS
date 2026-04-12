import { useMemo, useState } from 'react';

/* ═══════════════════════════════════════════
   LOGIN PLATFORM PANEL
   Shows a realistic login flow on the left 25%
   of the screen in step-by-step mode.
   Transitions through stages as protocol nodes complete.
   User interactions on this panel drive the step flow.
   ═══════════════════════════════════════════ */

interface FlowStep {
  id: string;
  status: 'idle' | 'running' | 'done' | 'error';
}

interface LoginPlatformPanelProps {
  steps: FlowStep[];
  currentStepIdx: number;
  flowState: 'idle' | 'running' | 'paused' | 'done';
  onLoginClick: () => void;
  onAccountSelect: () => void;
  onConsentGrant: () => void;
}

const ACCOUNTS = [
  { name: 'Uzair Shaikh', email: 'uzair@gmail.com', initial: 'U', gradient: 'linear-gradient(135deg, #4285F4, #34A853)' },
  { name: 'Samagra', email: 'samagra@gmail.com', initial: 'S', gradient: 'linear-gradient(135deg, var(--cyan), var(--magenta))' },
  { name: 'Aaryan', email: 'aaryan@gmail.com', initial: 'A', gradient: 'linear-gradient(135deg, #EA4335, #FBBC05)' },
];

/*
  Stage mapping:
  0 — Login page (idle, no nodes active)
  1 — Redirecting to Google (nodes 0–4: hello, server, derive, finished, authorize)
  2 — Account selection (node 5: account_auth)
  3 — Consent screen (node 6: consent)
  4 — Returning to platform (node 7: token_exchange)
  5 — Creating secure session (node 8: session_bind)
  6 — Dashboard / logged in (node 9: resource_access completes)
*/

function deriveStage(steps: FlowStep[], currentStepIdx: number, flowState: string): number {
  if (flowState === 'idle') return 0;
  if (flowState === 'done') return 6;

  // Node 0-3 (hello through finished)
  if (currentStepIdx >= 0 && currentStepIdx <= 3) return 1;
  
  // Node 4 (authorize) and Node 5 (account_auth) -> Stage 2 (Choose Account)
  if (currentStepIdx === 4 ) return 2;
  
  // Node 6 (consent) -> Stage 3 (Consent)
  if (currentStepIdx === 5) return 3;
  
  // Node 7 (token_exchange) -> Stage 4 (Returning)
  if (currentStepIdx === 6) return 4;
  
  // Node 8 (session_bind) -> Stage 5 (Securing)
  if (currentStepIdx === 7) return 5;
  
  // Node 9 (resource_access)
  if (currentStepIdx === 8 || currentStepIdx === 9) return 6;

  return 0;
}

export function LoginPlatformPanel({ steps, currentStepIdx, flowState, onLoginClick, onAccountSelect, onConsentGrant }: LoginPlatformPanelProps) {
  const stage = useMemo(() => deriveStage(steps, currentStepIdx, flowState), [steps, currentStepIdx, flowState]);

  // Check if the flow is paused and waiting for user interaction on the login panel
  const isWaitingForAccount = stage === 2 && flowState === 'paused';
  const isWaitingForConsent = stage === 3 && flowState === 'paused';

  return (
    <div style={{
      width: '100%',
      height: '100%',
      display: 'flex',
      flexDirection: 'column',
      background: 'rgba(6, 13, 31, 0.92)',
      borderRight: '1px solid rgba(92, 168, 212, 0.08)',
      position: 'relative',
      overflow: 'hidden',
    }}>
      {/* Panel header */}
      <div style={{
        padding: '12px 16px',
        borderBottom: '1px solid rgba(92, 168, 212, 0.06)',
        display: 'flex',
        alignItems: 'center',
        gap: '8px',
        flexShrink: 0,
      }}>
        <div style={{
          width: '6px',
          height: '6px',
          borderRadius: '50%',
          background: stage === 6 ? 'var(--lime)' : isWaitingForAccount || isWaitingForConsent ? 'var(--magenta)' : stage > 0 ? 'var(--amber)' : 'var(--cyan)',
          boxShadow: stage === 6 ? '0 0 6px var(--lime)' : isWaitingForAccount || isWaitingForConsent ? '0 0 6px var(--magenta)' : stage > 0 ? '0 0 6px var(--amber)' : '0 0 6px var(--cyan)',
          animation: stage > 0 && stage < 6 ? 'pulse-glow 1s ease infinite' : 'none',
        }} />
        <span className="font-display" style={{
          fontSize: '9px',
          letterSpacing: '0.25em',
          color: 'var(--text-dim)',
        }}>
          USER PLATFORM VIEW
        </span>
        {(isWaitingForAccount || isWaitingForConsent) && (
          <span className="font-display" style={{
            fontSize: '8px',
            letterSpacing: '0.15em',
            color: 'var(--magenta)',
            marginLeft: 'auto',
            animation: 'pulse-glow 1.5s ease infinite',
          }}>
            AWAITING INPUT
          </span>
        )}
      </div>

      {/* Stage content */}
      <div style={{
        flex: 1,
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        padding: '20px 16px',
      }}>
        {stage === 0 && <StageLogin onLoginClick={onLoginClick} />}
        {stage === 1 && <StageRedirecting />}
        {stage === 2 && <StageAccountSelect onSelect={onAccountSelect} isWaiting={isWaitingForAccount} />}
        {stage === 3 && <StageConsent onContinue={onConsentGrant} isWaiting={isWaitingForConsent} />}
        {stage === 4 && <StageReturning />}
        {stage === 5 && <StageSecuring />}
        {stage === 6 && <StageDashboard />}
      </div>

      {/* Stage indicator bar */}
      <div style={{
        padding: '10px 16px',
        borderTop: '1px solid rgba(92, 168, 212, 0.06)',
        display: 'flex',
        alignItems: 'center',
        gap: '4px',
        flexShrink: 0,
      }}>
        {[0, 1, 2, 3, 4, 5, 6].map(i => (
          <div key={i} style={{
            flex: 1,
            height: '2px',
            borderRadius: '1px',
            background: i <= stage ? (i === stage && stage < 6 ? 'var(--amber)' : 'var(--lime)') : 'rgba(92, 168, 212, 0.1)',
            transition: 'background 0.4s ease',
            boxShadow: i <= stage ? `0 0 4px ${i === stage && stage < 6 ? 'var(--amber)' : 'var(--lime)'}` : 'none',
          }} />
        ))}
      </div>
    </div>
  );
}


/* ── STAGE 0: Login Page ── */
function StageLogin({ onLoginClick }: { onLoginClick: () => void }) {
  return (
    <div style={{
      width: '100%',
      maxWidth: '280px',
      display: 'flex',
      flexDirection: 'column',
      alignItems: 'center',
      gap: '24px',
    }}>
      {/* App logo */}
      <div style={{ textAlign: 'center' }}>
        <div className="font-display" style={{
          fontSize: '22px',
          fontWeight: 700,
          letterSpacing: '0.12em',
          background: 'linear-gradient(135deg, var(--cyan), var(--magenta))',
          WebkitBackgroundClip: 'text',
          WebkitTextFillColor: 'transparent',
          marginBottom: '4px',
        }}>
          SecureApp
        </div>
        <div className="font-code" style={{ fontSize: '10px', color: 'var(--text-dim)' }}>
          Post-Quantum Protected Platform
        </div>
      </div>

      {/* Login card */}
      <div style={{
        width: '100%',
        padding: '24px 20px',
        borderRadius: '12px',
        background: 'rgba(22, 31, 53, 0.6)',
        border: '1px solid rgba(92, 168, 212, 0.12)',
        backdropFilter: 'blur(12px)',
        display: 'flex',
        flexDirection: 'column',
        gap: '16px',
      }}>
        <div className="font-body" style={{
          fontSize: '16px',
          fontWeight: 600,
          color: 'var(--text-glow)',
          textAlign: 'center',
        }}>
          Sign in
        </div>

        <div className="font-body" style={{
          fontSize: '12px',
          color: 'var(--text-mid)',
          textAlign: 'center',
        }}>
          to continue to SecureApp
        </div>

        {/* Google Sign-in Button */}
        <button
          onClick={onLoginClick}
          data-hover
          style={{
            width: '100%',
            padding: '10px 16px',
            borderRadius: '8px',
            background: 'rgba(255, 255, 255, 0.05)',
            border: '1px solid rgba(255, 255, 255, 0.15)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            gap: '10px',
            transition: 'all 0.2s ease',
            outline: 'none',
            cursor: 'pointer',
          }}
          onMouseEnter={(e) => {
            (e.currentTarget as HTMLElement).style.background = 'rgba(255, 255, 255, 0.1)';
            (e.currentTarget as HTMLElement).style.borderColor = 'rgba(92, 168, 212, 0.4)';
            (e.currentTarget as HTMLElement).style.boxShadow = '0 0 12px rgba(92, 168, 212, 0.15)';
          }}
          onMouseLeave={(e) => {
            (e.currentTarget as HTMLElement).style.background = 'rgba(255, 255, 255, 0.05)';
            (e.currentTarget as HTMLElement).style.borderColor = 'rgba(255, 255, 255, 0.15)';
            (e.currentTarget as HTMLElement).style.boxShadow = 'none';
          }}
        >
          {/* Google G icon */}
          <svg width="18" height="18" viewBox="0 0 24 24">
            <path d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92a5.06 5.06 0 0 1-2.2 3.32v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.1z" fill="#4285F4"/>
            <path d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z" fill="#34A853"/>
            <path d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z" fill="#FBBC05"/>
            <path d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z" fill="#EA4335"/>
          </svg>
          <span className="font-body" style={{
            fontSize: '13px',
            fontWeight: 500,
            color: 'var(--text-glow)',
          }}>
            Continue with Google
          </span>
        </button>

        {/* Divider */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
          <div style={{ flex: 1, height: '1px', background: 'rgba(92, 168, 212, 0.1)' }} />
          <span className="font-code" style={{ fontSize: '9px', color: 'var(--text-dim)' }}>or</span>
          <div style={{ flex: 1, height: '1px', background: 'rgba(92, 168, 212, 0.1)' }} />
        </div>

        {/* Disabled email field */}
        <div style={{
          padding: '10px 14px',
          borderRadius: '8px',
          background: 'rgba(22, 31, 53, 0.4)',
          border: '1px solid rgba(92, 168, 212, 0.08)',
          opacity: 0.4,
        }}>
          <span className="font-body" style={{ fontSize: '12px', color: 'var(--text-dim)' }}>
            Email address
          </span>
        </div>
      </div>

      <div className="font-code" style={{ fontSize: '9px', color: 'var(--text-dim)', textAlign: 'center' }}>
        Protected by Post-Quantum KEMTLS
      </div>
    </div>
  );
}


/* ── STAGE 1: Redirecting ── */
function StageRedirecting() {
  return (
    <div style={{
      textAlign: 'center',
      display: 'flex',
      flexDirection: 'column',
      alignItems: 'center',
      gap: '20px',
      animation: 'slideInRight 0.3s ease',
    }}>
      <div style={{
        width: '48px',
        height: '48px',
        borderRadius: '50%',
        border: '2px solid rgba(92, 168, 212, 0.15)',
        borderTopColor: 'var(--cyan)',
        animation: 'hex-rotate 1s linear infinite',
      }} />
      <div>
        <div className="font-display" style={{
          fontSize: '13px',
          letterSpacing: '0.15em',
          color: 'var(--cyan)',
          marginBottom: '6px',
        }}>
          ESTABLISHING SECURE CHANNEL
        </div>
        <div className="font-code" style={{ fontSize: '11px', color: 'var(--text-mid)' }}>
          Redirecting to Google...
        </div>
        <div className="font-code" style={{ fontSize: '9px', color: 'var(--text-dim)', marginTop: '8px' }}>
          PQ-KEMTLS handshake in progress
        </div>
      </div>
    </div>
  );
}


/* ── STAGE 2: Google Account Selection ── */
function StageAccountSelect({ onSelect, isWaiting }: { onSelect: () => void; isWaiting: boolean }) {
  const [hoveredIdx, setHoveredIdx] = useState<number | null>(null);

  return (
    <div style={{
      width: '100%',
      maxWidth: '280px',
      display: 'flex',
      flexDirection: 'column',
      gap: '12px',
      animation: 'slideInRight 0.3s ease',
    }}>
      {/* Google header */}
      <div style={{ textAlign: 'center' }}>
        <div className="font-body" style={{ fontSize: '18px', fontWeight: 600, color: 'var(--text-glow)' }}>
          Choose an account
        </div>
        <div className="font-code" style={{ fontSize: '10px', color: 'var(--text-mid)', marginTop: '4px' }}>
          to continue to secureapp.example
        </div>
      </div>

      {/* Account cards */}
      {ACCOUNTS.map((account, i) => (
        <button
          key={account.email}
          onClick={isWaiting ? onSelect : undefined}
          data-hover
          style={{
            padding: '12px 14px',
            borderRadius: '10px',
            background: hoveredIdx === i && isWaiting ? 'rgba(92, 168, 212, 0.1)' : 'rgba(92, 168, 212, 0.04)',
            border: `1px solid ${hoveredIdx === i && isWaiting ? 'rgba(92, 168, 212, 0.3)' : 'rgba(92, 168, 212, 0.1)'}`,
            display: 'flex',
            alignItems: 'center',
            gap: '12px',
            width: '100%',
            textAlign: 'left',
            outline: 'none',
            cursor: isWaiting ? 'pointer' : 'default',
            transition: 'all 0.2s ease',
            opacity: isWaiting ? 1 : 0.5,
            pointerEvents: isWaiting ? 'auto' : 'none',
          }}
          onMouseEnter={() => setHoveredIdx(i)}
          onMouseLeave={() => setHoveredIdx(null)}
        >
          {/* Avatar */}
          <div style={{
            width: '36px',
            height: '36px',
            borderRadius: '50%',
            background: account.gradient,
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            fontSize: '14px',
            fontWeight: 700,
            color: '#fff',
            flexShrink: 0,
          }}>
            {account.initial}
          </div>
          <div style={{ flex: 1, minWidth: 0 }}>
            <div className="font-body" style={{ fontSize: '13px', fontWeight: 600, color: 'var(--text-glow)' }}>
              {account.name}
            </div>
            <div className="font-code" style={{ fontSize: '10px', color: 'var(--text-mid)' }}>
              {account.email}
            </div>
          </div>
          {isWaiting && hoveredIdx === i && (
            <div style={{
              width: '6px',
              height: '6px',
              borderRadius: '50%',
              background: 'var(--cyan)',
              boxShadow: '0 0 6px var(--cyan)',
            }} />
          )}
        </button>
      ))}

      <div className="font-code" style={{ fontSize: '9px', color: isWaiting ? 'var(--magenta)' : 'var(--text-dim)', textAlign: 'center', transition: 'color 0.3s' }}>
        {isWaiting ? '↑ Select an account to continue' : 'Authenticating via PQ-secure channel'}
      </div>
    </div>
  );
}


/* ── STAGE 3: Consent Screen ── */
function StageConsent({ onContinue, isWaiting }: { onContinue: () => void; isWaiting: boolean }) {
  return (
    <div style={{
      width: '100%',
      maxWidth: '280px',
      display: 'flex',
      flexDirection: 'column',
      gap: '16px',
      animation: 'slideInRight 0.3s ease',
    }}>
      <div style={{ textAlign: 'center' }}>
        <div className="font-body" style={{ fontSize: '14px', fontWeight: 600, color: 'var(--text-glow)' }}>
          SecureApp wants to access
        </div>
        <div className="font-body" style={{ fontSize: '12px', color: 'var(--text-mid)', marginTop: '2px' }}>
          your Google Account
        </div>
      </div>

      {/* Permissions */}
      <div style={{
        borderRadius: '10px',
        background: 'rgba(22, 31, 53, 0.5)',
        border: '1px solid rgba(92, 168, 212, 0.1)',
        overflow: 'hidden',
      }}>
        <div style={{ padding: '10px 14px', borderBottom: '1px solid rgba(92, 168, 212, 0.06)' }}>
          <div className="font-display" style={{ fontSize: '9px', letterSpacing: '0.15em', color: 'var(--text-dim)', marginBottom: '8px' }}>
            THIS WILL ALLOW SECUREAPP TO:
          </div>
          {['View your name', 'View your email address', 'View your profile picture'].map((perm, i) => (
            <div key={i} style={{ display: 'flex', alignItems: 'center', gap: '8px', padding: '5px 0' }}>
              <div style={{ width: '4px', height: '4px', borderRadius: '50%', background: 'var(--lime)', flexShrink: 0 }} />
              <span className="font-body" style={{ fontSize: '12px', color: 'var(--text-bright)' }}>{perm}</span>
            </div>
          ))}
        </div>

        {/* Account info */}
        <div style={{ padding: '10px 14px', display: 'flex', alignItems: 'center', gap: '8px' }}>
          <div style={{
            width: '24px', height: '24px', borderRadius: '50%',
            background: 'linear-gradient(135deg, var(--cyan), var(--magenta))',
            display: 'flex', alignItems: 'center', justifyContent: 'center',
            fontSize: '10px', fontWeight: 700, color: '#fff', flexShrink: 0,
          }}>S</div>
          <span className="font-code" style={{ fontSize: '10px', color: 'var(--text-mid)' }}>selected account</span>
        </div>
      </div>

      {/* Buttons */}
      <div style={{ display: 'flex', gap: '8px' }}>
        <div style={{
          flex: 1,
          padding: '8px',
          borderRadius: '8px',
          background: 'rgba(22, 31, 53, 0.4)',
          border: '1px solid rgba(92, 168, 212, 0.08)',
          textAlign: 'center',
          opacity: 0.35,
        }}>
          <span className="font-body" style={{ fontSize: '12px', color: 'var(--text-dim)' }}>Cancel</span>
        </div>
        <button
          onClick={isWaiting ? onContinue : undefined}
          data-hover
          style={{
            flex: 1,
            padding: '8px',
            borderRadius: '8px',
            background: isWaiting ? 'rgba(92, 168, 212, 0.15)' : 'rgba(92, 168, 212, 0.08)',
            border: `1px solid ${isWaiting ? 'rgba(92, 168, 212, 0.4)' : 'rgba(92, 168, 212, 0.15)'}`,
            textAlign: 'center',
            cursor: isWaiting ? 'pointer' : 'default',
            transition: 'all 0.2s ease',
            outline: 'none',
            opacity: isWaiting ? 1 : 0.5,
            pointerEvents: isWaiting ? 'auto' : 'none',
            animation: isWaiting ? 'pulse-glow 2s ease infinite' : 'none',
          }}
          onMouseEnter={(e) => {
            if (isWaiting) {
              (e.currentTarget as HTMLElement).style.background = 'rgba(92, 168, 212, 0.25)';
              (e.currentTarget as HTMLElement).style.boxShadow = '0 0 12px rgba(92, 168, 212, 0.2)';
            }
          }}
          onMouseLeave={(e) => {
            if (isWaiting) {
              (e.currentTarget as HTMLElement).style.background = 'rgba(92, 168, 212, 0.15)';
              (e.currentTarget as HTMLElement).style.boxShadow = 'none';
            }
          }}
        >
          <span className="font-body" style={{ fontSize: '12px', fontWeight: 600, color: 'var(--cyan)' }}>Continue</span>
        </button>
      </div>

      <div className="font-code" style={{ fontSize: '9px', color: isWaiting ? 'var(--magenta)' : 'var(--text-dim)', textAlign: 'center', transition: 'color 0.3s' }}>
        {isWaiting ? '↑ Click Continue to grant consent' : 'Authorization code will be issued'}
      </div>
    </div>
  );
}


/* ── STAGE 4: Returning to platform ── */
function StageReturning() {
  return (
    <div style={{
      textAlign: 'center',
      display: 'flex',
      flexDirection: 'column',
      alignItems: 'center',
      gap: '20px',
      animation: 'slideInRight 0.3s ease',
    }}>
      <div style={{
        width: '48px',
        height: '48px',
        borderRadius: '50%',
        border: '2px solid rgba(160, 120, 200, 0.15)',
        borderTopColor: 'var(--magenta)',
        animation: 'hex-rotate 1s linear infinite',
      }} />
      <div>
        <div className="font-display" style={{
          fontSize: '13px',
          letterSpacing: '0.15em',
          color: 'var(--magenta)',
          marginBottom: '6px',
        }}>
          EXCHANGING TOKENS
        </div>
        <div className="font-code" style={{ fontSize: '11px', color: 'var(--text-mid)' }}>
          Returning to SecureApp...
        </div>
        <div className="font-code" style={{ fontSize: '9px', color: 'var(--text-dim)', marginTop: '8px' }}>
          PQ-signed token issuance in progress
        </div>
      </div>
    </div>
  );
}


/* ── STAGE 5: Creating secure session ── */
function StageSecuring() {
  return (
    <div style={{
      textAlign: 'center',
      display: 'flex',
      flexDirection: 'column',
      alignItems: 'center',
      gap: '20px',
      animation: 'slideInRight 0.3s ease',
    }}>
      <div style={{
        width: '56px',
        height: '56px',
        borderRadius: '14px',
        border: '2px solid var(--violet)',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        fontSize: '24px',
        boxShadow: '0 0 16px rgba(144, 128, 200, 0.2)',
        animation: 'glow-breathe 2s ease infinite',
      }}>
        🔐
      </div>
      <div>
        <div className="font-display" style={{
          fontSize: '13px',
          letterSpacing: '0.15em',
          color: 'var(--violet)',
          marginBottom: '6px',
        }}>
          BINDING SESSION
        </div>
        <div className="font-code" style={{ fontSize: '11px', color: 'var(--text-mid)' }}>
          Verifying session binding...
        </div>
        <div className="font-code" style={{ fontSize: '9px', color: 'var(--text-dim)', marginTop: '8px' }}>
          cnf.kbh = SHA256(exporter || session_id)
        </div>
      </div>
    </div>
  );
}


/* ── STAGE 6: Dashboard (logged in) ── */
function StageDashboard() {
  return (
    <div style={{
      width: '100%',
      maxWidth: '280px',
      display: 'flex',
      flexDirection: 'column',
      gap: '14px',
      animation: 'slideInRight 0.3s ease',
    }}>
      {/* Welcome bar */}
      <div style={{
        display: 'flex',
        alignItems: 'center',
        gap: '10px',
        padding: '12px 14px',
        borderRadius: '10px',
        background: 'rgba(78, 201, 160, 0.06)',
        border: '1px solid rgba(78, 201, 160, 0.2)',
      }}>
        <div style={{
          width: '32px', height: '32px', borderRadius: '50%',
          background: 'linear-gradient(135deg, var(--cyan), var(--magenta))',
          display: 'flex', alignItems: 'center', justifyContent: 'center',
          fontSize: '13px', fontWeight: 700, color: '#fff', flexShrink: 0,
        }}>U</div>
        <div style={{ flex: 1 }}>
          <div className="font-body" style={{ fontSize: '13px', fontWeight: 600, color: 'var(--lime)' }}>
            Welcome back!
          </div>
          <div className="font-code" style={{ fontSize: '9px', color: 'var(--text-mid)' }}>
            Quantum-secured session active
          </div>
        </div>
        <div style={{
          width: '8px', height: '8px', borderRadius: '50%',
          background: 'var(--lime)', boxShadow: '0 0 8px var(--lime)',
        }} />
      </div>

      {/* Dashboard cards */}
      {[
        { label: 'Session', value: 'KEMTLS-bound', icon: '🔒' },
        { label: 'Binding', value: 'Session-bound ✓', icon: '🛡️' },
        { label: 'Channel', value: 'PQ-Secure ✓', icon: '📡' },
      ].map((card, i) => (
        <div key={i} style={{
          padding: '10px 14px',
          borderRadius: '8px',
          background: 'rgba(22, 31, 53, 0.5)',
          border: '1px solid rgba(92, 168, 212, 0.08)',
          display: 'flex',
          alignItems: 'center',
          gap: '10px',
        }}>
          <span style={{ fontSize: '16px' }}>{card.icon}</span>
          <div style={{ flex: 1 }}>
            <div className="font-display" style={{ fontSize: '8px', letterSpacing: '0.15em', color: 'var(--text-dim)' }}>
              {card.label.toUpperCase()}
            </div>
            <div className="font-code" style={{ fontSize: '11px', color: 'var(--text-bright)' }}>
              {card.value}
            </div>
          </div>
        </div>
      ))}

      <div className="font-code" style={{
        fontSize: '9px',
        color: 'var(--lime)',
        textAlign: 'center',
        textShadow: '0 0 4px rgba(78, 201, 160, 0.3)',
      }}>
        ✓ End-to-end post-quantum secure
      </div>
    </div>
  );
}
