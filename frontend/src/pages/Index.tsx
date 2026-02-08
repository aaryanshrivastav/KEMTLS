import { useState } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { 
  Shield, Lock, Key, FileKey, User, Server, 
  Play, RotateCcw, ChevronRight, Zap, CheckCircle2,
  ArrowRight, Fingerprint
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { TerminalWindow } from "@/components/TerminalWindow";
import { PhaseCard } from "@/components/PhaseCard";
import { KeyDisplay } from "@/components/KeyDisplay";
import { DataPacket } from "@/components/DataPacket";
import { JWTDisplay } from "@/components/JWTDisplay";
import { BenchmarkCard } from "@/components/BenchmarkCard";
import { StatusBadge } from "@/components/StatusBadge";
import { ArchitectureDiagram } from "@/components/ArchitectureDiagram";

type Phase = 0 | 1 | 2 | 3 | 4;

const Index = () => {
  const [activePhase, setActivePhase] = useState<Phase>(0);
  const [isRunning, setIsRunning] = useState(false);
  const [completedPhases, setCompletedPhases] = useState<number[]>([]);

  const runDemo = async () => {
    setIsRunning(true);
    setCompletedPhases([]);
    
    for (let i = 1; i <= 4; i++) {
      setActivePhase(i as Phase);
      await new Promise(resolve => setTimeout(resolve, 2000));
      setCompletedPhases(prev => [...prev, i]);
    }
    
    setIsRunning(false);
  };

  const resetDemo = () => {
    setActivePhase(0);
    setCompletedPhases([]);
    setIsRunning(false);
  };

  // Mock data for demo
  const mockKeys = {
    serverKyberPk: "MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA7Fk...",
    clientDilithiumPk: "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIB...",
    sessionKey: "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6",
  };

  const mockJWT = {
    header: { alg: "DILITHIUM3", typ: "JWT", kid: "server-signing-key" },
    payload: {
      iss: "https://auth.kemtls.demo",
      sub: "alice@example.com",
      aud: "client-app-id",
      iat: Date.now(),
      exp: Date.now() + 3600000,
      cnf: {
        jwk: { kty: "LWE", alg: "DILITHIUM3", use: "sig" },
        session_id: "kemtls-session-001",
        session_exp: Date.now() + 600000
      }
    },
    signature: "QmFzZTY0RW5jb2RlZERpbGl0aGl1bTNTaWduYXR1cmVIZXJlV2l0aFZlcnlMb25nQnl0ZXNBcHByb3hpbWF0ZWx5MzI5M0J5dGVz"
  };

  return (
    <div className="min-h-screen bg-background grid-pattern relative overflow-hidden">
      {/* Background effects */}
      <div className="fixed inset-0 pointer-events-none">
        <div className="absolute top-0 left-1/4 w-96 h-96 bg-primary/5 rounded-full blur-3xl" />
        <div className="absolute bottom-0 right-1/4 w-96 h-96 bg-accent/5 rounded-full blur-3xl" />
      </div>

      <div className="relative z-10">
        {/* Hero Header */}
        <header className="border-b border-primary/20 backdrop-cyber">
          <div className="container mx-auto px-4 py-6">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-3">
                <div className="w-10 h-10 rounded-lg bg-primary/10 border border-primary/30 flex items-center justify-center">
                  <Shield className="w-5 h-5 text-primary" />
                </div>
                <div>
                  <h1 className="text-xl font-bold neon-text">KEMTLS + OIDC</h1>
                  <p className="text-xs text-muted-foreground">Post-Quantum Secure Authentication</p>
                </div>
              </div>
              
              <div className="flex items-center gap-3">
                <StatusBadge 
                  status={isRunning ? "pending" : completedPhases.length === 4 ? "success" : "info"} 
                  text={isRunning ? "Running..." : completedPhases.length === 4 ? "Complete" : "Ready"} 
                />
                <Button
                  onClick={isRunning ? undefined : runDemo}
                  disabled={isRunning}
                  className="bg-primary hover:bg-primary/90 text-primary-foreground gap-2"
                >
                  <Play className="w-4 h-4" />
                  Run Demo
                </Button>
                <Button
                  onClick={resetDemo}
                  variant="outline"
                  className="border-primary/30 hover:bg-primary/10 gap-2"
                >
                  <RotateCcw className="w-4 h-4" />
                  Reset
                </Button>
              </div>
            </div>
          </div>
        </header>

        <main className="container mx-auto px-4 py-8 space-y-8">
          {/* Title Section */}
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            className="text-center max-w-3xl mx-auto"
          >
            <h2 className="text-4xl font-bold mb-4">
              <span className="text-gradient-cyber">Post-Quantum</span> OpenID Connect
            </h2>
            <p className="text-muted-foreground text-lg">
              First implementation of OIDC secured with KEMTLS - quantum-resistant authentication 
              using Kyber768 KEM and Dilithium3 signatures.
            </p>
          </motion.div>

          {/* Architecture Overview */}
          <motion.section
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.1 }}
          >
            <h3 className="text-lg font-semibold mb-4 flex items-center gap-2">
              <Server className="w-5 h-5 text-primary" />
              System Architecture
            </h3>
            <ArchitectureDiagram />
          </motion.section>

          {/* Phase Cards */}
          <section>
            <h3 className="text-lg font-semibold mb-4 flex items-center gap-2">
              <Zap className="w-5 h-5 text-primary" />
              Authentication Flow
            </h3>
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
              <PhaseCard
                phase={1}
                title="KEMTLS Handshake"
                subtitle="Kyber768 key exchange"
                icon={Lock}
                isActive={activePhase === 1}
                isComplete={completedPhases.includes(1)}
                onClick={() => setActivePhase(1)}
              >
                <div className="space-y-3">
                  <KeyDisplay 
                    type="kyber" 
                    label="Server Ephemeral" 
                    publicKey={mockKeys.serverKyberPk}
                  />
                  <DataPacket
                    from="Client"
                    to="Server"
                    data={[
                      { label: "ct_eph", value: "Kyber ciphertext" },
                      { label: "ct_lt", value: "Longterm cipher" },
                    ]}
                  />
                </div>
              </PhaseCard>

              <PhaseCard
                phase={2}
                title="OIDC Authorization"
                subtitle="OAuth 2.0 code flow"
                icon={User}
                isActive={activePhase === 2}
                isComplete={completedPhases.includes(2)}
                onClick={() => setActivePhase(2)}
              >
                <div className="space-y-2 text-xs font-mono">
                  <div className="p-2 rounded bg-muted/50">
                    <span className="text-primary">GET</span> /authorize
                  </div>
                  <div className="flex items-center gap-2 text-muted-foreground">
                    <ArrowRight className="w-3 h-3" />
                    <span>User authenticates</span>
                  </div>
                  <div className="p-2 rounded bg-secondary/20 text-secondary">
                    code: a8f3k2...
                  </div>
                </div>
              </PhaseCard>

              <PhaseCard
                phase={3}
                title="Token Exchange"
                subtitle="PQ-JWT issuance"
                icon={FileKey}
                isActive={activePhase === 3}
                isComplete={completedPhases.includes(3)}
                onClick={() => setActivePhase(3)}
              >
                <JWTDisplay 
                  header={mockJWT.header}
                  payload={mockJWT.payload}
                  signature={mockJWT.signature}
                />
              </PhaseCard>

              <PhaseCard
                phase={4}
                title="Resource Access"
                subtitle="PoP verification"
                icon={Fingerprint}
                isActive={activePhase === 4}
                isComplete={completedPhases.includes(4)}
                onClick={() => setActivePhase(4)}
              >
                <div className="space-y-2 text-xs">
                  <div className="flex items-center gap-2">
                    <CheckCircle2 className="w-4 h-4 text-success" />
                    <span>Token verified</span>
                  </div>
                  <div className="flex items-center gap-2">
                    <CheckCircle2 className="w-4 h-4 text-success" />
                    <span>PoP challenge passed</span>
                  </div>
                  <div className="flex items-center gap-2">
                    <CheckCircle2 className="w-4 h-4 text-success" />
                    <span>Resource granted</span>
                  </div>
                </div>
              </PhaseCard>
            </div>
          </section>

          {/* Detailed View */}
          <AnimatePresence mode="wait">
            {activePhase > 0 && (
              <motion.section
                key={activePhase}
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, y: -20 }}
              >
                <PhaseDetailView phase={activePhase} mockKeys={mockKeys} mockJWT={mockJWT} />
              </motion.section>
            )}
          </AnimatePresence>

          {/* Performance Benchmarks */}
          <section>
            <h3 className="text-lg font-semibold mb-4 flex items-center gap-2">
              <Zap className="w-5 h-5 text-primary" />
              Performance Benchmarks
            </h3>
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
              <BenchmarkCard
                operation="KEMTLS Handshake"
                time="~1.5 ms"
                comparison={{ label: "PQ-TLS", improvement: "-98.8%" }}
              />
              <BenchmarkCard
                operation="ID Token Creation"
                time="~0.55 ms"
                size="~7.5 KB"
                comparison={{ label: "PQ-TLS", improvement: "-93.8%" }}
              />
              <BenchmarkCard
                operation="Token Verification"
                time="~0.20 ms"
                comparison={{ label: "PQ-TLS", improvement: "-96.0%" }}
              />
              <BenchmarkCard
                operation="PoP Proof Creation"
                time="~0.50 ms"
                size="~4.4 KB"
              />
              <BenchmarkCard
                operation="PoP Verification"
                time="~0.15 ms"
              />
              <BenchmarkCard
                operation="End-to-End Flow"
                time="~3.0 ms"
                comparison={{ label: "PQ-TLS", improvement: "-98.5%" }}
              />
            </div>
          </section>

          {/* Crypto Primitives */}
          <section>
            <h3 className="text-lg font-semibold mb-4 flex items-center gap-2">
              <Key className="w-5 h-5 text-primary" />
              Cryptographic Primitives
            </h3>
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
              <TerminalWindow title="kyber768.kem">
                <div className="space-y-2">
                  <p className="text-primary">// Key Encapsulation</p>
                  <p className="text-muted-foreground">NIST Level 3</p>
                  <div className="pt-2 border-t border-primary/20 text-xs space-y-1">
                    <p><span className="text-secondary">pk:</span> 1184 bytes</p>
                    <p><span className="text-secondary">ct:</span> 1088 bytes</p>
                    <p><span className="text-secondary">ss:</span> 32 bytes</p>
                  </div>
                </div>
              </TerminalWindow>

              <TerminalWindow title="dilithium3.sig">
                <div className="space-y-2">
                  <p className="text-accent">// Digital Signatures</p>
                  <p className="text-muted-foreground">NIST Level 3</p>
                  <div className="pt-2 border-t border-accent/20 text-xs space-y-1">
                    <p><span className="text-secondary">pk:</span> 1952 bytes</p>
                    <p><span className="text-secondary">sk:</span> 4000 bytes</p>
                    <p><span className="text-secondary">sig:</span> 3293 bytes</p>
                  </div>
                </div>
              </TerminalWindow>

              <TerminalWindow title="chacha20-poly1305.aead">
                <div className="space-y-2">
                  <p className="text-secondary">// Symmetric Encryption</p>
                  <p className="text-muted-foreground">AEAD Cipher</p>
                  <div className="pt-2 border-t border-secondary/20 text-xs space-y-1">
                    <p><span className="text-secondary">key:</span> 32 bytes</p>
                    <p><span className="text-secondary">nonce:</span> 12 bytes</p>
                    <p><span className="text-secondary">tag:</span> 16 bytes</p>
                  </div>
                </div>
              </TerminalWindow>

              <TerminalWindow title="hkdf-sha256.kdf">
                <div className="space-y-2">
                  <p className="text-warning">// Key Derivation</p>
                  <p className="text-muted-foreground">Session Keys</p>
                  <div className="pt-2 border-t border-warning/20 text-xs space-y-1">
                    <p><span className="text-secondary">client_key:</span> 32 bytes</p>
                    <p><span className="text-secondary">server_key:</span> 32 bytes</p>
                    <p><span className="text-secondary">pop_key:</span> 32 bytes</p>
                  </div>
                </div>
              </TerminalWindow>
            </div>
          </section>

          {/* Footer */}
          <footer className="text-center py-8 border-t border-primary/20">
            <p className="text-muted-foreground text-sm">
              KEMTLS + OIDC • Post-Quantum Secure • Cybersecurity Challenge Hackathon 2026
            </p>
            <p className="text-xs text-muted-foreground/50 mt-2">
              IIT Kanpur • E3iHub • HACK IITK
            </p>
          </footer>
        </main>
      </div>
    </div>
  );
};

// Detailed phase view component
interface PhaseDetailViewProps {
  phase: number;
  mockKeys: { serverKyberPk: string; clientDilithiumPk: string; sessionKey: string };
  mockJWT: { header: object; payload: object; signature: string };
}

const PhaseDetailView = ({ phase, mockKeys, mockJWT }: PhaseDetailViewProps) => {
  if (phase === 1) {
    return (
      <TerminalWindow title="kemtls_handshake.log">
        <div className="space-y-3">
          <p className="text-success">✓ Server sends ServerHello</p>
          <div className="pl-4 text-xs space-y-1">
            <p><span className="text-muted-foreground">server_ephemeral_pk:</span> <span className="text-primary">{mockKeys.serverKyberPk.slice(0, 30)}...</span></p>
            <p><span className="text-muted-foreground">server_longterm_pk:</span> <span className="text-primary">Kyber768 (1184 bytes)</span></p>
            <p><span className="text-muted-foreground">session_id:</span> <span className="text-accent">kemtls-001</span></p>
          </div>
          <p className="text-success">✓ Client encapsulates to both keys</p>
          <div className="pl-4 text-xs space-y-1">
            <p><span className="text-muted-foreground">ct_ephemeral:</span> <span className="text-secondary">1088 bytes</span></p>
            <p><span className="text-muted-foreground">ct_longterm:</span> <span className="text-secondary">1088 bytes</span></p>
          </div>
          <p className="text-success">✓ Server decapsulates (authenticates!)</p>
          <p className="text-success">✓ Session keys derived via HKDF</p>
          <div className="pl-4 text-xs">
            <p><span className="text-muted-foreground">session_key:</span> <span className="text-warning">{mockKeys.sessionKey}</span></p>
          </div>
        </div>
      </TerminalWindow>
    );
  }

  if (phase === 2) {
    return (
      <TerminalWindow title="oidc_authorization.log">
        <div className="space-y-3">
          <p className="text-primary">→ GET /authorize</p>
          <div className="pl-4 text-xs space-y-1 text-muted-foreground">
            <p>response_type: <span className="text-foreground">code</span></p>
            <p>client_id: <span className="text-foreground">demo-client</span></p>
            <p>scope: <span className="text-foreground">openid profile email</span></p>
            <p>state: <span className="text-accent">random_state_123</span></p>
          </div>
          <p className="text-warning">⟳ User authentication...</p>
          <p className="text-success">✓ User authenticated: alice@example.com</p>
          <p className="text-success">✓ Authorization code issued</p>
          <div className="pl-4 text-xs">
            <p><span className="text-muted-foreground">code:</span> <span className="text-secondary">a8f3k2x9m1b7...</span></p>
            <p><span className="text-muted-foreground">expires_in:</span> <span className="text-foreground">600s</span></p>
          </div>
        </div>
      </TerminalWindow>
    );
  }

  if (phase === 3) {
    return (
      <TerminalWindow title="token_exchange.log">
        <div className="space-y-3">
          <p className="text-primary">→ POST /token</p>
          <div className="pl-4 text-xs space-y-1 text-muted-foreground">
            <p>grant_type: <span className="text-foreground">authorization_code</span></p>
            <p>code: <span className="text-secondary">a8f3k2x9m1b7...</span></p>
          </div>
          <p className="text-success">✓ Code validated</p>
          <p className="text-success">✓ Creating PQ-JWT with Dilithium3</p>
          <div className="pl-4 text-xs space-y-1">
            <p><span className="text-accent">alg:</span> DILITHIUM3</p>
            <p><span className="text-muted-foreground">cnf.jwk:</span> <span className="text-primary">Client ephemeral pubkey embedded</span></p>
            <p><span className="text-muted-foreground">signature:</span> <span className="text-secondary">~3293 bytes</span></p>
          </div>
          <p className="text-success">✓ ID Token issued with PoP binding</p>
        </div>
      </TerminalWindow>
    );
  }

  if (phase === 4) {
    return (
      <TerminalWindow title="resource_access.log">
        <div className="space-y-3">
          <p className="text-primary">→ GET /api/userinfo</p>
          <p className="text-success">✓ Token signature verified (Dilithium3)</p>
          <p className="text-success">✓ Token not expired</p>
          <p className="text-warning">⟳ PoP Challenge issued</p>
          <div className="pl-4 text-xs space-y-1">
            <p><span className="text-muted-foreground">nonce:</span> <span className="text-accent">challenge_nonce_xyz</span></p>
            <p><span className="text-muted-foreground">timestamp:</span> <span className="text-foreground">{Date.now()}</span></p>
          </div>
          <p className="text-primary">→ Client signs challenge with ephemeral key</p>
          <p className="text-success">✓ PoP proof verified</p>
          <div className="pl-4 text-xs">
            <p><span className="text-muted-foreground">client_pk from:</span> <span className="text-primary">token.cnf.jwk.x</span></p>
          </div>
          <p className="text-success neon-text">✓ ACCESS GRANTED</p>
          <div className="mt-2 p-2 rounded bg-success/10 border border-success/30 text-xs">
            <p className="text-success">{"{"} user_id: "alice@example.com", name: "Alice" {"}"}</p>
          </div>
        </div>
      </TerminalWindow>
    );
  }

  return null;
};

export default Index;
