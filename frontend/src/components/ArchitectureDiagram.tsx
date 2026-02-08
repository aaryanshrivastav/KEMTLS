import { motion } from "framer-motion";
import { Monitor, Server, Database, Shield, ArrowLeftRight } from "lucide-react";

export const ArchitectureDiagram = () => {
  return (
    <div className="relative p-6 rounded-xl border border-primary/20 bg-card/30">
      <div className="grid grid-cols-3 gap-8 items-center">
        {/* Client */}
        <motion.div
          initial={{ opacity: 0, x: -20 }}
          animate={{ opacity: 1, x: 0 }}
          className="text-center"
        >
          <div className="w-16 h-16 mx-auto rounded-xl bg-primary/10 border border-primary/30 flex items-center justify-center mb-3">
            <Monitor className="w-8 h-8 text-primary" />
          </div>
          <h4 className="font-semibold text-foreground">Client</h4>
          <div className="mt-2 space-y-1 text-xs text-muted-foreground">
            <p>KEMTLS Handshake</p>
            <p>OIDC Client</p>
            <p>PoP (Dilithium Key)</p>
          </div>
        </motion.div>

        {/* Connection Lines */}
        <div className="relative">
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            transition={{ delay: 0.3 }}
            className="flex flex-col items-center gap-4"
          >
            <div className="flex items-center gap-2 px-3 py-2 rounded-lg bg-primary/10 border border-primary/30">
              <Shield className="w-4 h-4 text-primary" />
              <span className="text-xs font-mono text-primary">KEMTLS Channel</span>
            </div>
            <div className="text-xs text-muted-foreground text-center">
              <p>Kyber768 + ChaCha20-Poly1305</p>
            </div>
            <ArrowLeftRight className="w-6 h-6 text-primary animate-pulse" />
          </motion.div>
        </div>

        {/* Servers */}
        <motion.div
          initial={{ opacity: 0, x: 20 }}
          animate={{ opacity: 1, x: 0 }}
          className="space-y-4"
        >
          {/* Auth Server */}
          <div className="p-3 rounded-lg border border-accent/30 bg-accent/5">
            <div className="flex items-center gap-2 mb-2">
              <Server className="w-5 h-5 text-accent" />
              <span className="font-semibold text-sm">Auth Server</span>
            </div>
            <div className="text-xs text-muted-foreground space-y-0.5">
              <p>/authorize</p>
              <p>/token</p>
              <p>/discovery</p>
            </div>
          </div>

          {/* Resource Server */}
          <div className="p-3 rounded-lg border border-secondary/30 bg-secondary/5">
            <div className="flex items-center gap-2 mb-2">
              <Database className="w-5 h-5 text-secondary" />
              <span className="font-semibold text-sm">Resource Server</span>
            </div>
            <div className="text-xs text-muted-foreground space-y-0.5">
              <p>Token Verification</p>
              <p>PoP Challenge</p>
              <p>/api/userinfo</p>
            </div>
          </div>
        </motion.div>
      </div>
    </div>
  );
};
