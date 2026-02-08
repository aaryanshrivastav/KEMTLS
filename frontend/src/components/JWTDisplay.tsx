import { motion } from "framer-motion";
import { useState } from "react";
import { ChevronDown, ChevronUp } from "lucide-react";

interface JWTDisplayProps {
  header: object;
  payload: object;
  signature: string;
}

export const JWTDisplay = ({ header, payload, signature }: JWTDisplayProps) => {
  const [expanded, setExpanded] = useState(false);

  const formatJSON = (obj: object) => JSON.stringify(obj, null, 2);

  return (
    <motion.div
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      className="rounded-lg border border-primary/30 overflow-hidden bg-card"
    >
      <button
        onClick={() => setExpanded(!expanded)}
        className="w-full flex items-center justify-between p-3 bg-muted/30 hover:bg-muted/50 transition-colors"
      >
        <span className="font-mono text-sm text-primary">PQ-JWT (Dilithium3 Signed)</span>
        {expanded ? (
          <ChevronUp className="w-4 h-4 text-muted-foreground" />
        ) : (
          <ChevronDown className="w-4 h-4 text-muted-foreground" />
        )}
      </button>

      {expanded && (
        <div className="p-3 space-y-3">
          {/* Header */}
          <div>
            <span className="text-xs font-mono text-accent mb-1 block">HEADER</span>
            <pre className="text-xs font-mono p-2 rounded bg-accent/10 text-accent overflow-x-auto">
              {formatJSON(header)}
            </pre>
          </div>

          {/* Payload */}
          <div>
            <span className="text-xs font-mono text-primary mb-1 block">PAYLOAD</span>
            <pre className="text-xs font-mono p-2 rounded bg-primary/10 text-primary overflow-x-auto">
              {formatJSON(payload)}
            </pre>
          </div>

          {/* Signature */}
          <div>
            <span className="text-xs font-mono text-secondary mb-1 block">SIGNATURE (Dilithium3)</span>
            <p className="text-xs font-mono p-2 rounded bg-secondary/10 text-secondary break-all">
              {signature.slice(0, 64)}...
            </p>
            <span className="text-xs text-muted-foreground mt-1 block">~3293 bytes</span>
          </div>
        </div>
      )}
    </motion.div>
  );
};
