import { motion } from "framer-motion";
import { Key, Lock, Shield } from "lucide-react";

interface KeyDisplayProps {
  type: "kyber" | "dilithium" | "session";
  label: string;
  publicKey?: string;
  secretKey?: string;
  isExpanded?: boolean;
}

export const KeyDisplay = ({ type, label, publicKey, secretKey, isExpanded = false }: KeyDisplayProps) => {
  const icons = {
    kyber: Key,
    dilithium: Shield,
    session: Lock,
  };

  const colors = {
    kyber: "text-primary border-primary/30 bg-primary/5",
    dilithium: "text-accent border-accent/30 bg-accent/5",
    session: "text-secondary border-secondary/30 bg-secondary/5",
  };

  const Icon = icons[type];

  const truncateKey = (key: string) => {
    if (key.length <= 20) return key;
    return `${key.slice(0, 8)}...${key.slice(-8)}`;
  };

  return (
    <motion.div
      initial={{ opacity: 0, scale: 0.95 }}
      animate={{ opacity: 1, scale: 1 }}
      className={`p-3 rounded-lg border ${colors[type]}`}
    >
      <div className="flex items-center gap-2 mb-2">
        <Icon className="w-4 h-4" />
        <span className="text-xs font-semibold uppercase tracking-wider">{label}</span>
      </div>
      
      {publicKey && (
        <div className="mb-2">
          <span className="text-xs text-muted-foreground">Public Key:</span>
          <p className="font-mono text-xs break-all mt-1 text-foreground/80">
            {isExpanded ? publicKey : truncateKey(publicKey)}
          </p>
        </div>
      )}
      
      {secretKey && (
        <div>
          <span className="text-xs text-muted-foreground">Secret Key:</span>
          <p className="font-mono text-xs break-all mt-1 text-foreground/80">
            {isExpanded ? secretKey : truncateKey(secretKey)}
          </p>
        </div>
      )}
    </motion.div>
  );
};
