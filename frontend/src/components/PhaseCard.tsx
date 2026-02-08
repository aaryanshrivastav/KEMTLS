import { motion } from "framer-motion";
import { LucideIcon } from "lucide-react";
import { ReactNode } from "react";

interface PhaseCardProps {
  phase: number;
  title: string;
  subtitle: string;
  icon: LucideIcon;
  isActive: boolean;
  isComplete: boolean;
  onClick: () => void;
  children?: ReactNode;
}

export const PhaseCard = ({
  phase,
  title,
  subtitle,
  icon: Icon,
  isActive,
  isComplete,
  onClick,
  children,
}: PhaseCardProps) => {
  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ delay: phase * 0.1 }}
      onClick={onClick}
      className={`
        relative cursor-pointer rounded-xl border p-5 transition-all
        ${isActive 
          ? "border-primary bg-primary/5 shadow-lg shadow-primary/10" 
          : isComplete 
            ? "border-secondary/50 bg-secondary/5" 
            : "border-muted hover:border-primary/30 bg-card/50"
        }
      `}
    >
      {/* Phase indicator */}
      <div className="flex items-start justify-between mb-4">
        <div className={`
          w-10 h-10 rounded-lg flex items-center justify-center
          ${isActive 
            ? "bg-primary text-primary-foreground" 
            : isComplete 
              ? "bg-secondary text-secondary-foreground" 
              : "bg-muted text-muted-foreground"
          }
        `}>
          <Icon className="w-5 h-5" />
        </div>
        <span className={`
          text-xs font-mono px-2 py-1 rounded
          ${isActive 
            ? "bg-primary/20 text-primary" 
            : isComplete 
              ? "bg-secondary/20 text-secondary" 
              : "bg-muted text-muted-foreground"
          }
        `}>
          Phase {phase}
        </span>
      </div>

      <h3 className={`font-semibold text-lg mb-1 ${isActive ? "neon-text" : ""}`}>
        {title}
      </h3>
      <p className="text-sm text-muted-foreground">{subtitle}</p>

      {isActive && children && (
        <motion.div
          initial={{ opacity: 0, height: 0 }}
          animate={{ opacity: 1, height: "auto" }}
          className="mt-4 pt-4 border-t border-primary/20"
        >
          {children}
        </motion.div>
      )}

      {/* Glow effect for active */}
      {isActive && (
        <div className="absolute inset-0 rounded-xl pointer-events-none">
          <div className="absolute inset-0 rounded-xl opacity-20 blur-xl bg-primary" />
        </div>
      )}
    </motion.div>
  );
};
