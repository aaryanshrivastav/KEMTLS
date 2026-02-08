import { ReactNode } from "react";
import { motion } from "framer-motion";

interface TerminalWindowProps {
  title: string;
  children: ReactNode;
  className?: string;
}

export const TerminalWindow = ({ title, children, className = "" }: TerminalWindowProps) => {
  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      className={`terminal-window ${className}`}
    >
      <div className="terminal-header">
        <div className="terminal-dot bg-destructive" />
        <div className="terminal-dot bg-warning" />
        <div className="terminal-dot bg-success" />
        <span className="ml-3 text-xs font-mono text-muted-foreground">{title}</span>
      </div>
      <div className="terminal-body relative">
        <div className="scan-line" />
        {children}
      </div>
    </motion.div>
  );
};
