import { motion } from "framer-motion";
import { Check, Loader2, ArrowDown } from "lucide-react";
import { ReactNode } from "react";

interface FlowStepProps {
  step: number;
  title: string;
  description: string;
  status: "pending" | "active" | "complete";
  children?: ReactNode;
  showConnector?: boolean;
}

export const FlowStep = ({
  step,
  title,
  description,
  status,
  children,
  showConnector = true,
}: FlowStepProps) => {
  const statusStyles = {
    pending: "border-muted bg-muted/20",
    active: "border-primary bg-primary/10 pulse-glow",
    complete: "border-secondary bg-secondary/10",
  };

  const numberStyles = {
    pending: "bg-muted text-muted-foreground",
    active: "bg-primary text-primary-foreground",
    complete: "bg-secondary text-secondary-foreground",
  };

  return (
    <div className="relative">
      <motion.div
        initial={{ opacity: 0, x: -20 }}
        animate={{ opacity: 1, x: 0 }}
        transition={{ delay: step * 0.1 }}
        className={`p-4 rounded-lg border ${statusStyles[status]} transition-all`}
      >
        <div className="flex items-start gap-3">
          <div
            className={`w-8 h-8 rounded-full flex items-center justify-center text-sm font-bold ${numberStyles[status]}`}
          >
            {status === "complete" ? (
              <Check className="w-4 h-4" />
            ) : status === "active" ? (
              <Loader2 className="w-4 h-4 animate-spin" />
            ) : (
              step
            )}
          </div>
          <div className="flex-1">
            <h4 className="font-semibold text-foreground">{title}</h4>
            <p className="text-sm text-muted-foreground mt-1">{description}</p>
            {children && <div className="mt-3">{children}</div>}
          </div>
        </div>
      </motion.div>
      
      {showConnector && (
        <div className="flex justify-center py-2">
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            transition={{ delay: step * 0.1 + 0.2 }}
          >
            <ArrowDown className="w-5 h-5 text-primary/50" />
          </motion.div>
        </div>
      )}
    </div>
  );
};
