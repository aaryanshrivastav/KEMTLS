import { motion } from "framer-motion";

interface StatusBadgeProps {
  status: "success" | "pending" | "error" | "info";
  text: string;
}

export const StatusBadge = ({ status, text }: StatusBadgeProps) => {
  const styles = {
    success: "bg-success/20 text-success border-success/30",
    pending: "bg-warning/20 text-warning border-warning/30",
    error: "bg-destructive/20 text-destructive border-destructive/30",
    info: "bg-primary/20 text-primary border-primary/30",
  };

  return (
    <motion.span
      initial={{ scale: 0.9, opacity: 0 }}
      animate={{ scale: 1, opacity: 1 }}
      className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-mono border ${styles[status]}`}
    >
      <span className={`w-1.5 h-1.5 rounded-full ${
        status === "success" ? "bg-success" :
        status === "pending" ? "bg-warning animate-pulse" :
        status === "error" ? "bg-destructive" :
        "bg-primary"
      }`} />
      {text}
    </motion.span>
  );
};
