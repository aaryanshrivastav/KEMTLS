import { motion } from "framer-motion";
import { LucideIcon } from "lucide-react";

interface CryptoBlockProps {
  icon: LucideIcon;
  label: string;
  value: string;
  size?: string;
  variant?: "primary" | "secondary" | "accent";
}

export const CryptoBlock = ({ 
  icon: Icon, 
  label, 
  value, 
  size,
  variant = "primary" 
}: CryptoBlockProps) => {
  const variantStyles = {
    primary: "border-primary/30 bg-primary/5",
    secondary: "border-secondary/30 bg-secondary/5",
    accent: "border-accent/30 bg-accent/5",
  };

  const iconStyles = {
    primary: "text-primary",
    secondary: "text-secondary",
    accent: "text-accent",
  };

  return (
    <motion.div
      whileHover={{ scale: 1.02 }}
      className={`p-3 rounded-lg border ${variantStyles[variant]} transition-all`}
    >
      <div className="flex items-center gap-2 mb-1">
        <Icon className={`w-4 h-4 ${iconStyles[variant]}`} />
        <span className="text-xs font-mono text-muted-foreground">{label}</span>
      </div>
      <p className="font-mono text-sm text-foreground truncate">{value}</p>
      {size && (
        <span className="text-xs text-muted-foreground">{size}</span>
      )}
    </motion.div>
  );
};
