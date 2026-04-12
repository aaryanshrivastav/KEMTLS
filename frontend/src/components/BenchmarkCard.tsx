import { motion } from "framer-motion";
import { HardDrive, Loader2 } from "lucide-react";

interface BenchmarkCardProps {
  operation: string;
  time?: string;
  size?: string;
  comparison?: {
    label: string;
    improvement: string;
  };
  loading?: boolean;
}

export const BenchmarkCard = ({ operation, time, size, comparison, loading = false }: BenchmarkCardProps) => {
  return (
    <motion.div
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      whileHover={{ scale: loading ? 1 : 1.02 }}
      className="p-4 rounded-lg border border-primary/20 bg-card/50 hover:border-primary/40 transition-all"
    >
      <h4 className="font-medium text-sm text-foreground mb-3">{operation}</h4>
      
      {loading ? (
        <div className="flex items-center gap-2 text-muted-foreground">
          <Loader2 className="w-4 h-4 animate-spin" />
          <span className="text-sm">Running...</span>
        </div>
      ) : (
        <>
          <div className="flex items-center gap-4">
            {size && (
              <div className="flex items-center gap-2">
                <HardDrive className="w-4 h-4 text-secondary" />
                <span className="font-mono text-sm text-secondary">{size}</span>
              </div>
            )}
          </div>
          
          {comparison && (
            <div className="mt-3 pt-3 border-t border-primary/10">
              <div className="flex justify-between items-center text-xs">
                <span className="text-muted-foreground">vs {comparison.label}</span>
                <span className="text-success font-mono">{comparison.improvement}</span>
              </div>
            </div>
          )}
        </>
      )}
    </motion.div>
  );
};
