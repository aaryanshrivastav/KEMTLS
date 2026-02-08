import { motion } from "framer-motion";
import { ArrowRight } from "lucide-react";

interface DataPacketProps {
  from: string;
  to: string;
  data: { label: string; value: string }[];
  direction?: "left" | "right";
  delay?: number;
}

export const DataPacket = ({ from, to, data, direction = "right", delay = 0 }: DataPacketProps) => {
  return (
    <motion.div
      initial={{ opacity: 0, x: direction === "right" ? -20 : 20 }}
      animate={{ opacity: 1, x: 0 }}
      transition={{ delay }}
      className="flex items-center gap-3"
    >
      <div className="text-xs font-mono text-muted-foreground w-20 text-right">{from}</div>
      
      <div className="flex-1 relative">
        <div className="absolute inset-y-0 left-0 right-0 flex items-center">
          <div className={`flex-1 h-px bg-gradient-to-r ${
            direction === "right" ? "from-primary/50 to-primary" : "from-primary to-primary/50"
          }`} />
          <motion.div
            animate={{ x: direction === "right" ? [0, 10, 0] : [0, -10, 0] }}
            transition={{ repeat: Infinity, duration: 1.5 }}
          >
            <ArrowRight className={`w-4 h-4 text-primary ${direction === "left" ? "rotate-180" : ""}`} />
          </motion.div>
        </div>
        
        <div className="relative bg-card border border-primary/30 rounded-lg p-2 mx-8">
          {data.map((item, i) => (
            <div key={i} className="flex justify-between text-xs font-mono gap-4">
              <span className="text-muted-foreground">{item.label}:</span>
              <span className="text-primary truncate max-w-[150px]">{item.value}</span>
            </div>
          ))}
        </div>
      </div>
      
      <div className="text-xs font-mono text-muted-foreground w-20">{to}</div>
    </motion.div>
  );
};
