import { useEffect, useState, useCallback, useRef } from 'react';
import { io, Socket } from 'socket.io-client';

export interface LogMessage {
  message: string;
  level: 'info' | 'success' | 'error' | 'warning';
  timestamp: number;
}

export interface PhaseEvent {
  phase: number;
  name: string;
  details?: Record<string, any>;
  timestamp: number;
  duration?: number;
}

export interface DemoCompleteEvent {
  success: boolean;
  total_time: number;
  summary: Record<string, any>;
  timestamp: number;
}

export interface BenchmarkResults {
  kemtls_handshake: number;
  token_creation: number;
  token_verification: number;
  pop_proof_creation: number;
  pop_verification: number;
  end_to_end: number;
}

export interface UseDemoWebSocketReturn {
  isConnected: boolean;
  isRunning: boolean;
  activePhase: number;
  completedPhases: number[];
  logs: LogMessage[];
  startDemo: () => void;
  resetDemo: () => void;
  error: string | null;
  benchmarkResults: BenchmarkResults | null;
  benchmarksLoading: boolean;
}

const SOCKET_URL = 'http://localhost:5002';

export const useDemoWebSocket = (): UseDemoWebSocketReturn => {
  const [isConnected, setIsConnected] = useState(false);
  const [isRunning, setIsRunning] = useState(false);
  const [activePhase, setActivePhase] = useState(0);
  const [completedPhases, setCompletedPhases] = useState<number[]>([]);
  const [logs, setLogs] = useState<LogMessage[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [benchmarkResults, setBenchmarkResults] = useState<BenchmarkResults | null>(null);
  const [benchmarksLoading, setBenchmarksLoading] = useState(false);
  
  const socketRef = useRef<Socket | null>(null);

  useEffect(() => {
    // Initialize socket connection
    const socket = io(SOCKET_URL, {
      transports: ['polling'],
      reconnection: true,
      reconnectionAttempts: 5,
      reconnectionDelay: 1000,
    });

    socketRef.current = socket;

    // Connection events
    socket.on('connect', () => {
      console.log('WebSocket connected');
      setIsConnected(true);
      setError(null);
    });

    socket.on('disconnect', () => {
      console.log('WebSocket disconnected');
      setIsConnected(false);
    });

    socket.on('connected', (data) => {
      console.log('Demo server ready:', data);
    });

    // Demo events
    socket.on('demo_started', () => {
      console.log('Demo started');
      setIsRunning(true);
      setActivePhase(0);
      setCompletedPhases([]);
      setLogs([]);
      setError(null);
    });

    // Benchmark events
    socket.on('benchmark_start', () => {
      console.log('Benchmarks starting');
      setBenchmarksLoading(true);
      setBenchmarkResults(null);
    });

    socket.on('benchmark_progress', (data: { current: number; total: number; operation: string }) => {
      console.log('Benchmark progress:', data);
    });

    socket.on('benchmark_complete', (data: { results: BenchmarkResults }) => {
      console.log('Benchmarks complete:', data.results);
      setBenchmarkResults(data.results);
      setBenchmarksLoading(false);
    });

    socket.on('phase_start', (data: PhaseEvent) => {
      console.log('Phase started:', data);
      setActivePhase(data.phase);
    });

    socket.on('phase_complete', (data: PhaseEvent) => {
      console.log('Phase completed:', data);
      setCompletedPhases(prev => [...prev, data.phase]);
    });

    socket.on('log', (data: LogMessage) => {
      setLogs(prev => [...prev, data]);
    });

    socket.on('demo_complete', (data: DemoCompleteEvent) => {
      console.log('Demo complete:', data);
      setIsRunning(false);
      setActivePhase(0);
    });

    socket.on('error', (data: { message: string; error: string }) => {
      console.error('Demo error:', data);
      setError(data.message + ': ' + data.error);
      setIsRunning(false);
    });

    // Cleanup on unmount
    return () => {
      socket.disconnect();
    };
  }, []);

  const startDemo = useCallback(() => {
    if (socketRef.current && isConnected && !isRunning) {
      console.log('Sending start_demo event');
      socketRef.current.emit('start_demo');
    }
  }, [isConnected, isRunning]);

  const resetDemo = useCallback(() => {
    console.log('Resetting demo state');
    setIsRunning(false);
    setActivePhase(0);
    setCompletedPhases([]);
    setLogs([]);
    setError(null);
    setBenchmarkResults(null);
    setBenchmarksLoading(false);
  }, []);

  return {
    isConnected,
    isRunning,
    activePhase,
    completedPhases,
    logs,
    startDemo,
    resetDemo,
    error,
    benchmarkResults,
    benchmarksLoading,
  };
};
