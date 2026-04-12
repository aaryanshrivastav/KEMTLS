import sys
from pathlib import Path
import time

# Add src and benchmarks/collect to path
ROOT_DIR = Path("d:/project/KEMTLS")
SRC_DIR = ROOT_DIR / "src"
COLLECT_DIR = ROOT_DIR / "benchmarks" / "collect"
sys.path.insert(0, str(SRC_DIR))
sys.path.insert(0, str(COLLECT_DIR))

try:
    from runtime_support import BenchmarkStack
    print("Imports successful")
except ImportError as e:
    print(f"Import failed: {e}")
    sys.exit(1)

def test():
    with BenchmarkStack(transport="tcp") as stack:
        print("Starting servers...")
        auth, resource = stack.start_oidc_servers()
        print(f"Auth server: {auth.host}:{auth.port}")
        print(f"Resource server: {resource.host}:{resource.port}")
        
        # Try a simple connection
        import socket
        for name, port in [("auth", auth.port), ("resource", resource.port)]:
            try:
                with socket.create_connection((auth.host, port), timeout=1):
                    print(f"Successfully connected to {name} server")
            except Exception as e:
                print(f"Failed to connect to {name} server: {e}")

if __name__ == "__main__":
    test()
