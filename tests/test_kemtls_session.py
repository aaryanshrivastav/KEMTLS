import sys
import os

ROOT_DIR = os.path.dirname(os.path.dirname(__file__))
SRC_DIR = os.path.join(ROOT_DIR, "src")
if SRC_DIR not in sys.path:
    sys.path.insert(0, SRC_DIR)

from kemtls.session import KEMTLSSession

session = KEMTLSSession(
    session_id="sess-1",
    peer_identity="server-1",
    handshake_mode="baseline",
)

assert session.session_id == "sess-1"
assert session.peer_identity == "server-1"
assert session.handshake_mode == "baseline"
assert session.client_write_key is None
assert session.server_write_key is None

print("✓ KEMTLS session data model test passed")
