import sys
import os

ROOT_DIR = os.path.dirname(os.path.dirname(__file__))
SRC_DIR = os.path.join(ROOT_DIR, "src")
if SRC_DIR not in sys.path:
    sys.path.insert(0, SRC_DIR)

from kemtls.session import KEMTLSSession

session = KEMTLSSession(is_server=False)

try:
    session.establish_channel()
    raise AssertionError
except RuntimeError:
    pass
print("✓ KEMTLS session test passed")
