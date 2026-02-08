import sys
import os

ROOT_DIR = os.path.dirname(os.path.dirname(__file__))
SRC_DIR = os.path.join(ROOT_DIR, "src")
if SRC_DIR not in sys.path:
    sys.path.insert(0, SRC_DIR)

from kemtls.channel import KEMTLSChannel

keys = {
    "client_write_key": b"a" * 32,
    "server_write_key": b"b" * 32,
}

client = KEMTLSChannel(keys, is_server=False)
server = KEMTLSChannel(keys, is_server=True)

msg = b"hello"
enc = client.send(msg)
dec = server.receive(enc)

assert dec == msg
print("✓ KEMTLS channel test passed")
