import sys
import os

ROOT_DIR = os.path.dirname(os.path.dirname(__file__))
SRC_DIR = os.path.join(ROOT_DIR, "src")
if SRC_DIR not in sys.path:
    sys.path.insert(0, SRC_DIR)

from kemtls.session import KEMTLSSession
from crypto.kyber_kem import KyberKEM

# Generate real keypairs
kem = KyberKEM()
lt_pk, lt_sk = kem.generate_keypair()

server = KEMTLSSession(is_server=True)
client = KEMTLSSession(is_server=False)

server_hello = server.handshake.server_init_handshake(
    lt_sk, lt_pk
)

client_kex, _ = client.handshake.client_process_server_hello(
    server_hello,
    trusted_longterm_pk=lt_pk
)

server.handshake.server_process_client_key_exchange(client_kex)

client_channel = client.establish_channel()
server_channel = server.establish_channel()

msg = b"KEMTLS OK"
cipher = client_channel.send(msg)
plain = server_channel.receive(cipher)

assert plain == msg
print("✓ KEMTLS full test passed")
