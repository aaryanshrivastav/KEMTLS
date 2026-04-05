import sys
import os

ROOT_DIR = os.path.dirname(os.path.dirname(__file__))
SRC_DIR = os.path.join(ROOT_DIR, "src")
if SRC_DIR not in sys.path:
    sys.path.insert(0, SRC_DIR)

from kemtls.session import KEMTLSSession
from kemtls.handshake import KEMTLSHandshake
from kemtls.channel import KEMTLSChannel
from crypto.ml_kem import KyberKEM

# Generate real keypairs
kem = KyberKEM()
lt_pk, lt_sk = kem.generate_keypair()

server = KEMTLSHandshake(is_server=True)
client = KEMTLSHandshake(is_server=False)

server_hello = server.server_init_handshake(
    lt_sk, lt_pk
)

client_kex, _ = client.client_process_server_hello(
    server_hello,
    trusted_longterm_pk=lt_pk
)

server_keys = server.server_process_client_key_exchange(client_kex)
client_keys = client.get_session_keys()

assert client_keys == server_keys

client_channel = KEMTLSChannel(client_keys, is_server=False)
server_channel = KEMTLSChannel(server_keys, is_server=True)

msg = b"KEMTLS OK"
cipher = client_channel.send(msg)
plain = server_channel.receive(cipher)

assert plain == msg
print("✓ KEMTLS full test passed")
