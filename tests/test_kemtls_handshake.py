import sys
from tests.mocks_crypto import install_mocks
install_mocks(sys)

from src.kemtls.handshake import KEMTLSHandshake

server = KEMTLSHandshake(is_server=True)
client = KEMTLSHandshake(is_server=False)

server_hello = server.server_init_handshake(b"lt_sk", b"lt_pk")

client_kex, _ = client.client_process_server_hello(
    server_hello,
    trusted_longterm_pk=b"lt_pk"
)

server_keys = server.server_process_client_key_exchange(client_kex)
client_keys = client.get_session_keys()

assert server_keys == client_keys
