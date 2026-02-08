import sys
from tests.mocks_crypto import install_mocks
install_mocks(sys)

from src.kemtls.session import KEMTLSSession

server = KEMTLSSession(is_server=True)
client = KEMTLSSession(is_server=False)

server_hello = server.handshake.server_init_handshake(
    b"lt_sk", b"lt_pk"
)

client_kex, _ = client.handshake.client_process_server_hello(
    server_hello,
    trusted_longterm_pk=b"lt_pk"
)

server.handshake.server_process_client_key_exchange(client_kex)

client_channel = client.establish_channel()
server_channel = server.establish_channel()

msg = b"KEMTLS OK"
cipher = client_channel.send(msg)
plain = server_channel.receive(cipher)

assert plain == msg
