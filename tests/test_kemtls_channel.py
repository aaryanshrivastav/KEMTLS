import sys
from tests.mocks_crypto import install_mocks
install_mocks(sys)

from src.kemtls.channel import KEMTLSChannel

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
