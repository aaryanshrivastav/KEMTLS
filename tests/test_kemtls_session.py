import sys
from tests.mocks_crypto import install_mocks
install_mocks(sys)

from src.kemtls.session import KEMTLSSession

session = KEMTLSSession(is_server=False)

try:
    session.establish_channel()
    raise AssertionError
except RuntimeError:
    pass
