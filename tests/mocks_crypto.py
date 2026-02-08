from types import SimpleNamespace

class MockKyberKEM:
    def generate_keypair(self):
        return b"pk", b"sk"
    def encapsulate(self, pk):
        return b"ct", b"ss"
    def decapsulate(self, sk, ct):
        return b"ss"

class MockDilithium:
    def generate_keypair(self):
        return b"sig_pk", b"sig_sk"
    def sign(self, sk, message):
        return b"signature"
    def verify(self, pk, message, signature):
        return signature == b"signature"


class MockKDF:
    @staticmethod
    def derive_session_keys(shared_secrets, transcript):
        return {
            "client_write_key": b"a" * 32,
            "server_write_key": b"b" * 32,
            "session_key": b"c" * 32,
            "pop_key": b"d" * 32,
        }

class MockAEAD:
    def __init__(self, key):
        self.key = key
    def encrypt(self, data, aad):
        return data
    def decrypt(self, data, aad):
        return data

def install_mocks(sys):
    sys.modules["src.crypto.kyber_kem"] = SimpleNamespace(KyberKEM=MockKyberKEM)
    sys.modules["src.crypto.dilithium_sig"] = SimpleNamespace(DilithiumSignature=MockDilithium)
    sys.modules["src.crypto.kdf"] = SimpleNamespace(KeyDerivation=MockKDF)
    sys.modules["src.crypto.aead"] = SimpleNamespace(AEADCipher=MockAEAD)
