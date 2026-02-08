"""
Client-Side Proof-of-Possession
"""

import hashlib
from src.crypto.dilithium_sig import DilithiumSignature
from src.utils.encoding import base64url_encode
from src.utils.serialization import serialize_message


class PoPClient:
    def __init__(self, client_ephemeral_sk: bytes):
        self.client_ephemeral_sk = client_ephemeral_sk
        self.sig = DilithiumSignature()
    
    def create_pop_proof(self, challenge: dict, token: str) -> str:
        message = serialize_message({
            'nonce': challenge['nonce'],
            'token_hash': hashlib.sha256(token.encode()).hexdigest(),
            'timestamp': challenge['timestamp']
        })
        signature = self.sig.sign(self.client_ephemeral_sk, message)
        return base64url_encode(signature)
