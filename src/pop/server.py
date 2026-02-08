"""
Server-Side PoP Verification
"""

import hashlib
from src.crypto.dilithium_sig import DilithiumSignature
from src.utils.helpers import generate_random_string, get_timestamp
from src.utils.encoding import base64url_decode
from src.utils.serialization import serialize_message


class ProofOfPossession:
    def __init__(self):
        self.sig = DilithiumSignature()
        self.active_challenges = {}
    
    def generate_challenge(self, session_id=None):
        nonce = generate_random_string(32)
        timestamp = get_timestamp()
        challenge = {'nonce': nonce, 'timestamp': timestamp}
        if session_id:
            challenge['session_id'] = session_id
        self.active_challenges[nonce] = {'challenge': challenge, 'created_at': timestamp}
        return challenge
    
    def verify_pop_response(self, challenge, proof, client_eph_pk, token):
        nonce = challenge['nonce']
        if nonce not in self.active_challenges:
            return False
        
        if get_timestamp() - self.active_challenges[nonce]['created_at'] > 300:
            del self.active_challenges[nonce]
            return False
        
        message = serialize_message({
            'nonce': nonce,
            'token_hash': hashlib.sha256(token.encode()).hexdigest(),
            'timestamp': challenge['timestamp']
        })
        
        try:
            signature = base64url_decode(proof)
            is_valid = self.sig.verify(client_eph_pk, message, signature)
            if is_valid:
                del self.active_challenges[nonce]
            return is_valid
        except Exception:
            return False

