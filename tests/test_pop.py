import sys
import os

ROOT_DIR = os.path.dirname(os.path.dirname(__file__))
SRC_DIR = os.path.join(ROOT_DIR, "src")
if SRC_DIR not in sys.path:
    sys.path.insert(0, SRC_DIR)

from pop.client import PoPClient
from pop.server import ProofOfPossession
from crypto.dilithium_sig import DilithiumSignature

# Generate real Dilithium keypair
sig = DilithiumSignature()
client_pk, client_sk = sig.generate_keypair()
token = "dummy.jwt.token"

server = ProofOfPossession()
client = PoPClient(client_sk)

challenge = server.generate_challenge(session_id="sess1")

proof = client.create_pop_proof(challenge, token)

assert server.verify_pop_response(
    challenge=challenge,
    proof=proof,
    client_eph_pk=client_pk,
    token=token
) is True

assert server.verify_pop_response(
    challenge=challenge,
    proof=proof,
    client_eph_pk=client_pk,
    token=token
) is False
print("✓ PoP test passed")
