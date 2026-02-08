import sys
from tests.mocks_crypto import install_mocks
install_mocks(sys)


from src.pop.client import PoPClient
from src.pop.server import ProofOfPossession

client_sk = b"client_sk"
client_pk = b"client_pk"
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
