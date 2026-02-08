"""Role: Security tests.

Tests:
- Token theft scenarios
- Replay attacks
- Expired token handling
- Invalid signature detection

Ensures: Security properties hold
"""

import os
import sys
import time
import unittest


ROOT_DIR = os.path.dirname(os.path.dirname(__file__))
SRC_DIR = os.path.join(ROOT_DIR, "src")
if SRC_DIR not in sys.path:
	sys.path.insert(0, SRC_DIR)


from oidc.authorization import AuthorizationEndpoint
from oidc.token import TokenEndpoint
from oidc.jwt_handler import PQJWT
from crypto.dilithium_sig import DilithiumSignature
from utils.helpers import get_timestamp


class TestAuthorizationCodeReplay(unittest.TestCase):
	def test_authorization_code_replay(self):
		endpoint = AuthorizationEndpoint()
		result = endpoint.handle_authorize_request(
			client_id="client123",
			redirect_uri="https://client.example/cb",
			scope="openid",
			state="state123",
			user_id="alice",
		)
		code = result["code"]

		first = endpoint.validate_code(code, "client123", "https://client.example/cb")
		self.assertIsNotNone(first)

		second = endpoint.validate_code(code, "client123", "https://client.example/cb")
		self.assertIsNone(second)


class TestTokenSecurity(unittest.TestCase):
	def setUp(self):
		sig = DilithiumSignature()
		self.issuer_pk, self.issuer_sk = sig.generate_keypair()
		self.client_pk, _ = sig.generate_keypair()

		self.auth = AuthorizationEndpoint()
		self.token_endpoint = TokenEndpoint(
			issuer_url="https://issuer.example",
			issuer_sk=self.issuer_sk,
			issuer_pk=self.issuer_pk,
		)

	def _issue_token(self, exp_offset: int = 3600):
		result = self.auth.handle_authorize_request(
			client_id="client123",
			redirect_uri="https://client.example/cb",
			scope="openid profile email",
			state="state123",
			nonce="nonce123",
			user_id="alice",
		)
		code = result["code"]
		code_data = self.auth.validate_code(code, "client123", "https://client.example/cb")

		# Manually override exp for security tests
		code_data["issued_at"] = get_timestamp()
		code_data["expires_at"] = get_timestamp() + 600

		response = self.token_endpoint.handle_token_request(
			grant_type="authorization_code",
			code=code,
			code_data=code_data,
			client_ephemeral_pk=self.client_pk,
			session_id="session-123",
			session_key=b"\x02" * 32,
		)

		return response["id_token"]

	def test_token_theft_invalid_signature(self):
		id_token = self._issue_token()
		parts = id_token.split(".")
		# Tamper signature to simulate theft/tampering
		parts[2] = "tampered"
		tampered = ".".join(parts)

		jwt = PQJWT()
		with self.assertRaises(ValueError):
			jwt.verify_id_token(tampered, self.issuer_pk)

	def test_expired_token_handling(self):
		id_token = self._issue_token()
		jwt = PQJWT()
		claims = jwt.verify_id_token(id_token, self.issuer_pk)

		# Force expiration by waiting or modifying exp claim
		claims["exp"] = int(time.time()) - 1

		# Recreate token with expired exp
		expired_token = jwt.create_id_token(
			claims,
			self.issuer_sk,
			self.issuer_pk,
			client_ephemeral_pk=self.client_pk,
			session_key=b"\x02" * 32,
			session_id="session-123",
		)

		with self.assertRaises(ValueError):
			jwt.verify_id_token(expired_token, self.issuer_pk)

	def test_invalid_signature_detection(self):
		id_token = self._issue_token()
		jwt = PQJWT()

		# Verify with wrong issuer key
		sig = DilithiumSignature()
		wrong_pk, _ = sig.generate_keypair()

		with self.assertRaises(ValueError):
			jwt.verify_id_token(id_token, wrong_pk)

	def test_token_replay_same_token(self):
		id_token = self._issue_token()
		jwt = PQJWT()

		first = jwt.verify_id_token(id_token, self.issuer_pk)
		second = jwt.verify_id_token(id_token, self.issuer_pk)

		# Replay is not prevented at JWT layer; ensure claims are identical
		self.assertEqual(first, second)


if __name__ == "__main__":
	unittest.main()
