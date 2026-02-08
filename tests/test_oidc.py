"""Role: Unit tests for OIDC protocol.

Tests:
- Authorization code flow
- Token issuance
- JWT structure
- Claims inclusion

Ensures: OIDC compliance
"""

import json
import os
import sys
import unittest


ROOT_DIR = os.path.dirname(os.path.dirname(__file__))
SRC_DIR = os.path.join(ROOT_DIR, "src")
if SRC_DIR not in sys.path:
	sys.path.insert(0, SRC_DIR)


from oidc.authorization import AuthorizationEndpoint
from oidc.token import TokenEndpoint
from oidc.jwt_handler import PQJWT
from utils.encoding import base64url_decode
from utils.helpers import get_timestamp
from crypto.dilithium_sig import DilithiumSignature


class TestAuthorizationCodeFlow(unittest.TestCase):
	def test_authorization_code_flow(self):
		endpoint = AuthorizationEndpoint()

		result = endpoint.handle_authorize_request(
			client_id="client123",
			redirect_uri="https://client.example/cb",
			scope="openid profile email",
			state="state123",
			nonce="nonce123",
			user_id="alice",
		)

		self.assertIn("code", result)
		self.assertEqual(result["state"], "state123")

		code_data = endpoint.validate_code(
			result["code"],
			client_id="client123",
			redirect_uri="https://client.example/cb",
		)
		self.assertIsNotNone(code_data)
		self.assertEqual(code_data["user_id"], "alice")
		self.assertEqual(code_data["scope"], "openid profile email")
		self.assertEqual(code_data["nonce"], "nonce123")

		# One-time use
		self.assertIsNone(
			endpoint.validate_code(
				result["code"],
				client_id="client123",
				redirect_uri="https://client.example/cb",
			)
		)


class TestTokenIssuance(unittest.TestCase):
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

	def _issue_code(self):
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
		return code, code_data

	def test_token_issuance(self):
		code, code_data = self._issue_code()
		self.assertIsNotNone(code_data)

		response = self.token_endpoint.handle_token_request(
			grant_type="authorization_code",
			code=code,
			code_data=code_data,
			client_ephemeral_pk=self.client_pk,
			session_id="session-123",
			session_key=b"\x02" * 32,
		)

		self.assertEqual(response["token_type"], "Bearer")
		self.assertIn("access_token", response)
		self.assertIn("id_token", response)
		self.assertEqual(response["expires_in"], 3600)
		self.assertIn("profile", response["scope"])
		self.assertIn("email", response["scope"])

	def test_jwt_structure(self):
		code, code_data = self._issue_code()
		response = self.token_endpoint.handle_token_request(
			grant_type="authorization_code",
			code=code,
			code_data=code_data,
			client_ephemeral_pk=self.client_pk,
			session_id="session-123",
			session_key=b"\x02" * 32,
		)

		id_token = response["id_token"]
		parts = id_token.split(".")
		self.assertEqual(len(parts), 3)

		header = json.loads(base64url_decode(parts[0]))
		self.assertEqual(header.get("alg"), "DILITHIUM3")
		self.assertEqual(header.get("typ"), "JWT")
		self.assertEqual(header.get("kid"), "server-signing-key")

	def test_claims_inclusion(self):
		code, code_data = self._issue_code()
		response = self.token_endpoint.handle_token_request(
			grant_type="authorization_code",
			code=code,
			code_data=code_data,
			client_ephemeral_pk=self.client_pk,
			session_id="session-123",
			session_key=b"\x02" * 32,
		)

		jwt = PQJWT()
		claims = jwt.verify_id_token(response["id_token"], self.issuer_pk)
		self.assertEqual(claims["iss"], "https://issuer.example")
		self.assertEqual(claims["sub"], "alice")
		self.assertEqual(claims["aud"], "client123")
		self.assertEqual(claims["nonce"], "nonce123")
		self.assertEqual(claims["name"], "User alice")
		self.assertEqual(claims["email"], "alice@example.com")
		self.assertTrue(claims["email_verified"])
		self.assertIn("cnf", claims)
		self.assertIn("exp", claims)
		self.assertGreater(claims["exp"], get_timestamp())


if __name__ == "__main__":
	unittest.main()
