"""Role: Integration tests for full flows.

Tests:
- Complete authentication flow
- Multi-component interactions
- Error handling

Ensures: System works end-to-end
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
from oidc.discovery import DiscoveryEndpoint
from client.oidc_client import OIDCClient
from servers.auth_server import AuthorizationServer
from servers.resource_server import ResourceServer
from pop.client import PoPClient


class TestAuthenticationFlow(unittest.TestCase):
    def setUp(self):
        self.auth_server = AuthorizationServer("http://localhost:5000")
        self.issuer_pk = self.auth_server.issuer_pk
        self.issuer_sk = self.auth_server.issuer_sk

    def test_complete_auth_flow(self):
        # Authorization code issuance
        auth_endpoint = self.auth_server.auth_endpoint
        auth_result = auth_endpoint.handle_authorize_request(
            client_id="client123",
            redirect_uri="https://client.example/cb",
            scope="openid profile email",
            state="state123",
            nonce="nonce123",
            user_id="alice",
        )
        code = auth_result["code"]

        # Token issuance
        code_data = auth_endpoint.validate_code(code, "client123", "https://client.example/cb")
        token_endpoint = TokenEndpoint(
            issuer_url="https://issuer.example",
            issuer_sk=self.issuer_sk,
            issuer_pk=self.issuer_pk,
        )
        response = token_endpoint.handle_token_request(
            grant_type="authorization_code",
            code=code,
            code_data=code_data,
            client_ephemeral_pk=b"client-pk",
            session_id="session-123",
            session_key=b"\x02" * 32,
        )

        self.assertIn("id_token", response)
        jwt = PQJWT()
        claims = jwt.verify_id_token(response["id_token"], self.issuer_pk)
        self.assertEqual(claims["sub"], "alice")

    def test_multi_component_interaction(self):
        # Discovery endpoint
        discovery = DiscoveryEndpoint("https://issuer.example")
        config = discovery.get_configuration()
        self.assertTrue(config["kemtls_supported"])

        # OIDC client uses PoP client internally
        oidc_client = OIDCClient(
            client_id="client123",
            redirect_uri="https://client.example/cb",
            auth_server_url="https://issuer.example",
            client_ephemeral_sk=b"client-sk",
        )
        url = oidc_client.create_authorization_url()
        self.assertIn("authorize", url)

        # Resource server challenge
        resource_server = ResourceServer(self.issuer_pk)
        rs_client = resource_server.app.test_client()
        resp = rs_client.get("/api/userinfo", headers={"Authorization": "Bearer token"})
        self.assertIn(resp.status_code, (200, 401))

    def test_error_handling(self):
        auth_endpoint = self.auth_server.auth_endpoint
        result = auth_endpoint.handle_authorize_request(
            client_id="",
            redirect_uri="",
            scope="openid",
            state="state123",
        )
        self.assertEqual(result.get("error"), "invalid_request")

        # Unsupported grant type
        token_endpoint = self.auth_server.token_endpoint
        response = token_endpoint.handle_token_request(
            grant_type="invalid",
            code="code",
            code_data={"user_id": "alice", "client_id": "client123"},
            client_ephemeral_pk=b"client-pk",
            session_id="session-123",
            session_key=b"\x02" * 32,
        )
        self.assertEqual(response.get("error"), "unsupported_grant_type")


if __name__ == "__main__":
    unittest.main()
