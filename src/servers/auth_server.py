"""Compatibility wrapper around the new authorization server app factory."""

from __future__ import annotations

from crypto.ml_dsa import MLDSA65

from .auth_server_app import create_auth_server_app


class AuthorizationServer:
    def __init__(self, issuer_url: str = "http://localhost:5000", config=None, stores=None):
        issuer_pk, issuer_sk = MLDSA65.generate_keypair()
        merged_config = {
            "issuer": issuer_url,
            "issuer_public_key": issuer_pk,
            "issuer_secret_key": issuer_sk,
            "signing_kid": "signing-key-1",
            "clients": {
                "client123": {"redirect_uris": ["https://client.example/cb"]},
            },
            "demo_user": "alice",
            "introspection_endpoint": f"{issuer_url.rstrip('/')}/introspect",
        }
        if config:
            merged_config.update(config)

        self.issuer_url = merged_config["issuer"]
        self.issuer_pk = merged_config["issuer_public_key"]
        self.issuer_sk = merged_config["issuer_secret_key"]
        self.app = create_auth_server_app(merged_config, stores)
        self.auth_endpoint = self.app.extensions["auth_endpoint"]
        self.token_endpoint = self.app.extensions["token_endpoint"]
        self.discovery_endpoint = self.app.extensions["discovery_endpoint"]

    def run(self, host: str = "0.0.0.0", port: int = 5000):
        self.app.run(host=host, port=port)


__all__ = ["AuthorizationServer"]
