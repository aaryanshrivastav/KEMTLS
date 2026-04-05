"""Compatibility wrapper around the new resource server app factory."""

from __future__ import annotations

from .resource_server_app import create_resource_server_app


class ResourceServer:
    def __init__(self, issuer_pk: bytes, config=None, stores=None):
        merged_config = {
            "issuer": "https://issuer.example",
            "issuer_public_key": issuer_pk,
            "resource_audience": "client123",
        }
        if config:
            merged_config.update(config)

        self.issuer_pk = merged_config["issuer_public_key"]
        self.app = create_resource_server_app(merged_config, stores)

    def run(self, host: str = "0.0.0.0", port: int = 5001):
        self.app.run(host=host, port=port)


__all__ = ["ResourceServer"]
