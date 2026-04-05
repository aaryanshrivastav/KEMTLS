"""JWKS publishing for ML-DSA public signing keys."""

from __future__ import annotations

from typing import Dict, Optional

from flask import jsonify

from crypto.ml_dsa import MLDSA65


class JWKSEndpoint:
    """Publishes a normal JWKS document with one or more ML-DSA signing keys."""

    def __init__(self, keys: Optional[Dict[str, bytes]] = None):
        self._keys: Dict[str, bytes] = {}
        if keys:
            for kid, public_key in keys.items():
                self.add_key(kid, public_key)

    def add_key(self, kid: str, public_key: bytes) -> None:
        if not isinstance(kid, str) or not kid:
            raise ValueError("kid must be a non-empty string")
        MLDSA65._validate_public_key(public_key)
        self._keys[kid] = public_key

    def get_key(self, kid: str) -> Optional[bytes]:
        if not isinstance(kid, str) or not kid:
            return None
        return self._keys.get(kid)

    def get_jwks(self) -> Dict[str, list]:
        return {
            "keys": [
                MLDSA65.public_key_to_jwk(public_key, kid=kid)
                for kid, public_key in self._keys.items()
            ]
        }

    def register_routes(self, app) -> None:
        @app.route("/jwks", methods=["GET"])
        def jwks_route():
            return jsonify(self.get_jwks())


__all__ = ["JWKSEndpoint"]
