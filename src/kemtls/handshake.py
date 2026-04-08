"""
KEMTLS Handshake Protocol (Post-Quantum)

Implements the KEM-based handshake protocol for establishing a secure KEMTLS session,
supporting both certificate-based (baseline) and pre-distributed key (pdk) authentication.
"""

import hmac
import hashlib
from typing import Dict, Any, List, Optional, Tuple
from rust_ext import handshake as rust_handshake
from rust_ext import hashing as rust_hashing
from crypto.ml_kem import MLKEM768
from crypto.ml_kem import KyberKEM
from crypto.ml_dsa import DilithiumSignature
from crypto.key_schedule import KeyDerivation
from crypto.key_schedule import (
    hkdf_expand_label,
    compute_transcript_hash,
    derive_handshake_secret,
    derive_handshake_traffic_secrets,
    derive_finished_keys,
    derive_application_traffic_secrets,
    HASH_LEN
)
from .certs import validate_certificate
from .pdk import PDKTrustStore
from .session import KEMTLSSession
from .exporter import (
    derive_exporter_secret,
    derive_session_binding_id,
    derive_refresh_binding_id
)
from utils.encoding import base64url_encode, base64url_decode
from utils.serialization import serialize_message, deserialize_message
from utils.helpers import generate_random_string


def _decode_bytes_field(message: Dict[str, Any], field_name: str) -> bytes:
    """Decode a serialized Base64url field back to bytes."""
    value = message.get(field_name)
    if isinstance(value, str):
        return base64url_decode(value)
    if isinstance(value, bytes):
        return value
    raise TypeError(f"{field_name} must be bytes")


def _encode_client_hello_python(
    client_random: str,
    expected_identity: str,
    modes: List[str],
) -> bytes:
    return serialize_message(
        {
            'type': 'ClientHello',
            'version': 'KEMTLS/1.0',
            'random': client_random,
            'modes': modes,
            'expected_identity': expected_identity,
        }
    )


def _encode_client_key_exchange_python(ct_eph: bytes, ct_lt: bytes) -> bytes:
    return serialize_message(
        {
            'type': 'ClientKeyExchange',
            'ct_ephemeral': ct_eph,
            'ct_longterm': ct_lt,
        }
    )


def _encode_finished_python(message_type: str, mac: bytes) -> bytes:
    return serialize_message({'type': message_type, 'mac': mac})


def _encode_client_hello(client_random: str, expected_identity: str, modes: List[str]) -> bytes:
    return rust_handshake.client_hello(
        client_random,
        expected_identity,
        modes,
        fallback=_encode_client_hello_python,
    )


def _encode_client_key_exchange(ct_eph: bytes, ct_lt: bytes) -> bytes:
    return rust_handshake.client_key_exchange(
        ct_eph,
        ct_lt,
        fallback=_encode_client_key_exchange_python,
    )


def _encode_finished_message(message_type: str, mac: bytes) -> bytes:
    return rust_handshake.finished(
        message_type,
        mac,
        fallback=_encode_finished_python,
    )


class ClientHandshake:
    """
    Client-side KEMTLS handshake state machine.
    """
    def __init__(
        self,
        expected_identity: str,
        ca_pk: Optional[bytes] = None,
        pdk_store: Optional[PDKTrustStore] = None,
        mode: str = "auto",
        collector: Optional[Any] = None
    ):
        self.expected_identity = expected_identity
        self.ca_pk = ca_pk
        self.pdk_store = pdk_store
        self.mode = mode
        self.collector = collector
        self.transcript: List[bytes] = []
        self.client_random = generate_random_string(32)
        
        # Internal state
        self.ss_eph: Optional[bytes] = None
        self.ss_lt: Optional[bytes] = None
        self.handshake_secret: Optional[bytes] = None
        self.client_fin_key: Optional[bytes] = None
        self.server_fin_key: Optional[bytes] = None

    def client_hello(self) -> bytes:
        """Generate ClientHello."""
        supported_modes = ["baseline", "pdk"] if self.mode == "auto" else [self.mode]
        msg = _encode_client_hello(self.client_random, self.expected_identity, supported_modes)
        if self.collector:
            self.collector.client_hello_size = len(msg)
        self.transcript.append(msg)
        return msg

    def process_server_hello(self, msg_bytes: bytes) -> Tuple[bytes, KEMTLSSession]:
        """Process ServerHello and return ClientKeyExchange."""
        sh = deserialize_message(msg_bytes)
        if self.collector:
            self.collector.server_hello_size = len(msg_bytes)
            self.collector.mode = sh.get('mode', 'kemtls')
        self.transcript.append(msg_bytes)
        
        if sh.get('version') != 'KEMTLS/1.0':
            raise ValueError("Incompatible KEMTLS version")
            
        mode = sh.get('mode')
        server_eph_pk = _decode_bytes_field(sh, 'eph_pk')
        
        # 1. Identity Validation
        if mode == 'baseline':
            cert = sh.get('cert')
            if not self.ca_pk:
                raise ValueError("Baseline mode requires CA public key")
            
            import time
            start_ns = time.perf_counter_ns()
            server_lt_pk = validate_certificate(cert, self.ca_pk, self.expected_identity)
            if self.collector:
                self.collector.cert_verify_ns = time.perf_counter_ns() - start_ns
            
            trusted_key_id = None
        elif mode == 'pdk':
            key_id = sh.get('key_id')
            if not self.pdk_store:
                raise ValueError("PDK mode requires PDK trust store")
            
            import time
            start_ns = time.perf_counter_ns()
            entry = self.pdk_store.resolve_expected_identity(self.expected_identity, key_id)
            if self.collector:
                self.collector.pdk_lookup_ns = time.perf_counter_ns() - start_ns
            
            server_lt_pk = entry['ml_kem_public_key']
            trusted_key_id = key_id
        else:
            raise ValueError(f"Server selected unsupported mode: {mode}")

        # 2. Key Exchange
        ct_eph, self.ss_eph = MLKEM768.encapsulate(server_eph_pk)
        ct_lt, self.ss_lt = MLKEM768.encapsulate(server_lt_pk)
        
        msg = _encode_client_key_exchange(ct_eph, ct_lt)
        if self.collector:
            self.collector.client_finish_size = len(msg)
        self.transcript.append(msg)
        
        # 3. Derive Handshake Secrets
        self.handshake_secret = derive_handshake_secret([self.ss_eph, self.ss_lt])
        t1 = compute_transcript_hash(self.transcript[:2]) # Up to SH
        traffic = derive_handshake_traffic_secrets(self.handshake_secret, t1)
        fin_keys = derive_finished_keys(
            traffic['client_handshake_traffic_secret'],
            traffic['server_handshake_traffic_secret']
        )
        self.client_fin_key = fin_keys['client_finished_key']
        self.server_fin_key = fin_keys['server_finished_key']
        
        session = KEMTLSSession(
            session_id=sh['session_id'],
            peer_identity=self.expected_identity,
            handshake_mode=sh['mode'],
            trusted_key_id=trusted_key_id,
        )

        return msg, session

    def process_server_finished(
        self,
        msg_bytes: bytes,
        session: Optional[KEMTLSSession] = None,
    ) -> KEMTLSSession:
        """Verify ServerFinished and finalize session."""
        t1 = compute_transcript_hash(self.transcript[:2])
        sf = deserialize_message(msg_bytes)
        
        # Verify MAC
        server_mac = _decode_bytes_field(sf, 'mac')
        expected_mac = rust_handshake.hmac_sha256(
            self.server_fin_key,
            t1,
            fallback=_hmac_sha256_python,
        )
        if server_mac != expected_mac:
            raise ValueError("ServerFinished MAC verification failed")
            
        if self.collector:
            self.collector.server_finish_size = len(msg_bytes)

        self.transcript.append(msg_bytes)
        t2 = compute_transcript_hash(self.transcript[:3]) # Up to CKE
        t3 = compute_transcript_hash(self.transcript)    # Up to SF
        
        # Finalize Application Keys
        app_traffic = derive_application_traffic_secrets(self.handshake_secret, t3)
        exporter_secret = derive_exporter_secret(self.handshake_secret, t3)
        
        sh = deserialize_message(self.transcript[1])
        
        # Use simple key derivation for IVs (8 bytes from secret)
        client_iv = hkdf_expand_label(app_traffic['client_application_traffic_secret'], b"iv", b"", 12)
        server_iv = hkdf_expand_label(app_traffic['server_application_traffic_secret'], b"iv", b"", 12)

        if session is None:
            session = KEMTLSSession(
                session_id=sh['session_id'],
                peer_identity=self.expected_identity,
                handshake_mode=sh['mode'],
                trusted_key_id=sh.get('key_id'),
            )

        session.client_app_secret = app_traffic['client_application_traffic_secret']
        session.server_app_secret = app_traffic['server_application_traffic_secret']
        session.client_write_key = app_traffic['client_application_traffic_secret']
        session.client_write_iv = client_iv
        session.server_write_key = app_traffic['server_application_traffic_secret']
        session.server_write_iv = server_iv
        session.exporter_secret = exporter_secret
        session.session_binding_id = derive_session_binding_id(exporter_secret)
        session.refresh_binding_id = derive_refresh_binding_id(exporter_secret)

        return session

    def client_finished(self) -> bytes:
        """Generate ClientFinished."""
        t2 = compute_transcript_hash(self.transcript[:3])
        mac = rust_handshake.hmac_sha256(
            self.client_fin_key,
            t2,
            fallback=_hmac_sha256_python,
        )
        msg = _encode_finished_message('ClientFinished', mac)
        self.transcript.append(msg)
        return msg


def _hmac_sha256_python(key: bytes, data: bytes) -> bytes:
    return hmac.new(key, data, hashlib.sha256).digest()


class ServerHandshake:
    """
    Server-side KEMTLS handshake state machine.
    """
    def __init__(
        self,
        server_identity: str,
        server_lt_sk: bytes,
        cert: Optional[Dict[str, Any]] = None,
        pdk_key_id: Optional[str] = None,
        collector: Optional[Any] = None
    ):
        self.server_identity = server_identity
        self.server_lt_sk = server_lt_sk
        self.cert = cert
        self.pdk_key_id = pdk_key_id
        self.collector = collector
        self.transcript: List[bytes] = []
        self.session_id = generate_random_string(16)
        
        # Ephemeral keys
        self.eph_pk, self.eph_sk = MLKEM768.generate_keypair()
        
        # Internal state
        self.handshake_secret: Optional[bytes] = None
        self.client_fin_key: Optional[bytes] = None
        self.server_fin_key: Optional[bytes] = None

    def process_client_hello(self, msg_bytes: bytes) -> bytes:
        """Process ClientHello and return ServerHello."""
        ch = deserialize_message(msg_bytes)
        if self.collector:
            self.collector.client_hello_size = len(msg_bytes)
        self.transcript.append(msg_bytes)
        
        modes = ch.get('modes', [])
        # Negotiation logic
        if self.pdk_key_id and 'pdk' in modes:
            mode = 'pdk'
        elif self.cert and 'baseline' in modes:
            mode = 'baseline'
        else:
            raise ValueError("No mutually supported authentication modes")
            
        sh = {
            'type': 'ServerHello',
            'version': 'KEMTLS/1.0',
            'session_id': self.session_id,
            'mode': mode,
            'eph_pk': self.eph_pk
        }
        if mode == 'baseline':
            sh['cert'] = self.cert
        else:
            sh['key_id'] = self.pdk_key_id
            
        msg = serialize_message(sh)
        if self.collector:
            self.collector.server_hello_size = len(msg)
            self.collector.mode = mode
        self.transcript.append(msg)
        return msg

    def process_client_key_exchange(self, msg_bytes: bytes) -> bytes:
        """Process ClientKeyExchange and return ServerFinished."""
        cke = deserialize_message(msg_bytes)
        if self.collector:
            self.collector.client_finish_size = len(msg_bytes)
        self.transcript.append(msg_bytes)
        
        # 1. Decapsulate
        ct_eph = _decode_bytes_field(cke, 'ct_ephemeral')
        ct_lt = _decode_bytes_field(cke, 'ct_longterm')
        ss_eph = MLKEM768.decapsulate(self.eph_sk, ct_eph)
        ss_lt = MLKEM768.decapsulate(self.server_lt_sk, ct_lt)
        
        # 2. Derive Handshake Secrets
        self.handshake_secret = derive_handshake_secret([ss_eph, ss_lt])
        t1 = compute_transcript_hash(self.transcript[:2])
        traffic = derive_handshake_traffic_secrets(self.handshake_secret, t1)
        fin_keys = derive_finished_keys(
            traffic['client_handshake_traffic_secret'],
            traffic['server_handshake_traffic_secret']
        )
        self.client_fin_key = fin_keys['client_finished_key']
        self.server_fin_key = fin_keys['server_finished_key']
        
        # 3. Generate ServerFinished
        mac = rust_handshake.hmac_sha256(
            self.server_fin_key,
            t1,
            fallback=_hmac_sha256_python,
        )
        msg = _encode_finished_message('ServerFinished', mac)
        if self.collector:
            self.collector.server_finish_size = len(msg)
        self.transcript.append(msg)
        return msg

    def verify_client_finished(self, msg_bytes: bytes) -> KEMTLSSession:
        """Verify ClientFinished and finalize session."""
        t2 = compute_transcript_hash(self.transcript[:3])
        cf = deserialize_message(msg_bytes)
        
        client_mac = _decode_bytes_field(cf, 'mac')
        if rust_handshake.hmac_sha256(
            self.client_fin_key,
            t2,
            fallback=_hmac_sha256_python,
        ) != client_mac:
            raise ValueError("ClientFinished MAC verification failed")
            
        self.transcript.append(msg_bytes)
        # SF is msg 4 in transcript
        t3 = compute_transcript_hash(self.transcript[:4])
        
        # Finalize Application Keys
        app_traffic = derive_application_traffic_secrets(self.handshake_secret, t3)
        exporter_secret = derive_exporter_secret(self.handshake_secret, t3)
        
        sh = deserialize_message(self.transcript[1])
        client_iv = hkdf_expand_label(app_traffic['client_application_traffic_secret'], b"iv", b"", 12)
        server_iv = hkdf_expand_label(app_traffic['server_application_traffic_secret'], b"iv", b"", 12)

        return KEMTLSSession(
            session_id=self.session_id,
            peer_identity="client", # In this simplified flow, client is anonymous
            handshake_mode=sh['mode'],
            trusted_key_id=self.pdk_key_id if sh['mode'] == 'pdk' else None,
            client_app_secret=app_traffic['client_application_traffic_secret'],
            server_app_secret=app_traffic['server_application_traffic_secret'],
            client_write_key=app_traffic['client_application_traffic_secret'],
            client_write_iv=client_iv,
            server_write_key=app_traffic['server_application_traffic_secret'],
            server_write_iv=server_iv,
            exporter_secret=exporter_secret,
            session_binding_id=derive_session_binding_id(exporter_secret),
            refresh_binding_id=derive_refresh_binding_id(exporter_secret)
        )


class KEMTLSHandshake:
    """Backward-compatible facade kept for legacy demos/tests."""

    def __init__(self, is_server: bool = False):
        self.is_server = is_server
        self.kem = KyberKEM()
        self.sig = DilithiumSignature()
        self.transcript = b""
        self.session_keys: Optional[Dict[str, bytes]] = None
        self.session_id: Optional[str] = None

        self.server_ephemeral_sk: Optional[bytes] = None
        self.server_longterm_sk: Optional[bytes] = None
        self.client_ephemeral_sk: Optional[bytes] = None
        self.client_ephemeral_pk: Optional[bytes] = None

    def server_init_handshake(self, server_longterm_sk: bytes, server_longterm_pk: bytes) -> Dict[str, Any]:
        eph_pk, eph_sk = self.kem.generate_keypair()
        self.server_ephemeral_sk = eph_sk
        self.server_longterm_sk = server_longterm_sk
        self.session_id = generate_random_string(16)

        server_hello = {
            "type": "ServerHello",
            "server_ephemeral_pk": base64url_encode(eph_pk),
            "server_longterm_pk": base64url_encode(server_longterm_pk),
            "session_id": self.session_id,
        }

        self.transcript += serialize_message(server_hello)
        return server_hello

    def server_process_client_key_exchange(self, client_key_exchange: Dict[str, Any]) -> Dict[str, bytes]:
        self.transcript += serialize_message(client_key_exchange)

        ct_eph = base64url_decode(client_key_exchange["ciphertext_ephemeral"])
        ct_lt = base64url_decode(client_key_exchange["ciphertext_longterm"])

        ss_eph = self.kem.decapsulate(self.server_ephemeral_sk, ct_eph)
        ss_lt = self.kem.decapsulate(self.server_longterm_sk, ct_lt)

        self.client_ephemeral_pk = base64url_decode(client_key_exchange["client_ephemeral_pk"])

        transcript_hash = rust_hashing.sha256_digest(
            self.transcript,
            fallback=lambda data: hashlib.sha256(data).digest(),
        )
        self.session_keys = KeyDerivation.derive_session_keys([ss_eph, ss_lt], transcript_hash)
        return self.session_keys

    def client_process_server_hello(
        self, server_hello: Dict[str, Any], trusted_longterm_pk: bytes
    ) -> Tuple[Dict[str, Any], bytes]:
        self.transcript += serialize_message(server_hello)

        server_eph_pk = base64url_decode(server_hello["server_ephemeral_pk"])
        server_lt_pk = base64url_decode(server_hello["server_longterm_pk"])

        if server_lt_pk != trusted_longterm_pk:
            raise ValueError("Server authentication failed: untrusted long-term key")

        self.session_id = server_hello["session_id"]

        ct_eph, ss_eph = self.kem.encapsulate(server_eph_pk)
        ct_lt, ss_lt = self.kem.encapsulate(server_lt_pk)

        client_eph_pk, client_eph_sk = self.sig.generate_keypair()
        self.client_ephemeral_pk = client_eph_pk
        self.client_ephemeral_sk = client_eph_sk

        client_key_exchange = {
            "type": "ClientKeyExchange",
            "ciphertext_ephemeral": base64url_encode(ct_eph),
            "ciphertext_longterm": base64url_encode(ct_lt),
            "client_ephemeral_pk": base64url_encode(client_eph_pk),
            "session_id": self.session_id,
        }

        self.transcript += serialize_message(client_key_exchange)

        transcript_hash = rust_hashing.sha256_digest(
            self.transcript,
            fallback=lambda data: hashlib.sha256(data).digest(),
        )
        self.session_keys = KeyDerivation.derive_session_keys([ss_eph, ss_lt], transcript_hash)
        return client_key_exchange, client_eph_pk

    def get_session_keys(self) -> Optional[Dict[str, bytes]]:
        return self.session_keys

    def get_session_id(self) -> Optional[str]:
        return self.session_id

    def get_client_ephemeral_pubkey(self) -> Optional[bytes]:
        return self.client_ephemeral_pk
