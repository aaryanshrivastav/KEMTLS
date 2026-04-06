"""
KEMTLS HTTP Client

A high-level client that provides an asynchronous (requests-like) API over the 
KEMTLS transport. It supports URL parsing, request formatting, and 
response parsing for KEMTLS-secured HTTP interaction.
"""

import json
from typing import Dict, Any, Optional, Tuple
from urllib.parse import urlparse, urlencode
from kemtls.client import KEMTLSClient
from kemtls.pdk import PDKTrustStore


class KEMTLSHttpClient:
    """
    High-level HTTP client over KEMTLS.
    Supports only 'kemtls://' URLs.
    """
    
    def __init__(
        self,
        ca_pk: Optional[bytes] = None,
        pdk_store: Optional[PDKTrustStore] = None,
        expected_identity: str = "server",
        mode: str = "auto",
        keep_alive: bool = False,
    ):
        """
        Initialize the HTTP client.
        
        Args:
            ca_pk: Certificate Authority public key (ML-DSA)
            pdk_store: PDK Trust Store for pre-distributed keys
            expected_identity: Target server's identity
            mode: Handshake mode (baseline, pdk, or auto)
        """
        self.ca_pk = ca_pk
        self.pdk_store = pdk_store
        self.expected_identity = expected_identity
        self.mode = mode
        self.keep_alive = keep_alive
        
        # Internal transport client
        self.client = KEMTLSClient(
            expected_identity=expected_identity,
            ca_pk=ca_pk,
            pdk_store=pdk_store,
            mode=mode
        )

    def close(self) -> None:
        """Close any active persistent KEMTLS connection."""
        self.client.close()

    def get(self, url: str, headers: Optional[Dict[str, str]] = None, params: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
        """Perform an HTTP GET request."""
        return self.request("GET", url, headers=headers, params=params)

    def post(self, url: str, headers: Optional[Dict[str, str]] = None, data: Optional[Dict[str, str]] = None, json_data: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Perform an HTTP POST request."""
        if json_data:
            headers = headers or {}
            headers['Content-Type'] = 'application/json'
            body = json.dumps(json_data).encode('utf-8')
        elif data:
            # Form encoding with proper escaping.
            body = urlencode(data).encode('utf-8')
            headers = headers or {}
            headers['Content-Type'] = 'application/x-www-form-urlencoded'
        else:
            body = b""
            
        return self.request("POST", url, headers=headers, body=body)

    def request(self, method: str, url: str, headers: Optional[Dict[str, str]] = None, params: Optional[Dict[str, str]] = None, body: bytes = b"") -> Dict[str, Any]:
        """
        Dispatch an HTTP request over KEMTLS.
        """
        # Keep the underlying transport client aligned with mutable public fields.
        self.client.expected_identity = self.expected_identity
        self.client.ca_pk = self.ca_pk
        self.client.pdk_store = self.pdk_store
        self.client.mode = self.mode

        parsed = urlparse(url)
        if parsed.scheme != "kemtls":
            raise ValueError(f"Unsupported scheme: {parsed.scheme}. Only 'kemtls://' is supported.")
            
        host = parsed.hostname
        port = parsed.port or 4433
        path = parsed.path or "/"
        if parsed.query:
            path = f"{path}?{parsed.query}"
        
        if params:
            query = "&".join([f"{k}={v}" for k, v in params.items()])
            path = f"{path}?{query}"
            
        # Format headers
        full_headers = dict(headers or {})
        if 'Host' not in full_headers:
            full_headers['Host'] = host
            
        # Invoke Transport Layer
        # Note: KEMTLSClient.request handles the handshake and one HTTP message per connection
        raw_response, session = self.client.request(
            host=host,
            port=port,
            method=method,
            path=path,
            headers=full_headers,
            body=body,
            keep_alive=self.keep_alive,
        )
        
        # Parse Response
        resp_dict = self._parse_response(raw_response)
        
        # Attach session metadata
        resp_dict['kemtls_metadata'] = {
            'mode': session.handshake_mode,
            'session_id': session.session_id,
            'session_binding_id': session.session_binding_id,
            'trusted_key_id': session.trusted_key_id
        }
        
        return resp_dict

    def _parse_response(self, raw_data: bytes) -> Dict[str, Any]:
        """
        Parse HTTP/1.1 response bytes into a dictionary.
        """
        try:
            # Split headers and body
            header_end = raw_data.find(b"\r\n\r\n")
            if header_end == -1:
                # Malformed response? Try single CRLF if body missing?
                header_part = raw_data
                body = b""
            else:
                header_part = raw_data[:header_end]
                body = raw_data[header_end + 4:]
                
            header_lines = header_part.decode('ascii').split("\r\n")
            status_line = header_lines[0].split(" ", 2)
            
            status_code = int(status_line[1])
            status_text = status_line[2] if len(status_line) > 2 else ""
            
            headers = {}
            for line in header_lines[1:]:
                if ":" in line:
                    key, val = line.split(":", 1)
                    headers[key.strip()] = val.strip()
                    
            # Try parsing body as JSON if needed
            parsed_body = body
            content_type = headers.get('Content-Type', headers.get('content-type', '')).lower()
            if content_type.startswith('application/json'):
                try:
                    parsed_body = json.loads(body.decode('utf-8'))
                except:
                    pass
            elif content_type.startswith('text/'):
                try:
                    parsed_body = body.decode('utf-8')
                except:
                    pass

            return {
                'status': status_code,
                'status_text': status_text,
                'headers': headers,
                'body': parsed_body
            }
        except Exception as e:
            raise ValueError(f"Failed to parse HTTP response: {e}")
