"""
KEMTLS HTTP Bridge (In-Process Flask Integration)

Parses simple HTTP/1.1 requests from bytes and calls a Flask app’s 
internal WSGI handler.
"""

from io import BytesIO
from typing import Dict, Any, Optional
from flask import Flask, request, g
from .session import KEMTLSSession
from rust_ext import http as rust_http


def parse_http_request(raw_data: bytes) -> Dict[str, Any]:
    """
    Minimalistic HTTP/1.1 request parser.
    """
    return rust_http.parse_http_request(raw_data, fallback=_parse_http_request_python)


def _parse_http_request_python(raw_data: bytes) -> Dict[str, Any]:
    """Pure Python fallback parser used when Rust backend is unavailable."""
    lines = raw_data.split(b"\r\n")
    if not lines:
        raise ValueError("Empty request")
        
    request_line = lines[0].split(b" ")
    if len(request_line) < 3:
        raise ValueError("Invalid HTTP request line")
        
    method, path, version = request_line
    headers = {}
    
    # Simple header parsing
    for line in lines[1:]:
        if not line: # End of headers
            break
        if b":" in line:
            k, v = line.split(b":", 1)
            headers[k.strip().decode('ascii').lower()] = v.strip().decode('ascii')
            
    # Find body start
    body_start = raw_data.find(b"\r\n\r\n")
    body = raw_data[body_start + 4:] if body_start != -1 else b""
    
    return {
        'method': method.decode('ascii'),
        'path': path.decode('ascii'),
        'version': version.decode('ascii'),
        'headers': headers,
        'body': body
    }


def call_flask_app(app: Flask, session: KEMTLSSession, raw_request: bytes) -> bytes:
    """
    Injects KEMTLS session and calls the Flask app's WSGI interface.
    """
    req = parse_http_request(raw_request)
    path, _, query = req['path'].partition('?')
    req_headers = req['headers']
    content_type = req_headers.get('content-type', '')
    content_length = req_headers.get('content-length')
    if not content_length:
        content_length = str(len(req['body']))
    
    # Mock WSGI environment
    environ = {
        'wsgi.version': (1, 0),
        'wsgi.url_scheme': 'https', # We're always secure over KEMTLS
        'wsgi.input': BytesIO(req['body']),
        'wsgi.errors': BytesIO(),
        'wsgi.multithread': False,
        'wsgi.multiprocess': False,
        'wsgi.run_once': False,
        'SERVER_PROTOCOL': req['version'],
        'REQUEST_METHOD': req['method'],
        'SCRIPT_NAME': '',
        'PATH_INFO': path,
        'QUERY_STRING': query,
        'SERVER_NAME': 'localhost',
        'SERVER_PORT': '443',
        'REMOTE_ADDR': '127.0.0.1',
        'CONTENT_TYPE': content_type,
        'CONTENT_LENGTH': content_length,
        'kemtls.session': session,
        'kemtls.mode': session.handshake_mode
    }

    # Populate standard WSGI HTTP_ headers expected by Flask/Werkzeug.
    for key, value in req_headers.items():
        if key in ('content-type', 'content-length'):
            continue
        wsgi_key = 'HTTP_' + key.upper().replace('-', '_')
        environ[wsgi_key] = value
    
    # Simple WSGI call logic
    response_body = []
    response_status = [None]
    response_headers = [None]
    
    def start_response(status, headers, exc_info=None):
        response_status[0] = status
        response_headers[0] = headers
        return response_body.append
        
    app_iter = app(environ, start_response)
    for part in app_iter:
        response_body.append(part)
        
    # Serialize response
    status_line = f"HTTP/1.1 {response_status[0]}\r\n"
    header_lines = "".join([f"{k}: {v}\r\n" for k, v in response_headers[0]])
    
    return status_line.encode('ascii') + header_lines.encode('ascii') + b"\r\n" + b"".join(response_body)
