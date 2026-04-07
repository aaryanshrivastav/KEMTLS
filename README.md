# Post-Quantum OpenID Connect with KEMTLS

A complete implementation of a post-quantum secure authentication system combining KEMTLS (Key Encapsulation Mechanism Transport Layer Security) with OpenID Connect (OIDC). This project demonstrates quantum-resistant authentication and authorization using NIST-standardized post-quantum cryptographic algorithms, featuring a real-time interactive web-based demonstration with live benchmarking.

## Overview

This project implements a novel approach to post-quantum authentication by integrating:
- **KEMTLS**: A post-quantum transport layer security protocol that uses KEM-based authentication instead of traditional certificate-based TLS
- **Post-Quantum OIDC**: OpenID Connect protocol enhanced with post-quantum cryptographic primitives
- **Proof-of-Possession (PoP)**: Asymmetric token binding mechanism for enhanced security
- **Real-Time WebSocket Demo**: Live streaming of authentication flow execution with interactive visualization
- **Automated Benchmarking**: Dynamic performance measurement integrated into the demo workflow

### Key Innovation

Unlike traditional TLS which uses digital signatures for server authentication, KEMTLS authenticates the server through successful KEM decapsulation. This eliminates the need for signature operations in the handshake, providing both security and performance benefits.

## Features

### 🔐 Post-Quantum Security
- **Kyber768** (NIST Level 3) for key exchange
- **Dilithium3** (ML-DSA-65) for digital signatures
- **ChaCha20-Poly1305** for authenticated encryption
- Complete quantum-resistance - no classical cryptographic algorithms

### 🚀 Performance
- **90% faster** than PQ-TLS-based reference implementations
- Average end-to-end authentication time: **1.85ms** (vs 18.50ms reference)
- Optimized cryptographic operations using liboqs

### 🏗️ Complete Implementation
- Full KEMTLS handshake protocol
- Complete OIDC flow (authorization, token, discovery endpoints)
- Asymmetric Proof-of-Possession mechanism
- Resource server with token validation
- Real-time WebSocket demo with Flask-SocketIO
- Interactive React + TypeScript frontend
- Multi-server architecture with coordinated execution

### 📊 Comprehensive Benchmarking
- Real-time benchmark execution during demo
- Cryptographic operation benchmarks
- Protocol-level performance measurements
- End-to-end latency analysis
- Comparison with PQ-TLS reference implementations
### System Architecture
```
┌─────────────────────────────────────────────────────────────┐
│                  FRONTEND (React + TS)                      │
│  Port: 5173                                                 │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────┐   │
│  │  Phase Cards │  │  Live Logs   │  │  Benchmark Cards │   │
│  │  (Framer)    │  │  (Terminal)  │  │  (Real-time)     │   │
│  └──────────────┘  └──────────────┘  └──────────────────┘   │
└─────────────────┬───────────────────────────────────────────┘
                  │
                  │ WebSocket (Socket.io)
                  │ Events: phase_start, log, benchmark_complete
                  │
┌─────────────────┴────────────────────────────────────────────┐
│              DEMO SERVER (Flask-SocketIO)                    │
│  Port: 5002                                                  │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────┐    │
│  │  WebSocket   │  │  Benchmark   │  │  Demo Flow       │    │
│  │  Handler     │  │  Executor    │  │  Orchestrator    │    │
│  └──────────────┘  └──────────────┘  └──────────────────┘    │
└──────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│                         CLIENT LOGIC                        │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────┐   │
│  │  KEMTLS      │  │  OIDC Client │  │  PoP Client      │   │
│  │  Handshake   │  │  Logic       │  │  (Dilithium Key) │   │
│  └──────────────┘  └──────────────┘  └──────────────────┘   │
└─────────────────┬───────────────────────────────────────────┘
                  │
                  │ KEMTLS Encrypted Channel
                  │ (Kyber KEM + ChaCha20-Poly1305)
                  │
┌─────────────────┴────────────────────────────────────────────┐
│         AUTHORIZATION SERVER (Flask)                         │
│  Port: 5000                                                  │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────┐    │
│  │  KEMTLS      │  │  OIDC        │  │  JWT Issuance    │    │
│  │  Server      │  │  Endpoints   │  │  (Dilithium Sig) │    │
│  └──────────────┘  └──────────────┘  └──────────────────┘    │
└──────────────────┬───────────────────────────────────────────┘
                   │
                   │ Issuer's Dilithium Public Key
                   │
┌──────────────────┴───────────────────────────────────────────┐
│            RESOURCE SERVER (Flask)                           │
│  Port: 5001                                                  │
│  ┌──────────────────┐  ┌──────────────────────────────┐      │
│  │  Token           │  │  PoP Verification            │      │
│  │  Verification    │  │  - Extracts client pubkey    │      │
│  │  - Dilithium sig │  │  - Issues challenge          │      │
│  │  - Expiry check  │  │  - Verifies Dilithium sig    │      │
│  └──────────────────┘  └──────────────────────────────┘      │
└──────────────────────────────────────────────────────────────┘
```

### Multi-Server Architecture

The system runs **4 separate servers** that communicate in real-time:

1. **Authorization Server** (Port 4433)
   - OIDC endpoints (/.well-known/openid-configuration, /authorize, /token)
   - JWT token issuance with Dilithium3 signatures
   - Server long-term Kyber/Dilithium keys

2. **Resource Server** (Port 4434)
   - Protected resource endpoints (/api/userinfo)
   - Token verification with Dilithium3
   - PoP challenge generation and verification

3. **Demo WebSocket Server** (Port 5002)
   - Real-time demo execution orchestration
   - Benchmark execution (subprocess-based)
   - WebSocket event streaming to frontend
   - Background thread execution

4. **Frontend Dev Server** (Port 5173)
   - React application with Vite
   - Socket.io-client connection
   - Real-time UI updates            
   
The demo requires **4 terminals** running simultaneously:

#### Terminal 1: Authorization Server
```bash
python scripts/run_kemtls_auth_server.py
# Starts on kemtls://127.0.0.1:4433
# Provides OIDC endpoints and JWT token issuance
```

#### Terminal 2: Resource Server
```bash
python scripts/run_kemtls_resource_server.py
# Starts on kemtls://127.0.0.1:4434
# Provides protected resources with PoP verification
```

#### Terminal 3: Demo WebSocket Server
```bash
python scripts/step_flow_server.py
# Starts on http://localhost:5002
# Orchestrates demo execution and streams events to frontend
# Runs benchmarks automatically before demo phases
```

#### Terminal 4: Frontend Development Server
```bash
cd frontend
npm run dev
# Starts on http://localhost:5173
# React application with real-time WebSocket connection
```

#### Using the Demo

1. **Open your browser** to `http://localhost:5173/`

2. **Check connection status*      # Cryptographic primitives
```
│   │   ├── ml_kem.py              # ML-KEM-768 operations
│   │   ├── ml_dsa.py              # ML-DSA-65 signatures
│   │   ├── aead.py                # ChaCha20-Poly1305 AEAD
│   │   └── key_schedule.py        # HKDF/key schedule derivation
│   ├── kemtls/                    # KEMTLS protocol
│   │   ├── handshake.py           # Handshake protocol
│   │   ├── channel.py             # Encrypted channel
│   │   └── session.py             # Session management
│   ├── oidc/                      # OIDC implementation
│   │   ├── jwt_handler.py         # PQ-JWT creation/verification
│   │   ├── authorization.py       # Authorization endpoint
│   │   ├── token.py               # Token endpoint
│   │   └── discovery.py           # Discovery endpoint
│   ├── pop/                       # Proof-of-Possession
│   │   ├── client.py              # Client-side PoP
│   │   └── server.py              # Server-side PoP verification
│   ├── servers/                   # Server implementations
│   │   ├── auth_server_app.py     # Auth server app factory
│   │   ├── resource_server_app.py # Resource server app factory
│   │   ├── auth_server.py         # Compatibility wrapper
│   │   └── resource_server.py     # Compatibility wrapper
│   └── client/                    # Client implementation
│       ├── kemtls_client.py       # KEMTLS client
│       └── oidc_client.py         # OIDC client logic
├── scripts/                       # Execution scripts
│   ├── bootstrap_ca.py            # Generate CA/server keys and certificates
│   ├── run_kemtls_auth_server.py  # Start KEMTLS authorization server
│   ├── run_kemtls_resource_server.py # Start KEMTLS resource server
│   ├── step_flow_server.py        # WebSocket step-flow server (Flask-SocketIO)
│   ├── demo_full_flow.py          # Run end-to-end demo flow
│   ├── run_tests.py               # Execute test suite
│   ├── run_benchmarks.py          # Run all benchmarks
│   └── __pycache__/               # Python bytecode cache
├── benchmarks/                    # Benchmarking scripts
│   ├── crypto_benchmarks.py       # Crypto operation benchmarks
│   ├── protocol_benchmarks.py     # Protocol-level benchmarks
│   ├── end_to_end_benchmark.py    # Complete flow benchmarks
│   └── compare_reference.py       # Compare with PQ-TLS reference
├── demos/                         # Demo scripts
│   ├── demo_full_flow.py          # Complete authentication flow
│   ├── demo_kemtls.py             # KEMTLS handshake only
│   └── demo_pop.py                # PoP demonstration
├── frontend/                      # React + TypeScript UI
│   ├── src/
│   │   ├── pages/
│   │   │   └── Index.tsx          # Main demo page
│   │   ├── components/
│   │   │   ├── PhaseCard.tsx      # Phase progress cards
│   │   │   ├── BenchmarkCard.tsx  # Benchmark result cards
│   │   │   ├── TerminalWindow.tsx # Log display component
│   │   │   ├── StatusBadge.tsx    # Connection status
│   │   │   └── ...                # Other UI components
│   │   ├── hooks/
│   │   │   └── useDemoWebSocket.ts # WebSocket connection hook
│   │   └── index.css              # Cyber-themed styling
│   ├── package.json               # Node dependencies
│   └── vite.config.ts             # Vite configuration
├── keys/                          # Generated cryptographic artifacts
│   ├── ca/
│   ├── auth_server/
│   ├── resource_server/
│   └── pdk/
├── papers/                        # Research/notes artifacts
├── tests/                         # Unit and integration tests
├── results_benchmarks/            # Benchmark results (JSON)
│   ├── protocol_benchmark_results.json
│   ├── end_to_end_benchmark_results.json
│   └── crypto_benchmark_results.json
└── requirements.txt               # Python dependencie
```
## Quick Start

### Prerequisites

- Python 3.8+
- Node.js 18+ (for frontend demo)
- Git

### Installation

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd KEMTLS
   ```

2. **Install Python dependencies**
   ```bash
   pip install -r requirements.txt
   ```

3. **Generate cryptographic keys**
   ```bash
   python scripts/bootstrap_ca.py
   ```

## Benchmark Execution (Real Data)

The benchmark stack runs real cryptographic operations and real KEMTLS/OIDC flows. Synthetic timings are not used.

- Windows to WSL entrypoint: `scripts/run_benchmarks_windows.ps1`
- WSL loopback runner: `benchmarks/collect/run_all_wsl.sh`
- Linux netem runner: `benchmarks/collect/run_all_netem.sh`
- Detailed methodology and outputs: `benchmarks/README.md`

4. **Install frontend dependencies** (for web demo)
   ```bash
   cd frontend
   npm install
   ```

### Running the Demo

1. **Start the authorization server** (Terminal 1)
   ```bash
   python scripts/run_kemtls_auth_server.py
   ```

2. **Start the resource server** (Terminal 2)
   ```bash
   python scripts/run_kemtls_resource_server.py
   ```

3. **Start the step-flow WebSocket server** (Terminal 3)
   ```bash
   python scripts/step_flow_server.py
   ```

4. **Start the frontend** (Terminal 4)
   ```bash
   cd frontend
   npm run dev
   ```

5. **Open** `http://localhost:5173` **in your browser**

### Real-Time Benchmarks (50 iterations, displayed in UI)
The demo automatically runs benchmarks before execution:
- **KEMTLS Handshake**: ~0.56 ms
- **ID Token Creation**: ~0.50 ms
- **Token Verification**: ~0.14 ms
- **PoP Proof Creation**: ~0.45 ms
- **PoP Verification**: ~0.12 ms
- **End-to-End Flow**: ~1.85 ms

### Comparison with PQ-TLS Reference
- **90% improvement** in total authentication time (Kyber768, Dilithium3)
- ✅ **Token Replay**: PoP with fresh nonces and timestamps
- ✅ **Token Theft**: Asymmetric PoP binding - token useless without private key
- ✅ **Man-in-the-Middle**: KEMTLS authenticated channel with KEM-based authentication
- ✅ **Harvest-Now-Decrypt-Later**: Forward secrecy with ephemeral Kyber keys
- ✅ **Token Tampering**: Dilithium3 signatures on all tokens
- ✅ **Session Hijacking**: Session keys bound to KEMTLS channel
- ✅ **Impersonation**: Client proves key possession via PoP challenge

### Security Properties
- **Confidentiality**: ChaCha20-Poly1305 AEAD encryption
- **Integrity**: AEAD authentication tags + Dilithium signatures
- **Authentication**: 
  - Server: KEM-based authentication (KEMTLS)
  - Client: PoP with Dilithium signatures
- **Forward Secrecy**: Ephemeral Kyber keys in handshake
- **Non-Repudiation**: Dilithium signatures on tokens
- **Quantum Resistance**: No classical algorithms (RSA/ECDSA) used

## Authentication Flow Phases

### Phase 1: KEMTLS Handshake
**Purpose:** Establish quantum-resistant encrypted channel

**Steps:**
1. Server sends Server Hello with ephemeral Kyber public key
2. Client verifies server's long-term public key
3. Client performs KEM encapsulation, sends ciphertext
4. Both derive session keys via HKDF
5. Secure channel established

**Output:** Session keys (client_write_key, server_write_key, session_key, pop_key)

### Phase 2: User Authentication (OIDC)
**Purpose:** Verify user identity via OpenID Connect

**Steps:**
1. Client generates Dilithium ephemeral keypair
2. Client creates authorization URL with scope and nonce
3. User provides credentials and grants consent
4. Authorization server returns authorization code

**Output:** Authorization code for token exchange

### Phase 3: Token Issuance
**Purpose:** Issue cryptographically signed tokens with PoP binding

**Steps:**
1. Client exchanges authorization code for tokens
2. Authorization server loads Dilithium signing keys
3. Server creates ID token with user claims
4. Server signs token with Dilithium3
5. Server embeds client's ephemeral public key (PoP binding)
6. Access token generated

**Output:** ID Token (~7.5KB) and Access Token

### Phase 4: Resource Access with PoP
**Purpose:** Prove possession of bound private key

**Steps:**
1. Client requests protected resource with access token
2. Resource server generates challenge (nonce + timestamp)
3. Client signs challenge with ephemeral secret key
4. Resource server verifies:
   - Signature matches public key from token
   Technology Stack

### Backend
- **Python 3.8+**: Core language
- **Flask 3.0.0**: Web framework for servers
- **Flask-SocketIO 5.3.6**: WebSocket server
- **Flask-CORS 4.0.0**: Cross-origin resource sharing
- **pqcrypto 0.4.0**: Post-quantum cryptographic operations (Kyber, Dilithium)
- **pycryptodomex 3.20.0**: Symmetric encryption (ChaCha20-Poly1305)
- **cryptography**: HKDF key derivation

### Frontend
- **React 18**: UI library
- **TypeScript**: Type-safe JavaScript
- **Vite**: Fast build tool with HMR
- **Socket.io-client**: WebSocket client
- **Framer Motion**: Animation library
- **Radix UI**: Accessible component primitives
- **Tailwind CSS**: Utility-first styling
- **Lucide React**: Icon library

### Testing & Benchmarking
- **pytest**: Unit and integration testing
- **pytest-cov**: Code coverage
- **Python time.perf_counter()**: High-precision timing

## Troubleshooting

### WebSocket Connection Issues
If you see "Disconnected" status:
1. Ensure demo server is running on port 5002
2. Check terminal for errors in step_flow_server.py
3. Verify Flask-SocketIO is installed: `pip install flask-socketio`
4. Try restarting the demo server

### Benchmark Not Running
If benchmark cards stay on "-- ms":
1. Check that demo server can execute benchmarks
2. Verify benchmark scripts exist in `benchmarks/` directory
3. Check `results_benchmarks/` directory permissions
4. Look for errors in demo server terminal

### Key Generation Errors
If you see "Server keys not found":
```bash
python scripts/bootstrap_ca.py
```
This creates keys in the `keys/` directory.

### Port Already in Use
If ports 5000, 5001, 5002, or 5173 are occupied:
- Kill existing processes or change ports in respective scripts
- Auth Server: Edit `scripts/run_kemtls_auth_server.py`
- Resource Server: Edit `scripts/run_kemtls_resource_server.py`
- Demo Server: Edit `scripts/step_flow_server.py`
- Frontend: Edit `vite.config.ts`

## Development

### Running Tests
```bash
# Run all tests
python scripts/run_tests.py

# Run with coverage
pytest --cov=src tests/

# Run specific test file
pytest tests/test_kemtls.py
```

### Code Structure Guidelines
- **src/**: Core implementation (no UI dependencies)
- **scripts/**: Execution entry points
- **demos/**: Standalone demonstration scripts
- **frontend/**: React application (separate from Python)
- **benchmarks/**: Performance measurement scripts

### Adding New Features
1. Implement core logic in `src/`
2. Add tests in `tests/`
3. Create demo script in `demos/` if applicable
4. Update frontend components if UI changes needed
5. Document in relevant README sections

## License

See [LICENSE](../LICENSE) file for details.

## References

### Research Papers
- **KEMTLS Protocol**: Wiggers et al., "Post-Quantum TLS Without Handshake Signatures", CCS 2020
- **Post-Quantum OIDC**: Schardong et al., "Post-Quantum OpenID Connect: A Quantum-Resistant Authentication Approach", IEEE 2023
- **Proof-of-Possession**: RFC 7800 - Proof-of-Possession Key Semantics for JSON Web Tokens (JWTs)

### Standards
- **NIST PQC Standards**: 
  - Kyber: FIPS 203 (ML-KEM) - Module Lattice-Based Key Encapsulation Mechanism
  - Dilithium: FIPS 204 (ML-DSA) - Module Lattice-Based Digital Signature Algorithm
- **OpenID Connect**: OpenID Connect Core 1.0
- **OAuth 2.0**: RFC 6749
- **JWT**: RFC 7519
- **HKDF**: RFC 5869

### Libraries
- **liboqs**: Open Quantum Safe project - Post-quantum cryptographic library
- **pqcrypto**: Python bindings for liboqs
- **Flask**: Lightweight WSGI web application framework
- **Socket.io**: Real-time bidirectional event-based communication

## Acknowledgments

This implementation is based on research in post-quantum cryptography and authentication protocols. Special thanks to:
- NIST Post-Quantum Cryptography standardization process
- Open Quantum Safe (OQS) project
- OpenID Foundation
- Flask and React communities

## Contributing

Contributions are welcome! Areas for improvement:
- Additional post-quantum algorithms (when standardized)
- Performance optimizations
- Extended test coverage
- Documentation improvements
- UI/UX enhancements

## Citation

If you use this implementation in research, please cite:
```
@misc{kemtls-oidc-2026,
  title={Post-Quantum OpenID Connect with KEMTLS: A Complete Implementation},
  author={[Your Names]},
  year={2026},
  howpublished={\url{https://github.com/[YourRepo]/KEMTLS}}
}
```

---

**Project Status**: Production-ready demonstration  
**Last Updated**: 2026-02-09  
**Version**: 1.0.0
## Project Structure

```
KEMTLS/
├── src/
│   ├── crypto/              # Cryptographic primitives
│   │   ├── ml_kem.py        # ML-KEM-768 operations
│   │   ├── ml_dsa.py        # ML-DSA-65 signatures
│   │   ├── aead.py          # ChaCha20-Poly1305 AEAD
│   │   └── key_schedule.py  # HKDF/key schedule derivation
│   ├── kemtls/              # KEMTLS protocol
│   │   ├── handshake.py     # Handshake protocol
│   │   ├── channel.py       # Encrypted channel
│   │   └── session.py       # Session management
│   ├── oidc/                # OIDC implementation
│   │   ├── jwt_handler.py   # PQ-JWT creation/verification
│   │   ├── authorization.py # Authorization endpoint
│   │   ├── token.py         # Token endpoint
│   │   └── discovery.py     # Discovery endpoint
│   ├── pop/                 # Proof-of-Possession
│   │   ├── client.py        # Client-side PoP
│   │   └── server.py        # Server-side PoP verification
│   ├── servers/             # Server implementations
│   │   ├── auth_server_app.py # Auth server app factory
│   │   ├── resource_server_app.py # Resource server app factory
│   │   ├── auth_server.py   # Compatibility wrapper
│   │   └── resource_server.py # Compatibility wrapper
│   └── client/              # Client implementation
│       └── kemtls_client.py # KEMTLS client
├── benchmarks/              # Benchmarking scripts
├── demos/                   # Demo scripts
├── frontend/                # Web-based demo UI
└── results_benchmarks/      # Benchmark results
```

## Cryptographic Algorithms

### Key Exchange: Kyber768
- **Security Level**: NIST Level 3
- **Public Key Size**: 1,184 bytes
- **Ciphertext Size**: 1,088 bytes
- **Shared Secret**: 32 bytes
- **Average KeyGen**: 0.001 ms
- **Average Encap**: 0.002 ms
- **Average Decap**: 0.001 ms

### Digital Signatures: Dilithium3 (ML-DSA-65)
- **Security Level**: NIST Level 3
- **Public Key Size**: 1,952 bytes
- **Signature Size**: 3,293 bytes
- **Average KeyGen**: 0.2 ms
- **Average Sign**: 0.454 ms
- **Average Verify**: 0.11 ms

### Symmetric Encryption: ChaCha20-Poly1305
- **Key Size**: 32 bytes
- **Nonce Size**: 12 bytes
- **Tag Size**: 16 bytes
- **Average Encrypt**: 0.007 ms (470 bytes)
- **Average Decrypt**: 0.006 ms (470 bytes)

## Performance Results

### End-to-End Authentication
- **Total Time**: 1.85 ms (average)
- **Phase 1 (KEMTLS Handshake)**: 0.73 ms
- **Phase 2 (Authorization)**: 0.002 ms
- **Phase 3 (Token Exchange)**: 0.485 ms
- **Phase 4 (Resource Access)**: 0.624 ms

### Comparison with PQ-TLS Reference
- **90% improvement** in total authentication time
- **93.4% faster** KEMTLS handshake
- **83.5% faster** JWT creation
- **91.3% faster** JWT verification


## Security Features

### Threat Mitigation
- ✅ **Quantum Adversary**: Post-quantum algorithms throughout
- ✅ **Token Replay**: PoP with fresh nonces
- ✅ **Token Theft**: Asymmetric PoP binding
- ✅ **Man-in-the-Middle**: KEMTLS authenticated channel
- ✅ **Harvest-Now-Decrypt-Later**: Forward secrecy with ephemeral keys
- ✅ **Token Tampering**: Dilithium signatures

### Security Properties
- **Confidentiality**: ChaCha20-Poly1305 AEAD encryption
- **Integrity**: AEAD authentication tags + Dilithium signatures
- **Authentication**: KEM-based server auth + PoP client auth
- **Forward Secrecy**: Ephemeral keys in handshake
- **Non-Repudiation**: Dilithium signatures on tokens

## License

See [LICENSE](../LICENSE) file for details.

## References

- **KEMTLS Protocol**: Wiggers et al., "Post-Quantum TLS Without Handshake Signatures"
- **Post-Quantum OIDC**: Schardong et al., "Post-Quantum OpenID Connect: A Quantum-Resistant Authentication Approach" (2023)
- **NIST PQC Standards**: 
  - Kyber: FIPS 203 (ML-KEM)
  - Dilithium: FIPS 204 (ML-DSA)

## Acknowledgments

This implementation is based on research in post-quantum cryptography and authentication protocols. Special thanks to the NIST Post-Quantum Cryptography standardization process and the open-source cryptographic community.

---