"""
Run Test Suite
Role: Execute test suite with coverage reporting

Runs pytest with coverage reporting for all tests in the tests/ directory.
Provides detailed test results and code coverage metrics.
"""

import os
import sys
import subprocess

# Curated test categories aligned with files present in tests/
CATEGORY_TESTS = {
    "1": {
        "name": "Crypto + Encoding",
        "files": [
            "test_aead.py",
            "test_certs.py",
            "test_encoding.py",
            "test_key_schedule.py",
            "test_ml_dsa.py",
            "test_ml_kem.py",
            "test_serialization.py",
        ],
    },
    "2": {
        "name": "KEMTLS + Session",
        "files": [
            "test_handshake_baseline.py",
            "test_handshake_pdk.py",
            "test_pdk.py",
            "test_record_layer.py",
            "test_exporter.py",
            "test_session_binding.py",
            "test_replay_rejected_on_new_session.py",
            "test_metadata_jwks_integrity.py",
        ],
    },
    "3": {
        "name": "OIDC + Tokens + Endpoints",
        "files": [
            "test_oidc.py",
            "test_oidc_pkce.py",
            "test_auth_endpoints.py",
            "test_token_endpoints.py",
            "test_userinfo_endpoints.py",
            "test_discovery.py",
            "test_jwks.py",
            "test_introspection_endpoints.py",
            "test_jwt_handler.py",
            "test_jwt_validation.py",
            "test_refresh_store.py",
            "test_refresh_token_rotation.py",
            "test_session_bound_access_tokens.py",
        ],
    },
    "4": {
        "name": "Integration + Server + Security",
        "files": [
            "test_client_logic.py",
            "test_server_apps.py",
            "test_integration.py",
            "test_security.py",
            "test_full_flow_baseline.py",
            "test_full_flow_pdk.py",
            "test_helpers.py",
        ],
    },
    "5": {
        "name": "All tests",
        "files": None,
    },
}

# Add src to path
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR = os.path.dirname(SCRIPT_DIR)
SRC_DIR = os.path.join(ROOT_DIR, "src")
TESTS_DIR = os.path.join(ROOT_DIR, "tests")

if SRC_DIR not in sys.path:
    sys.path.insert(0, SRC_DIR)


def run_tests(verbose=True, coverage=True, test_path=None):
    """
    Run pytest with coverage reporting
    
    Args:
        verbose: Show verbose output
        coverage: Enable coverage reporting
        test_path: Specific test file/dir or list of files (default: all tests)
    """
    print("=" * 70)
    print("KEMTLS POST-QUANTUM OIDC - TEST SUITE")
    print("=" * 70)
    
    # Build pytest command
    cmd = ["pytest"]
    
    # Add test target(s) (default to tests directory)
    if isinstance(test_path, list):
        cmd.extend(test_path)
    elif test_path:
        cmd.append(test_path)
    else:
        cmd.append(TESTS_DIR)
    
    # Add verbose flag
    if verbose:
        cmd.append("-v")
    
    # Add coverage options
    if coverage:
        cmd.extend([
            "--cov=src",
            "--cov-report=term-missing",
            "--cov-report=html"
        ])
    
    # Add color output
    cmd.append("--color=yes")
    
    print(f"\nRunning command: {' '.join(cmd)}")
    print("-" * 70)
    
    try:
        # Run pytest
        result = subprocess.run(cmd, cwd=ROOT_DIR)
        
        print("-" * 70)
        if result.returncode == 0:
            print("✓ All tests passed!")
            if coverage:
                coverage_path = os.path.join(ROOT_DIR, "htmlcov", "index.html")
                print(f"\n📊 Coverage report generated: {coverage_path}")
        else:
            print("✗ Some tests failed!")
            sys.exit(result.returncode)
    
    except FileNotFoundError:
        print("\n✗ Error: pytest not found!")
        print("Please install test dependencies:")
        print("  pip install -r requirements.txt")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\n\n✗ Tests interrupted by user")
        sys.exit(1)


def run_specific_tests():
    """Run specific test categories"""
    print("\nAvailable test categories:")
    print("  1. Crypto + Encoding")
    print("  2. KEMTLS + Session")
    print("  3. OIDC + Tokens + Endpoints")
    print("  4. Integration + Server + Security")
    print("  5. All tests")
    
    choice = input("\nSelect test category (1-5): ").strip()

    selected = CATEGORY_TESTS.get(choice)
    if not selected:
        print("Invalid choice!")
        sys.exit(1)

    files = selected["files"]
    if files is None:
        run_tests(test_path=None)
        return

    test_paths = [os.path.join(TESTS_DIR, filename) for filename in files]
    missing = [path for path in test_paths if not os.path.exists(path)]
    if missing:
        print("\n✗ Category contains missing test files:")
        for path in missing:
            print(f"  - {path}")
        sys.exit(1)

    print(f"\nSelected category: {selected['name']}")
    run_tests(test_path=test_paths)


def main():
    """Main entry point"""
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Run KEMTLS test suite with coverage"
    )
    parser.add_argument(
        "-q", "--quiet",
        action="store_true",
        help="Quiet mode (less verbose)"
    )
    parser.add_argument(
        "--no-cov",
        action="store_true",
        help="Disable coverage reporting"
    )
    parser.add_argument(
        "-t", "--test",
        help="Specific test file or directory to run"
    )
    parser.add_argument(
        "-i", "--interactive",
        action="store_true",
        help="Interactive mode - select test category"
    )
    
    args = parser.parse_args()
    
    if args.interactive:
        run_specific_tests()
    else:
        run_tests(
            verbose=not args.quiet,
            coverage=not args.no_cov,
            test_path=args.test
        )


if __name__ == "__main__":
    main()
