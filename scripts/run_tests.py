"""
Run Test Suite
Role: Execute test suite with coverage reporting

Runs pytest with coverage reporting for all tests in the tests/ directory.
Provides detailed test results and code coverage metrics.
"""

import os
import sys
import subprocess

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
        test_path: Specific test file or directory (default: all tests)
    """
    print("=" * 70)
    print("KEMTLS POST-QUANTUM OIDC - TEST SUITE")
    print("=" * 70)
    
    # Build pytest command
    cmd = ["pytest"]
    
    # Add test path (default to tests directory)
    if test_path:
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
    print("  1. Crypto tests (test_crypto.py)")
    print("  2. KEMTLS tests (test_kemtls*.py)")
    print("  3. OIDC tests (test_oidc.py)")
    print("  4. PoP tests (test_pop.py)")
    print("  5. Integration tests (test_integration.py)")
    print("  6. Security tests (test_security.py)")
    print("  7. All tests")
    
    choice = input("\nSelect test category (1-7): ").strip()
    
    test_map = {
        "1": os.path.join(TESTS_DIR, "test_crypto.py"),
        "2": os.path.join(TESTS_DIR, "test_kemtls*.py"),
        "3": os.path.join(TESTS_DIR, "test_oidc.py"),
        "4": os.path.join(TESTS_DIR, "test_pop.py"),
        "5": os.path.join(TESTS_DIR, "test_integration.py"),
        "6": os.path.join(TESTS_DIR, "test_security.py"),
        "7": None
    }
    
    test_path = test_map.get(choice)
    if choice == "7" or choice in test_map:
        run_tests(test_path=test_path)
    else:
        print("Invalid choice!")
        sys.exit(1)


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
