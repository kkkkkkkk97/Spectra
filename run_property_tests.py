#!/usr/bin/env python3
"""
Unified TLS Property Testing CLI

This script provides a unified interface for testing TLS 1.3 security properties
against multiple implementations.

Usage:
    python3 run_property_tests.py --mode client --target openssl --property all
    python3 run_property_tests.py --mode client --target openssl --property C1 --verbose
    python3 run_property_tests.py --mode server --target openssl --property C2 --html report.html
"""

import argparse
import sys
from pathlib import Path

# Import framework modules
from property_test_framework.config import TestConfig
from property_test_framework.test_registry import registry
from property_test_framework.test_runner import PropertyTestRunner
from property_test_framework.results import TestSuiteResult
from property_test_framework.reports import ReportGenerator

# Import test modules to register tests
import property_test_framework.client_tests
import property_test_framework.server_tests


def parse_arguments():
    """Parse command-line arguments"""
    parser = argparse.ArgumentParser(
        description='TLS 1.3 Security Property Testing Framework',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  # Test all client properties against OpenSSL
  python3 run_property_tests.py --mode client --target openssl --property all

  # Test single property with verbose output
  python3 run_property_tests.py --mode client --target openssl --property C1 --verbose

  # Generate HTML and JSON reports
  python3 run_property_tests.py --mode client --target openssl --property all \\
      --html reports/openssl_client.html --json reports/openssl_client.json

  # Test server properties (malicious server testing clients)
  python3 run_property_tests.py --mode server --target openssl --property C2

Available targets:
  openssl, gnutls-3.6, gnutls-3.8, wolfssl-5.2.0, wolfssl-5.6.0,
  wolfssl-5.8.4, mbedtls, openhitls
        '''
    )

    # Required arguments (but not for --list-* commands)
    parser.add_argument('--mode', type=str, choices=['client', 'server'],
                        help='Test mode: client (test servers) or server (test clients)')

    parser.add_argument('--target', type=str,
                        help='Target implementation (e.g., openssl, gnutls-3.6, mbedtls)')

    parser.add_argument('--property', type=str,
                        help='Property to test (e.g., C1, C2, ..., or "all" for all properties)')

    # Optional arguments
    parser.add_argument('--config', type=str, default='config.yaml',
                        help='Path to configuration file (default: config.yaml)')

    parser.add_argument('--html', type=str,
                        help='Path to output HTML report')

    parser.add_argument('--json', type=str,
                        help='Path to output JSON report')

    parser.add_argument('--verbose', action='store_true',
                        help='Print detailed output during test execution')

    parser.add_argument('--detailed', action='store_true',
                        help='Print detailed results in console output')

    parser.add_argument('--list-properties', action='store_true',
                        help='List all available properties for the specified mode and exit')

    parser.add_argument('--list-targets', action='store_true',
                        help='List all available target implementations and exit')

    return parser.parse_args()


def list_properties(mode: str):
    """List all available properties for a mode"""
    print(f"\nAvailable properties for {mode} mode:")
    print("=" * 70)

    props = registry.list_properties(mode)
    if not props:
        print(f"No properties registered for {mode} mode")
        return

    for prop_id in props:
        test = registry.get_test(prop_id, mode)
        if test:
            print(f"  {prop_id:5s} - {test.description[:60]}")

    print()


def list_targets(config: TestConfig):
    """List all available target implementations"""
    print("\nAvailable target implementations:")
    print("=" * 70)

    # Docker implementations
    docker_impls = config.list_implementations(target_type='docker')
    if docker_impls:
        print("\n  Docker Implementations:")
        for name in docker_impls:
            impl = config.get_implementation(name)
            print(f"    {name:30s} - {impl['name']} {impl['version']} (port {impl['port']})")

    # Local implementations
    local_impls = config.list_implementations(target_type='local')
    if local_impls:
        print("\n  Local Implementations (script-based):")
        for name in local_impls:
            impl = config.get_implementation(name)
            script_name = Path(impl['script_path']).name
            print(f"    {name:30s} - {impl['name']} {impl['version']} (port {impl['port']}) [{script_name}]")

    print()


def main():
    """Main entry point"""
    args = parse_arguments()

    # Load configuration
    try:
        config = TestConfig(args.config)
    except FileNotFoundError as e:
        print(f"Error: {e}")
        return 1
    except Exception as e:
        print(f"Error loading configuration: {e}")
        return 1

    # Handle list commands
    if args.list_targets:
        list_targets(config)
        return 0

    if args.list_properties:
        if not args.mode:
            print("Error: --mode is required when using --list-properties")
            return 1
        list_properties(args.mode)
        return 0

    # Validate required arguments for test execution
    if not args.mode:
        print("Error: --mode is required")
        return 1
    if not args.target:
        print("Error: --target is required")
        return 1
    if not args.property:
        print("Error: --property is required")
        return 1

    # Validate target
    try:
        target_config = config.get_implementation(args.target)
    except ValueError as e:
        print(f"Error: {e}")
        print(f"\nUse --list-targets to see available implementations")
        return 1

    # Determine which properties to test
    if args.property.lower() == 'all':
        properties = None  # Will test all properties for mode
        properties_list = config.get_all_properties(args.mode)
    else:
        properties = [args.property.upper()]
        properties_list = properties

    # Get tests from registry
    tests = registry.get_tests(args.mode, properties)

    if not tests:
        print(f"Error: No tests found for mode '{args.mode}' and properties {properties_list}")
        print(f"\nUse --list-properties --mode {args.mode} to see available properties")
        return 1

    print(f"\n{'=' * 70}")
    print(f"TLS 1.3 Security Property Testing Framework")
    print(f"{'=' * 70}")
    print(f"Target:     {target_config['name']} {target_config['version']}")
    print(f"Mode:       {args.mode}")
    print(f"Properties: {', '.join([t.property_id for t in tests])}")
    print(f"Tests:      {len(tests)}")
    print(f"{'=' * 70}")

    # Create test runner
    runner = PropertyTestRunner(config, verbose=args.verbose)

    # Run tests
    try:
        results = runner.run_tests(tests, args.target)
    except Exception as e:
        print(f"\nError running tests: {e}")
        import traceback
        traceback.print_exc()
        return 1

    # Create test suite result
    suite_result = TestSuiteResult.from_results(
        mode=args.mode,
        target=target_config['name'],
        target_version=target_config['version'],
        properties_tested=properties_list,
        results=results
    )

    # Generate reports
    report_gen = ReportGenerator()

    # Console summary
    report_gen.print_console_summary(suite_result)

    # Detailed console output
    if args.detailed:
        report_gen.print_detailed_results(suite_result)

    # HTML report
    if args.html:
        try:
            report_gen.generate_html(suite_result, args.html)
        except Exception as e:
            print(f"Warning: Failed to generate HTML report: {e}")

    # JSON report
    if args.json:
        try:
            report_gen.generate_json(suite_result, args.json)
        except Exception as e:
            print(f"Warning: Failed to generate JSON report: {e}")

    # Exit with appropriate code
    if suite_result.is_success():
        print("✓ All tests passed!")
        return 0
    else:
        print("✗ Some tests failed")
        return 1


if __name__ == '__main__':
    sys.exit(main())
