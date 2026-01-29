"""
Test execution engine with timeout and error handling
"""

import time
import socket
import signal
import traceback
from contextlib import contextmanager
from typing import List, Dict
from .test_registry import PropertyTest
from .results import TestResult, TestStatus
from .config import TestConfig
from .local_adapter import LocalServerAdapter, ensure_port_available


class TimeoutError(Exception):
    """Raised when test exceeds timeout"""
    pass


class PropertyTestRunner:
    """Execute property tests with error handling and timeout protection"""

    def __init__(self, config: TestConfig, verbose: bool = False):
        """
        Initialize test runner

        Args:
            config: TestConfig instance
            verbose: Print detailed output during execution
        """
        self.config = config
        self.verbose = verbose
        self.test_settings = config.get_test_execution_settings()

    @contextmanager
    def timeout(self, seconds: int):
        """
        Context manager for test timeout using signal.SIGALRM

        Args:
            seconds: Timeout in seconds

        Raises:
            TimeoutError: If test exceeds timeout
        """
        def handler(signum, frame):
            raise TimeoutError(f"Test exceeded {seconds}s timeout")

        old_handler = signal.signal(signal.SIGALRM, handler)
        signal.alarm(seconds)
        try:
            yield
        finally:
            signal.alarm(0)
            signal.signal(signal.SIGALRM, old_handler)

    def run_test(self, test: PropertyTest, target_config: Dict) -> TestResult:
        """
        Run a single test with error handling (supports both Docker and local)

        Args:
            test: PropertyTest object
            target_config: Target implementation configuration

        Returns:
            TestResult object
        """
        # Route to local or Docker implementation
        if target_config.get('target_type') == 'local':
            return self._run_test_local(test, target_config)
        else:
            return self._run_test_docker(test, target_config)

    def _run_test_docker(self, test: PropertyTest, target_config: Dict) -> TestResult:
        """
        Run a test against a Docker implementation (original logic)

        Args:
            test: PropertyTest object
            target_config: Target implementation configuration

        Returns:
            TestResult object
        """
        result = TestResult(
            property_id=test.property_id,
            test_name=test.name,
            target=target_config['name'],
            target_version=target_config['version']
        )

        try:
            timeout_seconds = self.test_settings['default_timeout']

            with self.timeout(timeout_seconds):
                start_time = time.time()

                # Execute test function
                if self.verbose:
                    print(f"  Running {test.property_id}: {test.description[:60]}...")

                test_output = test.test_func(target_config, self.config)

                result.duration = time.time() - start_time
                result.status = TestStatus.PASSED
                result.output = test_output

                if self.verbose:
                    print(f"    ✓ Passed in {result.duration:.2f}s")

        except TimeoutError as e:
            result.status = TestStatus.TIMEOUT
            result.error_message = str(e)
            if self.verbose:
                print(f"    ⏱ Timeout: {e}")

        except Exception as e:
            result.status = TestStatus.FAILED
            result.error_message = str(e)
            result.traceback = traceback.format_exc()
            if self.verbose:
                print(f"    ✗ Failed: {e}")

        return result

    def _run_test_local(self, test: PropertyTest, target_config: Dict) -> TestResult:
        """
        Run a test against a local implementation

        Args:
            test: PropertyTest object
            target_config: Local implementation configuration

        Returns:
            TestResult object
        """
        # Route based on test mode
        if test.mode == 'client':
            return self._run_client_mode_local(test, target_config)
        else:
            return self._run_server_mode_local(test, target_config)

    def _run_client_mode_local(self, test: PropertyTest, target_config: Dict) -> TestResult:
        """
        Client mode: Start local server, test connects as malicious client

        Args:
            test: PropertyTest object
            target_config: Local implementation configuration

        Returns:
            TestResult object
        """
        result = TestResult(
            property_id=test.property_id,
            test_name=test.name,
            target=target_config['name'],
            target_version=target_config['version']
        )

        try:
            timeout_seconds = self.test_settings['default_timeout']

            with self.timeout(timeout_seconds):
                start_time = time.time()

                if self.verbose:
                    print(f"  Running {test.property_id}: {test.description[:60]}...")

                # Start local server using adapter
                with LocalServerAdapter(target_config) as adapter:
                    # Start server (no client verification)
                    if not adapter.start_server(verify_client=False):
                        raise RuntimeError("Failed to start local server")

                    # Run test (test acts as malicious client)
                    test_output = test.test_func(target_config, self.config)

                    result.duration = time.time() - start_time
                    result.status = TestStatus.PASSED
                    result.output = test_output

                    if self.verbose:
                        print(f"    ✓ Passed in {result.duration:.2f}s")

        except TimeoutError as e:
            result.status = TestStatus.TIMEOUT
            result.error_message = str(e)
            if self.verbose:
                print(f"    ⏱ Timeout: {e}")

        except Exception as e:
            result.status = TestStatus.FAILED
            result.error_message = str(e)
            result.traceback = traceback.format_exc()
            if self.verbose:
                print(f"    ✗ Failed: {e}")

        return result

    def _run_server_mode_local(self, test: PropertyTest, target_config: Dict) -> TestResult:
        """
        Server mode: Test starts malicious server, local client connects to it

        Args:
            test: PropertyTest object
            target_config: Local implementation configuration

        Returns:
            TestResult object
        """
        result = TestResult(
            property_id=test.property_id,
            test_name=test.name,
            target=target_config['name'],
            target_version=target_config['version']
        )

        adapter = None
        try:
            timeout_seconds = self.test_settings['default_timeout']

            with self.timeout(timeout_seconds):
                start_time = time.time()

                if self.verbose:
                    print(f"  Running {test.property_id}: {test.description[:60]}...")

                # Create adapter for client launching
                adapter = LocalServerAdapter(target_config)

                # Inject client launcher into config for test to use
                target_config['_client_launcher'] = lambda: adapter.start_client()

                # Run test (test starts malicious server)
                test_output = test.test_func(target_config, self.config)

                result.duration = time.time() - start_time
                result.status = TestStatus.PASSED
                result.output = test_output

                if self.verbose:
                    print(f"    ✓ Passed in {result.duration:.2f}s")

        except TimeoutError as e:
            result.status = TestStatus.TIMEOUT
            result.error_message = str(e)
            if self.verbose:
                print(f"    ⏱ Timeout: {e}")

        except Exception as e:
            result.status = TestStatus.FAILED
            result.error_message = str(e)
            result.traceback = traceback.format_exc()
            if self.verbose:
                print(f"    ✗ Failed: {e}")

        finally:
            if adapter:
                adapter.stop()

        return result

    def run_tests(self, tests: List[PropertyTest], target: str) -> List[TestResult]:
        """
        Run multiple tests against a target (supports Docker and local)

        Args:
            tests: List of PropertyTest objects
            target: Target implementation name

        Returns:
            List of TestResult objects
        """
        target_config = self.config.get_implementation(target)
        results = []

        continue_on_error = self.test_settings['continue_on_error']

        print(f"\nRunning {len(tests)} tests against {target_config['name']} {target_config['version']}")
        print("=" * 70)

        # For local implementations, ensure port is available before starting
        if target_config.get('target_type') == 'local':
            port = target_config.get('port', 4433)
            if not ensure_port_available(port, timeout=5):
                print(f"ERROR: Port {port} is not available after 5s")
                # Return empty results
                return results

        for test in tests:
            result = self.run_test(test, target_config)
            results.append(result)

            # Check if we should continue
            if result.status not in [TestStatus.PASSED, TestStatus.SKIPPED] and not continue_on_error:
                print(f"\nTest failed, stopping execution (continue_on_error=False)")
                break

            # For local implementations, add delay between tests to ensure port cleanup
            if target_config.get('target_type') == 'local':
                time.sleep(1)

        return results

    def run_tests_with_retry(self, tests: List[PropertyTest], target: str) -> List[TestResult]:
        """
        Run tests with retry on failure

        Args:
            tests: List of PropertyTest objects
            target: Target implementation name

        Returns:
            List of TestResult objects
        """
        retry_count = self.test_settings.get('retry_count', 0)

        if retry_count == 0:
            return self.run_tests(tests, target)

        target_config = self.config.get_implementation(target)
        results = []

        for test in tests:
            best_result = None

            for attempt in range(retry_count + 1):
                result = self.run_test(test, target_config)

                if result.status == TestStatus.PASSED:
                    best_result = result
                    break

                if best_result is None or result.status.value < best_result.status.value:
                    best_result = result

                if attempt < retry_count:
                    if self.verbose:
                        print(f"    Retry {attempt + 1}/{retry_count}...")
                    time.sleep(1)

            results.append(best_result)

        return results
