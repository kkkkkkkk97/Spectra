"""
Test result data structures
"""

from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime
from typing import Optional, List, Dict


class TestStatus(Enum):
    """Test execution status"""
    PASSED = "passed"
    FAILED = "failed"
    TIMEOUT = "timeout"
    SKIPPED = "skipped"
    ERROR = "error"


@dataclass
class TestResult:
    """Result of a single property test"""
    property_id: str
    test_name: str
    target: str
    target_version: str
    status: TestStatus = TestStatus.SKIPPED
    duration: float = 0.0
    timestamp: datetime = field(default_factory=datetime.now)
    output: Optional[str] = None
    error_message: Optional[str] = None
    traceback: Optional[str] = None

    def to_dict(self) -> Dict:
        """Convert to dictionary for JSON serialization"""
        return {
            'property_id': self.property_id,
            'test_name': self.test_name,
            'target': self.target,
            'target_version': self.target_version,
            'status': self.status.value,
            'duration': round(self.duration, 3),
            'timestamp': self.timestamp.isoformat(),
            'output': self.output,
            'error_message': self.error_message,
            'traceback': self.traceback
        }

    def __repr__(self):
        return f"TestResult({self.property_id}: {self.status.value})"


@dataclass
class TestSuiteResult:
    """Aggregated results for a test suite"""
    mode: str
    target: str
    target_version: str
    properties_tested: List[str]
    total_tests: int
    passed: int
    failed: int
    timeout: int
    skipped: int
    error: int
    total_duration: float
    results: List[TestResult]
    timestamp: datetime = field(default_factory=datetime.now)

    @staticmethod
    def from_results(mode: str, target: str, target_version: str,
                     properties_tested: List[str], results: List[TestResult]) -> 'TestSuiteResult':
        """
        Create TestSuiteResult from a list of TestResult objects

        Args:
            mode: Test mode ('client' or 'server')
            target: Target implementation name
            target_version: Target version
            properties_tested: List of property IDs tested
            results: List of TestResult objects

        Returns:
            TestSuiteResult object with aggregated statistics
        """
        total_tests = len(results)
        passed = sum(1 for r in results if r.status == TestStatus.PASSED)
        failed = sum(1 for r in results if r.status == TestStatus.FAILED)
        timeout = sum(1 for r in results if r.status == TestStatus.TIMEOUT)
        skipped = sum(1 for r in results if r.status == TestStatus.SKIPPED)
        error = sum(1 for r in results if r.status == TestStatus.ERROR)
        total_duration = sum(r.duration for r in results)

        return TestSuiteResult(
            mode=mode,
            target=target,
            target_version=target_version,
            properties_tested=properties_tested,
            total_tests=total_tests,
            passed=passed,
            failed=failed,
            timeout=timeout,
            skipped=skipped,
            error=error,
            total_duration=total_duration,
            results=results
        )

    def to_dict(self) -> Dict:
        """Convert to dictionary for JSON serialization"""
        return {
            'mode': self.mode,
            'target': self.target,
            'target_version': self.target_version,
            'properties_tested': self.properties_tested,
            'timestamp': self.timestamp.isoformat(),
            'summary': {
                'total': self.total_tests,
                'passed': self.passed,
                'failed': self.failed,
                'timeout': self.timeout,
                'skipped': self.skipped,
                'error': self.error
            },
            'total_duration': round(self.total_duration, 3),
            'results': [r.to_dict() for r in self.results]
        }

    def is_success(self) -> bool:
        """Check if all tests passed"""
        return self.failed == 0 and self.timeout == 0 and self.error == 0

    def __repr__(self):
        return f"TestSuiteResult({self.target}: {self.passed}/{self.total_tests} passed)"
