"""
Report generation for TLS property testing framework
"""

import json
from jinja2 import Template
from pathlib import Path
from typing import List
from .results import TestSuiteResult, TestStatus


class ReportGenerator:
    """Generate test reports in various formats"""

    def __init__(self, template_path: str = 'templates/report_template.html'):
        """
        Initialize report generator

        Args:
            template_path: Path to HTML template file
        """
        self.template_path = Path(template_path)

    def generate_html(self, suite_result: TestSuiteResult, output_path: str):
        """
        Generate HTML report

        Args:
            suite_result: TestSuiteResult object
            output_path: Path to output HTML file
        """
        if not self.template_path.exists():
            print(f"Warning: Template not found at {self.template_path}, skipping HTML report")
            return

        with open(self.template_path) as f:
            template = Template(f.read())

        html = template.render(
            target_name=suite_result.target,
            target_version=suite_result.target_version,
            mode=suite_result.mode,
            timestamp=suite_result.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
            total_duration=suite_result.total_duration,
            passed=suite_result.passed,
            failed=suite_result.failed,
            timeout=suite_result.timeout,
            error=suite_result.error,
            results=suite_result.results
        )

        with open(output_path, 'w') as f:
            f.write(html)

        print(f"\nHTML report generated: {output_path}")

    def generate_json(self, suite_result: TestSuiteResult, output_path: str):
        """
        Generate JSON report

        Args:
            suite_result: TestSuiteResult object
            output_path: Path to output JSON file
        """
        with open(output_path, 'w') as f:
            json.dump(suite_result.to_dict(), f, indent=2)

        print(f"JSON report generated: {output_path}")

    def print_console_summary(self, suite_result: TestSuiteResult):
        """
        Print summary to console

        Args:
            suite_result: TestSuiteResult object
        """
        print("\n" + "=" * 70)
        print(f"Test Suite Summary: {suite_result.target} {suite_result.target_version} ({suite_result.mode} mode)")
        print("=" * 70)
        print(f"Total Tests:    {suite_result.total_tests}")
        print(f"✓ Passed:       {suite_result.passed}")
        print(f"✗ Failed:       {suite_result.failed}")
        print(f"⏱ Timeout:      {suite_result.timeout}")
        print(f"⚠ Error:        {suite_result.error}")
        print(f"Duration:       {suite_result.total_duration:.2f}s")
        print("=" * 70)

        if suite_result.failed > 0 or suite_result.error > 0:
            print("\nFailed Tests:")
            for result in suite_result.results:
                if result.status in [TestStatus.FAILED, TestStatus.ERROR]:
                    print(f"  ✗ {result.property_id}: {result.error_message}")

        if suite_result.timeout > 0:
            print("\nTimeout Tests:")
            for result in suite_result.results:
                if result.status == TestStatus.TIMEOUT:
                    print(f"  ⏱ {result.property_id}: {result.error_message}")

        print()

    def print_detailed_results(self, suite_result: TestSuiteResult):
        """
        Print detailed test results to console

        Args:
            suite_result: TestSuiteResult object
        """
        print("\nDetailed Test Results:")
        print("-" * 70)

        for result in suite_result.results:
            status_symbol = {
                TestStatus.PASSED: "✓",
                TestStatus.FAILED: "✗",
                TestStatus.TIMEOUT: "⏱",
                TestStatus.ERROR: "⚠",
                TestStatus.SKIPPED: "○"
            }.get(result.status, "?")

            print(f"\n{status_symbol} {result.property_id}: {result.test_name}")
            print(f"   Status: {result.status.value.upper()}")
            print(f"   Duration: {result.duration:.2f}s")

            if result.output:
                print(f"   Output:")
                for line in result.output.split('\n'):
                    print(f"     {line}")

            if result.error_message:
                print(f"   Error: {result.error_message}")

            if result.traceback:
                print(f"   Traceback:")
                for line in result.traceback.split('\n'):
                    if line.strip():
                        print(f"     {line}")

        print("-" * 70)
