"""
Test registry for TLS property testing framework
"""

from typing import Callable, List, Dict, Optional
from dataclasses import dataclass


@dataclass
class PropertyTest:
    """Metadata for a property test"""
    property_id: str
    name: str
    mode: str  # 'client' or 'server'
    test_func: Callable
    description: str

    def __repr__(self):
        return f"PropertyTest({self.property_id}, mode={self.mode})"


class TestRegistry:
    """Registry for property tests with decorator-based registration"""

    def __init__(self):
        self.tests: Dict[str, PropertyTest] = {}

    def register(self, property_id: str, mode: str):
        """
        Decorator to register test functions

        Args:
            property_id: Property identifier (e.g., 'C1')
            mode: Test mode ('client' or 'server')

        Usage:
            @registry.register('C1', mode='client')
            def test_property_C1(target_config, config):
                # Test implementation
                pass
        """
        def decorator(func: Callable):
            test = PropertyTest(
                property_id=property_id,
                name=func.__name__,
                mode=mode,
                test_func=func,
                description=func.__doc__ or ""
            )
            # Use property_id + mode as unique key
            key = f"{property_id}_{mode}"
            self.tests[key] = test
            return func
        return decorator

    def get_test(self, property_id: str, mode: str) -> Optional[PropertyTest]:
        """
        Get a specific test

        Args:
            property_id: Property identifier
            mode: Test mode

        Returns:
            PropertyTest object or None if not found
        """
        key = f"{property_id}_{mode}"
        return self.tests.get(key)

    def get_tests(self, mode: str, properties: Optional[List[str]] = None) -> List[PropertyTest]:
        """
        Get tests matching mode and property list

        Args:
            mode: Test mode ('client' or 'server')
            properties: List of property IDs, or None/'all' for all properties

        Returns:
            List of PropertyTest objects
        """
        # Filter by mode
        tests = [t for t in self.tests.values() if t.mode == mode]

        # Filter by property list
        if properties and 'all' not in properties:
            tests = [t for t in tests if t.property_id in properties]

        # Sort by property ID
        tests.sort(key=lambda t: t.property_id)

        return tests

    def list_properties(self, mode: Optional[str] = None) -> List[str]:
        """
        List all registered property IDs

        Args:
            mode: Filter by mode, or None for all

        Returns:
            Sorted list of property IDs
        """
        if mode:
            props = [t.property_id for t in self.tests.values() if t.mode == mode]
        else:
            props = [t.property_id for t in self.tests.values()]

        return sorted(list(set(props)))

    def __len__(self):
        """Return number of registered tests"""
        return len(self.tests)

    def __repr__(self):
        return f"TestRegistry({len(self.tests)} tests registered)"


# Global registry instance
registry = TestRegistry()
