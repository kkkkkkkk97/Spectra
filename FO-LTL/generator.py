"""
Violation Test Case Generator
Generates test cases that violate combinations of security properties
"""

from z3 import *
import random
import itertools
from model import TLSModel
from properties import TLSProperties


class ViolationGenerator:
    """
    Generates test cases that violate security properties
    """

    def __init__(self, max_steps=10):
        """
        Initialize the violation generator

        Args:
            max_steps: Maximum number of messages in generated traces
        """
        self.max_steps = max_steps

    def generate_single_violation(self, property_name):
        """
        Generate a test case violating a single property

        Args:
            property_name: Name of property to violate (e.g., 'C1')

        Returns:
            (tls_model, z3_model, violated_properties) if successful, None otherwise
        """
        model = TLSModel(self.max_steps)
        props = TLSProperties(model)
        all_props = props.get_all_properties()

        if property_name not in all_props:
            return None

        # Ensure we have at least one message (avoid vacuous violations)
        model.add_constraint(model.msg_count >= 1)

        # Add all properties EXCEPT the one we want to violate
        for name, constraint in all_props.items():
            if name != property_name:
                model.add_constraint(constraint)

        # Explicitly negate the target property
        model.add_constraint(Not(all_props[property_name]))

        # Check satisfiability
        if model.check_sat() == sat:
            return model, model.get_model(), [property_name]
        return None

    def generate_multiple_violations(self, properties_to_violate):
        """
        Generate a test case violating multiple specific properties

        Args:
            properties_to_violate: List of property names to violate

        Returns:
            (tls_model, z3_model, violated_properties) if successful, None otherwise
        """
        model = TLSModel(self.max_steps)
        props = TLSProperties(model)
        all_props = props.get_all_properties()

        # Validate property names
        for prop_name in properties_to_violate:
            if prop_name not in all_props:
                return None

        # Ensure we have at least one message (avoid vacuous violations)
        model.add_constraint(model.msg_count >= 1)

        # Add all properties EXCEPT the ones we want to violate
        for name, constraint in all_props.items():
            if name not in properties_to_violate:
                model.add_constraint(constraint)

        # Negate the properties we want to violate
        violations = [Not(all_props[name]) for name in properties_to_violate]
        model.add_constraint(Or(violations))  # At least one must be violated

        # Check satisfiability
        if model.check_sat() == sat:
            return model, model.get_model(), properties_to_violate
        return None

    def generate_random_combination(self, num_violations=2, max_attempts=10):
        """
        Generate a test case violating a random combination of properties

        Args:
            num_violations: Number of properties to attempt to violate
            max_attempts: Maximum attempts to find a satisfiable combination

        Returns:
            (model, violated_properties) if successful, None otherwise
        """
        all_property_names = [f'C{i}' for i in range(1, 15)]

        for attempt in range(max_attempts):
            # Randomly select properties to violate
            selected = random.sample(all_property_names, min(num_violations, len(all_property_names)))

            result = self.generate_multiple_violations(selected)
            if result is not None:
                return result

        return None

    def generate_all_combinations(self, min_violations=1, max_violations=3, max_per_size=5):
        """
        Generate test cases for various combinations of violations

        Args:
            min_violations: Minimum number of properties to violate
            max_violations: Maximum number of properties to violate
            max_per_size: Maximum test cases to generate per combination size

        Returns:
            List of (model, violated_properties) tuples
        """
        results = []
        all_property_names = [f'C{i}' for i in range(1, 15)]

        for num_violations in range(min_violations, max_violations + 1):
            print(f"\nGenerating violations for {num_violations} properties...")

            # Get all combinations of this size
            combinations = list(itertools.combinations(all_property_names, num_violations))

            # Limit the number of combinations to try
            selected_combinations = random.sample(combinations, min(max_per_size, len(combinations)))

            for combo in selected_combinations:
                result = self.generate_multiple_violations(list(combo))
                if result is not None:
                    results.append(result)
                    print(f"  [OK] Found violation: {list(combo)}")
                else:
                    print(f"  [FAIL] No solution for: {list(combo)}")

        return results

    def generate_smart_combinations(self):
        """
        Generate interesting violation combinations based on property categories

        Returns:
            List of (model, violated_properties) tuples
        """
        results = []

        # Category 1: Violate ordering properties
        ordering_props = ['C1', 'C2', 'C4', 'C5', 'C7', 'C9', 'C10']

        # Category 2: Violate field constraints
        field_props = ['C11', 'C12', 'C13']

        # Category 3: Violate dependency constraints
        dependency_props = ['C6', 'C8']

        # Category 4: Mix different categories
        interesting_combos = [
            ['C1'],  # First message violation
            ['C2', 'C3'],  # HRR violations
            ['C5', 'C6'],  # Server auth violations
            ['C7', 'C8'],  # Client auth violations
            ['C10'],  # App data before finished
            ['C11', 'C12', 'C13'],  # All ClientHello field violations
            ['C1', 'C10'],  # First and last message violations
            ['C5', 'C7'],  # Both auth order violations
            ['C6', 'C8', 'C9'],  # Certificate and finished violations
        ]

        for combo in interesting_combos:
            print(f"Attempting: {combo}")
            result = self.generate_multiple_violations(combo)
            if result is not None:
                results.append(result)
                print(f"  [OK] Success")
            else:
                print(f"  [FAIL] Failed")

        return results

    def analyze_violation(self, z3_model, violated_props):
        """
        Analyze which properties are actually violated in the generated model

        Args:
            z3_model: Z3 model from solver
            violated_props: List of properties intended to be violated

        Returns:
            Dictionary with analysis results
        """
        # Create fresh model to evaluate
        model = TLSModel(self.max_steps)
        props = TLSProperties(model)
        all_props = props.get_all_properties()

        # Extract the actual trace from z3_model
        trace = self._extract_trace(z3_model, model)

        # Check each property
        actual_violations = []
        for name, constraint in all_props.items():
            # Create a solver just for this property check
            temp_solver = Solver()
            # Add the trace constraints
            for t in range(len(trace)):
                if t < model.msg_count:
                    temp_solver.add(model.msg_type[t] == trace[t]['msg_type'])
                    temp_solver.add(model.sender[t] == trace[t]['sender'])
            # Check if property holds
            temp_solver.add(Not(constraint))
            if temp_solver.check() == sat:
                actual_violations.append(name)

        return {
            'intended_violations': violated_props,
            'actual_violations': actual_violations,
            'trace': trace
        }

    def _extract_trace(self, z3_model, model):
        """
        Extract message trace from Z3 model

        Args:
            z3_model: Z3 model
            model: TLSModel instance

        Returns:
            List of message dictionaries
        """
        trace = []
        msg_count = z3_model.eval(model.msg_count).as_long()

        for t in range(msg_count):
            msg_info = {
                'time': t,
                'msg_type': z3_model.eval(model.msg_type[t]),
                'sender': z3_model.eval(model.sender[t]),
            }

            # Extract fields if relevant
            msg_type_val = z3_model.eval(model.msg_type[t])
            if msg_type_val == model.CH:
                msg_info['legacy_version'] = z3_model.eval(model.legacy_version[t]).as_long()
                msg_info['keyshare_Y'] = z3_model.eval(model.keyshare_Y[t]).as_long()
                msg_info['prime'] = z3_model.eval(model.prime[t]).as_long()
                msg_info['comp_method'] = z3_model.eval(model.comp_method[t]).as_long()

            if msg_type_val == model.SCert:
                msg_info['cert_empty'] = z3_model.eval(model.scert_empty[t])

            if msg_type_val == model.CCert:
                msg_info['cert_empty'] = z3_model.eval(model.ccert_empty[t])

            trace.append(msg_info)

        return trace
