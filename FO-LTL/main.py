#!/usr/bin/env python3
"""
TLS 1.3 Violation Test Case Generator
Main entry point for generating test cases that violate security properties
"""

import os
import sys
import argparse
from datetime import datetime

from generator import ViolationGenerator
from formatter import TestCaseFormatter


def generate_single_property_violations(max_steps=10, output_dir='examples'):
    """
    Generate test cases for each property violation individually

    Args:
        max_steps: Maximum trace length
        output_dir: Output directory for results
    """
    print("=" * 80)
    print("Generating Single Property Violations")
    print("=" * 80)

    generator = ViolationGenerator(max_steps)
    formatter = TestCaseFormatter()

    os.makedirs(output_dir, exist_ok=True)

    results = []

    # Properties: C1-C13, C16-C20 (C14/C15 are duplicates and omitted)
    property_names = ['C1', 'C2', 'C3', 'C4', 'C5', 'C6', 'C7', 'C8', 'C9', 'C10',
                      'C11', 'C12', 'C13', 'C16', 'C17', 'C18', 'C19', 'C20']

    for prop_name in property_names:
        print(f"\nTrying to violate {prop_name}...")

        result = generator.generate_single_violation(prop_name)

        if result:
            tls_model, z3_model, violated = result
            print(f"  [OK] Success! Generated violation for {prop_name}")

            # Format and save
            report = formatter.format_violation_report(z3_model, tls_model, violated)
            print(report)

            filename = os.path.join(output_dir, f'violation_{prop_name}.txt')
            formatter.save_to_file(report, filename)
            print(f"  Saved to: {filename}")

            results.append((prop_name, tls_model, z3_model, violated))
        else:
            print(f"  [FAIL] Could not generate violation for {prop_name}")

    print(f"\n{'=' * 80}")
    print(f"Generated {len(results)} single property violations")
    print(f"{'=' * 80}\n")

    return results


def generate_combination_violations(max_steps=10, output_dir='examples'):
    """
    Generate test cases for interesting combinations of violations

    Args:
        max_steps: Maximum trace length
        output_dir: Output directory for results
    """
    print("=" * 80)
    print("Generating Combination Property Violations")
    print("=" * 80)

    generator = ViolationGenerator(max_steps)
    formatter = TestCaseFormatter()

    os.makedirs(output_dir, exist_ok=True)

    # Generate smart combinations
    results = generator.generate_smart_combinations()

    print(f"\n{'=' * 80}")
    print(f"Generated {len(results)} combination violations")
    print(f"{'=' * 80}\n")

    # Format and save
    for idx, (tls_model, z3_model, violated) in enumerate(results):
        report = formatter.format_violation_report(z3_model, tls_model, violated)

        combo_name = "_".join(violated)
        filename = os.path.join(output_dir, f'violation_combo_{idx+1}_{combo_name}.txt')
        formatter.save_to_file(report, filename)
        print(f"Saved: {filename}")
        print(report)

    return results


def generate_random_violations(num_cases=10, max_violations=3, max_steps=10, output_dir='examples'):
    """
    Generate random violation combinations

    Args:
        num_cases: Number of test cases to generate
        max_violations: Maximum properties to violate per case
        max_steps: Maximum trace length
        output_dir: Output directory for results
    """
    print("=" * 80)
    print(f"Generating {num_cases} Random Violation Combinations")
    print("=" * 80)

    generator = ViolationGenerator(max_steps)
    formatter = TestCaseFormatter()

    os.makedirs(output_dir, exist_ok=True)

    results = []

    for i in range(num_cases):
        print(f"\nGenerating random case {i+1}/{num_cases}...")

        result = generator.generate_random_combination(
            num_violations=max_violations,
            max_attempts=20
        )

        if result:
            tls_model, z3_model, violated = result
            print(f"  [OK] Success! Violated: {violated}")

            report = formatter.format_violation_report(z3_model, tls_model, violated)

            combo_name = "_".join(violated)
            filename = os.path.join(output_dir, f'violation_random_{i+1}_{combo_name}.txt')
            formatter.save_to_file(report, filename)
            print(f"  Saved to: {filename}")

            results.append((tls_model, z3_model, violated))
        else:
            print(f"  [FAIL] Failed to generate random case {i+1}")

    print(f"\n{'=' * 80}")
    print(f"Generated {len(results)} random violations")
    print(f"{'=' * 80}\n")

    return results


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description='Generate TLS 1.3 violation test cases using SMT solver'
    )

    parser.add_argument(
        '--mode',
        choices=['single', 'combo', 'random', 'all', 'custom'],
        default='all',
        help='Generation mode: single properties, combinations, random, custom, or all'
    )

    parser.add_argument(
        '--properties',
        type=str,
        default='',
        help='Comma-separated property names for custom mode (e.g., "C1,C5,C11")'
    )

    parser.add_argument(
        '--max-steps',
        type=int,
        default=10,
        help='Maximum message trace length (default: 10)'
    )

    parser.add_argument(
        '--output-dir',
        type=str,
        default='examples',
        help='Output directory for test cases (default: examples)'
    )

    parser.add_argument(
        '--num-random',
        type=int,
        default=10,
        help='Number of random cases to generate (default: 10)'
    )

    parser.add_argument(
        '--max-violations',
        type=int,
        default=3,
        help='Maximum properties to violate in random mode (default: 3)'
    )

    args = parser.parse_args()

    print(f"\nTLS 1.3 Violation Test Case Generator")
    print(f"Started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Configuration:")
    print(f"  Mode: {args.mode}")
    print(f"  Max steps: {args.max_steps}")
    print(f"  Output directory: {args.output_dir}")
    if args.mode == 'custom':
        print(f"  Properties to violate: {args.properties}")
    print()

    # Create output directory
    os.makedirs(args.output_dir, exist_ok=True)

    # Generate based on mode
    if args.mode == 'custom':
        # Custom mode: violate specific properties
        if not args.properties:
            print("[FAIL] Error: --properties must be specified in custom mode")
            print("Example: python3 main.py --mode custom --properties C1,C5,C11")
            return

        prop_list = [p.strip() for p in args.properties.split(',')]
        print(f"{'=' * 80}")
        print(f"Generating Custom Violation: {', '.join(prop_list)}")
        print(f"{'=' * 80}\n")

        generator = ViolationGenerator(args.max_steps)
        formatter = TestCaseFormatter()

        result = generator.generate_multiple_violations(prop_list)

        if result:
            tls_model, z3_model, violated = result
            print(f"  [OK] Success! Generated violation for {', '.join(violated)}")

            # Format and save
            report = formatter.format_violation_report(z3_model, tls_model, violated)
            print(report)

            filename = os.path.join(args.output_dir, f'violation_{"_".join(prop_list)}.txt')
            formatter.save_to_file(report, filename)
            print(f"  Saved to: {filename}")
        else:
            print(f"  [FAIL] Could not generate violation for {', '.join(prop_list)}")

        print(f"\n{'=' * 80}\n")

    elif args.mode in ['single', 'all']:
        generate_single_property_violations(args.max_steps, args.output_dir)

    if args.mode in ['combo', 'all']:
        generate_combination_violations(args.max_steps, args.output_dir)

    if args.mode in ['random', 'all']:
        generate_random_violations(
            args.num_random,
            args.max_violations,
            args.max_steps,
            args.output_dir
        )

    print(f"\n[OK] All test cases generated successfully!")
    print(f"[OK] Check the '{args.output_dir}' directory for results")
    print(f"[OK] Finished at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")


if __name__ == '__main__':
    main()
