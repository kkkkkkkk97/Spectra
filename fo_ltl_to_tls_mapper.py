#!/usr/bin/env python3
"""
FO-LTL to TLSMapper Integration
================================

This module bridges FO-LTL (abstract message sequence generator) with TLSMapper
(concrete TLS packet executor) to enable automated property violation testing.

Architecture:
1. FO-LTL generates abstract violation sequences (CH -> SH -> EE -> ...)
2. This mapper converts them to TLSMapper alphabet
3. TLSMapper executes concrete packets against real implementations

Usage:
    from fo_ltl_to_tls_mapper import FOLTLToTLSMapper

    # Generate violation from FO-LTL
    mapper = FOLTLToTLSMapper()
    tls_sequence = mapper.convert_foltl_to_alphabet(foltl_trace)

    # Execute with TLSMapper
    sul.query(tls_sequence)
"""

import sys
import os
from pathlib import Path
from typing import List, Dict, Tuple, Optional

# Add FO-LTL to path
foltl_path = str(Path(__file__).parent / 'FO-LTL')
sys.path.insert(0, foltl_path)

from generator import ViolationGenerator
from formatter import TestCaseFormatter
from model import TLSModel


class FOLTLToTLSMapper:
    """
    Maps FO-LTL abstract message sequences to TLSMapper concrete alphabet
    """

    def __init__(self):
        """Initialize the mapper with message type mappings"""

        # FO-LTL message types to TLSMapper alphabet mapping
        # Based on FO-LTL/formatter.py:18-31 and TLSMapper/TLSSUT.py
        self.client_message_map = {
            'CH': 'ClientHello',
            'CCert': 'Certificate',  # Client certificate
            'CCV': 'CertificateVerify',  # Client certificate verify
            'CF': 'Finish',  # Client Finished
            'App': 'ApplicationData',
        }

        self.server_message_map = {
            'SH': 'ServerHello',
            'HRR': 'HelloRetryRequest',
            'EE': 'EncryptedExtensions',
            'CRq': 'CertificateRequest',
            'SCert': 'ServerCertificate',
            'SCV': 'ServerCertificateVerify',
            'SF': 'ServerFinished',
            'App': 'ApplicationData',
        }

    def convert_foltl_trace_to_alphabet(self, trace: List[Dict]) -> Tuple[List[str], List[str]]:
        """
        Convert FO-LTL trace to separate client and server alphabets

        Args:
            trace: FO-LTL trace from formatter.extract_trace()
                   Format: [{'time': 0, 'msg_type': 'CH', 'sender': 'cl', ...}, ...]

        Returns:
            Tuple of (client_sequence, server_sequence)
            - client_sequence: List of client messages to send
            - server_sequence: List of expected server responses
        """
        client_sequence = []
        server_sequence = []

        for msg in trace:
            msg_type = msg['msg_type']
            sender = msg['sender']

            # Handle ClientHello with special fields
            if msg_type == 'CH':
                # Check for empty keyshare
                if 'keyshare_Y' in msg and msg['keyshare_Y'] == 0:
                    client_sequence.append('ClientHelloEmptyKeyShare')
                else:
                    client_sequence.append('ClientHello')
                continue

            # Handle Certificate messages (check if empty)
            if msg_type == 'CCert':
                if msg.get('cert_empty', False):
                    client_sequence.append('EmptyCertificate')
                else:
                    client_sequence.append('Certificate')
                continue

            if msg_type == 'SCert':
                # Server certificate is expected response, not sent by client
                if msg.get('cert_empty', False):
                    server_sequence.append('ServerCertificate(empty)')
                else:
                    server_sequence.append('ServerCertificate')
                continue

            # Map other messages based on sender
            if sender == 'cl':  # Client message
                if msg_type in self.client_message_map:
                    client_sequence.append(self.client_message_map[msg_type])
            elif sender == 'sr':  # Server message
                if msg_type in self.server_message_map:
                    server_sequence.append(self.server_message_map[msg_type])

        return client_sequence, server_sequence

    def convert_foltl_to_test_sequence(self, trace: List[Dict]) -> List[str]:
        """
        Convert FO-LTL trace to a single interleaved test sequence

        This creates a sequence suitable for TLSSUT.query() where client
        messages are actions and server messages are expected responses.

        Args:
            trace: FO-LTL trace from formatter.extract_trace()

        Returns:
            List of message names in execution order
        """
        sequence = []

        for msg in trace:
            msg_type = msg['msg_type']
            sender = msg['sender']

            # Special handling for ClientHello
            if msg_type == 'CH':
                if 'keyshare_Y' in msg and msg['keyshare_Y'] == 0:
                    sequence.append('ClientHelloEmptyKeyShare')
                else:
                    sequence.append('ClientHello')
                continue

            # Special handling for certificates
            if msg_type == 'CCert':
                if msg.get('cert_empty', False):
                    sequence.append('EmptyCertificate')
                else:
                    sequence.append('Certificate')
                continue

            # Map based on sender
            if sender == 'cl':
                if msg_type in self.client_message_map:
                    sequence.append(self.client_message_map[msg_type])
            elif sender == 'sr':
                if msg_type in self.server_message_map:
                    sequence.append(self.server_message_map[msg_type])

        return sequence

    def generate_violation_test_case(self, property_name: str, max_steps: int = 10) -> Optional[Dict]:
        """
        Generate a complete test case for a property violation

        Args:
            property_name: Property to violate (e.g., 'C1', 'C2', ...)
            max_steps: Maximum trace length

        Returns:
            Dictionary with:
            - 'property': Property name
            - 'foltl_trace': Original FO-LTL trace
            - 'foltl_sequence': Compact FO-LTL sequence string
            - 'client_sequence': Client messages to send
            - 'server_sequence': Expected server responses
            - 'test_sequence': Interleaved test sequence
            - 'violated_properties': List of violated properties
        """
        # Generate violation using FO-LTL
        generator = ViolationGenerator(max_steps)
        result = generator.generate_single_violation(property_name)

        if not result:
            return None

        tls_model, z3_model, violated = result

        # Format the trace
        formatter = TestCaseFormatter()
        trace = formatter.extract_trace(z3_model, tls_model)
        compact_sequence = formatter.format_trace(trace)

        # Convert to TLSMapper alphabet
        client_seq, server_seq = self.convert_foltl_trace_to_alphabet(trace)
        test_seq = self.convert_foltl_to_test_sequence(trace)

        return {
            'property': property_name,
            'foltl_trace': trace,
            'foltl_sequence': compact_sequence,
            'client_sequence': client_seq,
            'server_sequence': server_seq,
            'test_sequence': test_seq,
            'violated_properties': violated
        }

    def generate_all_violation_test_cases(self, max_steps: int = 10) -> List[Dict]:
        """
        Generate test cases for all properties

        Args:
            max_steps: Maximum trace length

        Returns:
            List of test case dictionaries
        """
        property_names = ['C1', 'C2', 'C3', 'C4', 'C5', 'C6', 'C7', 'C8', 'C9', 'C10',
                          'C11', 'C12', 'C13', 'C16', 'C17', 'C18', 'C19', 'C20']

        test_cases = []
        for prop_name in property_names:
            print(f"Generating test case for {prop_name}...")
            test_case = self.generate_violation_test_case(prop_name, max_steps)
            if test_case:
                test_cases.append(test_case)
                print(f"  ✓ Success: {test_case['foltl_sequence']}")
            else:
                print(f"  ✗ Failed to generate")

        return test_cases


def main():
    """Example usage"""
    print("=" * 80)
    print("FO-LTL to TLSMapper Integration")
    print("=" * 80)

    mapper = FOLTLToTLSMapper()

    # Generate a single violation test case
    print("\nGenerating violation for property C1...")
    test_case = mapper.generate_violation_test_case('C1', max_steps=10)

    if test_case:
        print(f"\nProperty: {test_case['property']}")
        print(f"Violated: {test_case['violated_properties']}")
        print(f"\nFO-LTL Sequence:")
        print(f"  {test_case['foltl_sequence']}")
        print(f"\nClient Messages to Send:")
        print(f"  {test_case['client_sequence']}")
        print(f"\nExpected Server Responses:")
        print(f"  {test_case['server_sequence']}")
        print(f"\nTest Sequence for TLSSUT.query():")
        print(f"  {test_case['test_sequence']}")

        print("\n" + "=" * 80)
        print("Integration Example:")
        print("=" * 80)
        print("""
# Example: Execute this test case with TLSMapper
from TLSMapper.TLSSUT import TLSSUT
from TLSMapper.TLSProtocol import TLSProtocol
from tlslite.constants import CipherSuite

# Setup TLS protocol
ciphersuites = [CipherSuite.TLS_AES_128_GCM_SHA256]
tlspro = TLSProtocol(
    version=(3,4),
    cipher_suite=ciphersuites,
    implementation='mbedTLS',
    target=('127.0.0.1', 4433),
    verify=True,
    fuzz_tls=(False, None, None),
    imp_ver='3.6.0-1'
)

# Create SUL (System Under Learning)
sul = TLSSUT(
    keyfile='./TLSMapper/key/declient.key',
    certfile='./TLSMapper/key/client.cer',
    TLSpro=tlspro
)

# Execute the violation test case
result = sul.query(test_case['test_sequence'])
print(f"Test result: {result}")
""")
    else:
        print("Failed to generate test case")


if __name__ == '__main__':
    main()
