"""
Test Case Formatter
Extracts and formats test cases from Z3 models
"""

from z3 import *
from model import TLSModel
from properties import TLSProperties


class TestCaseFormatter:
    """
    Formats test cases from Z3 solver models
    """

    def __init__(self):
        """Initialize formatter"""
        self.msg_type_names = {
            'CH': 'ClientHello',
            'SH': 'ServerHello',
            'HRR': 'HelloRetryRequest',
            'EE': 'EncryptedExtensions',
            'CRq': 'CertificateRequest',
            'SCert': 'ServerCertificate',
            'SCV': 'ServerCertificateVerify',
            'SF': 'ServerFinished',
            'CCert': 'ClientCertificate',
            'CCV': 'ClientCertificateVerify',
            'CF': 'ClientFinished',
            'App': 'ApplicationData'
        }

    def extract_trace(self, z3_model, tls_model):
        """
        Extract message trace from Z3 model

        Args:
            z3_model: Z3 satisfying model
            tls_model: TLSModel instance

        Returns:
            List of message dictionaries
        """
        from z3 import is_int_value

        trace = []
        msg_count_val = z3_model.eval(tls_model.msg_count, model_completion=True)

        # Convert Z3 value to integer
        if is_int_value(msg_count_val):
            msg_count = msg_count_val.as_long()
        else:
            # Fallback: try to parse as string
            try:
                msg_count = int(str(msg_count_val))
            except:
                # If we still can't get a value, iterate through all possible steps
                # and check which ones have valid messages
                msg_count = 0
                for t in range(tls_model.N):
                    # Try to check if this time step has a valid message
                    try:
                        msg_type_val = z3_model.eval(tls_model.msg_type[t], model_completion=True)
                        if msg_type_val is not None:
                            msg_count = t + 1
                    except:
                        break

        for t in range(msg_count):
            msg_type = z3_model.eval(tls_model.msg_type[t])
            sender = z3_model.eval(tls_model.sender[t])

            # Get string representation of message type
            msg_type_str = str(msg_type)
            sender_str = str(sender)

            msg_info = {
                'time': t,
                'msg_type': msg_type_str,
                'msg_type_full': self.msg_type_names.get(msg_type_str, msg_type_str),
                'sender': sender_str,
            }

            # Extract fields for ClientHello
            if msg_type == tls_model.CH:
                try:
                    val = z3_model.eval(tls_model.legacy_version[t])
                    if hasattr(val, 'as_long'):
                        msg_info['legacy_version'] = hex(val.as_long())
                    else:
                        msg_info['legacy_version'] = hex(int(str(val)))
                except:
                    msg_info['legacy_version'] = 'unknown'

                try:
                    val = z3_model.eval(tls_model.keyshare_Y[t])
                    if hasattr(val, 'as_long'):
                        msg_info['keyshare_Y'] = val.as_long()
                    else:
                        msg_info['keyshare_Y'] = int(str(val))
                except:
                    msg_info['keyshare_Y'] = 'unknown'

                try:
                    val = z3_model.eval(tls_model.prime[t])
                    if hasattr(val, 'as_long'):
                        msg_info['prime'] = val.as_long()
                    else:
                        msg_info['prime'] = int(str(val))
                except:
                    msg_info['prime'] = 'unknown'

                try:
                    val = z3_model.eval(tls_model.comp_method[t])
                    if hasattr(val, 'as_long'):
                        msg_info['comp_method'] = val.as_long()
                    else:
                        msg_info['comp_method'] = int(str(val))
                except:
                    msg_info['comp_method'] = 'unknown'

            # Extract certificate emptiness
            if msg_type == tls_model.SCert:
                try:
                    is_empty = z3_model.eval(tls_model.scert_empty[t])
                    msg_info['cert_empty'] = is_true(is_empty)
                except:
                    msg_info['cert_empty'] = False

            if msg_type == tls_model.CCert:
                try:
                    is_empty = z3_model.eval(tls_model.ccert_empty[t])
                    msg_info['cert_empty'] = is_true(is_empty)
                except:
                    msg_info['cert_empty'] = False

            trace.append(msg_info)

        return trace

    def format_message(self, msg_info):
        """
        Format a single message for display

        Args:
            msg_info: Message information dictionary

        Returns:
            Formatted string
        """
        msg_type = msg_info['msg_type']
        full_name = msg_info['msg_type_full']
        sender = msg_info['sender']

        # Basic format
        result = f"{msg_type}"

        # Add fields if it's ClientHello
        if msg_type == 'CH' and 'legacy_version' in msg_info:
            fields = []
            if msg_info.get('legacy_version') != 'unknown':
                fields.append(f"legacy_version={msg_info['legacy_version']}")
            if msg_info.get('keyshare_Y') != 'unknown':
                fields.append(f"KeyShareY={msg_info['keyshare_Y']}")
            if msg_info.get('prime') != 'unknown':
                fields.append(f"prime={msg_info['prime']}")
            if msg_info.get('comp_method') != 'unknown':
                fields.append(f"comp_method={msg_info['comp_method']}")

            if fields:
                result += f"({', '.join(fields)})"

        # Add certificate status
        if 'cert_empty' in msg_info:
            if msg_info['cert_empty']:
                result += "(empty)"
            else:
                result += "(non-empty)"

        return result

    def format_trace(self, trace):
        """
        Format entire trace as string

        Args:
            trace: List of message dictionaries

        Returns:
            Formatted trace string
        """
        messages = [self.format_message(msg) for msg in trace]
        return " -> ".join(messages)

    def format_trace_detailed(self, trace):
        """
        Format trace with detailed information

        Args:
            trace: List of message dictionaries

        Returns:
            Detailed formatted string
        """
        lines = []
        lines.append("Message Trace (detailed):")
        lines.append("-" * 80)

        for msg in trace:
            time = msg['time']
            msg_str = self.format_message(msg)
            full_name = msg['msg_type_full']
            sender = msg['sender']

            line = f"  [{time}] {msg_str:30} ({full_name}, from {sender})"
            lines.append(line)

        lines.append("-" * 80)
        return "\n".join(lines)

    def format_violation_report(self, z3_model, tls_model, violated_properties):
        """
        Format a complete violation report

        Args:
            z3_model: Z3 satisfying model
            tls_model: TLSModel instance
            violated_properties: List of violated property names

        Returns:
            Formatted report string
        """
        trace = self.extract_trace(z3_model, tls_model)
        props = TLSProperties(tls_model)
        descriptions = props.get_property_descriptions()

        lines = []
        lines.append("=" * 80)
        lines.append(f"VIOLATION TEST CASE")
        lines.append("=" * 80)

        # Violated properties
        lines.append("\nViolated Properties:")
        for prop in violated_properties:
            desc = descriptions.get(prop, "Unknown property")
            lines.append(f"  - {prop}: {desc}")

        # Compact trace
        lines.append("\nMessage Sequence:")
        lines.append(f"  {self.format_trace(trace)}")

        # Detailed trace
        lines.append("\n" + self.format_trace_detailed(trace))

        lines.append("=" * 80)

        return "\n".join(lines)

    def export_to_dict(self, z3_model, tls_model, violated_properties):
        """
        Export test case as dictionary (for JSON/YAML export)

        Args:
            z3_model: Z3 satisfying model
            tls_model: TLSModel instance
            violated_properties: List of violated property names

        Returns:
            Dictionary representation
        """
        trace = self.extract_trace(z3_model, tls_model)
        props = TLSProperties(tls_model)
        descriptions = props.get_property_descriptions()

        return {
            'violated_properties': [
                {'name': prop, 'description': descriptions.get(prop, 'Unknown')}
                for prop in violated_properties
            ],
            'trace': trace,
            'trace_compact': self.format_trace(trace),
            'message_count': len(trace)
        }

    def save_to_file(self, report, filename):
        """
        Save report to file

        Args:
            report: Formatted report string
            filename: Output file path
        """
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(report)
