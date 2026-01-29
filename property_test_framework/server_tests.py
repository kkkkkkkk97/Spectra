"""
Server-mode property tests for TLS 1.3 security properties

These tests configure a malicious TLS server to send invalid message sequences
to clients to verify that clients correctly reject them.

Note: Server-mode tests require a different approach than client-mode tests.
They need to listen for connections and send malicious sequences. For the
unified framework, we define the violation scenarios that should be tested.
"""

from tls_server_with_alphabet import TLSServerWithAlphabet
import socket
from .test_registry import registry


@registry.register('C2', mode='server')
def test_property_C2(target_config, config):
    """
    C2: Server responds with SH or HRR to CH
    Test: Send other messages instead of ServerHello/HRR
    Expected: Client should reject missing ServerHello
    """
    certs = config.get_server_certs(target_config)
    port = target_config['port']

    results = []

    # Test scenario: missing ServerHello, send EncryptedExtensions directly
    test_scenarios = [
        ('Missing ServerHello', ['EncryptedExtensions']),
        ('Valid ServerHello', ['ServerHello', 'EncryptedExtensions', 'Certificate',
                               'CertificateVerify', 'Finished']),
        ('Valid HRR', ['HelloRetryRequest'])
    ]

    for scenario_name, message_sequence in test_scenarios:
        listen_sock = None
        client_sock = None
        try:
            # Create listening socket
            listen_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            listen_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listen_sock.bind(('0.0.0.0', port))
            listen_sock.listen(1)
            listen_sock.settimeout(10)  # 10 second timeout

            # Wait for connection
            client_sock, client_addr = listen_sock.accept()
            results.append(f"{scenario_name}: Client connected from {client_addr}")

            # Create TLS server
            server = TLSServerWithAlphabet(
                client_sock,
                cert_file=str(certs['cert']),
                key_file=str(certs['key']),
                version=(3, 4)
            )

            # Run handshake
            server.run_handshake_loop(message_sequence)
            results.append(f"{scenario_name}: Handshake completed")

        except socket.timeout:
            results.append(f"{scenario_name}: Timeout waiting for client")
        except Exception as e:
            results.append(f"{scenario_name}: Expected failure - {e}")
        finally:
            if client_sock:
                client_sock.close()
            if listen_sock:
                listen_sock.close()

    return "\n".join(results)


@registry.register('C3', mode='server')
def test_property_C3(target_config, config):
    """
    C3: HRR can only appear once
    Test: Send HRR twice in handshake
    Expected: Client should reject multiple HRRs
    """
    certs = config.get_server_certs(target_config)
    port = target_config['port']

    results = []
    test_scenarios = [
        ('Double HRR', ['HelloRetryRequest', 'HelloRetryRequest']),
        # ('HRR after ServerHello', ['ServerHello', 'HelloRetryRequest'])
    ]

    for scenario_name, message_sequence in test_scenarios:
        listen_sock = None
        client_sock = None
        try:
            listen_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            listen_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listen_sock.bind(('0.0.0.0', port))
            listen_sock.listen(1)
            listen_sock.settimeout(10)

            client_sock, client_addr = listen_sock.accept()
            server = TLSServerWithAlphabet(client_sock, cert_file=str(certs['cert']),
                                          key_file=str(certs['key']), version=(3, 4))
            server.run_handshake_loop(message_sequence)
            results.append(f"{scenario_name}: Unexpected success")

        except Exception as e:
            results.append(f"{scenario_name}: Expected failure - {type(e).__name__}")
        finally:
            if client_sock:
                client_sock.close()
            if listen_sock:
                listen_sock.close()

    return "\n".join(results)


@registry.register('C5', mode='server')
def test_property_C5(target_config, config):
    """
    C5: ServerHello must be immediately followed by EE
    Test: Send other messages after ServerHello
    Expected: Client should reject non-EE after ServerHello
    """
    certs = config.get_server_certs(target_config)
    port = target_config['port']

    results = []
    test_scenarios = [
        ('SH->Certificate (not EE)', ['ServerHello', 'Certificate', 'EncryptedExtensions',
                                      'CertificateVerify', 'Finished']),
        ('SH->Finished', ['ServerHello', 'Finished'])
    ]

    for scenario_name, message_sequence in test_scenarios:
        listen_sock = None
        client_sock = None
        try:
            listen_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            listen_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listen_sock.bind(('0.0.0.0', port))
            listen_sock.listen(1)
            listen_sock.settimeout(10)

            client_sock, _ = listen_sock.accept()
            server = TLSServerWithAlphabet(client_sock, cert_file=str(certs['cert']),
                                          key_file=str(certs['key']), version=(3, 4))
            server.run_handshake_loop(message_sequence)
            results.append(f"{scenario_name}: Unexpected success")

        except Exception as e:
            results.append(f"{scenario_name}: Expected failure - {type(e).__name__}")
        finally:
            if client_sock:
                client_sock.close()
            if listen_sock:
                listen_sock.close()

    return "\n".join(results)


@registry.register('C6', mode='server')
def test_property_C6(target_config, config):
    """
    C6: EE must be immediately followed by CRq or SCert
    Test: Send invalid message after EncryptedExtensions
    Expected: Client should reject invalid messages after EE
    """
    certs = config.get_server_certs(target_config)
    port = target_config['port']

    results = []
    test_scenarios = [
        ('EE->CertificateVerify', ['ServerHello', 'EncryptedExtensions',
                                   'CertificateVerify', 'Finished']),
        ('EE->Finished', ['ServerHello', 'EncryptedExtensions', 'Finished']),
        ('EE->Certificate (valid)', ['ServerHello', 'EncryptedExtensions', 'Certificate',
                                     'CertificateVerify', 'Finished']),
        ('EE->CRq->Certificate (valid)', ['ServerHello', 'EncryptedExtensions',
                                          'CertificateRequest', 'Certificate',
                                          'CertificateVerify', 'Finished'])
    ]

    for scenario_name, message_sequence in test_scenarios:
        listen_sock = None
        client_sock = None
        try:
            listen_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            listen_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listen_sock.bind(('0.0.0.0', port))
            listen_sock.listen(1)
            listen_sock.settimeout(10)

            client_sock, _ = listen_sock.accept()
            server = TLSServerWithAlphabet(client_sock, cert_file=str(certs['cert']),
                                          key_file=str(certs['key']), version=(3, 4))
            server.run_handshake_loop(message_sequence)

            if 'valid' in scenario_name:
                results.append(f"{scenario_name}: Success (valid case)")
            else:
                results.append(f"{scenario_name}: Unexpected success")

        except Exception as e:
            results.append(f"{scenario_name}: Expected failure - {type(e).__name__}")
        finally:
            if client_sock:
                client_sock.close()
            if listen_sock:
                listen_sock.close()

    return "\n".join(results)


@registry.register('C7', mode='server')
def test_property_C7(target_config, config):
    """
    C7: CRq must be immediately followed by SCert
    Test: Send other messages after CertificateRequest
    Expected: Client should reject non-Certificate after CRq
    """
    certs = config.get_server_certs(target_config)
    port = target_config['port']

    results = []
    test_scenarios = [
        ('CRq->CertificateVerify', ['ServerHello', 'EncryptedExtensions',
                                    'CertificateRequest', 'CertificateVerify', 'Finished']),
        ('CRq->Finished', ['ServerHello', 'EncryptedExtensions',
                          'CertificateRequest', 'Finished'])
    ]

    for scenario_name, message_sequence in test_scenarios:
        listen_sock = None
        client_sock = None
        try:
            listen_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            listen_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listen_sock.bind(('0.0.0.0', port))
            listen_sock.listen(1)
            listen_sock.settimeout(10)

            client_sock, _ = listen_sock.accept()
            server = TLSServerWithAlphabet(client_sock, cert_file=str(certs['cert']),
                                          key_file=str(certs['key']), version=(3, 4))
            server.run_handshake_loop(message_sequence)
            results.append(f"{scenario_name}: Unexpected success")

        except Exception as e:
            results.append(f"{scenario_name}: Expected failure - {type(e).__name__}")
        finally:
            if client_sock:
                client_sock.close()
            if listen_sock:
                listen_sock.close()

    return "\n".join(results)


@registry.register('C8', mode='server')
def test_property_C8(target_config, config):
    """
    C8: SCert must be immediately followed by SCV
    Test: Send Finished directly after Certificate
    Expected: Client should reject missing CertificateVerify
    """
    certs = config.get_server_certs(target_config)
    port = target_config['port']

    results = []
    test_scenarios = [
        ('Certificate->Finished', ['ServerHello', 'EncryptedExtensions',
                                   'Certificate', 'Finished']),
        ('Certificate->CRq', ['ServerHello', 'EncryptedExtensions', 'Certificate',
                             'CertificateRequest', 'Finished']),
        ('Certificate->CRq', ['ServerHello', 'EncryptedExtensions', 'EmptyCertificate',
                             'CertificateVerify', 'Finished']),
        ('Certificate->CRq', ['ServerHello', 'EncryptedExtensions', 'Certificate',
                             'ErrorCertificateVerify', 'Finished']),
        ('Certificate->CRq', ['ServerHello', 'EncryptedExtensions', 'Certificate',
                             'ErrorCertificateVerify', 'Finished']),                         
    ]

    for scenario_name, message_sequence in test_scenarios:
        listen_sock = None
        client_sock = None
        try:
            listen_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            listen_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listen_sock.bind(('0.0.0.0', port))
            listen_sock.listen(1)
            listen_sock.settimeout(10)

            client_sock, _ = listen_sock.accept()
            server = TLSServerWithAlphabet(client_sock, cert_file=str(certs['cert']),
                                          key_file=str(certs['key']), version=(3, 4))
            server.run_handshake_loop(message_sequence)
            results.append(f"{scenario_name}: Unexpected success")

        except Exception as e:
            results.append(f"{scenario_name}: Expected failure - {type(e).__name__}")
        finally:
            if client_sock:
                client_sock.close()
            if listen_sock:
                listen_sock.close()

    return "\n".join(results)


@registry.register('C9', mode='server')
def test_property_C9(target_config, config):
    """
    C9: SCV must be immediately followed by SF
    Test: Send other messages after CertificateVerify
    Expected: Client should reject non-Finished after CertificateVerify
    """
    certs = config.get_server_certs(target_config)
    port = target_config['port']

    results = []
    test_scenarios = [
        ('CertV->Certificate', ['ServerHello', 'EncryptedExtensions', 'Certificate',
                                'CertificateVerify', 'Certificate']),
        ('CertV->EncryptedExtensions', ['ServerHello', 'EncryptedExtensions', 'Certificate',
                                        'CertificateVerify', 'EncryptedExtensions'])
    ]

    for scenario_name, message_sequence in test_scenarios:
        listen_sock = None
        client_sock = None
        try:
            listen_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            listen_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listen_sock.bind(('0.0.0.0', port))
            listen_sock.listen(1)
            listen_sock.settimeout(10)

            client_sock, _ = listen_sock.accept()
            server = TLSServerWithAlphabet(client_sock, cert_file=str(certs['cert']),
                                          key_file=str(certs['key']), version=(3, 4))
            server.run_handshake_loop(message_sequence)
            results.append(f"{scenario_name}: Unexpected success")

        except Exception as e:
            results.append(f"{scenario_name}: Expected failure - {type(e).__name__}")
        finally:
            if client_sock:
                client_sock.close()
            if listen_sock:
                listen_sock.close()

    return "\n".join(results)


@registry.register('C10', mode='server')
def test_property_C10(target_config, config):
    """
    C10: CRq cannot appear before EE
    Test: Send CertificateRequest before EncryptedExtensions
    Expected: Client should reject CRq before EE
    """
    certs = config.get_server_certs(target_config)
    port = target_config['port']

    results = []
    test_scenarios = [
        ('CRq before EE', ['ServerHello', 'CertificateRequest', 'EncryptedExtensions',
                          'Certificate', 'CertificateVerify', 'Finished']),
        ('CRq without EE', ['ServerHello', 'CertificateRequest', 'Certificate',
                           'CertificateVerify', 'Finished'])
    ]

    for scenario_name, message_sequence in test_scenarios:
        listen_sock = None
        client_sock = None
        try:
            listen_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            listen_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listen_sock.bind(('0.0.0.0', port))
            listen_sock.listen(1)
            listen_sock.settimeout(10)

            client_sock, _ = listen_sock.accept()
            server = TLSServerWithAlphabet(client_sock, cert_file=str(certs['cert']),
                                          key_file=str(certs['key']), version=(3, 4))
            server.run_handshake_loop(message_sequence)
            results.append(f"{scenario_name}: Unexpected success")

        except Exception as e:
            results.append(f"{scenario_name}: Expected failure - {type(e).__name__}")
        finally:
            if client_sock:
                client_sock.close()
            if listen_sock:
                listen_sock.close()

    return "\n".join(results)


@registry.register('C18', mode='server')
def test_property_C18(target_config, config):
    """
    C18: KeyShare value must be in valid range (1 < Y < p-1)
    Test: Send ServerHello with invalid KeyShare values
    Expected: Client should reject invalid KeyShare values
    """
    certs = config.get_server_certs(target_config)
    print(certs)
    port = target_config['port']

    results = []
    test_scenarios = [
        ('valid', ['ServerHello','EncryptedExtensions', 'Certificate', 'CertificateVerify', 'Finished']),
        ('KeyShare Y=0 (invalid)', ['ServerHello_FuzzKeyShare_zero','EncryptedExtensions', 'Certificate', 'CertificateVerify', 'Finished']),
        ('KeyShare Y=1 (invalid)', ['ServerHello_FuzzKeyShare_one','EncryptedExtensions']),
        ('KeyShare Y=p-1 (boundary)', ['ServerHello_FuzzKeyShare_max','EncryptedExtensions']),
        ('KeyShare Y>p-1 (out of range)', ['ServerHello_FuzzKeyShare_over_prime','EncryptedExtensions']),
        ('KeyShare invalid length', ['ServerHello_FuzzKeyShare_invalid_length','EncryptedExtensions']),
    ]

    for scenario_name, message_sequence in test_scenarios:
        print("++++++++++++++++++",scenario_name,"++++++++++++++++++")
        listen_sock = None
        client_sock = None
        try:
            listen_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            listen_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listen_sock.bind(('0.0.0.0', port))
            listen_sock.listen(1)
            listen_sock.settimeout(10)

            client_sock, client_addr = listen_sock.accept()
            results.append(f"{scenario_name}: Client connected from {client_addr}")

            server = TLSServerWithAlphabet(client_sock, cert_file=str(certs['cert']),
                                          key_file=str(certs['key']), version=(3, 4),
                                        #   debug=True,
                                          )
            server.run_handshake_loop(message_sequence)

            if 'boundary' in scenario_name:
                results.append(f"{scenario_name}: Completed (boundary case)")
            else:
                results.append(f"{scenario_name}: Unexpected success")

        except socket.timeout:
            results.append(f"{scenario_name}: Timeout waiting for client")
        except Exception as e:
            results.append(f"{scenario_name}: Expected failure - {type(e).__name__}")
        finally:
            if client_sock:
                client_sock.close()
            if listen_sock:
                listen_sock.close()

    return "\n".join(results)


@registry.register('C20', mode='server')
def test_property_C20(target_config, config):
    """
    C20: TLS record boundaries and required extensions
    Test 1: ServerHello and EncryptedExtensions merged into one TLS record
    Test 2: ServerHello missing KeyShare extension
    Expected: Client should reject both violations
    """
    certs = config.get_server_certs(target_config)
    port = target_config['port']

    results = []
    test_scenarios = [
        ('Merged SH+EE in one record', ['ServerHello_MergedWithEE', 'Certificate',
                                        'CertificateVerify', 'Finished']),
        ('Merged SH+EE+Cert in one record', ['ServerHello_MergedWithEE_Cert',
                                             'CertificateVerify', 'Finished']),
        ('Merged SH+EE+Cert+CV+Fin in one record', ['ServerHello_MergedWithEE_Cert_CV_Fin']),
        ('ServerHello no extension', ['ServerHello_NoKeyShare']),
        ('ServerHello missing KeyShare', ['CustomPacket']),

        ('Valid handshake (baseline)', ['ServerHello', 'EncryptedExtensions', 'Certificate',
                                        'CertificateVerify', 'Finished']),

    ]

    for scenario_name, message_sequence in test_scenarios:
        listen_sock = None
        client_sock = None
        try:
            listen_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            listen_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listen_sock.bind(('0.0.0.0', port))
            listen_sock.listen(1)
            listen_sock.settimeout(10)

            client_sock, client_addr = listen_sock.accept()
            results.append(f"{scenario_name}: Client connected from {client_addr}")

            server = TLSServerWithAlphabet(client_sock, cert_file=str(certs['cert']),
                                          key_file=str(certs['key']), version=(3, 4))
            server.run_handshake_loop(message_sequence)

            if 'baseline' in scenario_name:
                results.append(f"{scenario_name}: Success (valid case)")
            else:
                results.append(f"{scenario_name}: Unexpected success")

        except socket.timeout:
            results.append(f"{scenario_name}: Timeout waiting for client")
        except Exception as e:
            results.append(f"{scenario_name}: Expected failure - {type(e).__name__}")
        finally:
            if client_sock:
                client_sock.close()
            if listen_sock:
                listen_sock.close()

    return "\n".join(results)



@registry.register('AP', mode='server')
def test_property_All(target_config, config):
    """
    All properties test - comprehensive TLS 1.3 protocol violation testing
    """
    certs = config.get_server_certs(target_config)
    port = target_config['port']

    results = []
    test_scenarios = [
        # Baseline - Valid handshake
        ('Baseline: Valid handshake', ['ServerHello', 'EncryptedExtensions', 'Certificate', 'CertificateVerify', 'Finished']),

        # C2: Server responds with SH or HRR to CH
        ('C2: Missing ServerHello', ['EncryptedExtensions']),
        ('C2: Valid HRR', ['HelloRetryRequest']),

        # C3: HRR can only appear once
        ('C3: Double HRR', ['HelloRetryRequest', 'HelloRetryRequest']),
        ('C3: HRR after ServerHello', ['ServerHello', 'HelloRetryRequest']),

        # C5: ServerHello must be immediately followed by EE
        ('C5: SH->Certificate (not EE)', ['ServerHello', 'Certificate', 'EncryptedExtensions', 'CertificateVerify', 'Finished']),
        ('C5: SH->Certificate (not EE)', ['ServerHello', 'CertificateVerify', 'Finished']),
        ('C5: SH->Finished', ['ServerHello', 'Finished']),

        # C6: EE must be immediately followed by CRq or SCert
        ('C6: EE->CertificateVerify', ['ServerHello', 'EncryptedExtensions', 'CertificateVerify', 'Finished']),
        ('C6: EE->Finished', ['ServerHello', 'EncryptedExtensions', 'Finished']),
        ('C6: EE->EmptyCert', ['ServerHello', 'EncryptedExtensions', 'EmptyCertificate', 'CertificateVerify']),
        ('C6: EE->EmptyCertVerify', ['ServerHello', 'EncryptedExtensions', 'EmptyCertificateVerify']),


        # C7: CRq must be immediately followed by SCert
        ('C7: CRq->CertificateVerify', ['ServerHello', 'EncryptedExtensions', 'CertificateRequest', 'CertificateVerify', 'Finished']),
        ('C7: CRq->Finished', ['ServerHello', 'EncryptedExtensions', 'CertificateRequest', 'Finished']),
        ('C7: CRq->Finished', ['ServerHello', 'EncryptedExtensions', 'Certificate', 'CertificateRequest', 'Finished']),
        ('C7: CRq->Finished', ['ServerHello', 'EncryptedExtensions', 'CertificateRequest', 'EmptyCertificateVerify', 'Finished']),
        ('C7: CRq->Finished', ['ServerHello', 'EncryptedExtensions', 'CertificateRequest', 'Certificate', 'EmptyCertificateVerify', 'Finished']),


        # C8: SCert must be immediately followed by SCV
        ('C8: Certificate->Finished', ['ServerHello', 'EncryptedExtensions', 'Certificate', 'Finished']),
        ('C8: Certificate->CRq', ['ServerHello', 'EncryptedExtensions', 'Certificate', 'CertificateRequest', 'Finished']),

        # C9: SCV must be immediately followed by SF
        ('C9: CertV->Certificate', ['ServerHello', 'EncryptedExtensions', 'Certificate', 'CertificateVerify', 'Certificate']),
        ('C9: CertV->EncryptedExtensions', ['ServerHello', 'EncryptedExtensions', 'Certificate', 'CertificateVerify', 'EncryptedExtensions']),
        ('C9: CertV->Appdata', ['ServerHello', 'EncryptedExtensions', 'Certificate', 'CertificateVerify', 'ApplicationData', 'Finished']),
        ('C9: EmptyCert', ['ServerHello', 'EncryptedExtensions', 'Certificate', 'EmptyCertificateVerify', 'Finished']),


        # C10: CRq cannot appear before EE
        ('C10: CRq before EE', ['ServerHello', 'CertificateRequest', 'EncryptedExtensions', 'Certificate', 'CertificateVerify', 'Finished']),
        ('C10: CRq without EE', ['ServerHello', 'CertificateRequest', 'Certificate', 'CertificateVerify', 'Finished']),

        # C18: KeyShare value must be in valid range (1 < Y < p-1)
        ('C18: KeyShare Y=0 (invalid)', ['ServerHello_FuzzKeyShare_zero', 'EncryptedExtensions', 'Certificate', 'CertificateVerify', 'Finished']),
        ('C18: KeyShare Y=1 (invalid)', ['ServerHello_FuzzKeyShare_one', 'EncryptedExtensions']),
        ('C18: KeyShare Y=p-1 (boundary)', ['ServerHello_FuzzKeyShare_max', 'EncryptedExtensions']),
        ('C18: KeyShare Y>p-1 (out of range)', ['ServerHello_FuzzKeyShare_over_prime', 'EncryptedExtensions']),
        ('C18: KeyShare invalid length', ['ServerHello_FuzzKeyShare_invalid_length', 'EncryptedExtensions']),

        # C20: TLS record boundaries and required extensions
        ('C20: Merged SH+EE in one record', ['ServerHello_MergedWithEE', 'Certificate', 'CertificateVerify', 'Finished']),
        ('C20: Merged SH+EE+Cert in one record', ['ServerHello_MergedWithEE_Cert', 'CertificateVerify', 'Finished']),
        ('C20: Merged SH+EE+Cert+CV+Fin in one record', ['ServerHello_MergedWithEE_Cert_CV_Fin']),
        ('C20: ServerHello no extension', ['ServerHello_NoKeyShare']),
        ('C20: ServerHello missing KeyShare (custom)', ['CustomPacket']),
        ('C20: ServerHello missing KeyShare (custom)', ['CustomPacket']),
    ]

    for scenario_name, message_sequence in test_scenarios:
        listen_sock = None
        client_sock = None
        try:
            listen_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            listen_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listen_sock.bind(('0.0.0.0', port))
            listen_sock.listen(1)
            listen_sock.settimeout(10)

            client_sock, client_addr = listen_sock.accept()
            results.append(f"{scenario_name}: Client connected from {client_addr}")
            print("++++++++++++++++++++++++++  ",scenario_name,"  ++++++++++++++++++++++++++")

            server = TLSServerWithAlphabet(client_sock, cert_file=str(certs['cert']),
                                          key_file=str(certs['key']), version=(3, 4))
            server.run_handshake_loop(message_sequence)

            if 'baseline' in scenario_name:
                results.append(f"{scenario_name}: Success (valid case)")
            else:
                results.append(f"{scenario_name}: Unexpected success")

        except socket.timeout:
            results.append(f"{scenario_name}: Timeout waiting for client")
        except Exception as e:
            results.append(f"{scenario_name}: Expected failure - {type(e).__name__}")
        finally:
            if client_sock:
                client_sock.close()
            if listen_sock:
                listen_sock.close()

    return "\n".join(results)