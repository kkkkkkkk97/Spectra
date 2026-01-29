"""
Client-mode property tests for TLS 1.3 security properties

These tests send malicious client messages to TLS servers to verify
that servers correctly reject invalid message sequences.
"""

from TLSMapper.TLSSUT import TLSSUT
from TLSMapper.TLSProtocol import TLSProtocol
from tlslite.constants import CipherSuite
from .test_registry import registry

# Standard cipher suites for TLS 1.3
CIPHER_SUITES = [
    CipherSuite.TLS_AES_128_GCM_SHA256,
    CipherSuite.TLS_AES_256_GCM_SHA384,
    CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
    CipherSuite.TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
    CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
]


@registry.register('C1', mode='client')
def test_property_C1(target_config, config):
    """
    C1: Initial message must be ClientHello
    Test: Send non-ClientHello messages as first message
    Expected: Server should reject all non-ClientHello starts
    """
    # Get certificates (use target-specific certs if available)
    certs = config.get_client_certs(target_config)

    # Create TLS protocol instance for target
    tlsimp = TLSProtocol(
        version=(3, 4),
        cipher_suite=CIPHER_SUITES,
        implementation=target_config['name'],
        target=(target_config['host'], target_config['port']),
        verify=True,
        fuzz_tls=(False, None, None),
        imp_ver=target_config['version']
    )

    # Create SUT
    sul = TLSSUT(
        keyfile=str(certs['key']),
        certfile=str(certs['cert']),
        TLSpro=tlsimp
    )

    results = []
    test_cases = [
        ('ChangeCipherSpec start', ['ChangeCipherSpec']),
        ('Certificate start', ['Certificate']),
        ('CertificateVerify start', ['CertificateVerify']),
        ('Finish start', ['Finish']),
        ('ApplicationData start', ['ApplicationData'])
    ]

    for name, alphabet in test_cases:
        try:
            response = sul.query(alphabet)
            results.append(f"{name}: {response}")
        except Exception as e:
            results.append(f"{name}: ERROR - {e}")

    return "\n".join(results)


@registry.register('C4', mode='client')
def test_property_C4(target_config, config):
    """
    C4: HRR must be followed by ClientHello
    Test: Send other messages after HRR instead of ClientHello
    Expected: Server should reject non-ClientHello after HRR
    """
    certs = config.get_client_certs(target_config)

    tlsimp = TLSProtocol(
        version=(3, 4),
        cipher_suite=CIPHER_SUITES,
        implementation=target_config['name'],
        target=(target_config['host'], target_config['port']),
        verify=True,
        fuzz_tls=(False, None, None),
        imp_ver=target_config['version']
    )

    sul = TLSSUT(
        keyfile=str(certs['key']),
        certfile=str(certs['cert']),
        TLSpro=tlsimp
    )

    results = []
    test_cases = [
        ('CHEmptyKeyShare -> CHEmptyKeyShare', ['ClientHelloEmtyKeyShare', 'ClientHelloEmtyKeyShare']),
        ('CHEmptyKeyShare -> ChangeCipherSpec', ['ClientHelloEmtyKeyShare', 'ChangeCipherSpec']),
        ('CHEmptyKeyShare -> Certificate', ['ClientHelloEmtyKeyShare', 'Certificate'])
    ]

    for name, alphabet in test_cases:
        try:
            response = sul.query(alphabet)
            results.append(f"{name}: {response}")
        except Exception as e:
            results.append(f"{name}: ERROR - {e}")

    return "\n".join(results)


@registry.register('C11', mode='client')
def test_property_C11(target_config, config):
    """
    C11: CCert must be immediately followed by CCV
    Test: Insert other messages between Certificate and CertificateVerify
    Expected: Server should reject Certificate not followed by CertificateVerify
    """
    certs = config.get_client_certs(target_config)

    tlsimp = TLSProtocol(
        version=(3, 4),
        cipher_suite=CIPHER_SUITES,
        implementation=target_config['name'],
        target=(target_config['host'], target_config['port']),
        verify=True,
        fuzz_tls=(False, None, None),
        imp_ver=target_config['version']
    )

    sul = TLSSUT(
        keyfile=str(certs['key']),
        certfile=str(certs['cert']),
        TLSpro=tlsimp
    )

    results = []
    test_cases = [
        ('Cert->CCS->CV->Finish', ['ClientHello', 'Certificate', 'ChangeCipherSpec', 'CertificateVerify', 'Finish']),
        ('Cert->Finish', ['ClientHello', 'Certificate', 'Finish']),
        ('Cert->Cert->Finish', ['ClientHello', 'Certificate', 'Certificate', 'Finish']),
        ('EmptyCert->ErrCV->Finish', ['ClientHello', 'EmptyCertificate', 'ErrorCertificateVerify', 'Finish']),
        ('Cert->ErrCV->Finish', ['ClientHello', 'Certificate', 'ErrorCertificateVerify', 'Finish']),
        ('Cert->CCS->Finish', ['ClientHello', 'Certificate', 'ChangeCipherSpec', 'Finish']),
        ('EmptyCert->CV->Finish', ['ClientHello', 'EmptyCertificate', 'CertificateVerify', 'Finish']),
        ('EmptyCert->CV->Finish', ['ClientHello', 'EmptyCertificate', 'ErrorCertificateVerify', 'Finish']),
        ('EmptyCert->Finish->CV', ['ClientHello', 'Certificate', 'Finish', 'CertificateVerify']),

    ]

    for name, alphabet in test_cases:
        try:
            response = sul.query(alphabet)
            results.append(f"{name}: {response}")
        except Exception as e:
            results.append(f"{name}: ERROR - {e}")

    return "\n".join(results)


@registry.register('C12', mode='client')
def test_property_C12(target_config, config):
    """
    C12: CCV must be immediately followed by CF
    Test: Insert other messages between CertificateVerify and Finish
    Expected: Server should reject CertificateVerify not followed by Finish
    """
    certs = config.get_client_certs(target_config)

    tlsimp = TLSProtocol(
        version=(3, 4),
        cipher_suite=CIPHER_SUITES,
        implementation=target_config['name'],
        target=(target_config['host'], target_config['port']),
        verify=True,
        fuzz_tls=(False, None, None),
        imp_ver=target_config['version']
    )

    sul = TLSSUT(
        keyfile=str(certs['key']),
        certfile=str(certs['cert']),
        TLSpro=tlsimp
    )

    results = []
    test_cases = [
        ('CertV->CCS->Finish', ['ClientHello', 'Certificate', 'CertificateVerify', 'ChangeCipherSpec', 'Finish']),
        ('CertV->Cert->Finish', ['ClientHello', 'Certificate', 'CertificateVerify', 'Certificate', 'Finish']),
        ('CertV->EmptyCert->Finish', ['ClientHello', 'Certificate', 'CertificateVerify', 'EmptyCertificate', 'Finish']),

    ]

    for name, alphabet in test_cases:
        try:
            response = sul.query(alphabet)
            results.append(f"{name}: {response}")
        except Exception as e:
            results.append(f"{name}: ERROR - {e}")

    return "\n".join(results)


@registry.register('C13', mode='client')
def test_property_C13(target_config, config):
    """
    C13: If CRq sent, must have CCert
    Test: Skip Certificate when CertificateRequest received
    Expected: Server should reject missing client certificate
    Note: Requires server configured to request client certificate
    """
    certs = config.get_client_certs(target_config)

    tlsimp = TLSProtocol(
        version=(3, 4),
        cipher_suite=CIPHER_SUITES,
        implementation=target_config['name'],
        target=(target_config['host'], target_config['port']),
        verify=True,
        fuzz_tls=(False, None, None),
        imp_ver=target_config['version']
    )

    sul = TLSSUT(
        keyfile=str(certs['key']),
        certfile=str(certs['cert']),
        TLSpro=tlsimp
    )

    results = []
    test_cases = [
        ('ClientHello->Finish (no cert)', ['ClientHello', 'Finish']),
        ('ClientHello->empty cert->Finish (empty cert)', ['ClientHello', 'EmptyCertificate', 'Finish']),
        ('ClientHello->error cert->Finish (error cert)', ['ClientHello', 'ErrorCertificate', 'Finish']),
    ]

    for name, alphabet in test_cases:
        try:
            response = sul.query(alphabet)
            results.append(f"{name}: {response}")
        except Exception as e:
            results.append(f"{name}: ERROR - {e}")

    return "\n".join(results)


@registry.register('C16', mode='client')
def test_property_C16(target_config, config):
    """
    C16: Application data must be after Finished
    Test: Send ApplicationData before Finished
    Expected: Server should reject ApplicationData before Finished
    """
    certs = config.get_client_certs(target_config)

    tlsimp = TLSProtocol(
        version=(3, 4),
        cipher_suite=CIPHER_SUITES,
        implementation=target_config['name'],
        target=(target_config['host'], target_config['port']),
        verify=True,
        fuzz_tls=(False, None, None),
        imp_ver=target_config['version']
    )

    sul = TLSSUT(
        keyfile=str(certs['key']),
        certfile=str(certs['cert']),
        TLSpro=tlsimp
    )

    results = []
    test_cases = [
        ('CH->AppData', ['ClientHello', 'ApplicationData']),
        ('CH->Cert->AppData', ['ClientHello', 'Certificate', 'ApplicationData']),
        ('CH->Cert->CertV->AppData', ['ClientHello', 'Certificate', 'CertificateVerify', 'ApplicationData'])
    ]

    for name, alphabet in test_cases:
        try:
            response = sul.query(alphabet)
            results.append(f"{name}: {response}")
        except Exception as e:
            results.append(f"{name}: ERROR - {e}")

    return "\n".join(results)


@registry.register('C17', mode='client')
def test_property_C17(target_config, config):
    """
    C17: ClientHello.legacy_version must be 0x0303
    Test: Send ClientHello with incorrect legacy_version
    Expected: Server should reject incorrect legacy_version
    """
    certs = config.get_client_certs(target_config)

    tlsimp = TLSProtocol(
        version=(3, 4),
        cipher_suite=CIPHER_SUITES,
        implementation=target_config['name'],
        target=(target_config['host'], target_config['port']),
        verify=True,
        fuzz_tls=(False, None, None),
        imp_ver=target_config['version']
    )

    sul = TLSSUT(
        keyfile=str(certs['key']),
        certfile=str(certs['cert']),
        TLSpro=tlsimp
    )

    results = []
    test_cases = [
        ('Wrong legacy_version (3,2)', ['fuzz_ClientHello_version'])
    ]

    for name, alphabet in test_cases:
        try:
            response = sul.query(alphabet)
            results.append(f"{name}: {response}")
        except Exception as e:
            results.append(f"{name}: ERROR - {e}")

    return "\n".join(results)


@registry.register('C18', mode='client')
def test_property_C18(target_config, config):
    """
    C18: ClientHello.KeyShareY must be in valid range: 1 < Y < p-1
    Test: Send ClientHello with invalid KeyShare values for all 5 groups
    Expected: Server should reject invalid KeyShare (Y=0, Y=1, Y=p-1, Y>p-1)

    Tests all combinations:
    - 5 elliptic curve groups: secp256r1, secp384r1, secp521r1, x25519, x448
    - 5 fuzz types: zero, one, max, over, invalid_len
    - Total: 25 test cases
    """
    certs = config.get_client_certs(target_config)

    tlsimp = TLSProtocol(
        version=(3, 4),
        cipher_suite=CIPHER_SUITES,
        implementation=target_config['name'],
        target=(target_config['host'], target_config['port']),
        verify=True,
        fuzz_tls=(False, None, None),
        imp_ver=target_config['version']
    )

    sul = TLSSUT(
        keyfile=str(certs['key']),
        certfile=str(certs['cert']),
        TLSpro=tlsimp
    )

    results = []

    # Test all 5 groups × 5 fuzz types = 25 cases
    groups = ['secp256r1', 'secp384r1', 'secp521r1', 'x25519', 'x448']
    fuzz_types = [
        ('zero', 'Y=0 (all zeros)'),
        ('one', 'Y=1 (minimum)'),
        ('max', 'Y=p-1 (maximum)'),
        ('over', 'Y>p-1 (overflow)'),
        ('invalid', 'invalid length')
    ]

    for group in groups:
        for fuzz_short, fuzz_desc in fuzz_types:
            symbol = f'fuzz_ClientHello_keyshare_{fuzz_short}_{group}'
            test_name = f'{group:12s} {fuzz_desc:20s}'

            try:
                response = sul.query([symbol])
                results.append(f"{test_name}: {response}")
            except Exception as e:
                results.append(f"{test_name}: ERROR - {e}")
    
    response = sul.query(['fuzz_empty_keyshare_zero'])
    results.append(f"{'fuzz_empty_keyshare_zero'}: {response}")
    return "\n".join(results)


@registry.register('C18_ZERO_ALL', mode='client')
def test_property_C18_zero_all(target_config, config):
    """
    C18_zero_all: ClientHello.KeyShare Y=0 测试（所有群组）
    Test: Send ClientHello with Y=0 KeyShare values for all 8 groups
    Expected: Server should reject all invalid KeyShare (Y=0)

    Tests all 8 groups with fuzz_type='zero':
    - secp256r1, secp384r1, secp521r1 (Weierstrass curves)
    - x25519, x448 (Montgomery curves)
    - ffdhe2048, ffdhe3072, ffdhe4096 (FFDH groups)
    """
    certs = config.get_client_certs(target_config)

    tlsimp = TLSProtocol(
        version=(3, 4),
        cipher_suite=CIPHER_SUITES,
        implementation=target_config['name'],
        target=(target_config['host'], target_config['port']),
        verify=True,
        fuzz_tls=(False, None, None),
        imp_ver=target_config['version']
    )

    sul = TLSSUT(
        keyfile=str(certs['key']),
        certfile=str(certs['cert']),
        TLSpro=tlsimp
    )

    results = []

    # 测试所有 8 个群组的 zero 类型
    groups = [
        'secp256r1',
        'secp384r1',
        'secp521r1',
        'x25519',
        'x448',
        'ffdhe2048',
        'ffdhe3072',
        'ffdhe4096'
    ]

    for group in groups:
        symbol = f'fuzz_ClientHello_keyshare_zero_{group}'
        test_name = f'{group:12s} Y=0 (all zeros)'

        try:
            response = sul.query([symbol])
            results.append(f"{test_name}: {response}")
        except Exception as e:
            results.append(f"{test_name}: ERROR - {e}")

    return "\n".join(results)


@registry.register('C19', mode='client')
def test_property_C19(target_config, config):
    """
    C19: ClientHello.compression_methods must be [0]
    Test: Send ClientHello with non-null compression
    Expected: Server should reject non-null compression
    """
    certs = config.get_client_certs(target_config)

    tlsimp = TLSProtocol(
        version=(3, 4),
        cipher_suite=CIPHER_SUITES,
        implementation=target_config['name'],
        target=(target_config['host'], target_config['port']),
        verify=True,
        fuzz_tls=(False, None, None),
        imp_ver=target_config['version']
    )

    sul = TLSSUT(
        keyfile=str(certs['key']),
        certfile=str(certs['cert']),
        TLSpro=tlsimp
    )

    results = []
    test_cases = [
        ('compression_methods=[1]', ['fuzz_ClientHello_comp'])
    ]

    for name, alphabet in test_cases:
        try:
            response = sul.query(alphabet)
            results.append(f"{name}: {response}")
        except Exception as e:
            results.append(f"{name}: ERROR - {e}")

    return "\n".join(results)



@registry.register("C20", mode="client")
def test_property_C20(target_config, config):
    """
    C20: Key messages must be sent on record boundaries
    Test: Send ClientHello merged with other messages in same TLS record
    Expected: Server should reject merged records
    """
    certs = config.get_client_certs(target_config)

    tlsimp = TLSProtocol(
        version=(3, 4),
        cipher_suite=CIPHER_SUITES,
        implementation=target_config["name"],
        target=(target_config["host"], target_config["port"]),
        verify=True,
        fuzz_tls=(False, None, None),
        imp_ver=target_config["version"]
    )

    sul = TLSSUT(
        keyfile=str(certs["key"]),
        certfile=str(certs["cert"]),
        TLSpro=tlsimp
    )

    results = []
    test_cases = [
        # ("ClientHello+Finished merged", ["ClientHello+Finished"]),
        ("ClientHello+Certificate merged", ["ClientHello+Certificate","CertificateVerify"]),
        # ("Normal ClientHello", ["ClientHello"]),  # Control - should succeed
    ]

    for name, alphabet in test_cases:
        try:
            response = sul.query(alphabet)
            results.append(f"{name}: {response}")
        except Exception as e:
            results.append(f"{name}: ERROR - {e}")

    return "\n".join(results)

@registry.register("AP", mode="client")
def test_property_All(target_config, config):
    """
    All properties test - comprehensive TLS 1.3 client-side protocol violation testing
    """
    certs = config.get_client_certs(target_config)

    tlsimp = TLSProtocol(
        version=(3, 4),
        cipher_suite=CIPHER_SUITES,
        implementation=target_config["name"],
        target=(target_config["host"], target_config["port"]),
        verify=True,
        fuzz_tls=(False, None, None),
        imp_ver=target_config["version"]
    )

    sul = TLSSUT(
        keyfile=str(certs["key"]),
        certfile=str(certs["cert"]),
        TLSpro=tlsimp
    )

    results = []
    test_cases = [
        # Baseline - Valid handshake
        ('Baseline: Valid handshake', ['ClientHello', 'Certificate', 'CertificateVerify', 'Finish']),

        # C1: Initial message must be ClientHello
        ('C1: ChangeCipherSpec start', ['ChangeCipherSpec']),
        ('C1: Certificate start', ['Certificate']),
        ('C1: CertificateVerify start', ['CertificateVerify']),
        ('C1: Finish start', ['Finish']),
        ('C1: ApplicationData start', ['ApplicationData']),

        # C4: HRR must be followed by ClientHello
        ('C4: CHEmptyKeyShare -> CHEmptyKeyShare', ['ClientHelloEmtyKeyShare', 'ClientHelloEmtyKeyShare']),
        ('C4: CHEmptyKeyShare -> ChangeCipherSpec', ['ClientHelloEmtyKeyShare', 'ChangeCipherSpec']),
        ('C4: CHEmptyKeyShare -> Certificate', ['ClientHelloEmtyKeyShare', 'Certificate']),

        # C11: CCert must be immediately followed by CCV
        ('C11: Cert->CCS->CV->Finish', ['ClientHello', 'Certificate', 'ChangeCipherSpec', 'CertificateVerify', 'Finish']),
        ('C11: Cert->Finish', ['ClientHello', 'Certificate', 'Finish']),
        ('C11: Cert->Cert->Finish', ['ClientHello', 'Certificate', 'Certificate', 'Finish']),
        ('C11: EmptyCert->ErrCV->Finish', ['ClientHello', 'EmptyCertificate', 'ErrorCertificateVerify', 'Finish']),
        ('C11: Cert->ErrCV->Finish', ['ClientHello', 'Certificate', 'ErrorCertificateVerify', 'Finish']),
        ('C11: Cert->CCS->Finish', ['ClientHello', 'Certificate', 'ChangeCipherSpec', 'Finish']),
        ('C11: EmptyCert->CV->Finish', ['ClientHello', 'EmptyCertificate', 'CertificateVerify', 'Finish']),
        ('C11: EmptyCert->ErrCV->Finish', ['ClientHello', 'EmptyCertificate', 'ErrorCertificateVerify', 'Finish']),
        ('C11: Cert->Finish->CV', ['ClientHello', 'Certificate', 'Finish', 'CertificateVerify']),

        # C12: CCV must be immediately followed by CF
        ('C12: CertV->CCS->Finish', ['ClientHello', 'Certificate', 'EmptyCertificateVerify', 'ChangeCipherSpec', 'Finish']),
        ('C12: CertV->Cert->Finish', ['ClientHello', 'Certificate', 'CertificateVerify', 'Certificate', 'Finish']),
        ('C12: CertV->EmptyCert->Finish', ['ClientHello', 'Certificate', 'CertificateVerify', 'EmptyCertificate', 'Finish']),

        # C13: If CRq sent, must have CCert
        ('C13: ClientHello->Finish (no cert)', ['ClientHello', 'Finish']),
        ('C13: ClientHello->EmptyCert->Finish', ['ClientHello', 'EmptyCertificate', 'Finish']),
        ('C13: ClientHello->ErrorCert->Finish', ['ClientHello', 'ErrorCertificate', 'Finish']),

        # C16: Application data must be after Finished
        ('C16: CH->AppData', ['ClientHello', 'ApplicationData']),
        ('C16: CH->Cert->AppData', ['ClientHello', 'Certificate', 'ApplicationData']),
        ('C16: CH->Cert->CertV->AppData', ['ClientHello', 'Certificate', 'CertificateVerify', 'ApplicationData']),

        # C17: ClientHello.legacy_version must be 0x0303
        ('C17: Wrong legacy_version (3,2)', ['fuzz_ClientHello_version']),

        # C18: KeyShare value must be in valid range (1 < Y < p-1)
        # Test subset of critical cases (not all 25 combinations to avoid excessive test time)
        ('C18: secp256r1 Y=0', ['fuzz_ClientHello_keyshare_zero_secp256r1']),
        ('C18: secp256r1 Y=1', ['fuzz_ClientHello_keyshare_one_secp256r1']),
        ('C18: secp256r1 Y=p-1', ['fuzz_ClientHello_keyshare_max_secp256r1']),
        ('C18: secp256r1 Y>p-1', ['fuzz_ClientHello_keyshare_over_secp256r1']),
        ('C18: x25519 Y=0', ['fuzz_ClientHello_keyshare_zero_x25519']),
        ('C18: x25519 Y=1', ['fuzz_ClientHello_keyshare_one_x25519']),
        ('C18: x25519 Y=p-1', ['fuzz_ClientHello_keyshare_max_x25519']),
        ('C18: x25519 Y>p-1', ['fuzz_ClientHello_keyshare_over_x25519']),
        ('C18: empty keyshare', ['fuzz_empty_keyshare_zero']),

        # C19: ClientHello.compression_methods must be [0]
        ('C19: compression_methods=[1]', ['fuzz_ClientHello_comp']),

        # C20: Key messages must be sent on record boundaries
        ('C20: ClientHello+Certificate merged', ['ClientHello+Certificate', 'CertificateVerify']),
    ]

    for name, alphabet in test_cases:
        try:
            response = sul.query(alphabet)
            results.append(f"{name}: {response}")
        except Exception as e:
            results.append(f"{name}: ERROR - {e}")

    return "\n".join(results)

