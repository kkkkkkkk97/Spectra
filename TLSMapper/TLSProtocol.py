from tlslite.constants import *

class TLSProtocol:
    VALID_IMPLEMENTATIONS = {'Manual', 'OpenSSL', 'WolfSSL', 'MatrixSSL', 'GnuTLS', 'mbedTLS', 'BoringSSL'}
    def __init__(self, version, cipher_suite, implementation, verify, target=("127.0.0.1",4433),fuzz_tls=(False,None), imp_ver='None'):
        """
        Initialize a TLSProtocol instance with version, cipher_suite, and implementation.
        
        :param version: TLS version (e.g., 'TLS 1.2', 'TLS 1.3')
        :param cipher_suite: Cipher suite being used (e.g., 'AES256-GCM-SHA384')
        :param implementation: TLS library or implementation (e.g., 'OpenSSL', 'BoringSSL')
        """
        if implementation not in self.VALID_IMPLEMENTATIONS:
            raise ValueError(f"Invalid implementation: {implementation}. Must be one of {self.VALID_IMPLEMENTATIONS}")
        if implementation == 'BoringSSL':
            self.pre_set_extensions=[[(3,4),(3,3)],[GroupName.x25519,GroupName.secp256r1],[(6,1),(5,1),(4,1),(6,3),(5,3),(4,3)]] # [versions,groups,sig_algs]
        else:
            self.pre_set_extensions=None

                                                  
        self.version = version
        self.cipher_suite = cipher_suite
        self.implementation = implementation
        self.imp_ver = imp_ver
        self.prf_name = 'sha384' if cipher_suite[0] in CipherSuite.sha384PrfSuites else 'sha256'
        self.prf_size = 48 if cipher_suite[0] in CipherSuite.sha384PrfSuites else 32
        self.verify = verify
        self.SendClientHello = False        
        self.SendClientCert = False
        self.SendClientCertVerify = False
        self.SendClientKeyExchange = False
        self.SendClientFinish = False
        self.getServerHello = False
        self.getServerCert = False
        self.getServerCertVerify = False
        self.getServerFinish = False
        self.SendEarlyData = False
        self.SendEndofEarlyData = False
        self.another_change = False
        self.fuzz_tls = fuzz_tls
        self.not_enc = False
        self.target = target

    def reset(self):
        """Reset all protocol state flags to initial False values."""
        self.SendClientHello = False
        self.SendClientCert = False
        self.SendClientCertVerify = False
        self.SendClientKeyExchange = False
        self.SendClientFinish = False
        self.getServerHello = False
        self.getServerCert = False
        self.getServerCertVerify = False
        self.getServerFinish = False
        self.SendEarlyData = False
        self.SendEndofEarlyData = False
            

        # self.fuzz_log = log


    def get_info(self):
        """
        Returns a summary of the TLS protocol information.
        
        :return: A dictionary with version, cipher_suite, and implementation details.
        """
        return {
            "version": self.version,
            "cipher_suite": self.cipher_suite,
            "implementation": self.implementation
        }

    def is_secure(self):
        """
        Determines if the current TLS configuration is considered secure based on version and cipher suite.
        
        :return: Boolean value indicating if the configuration is secure.
        """
        # Example conditions for a secure setup
        secure_versions = ['TLS 1.2', 'TLS 1.3']
        secure_cipher_suites = ['AES256-GCM-SHA384', 'CHACHA20-POLY1305']

        if self.version in secure_versions and self.cipher_suite in secure_cipher_suites:
            return True
        return False
    
    def has_to_change_read(self):
        if self.not_enc == True:
            return False
        # print(self.SendClientHello,self.SendClientCert,self.SendClientCertVerify,self.another_change)
        if self.implementation == 'mbedTLS' and self.verify == True and self.another_change == False:
            if self.SendClientHello == True and self.SendClientCert == True and self.SendClientCertVerify == True:
                return True
            else:
                self.another_change = True
                return False
        elif self.implementation == 'mbedTLS' and self.verify == True and self.another_change == True:
            if self.SendClientHello == True and self.SendClientCert == True and self.SendClientCertVerify == True:
                return True
            
        elif self.implementation == 'mbedTLS' and self.verify == False:
            return True
        elif self.implementation != 'mbedTLS':
            return True
        # return True
    
    def has_to_change_write(self):
        if self.not_enc == True:
            return False

        # print(self.SendClientHello,self.SendClientCert,self.SendClientCertVerify)
        if self.implementation == 'mbedTLS' and self.verify == True:
            if self.SendClientHello == True and self.SendClientCert == True and self.SendClientCertVerify == True:
                return True
            else:
                return False
        elif self.implementation == 'mbedTLS' and self.verify == False:
            return True
        elif self.implementation != 'mbedTLS':
            return True
        # return True
    

    def changemessagestate(self,symbol):
        
        if symbol == 'ClientHelloDHE':
            self.SendClientHello = True
            
        elif symbol == 'ClientHelloRSA':
            self.SendClientHello = True

        elif symbol == 'ClientHello':
            self.SendClientHello = True
            
        elif symbol == 'ClientKeyExchange':
            self.SendClientKeyExchange = True

        # elif symbol == 'ChangeCipherSpec':
            # message = self.generateChangeCipherSpec()            
        elif symbol == 'Certificate':
            self.SendClientCert = True
        elif symbol == 'EmptyCertificate':
            self.SendClientCert = True
        elif symbol == 'CertificateVerify':
            self.SendClientCertVerify = True

        elif symbol == 'Finish':
            self.SendClientFinish = True


class TLSEnum(object):
    """Base class for different enums of TLS IDs"""

    @classmethod
    def _recursiveVars(cls, klass):
        """Call vars recursively on base classes"""
        fields = dict()
        for basecls in klass.__bases__:
            fields.update(cls._recursiveVars(basecls))
        fields.update(dict(vars(klass)))
        return fields

    @classmethod
    def toRepr(cls, value, blacklist=None):
        """
        Convert numeric type to string representation

        name if found, None otherwise
        """
        fields = cls._recursiveVars(cls)
        if blacklist is None:
            blacklist = []
        return next((key for key, val in fields.items() \
                    if key not in ('__weakref__', '__dict__', '__doc__',
                                   '__module__') and \
                       key not in blacklist and \
                        val == value), None)

    @classmethod
    def toStr(cls, value, blacklist=None):
        """Convert numeric type to human-readable string if possible"""
        ret = cls.toRepr(value, blacklist)
        if ret is not None:
            return ret
        else:
            return '{0}'.format(value)


class GroupName(TLSEnum):
    """Name of groups supported for (EC)DH key exchange"""

    # RFC4492
    sect163k1 = 1
    sect163r1 = 2
    sect163r2 = 3
    sect193r1 = 4
    sect193r2 = 5
    sect233k1 = 6
    sect233r1 = 7
    sect239k1 = 8
    sect283k1 = 9
    sect283r1 = 10
    sect409k1 = 11
    sect409r1 = 12
    sect571k1 = 13
    sect571r1 = 14
    secp160k1 = 15
    secp160r1 = 16
    secp160r2 = 17
    secp192k1 = 18
    secp192r1 = 19
    secp224k1 = 20
    secp224r1 = 21
    secp256k1 = 22
    secp256r1 = 23
    secp384r1 = 24
    secp521r1 = 25
    allEC = list(range(1, 26))

    # RFC7027
    brainpoolP256r1 = 26
    brainpoolP384r1 = 27
    brainpoolP512r1 = 28
    allEC.extend(list(range(26, 29)))

    # draft-ietf-tls-rfc4492bis
    x25519 = 29
    x448 = 30
    allEC.extend(list(range(29, 31)))

    # RFC7919
    ffdhe2048 = 256
    ffdhe3072 = 257
    ffdhe4096 = 258
    ffdhe6144 = 259
    ffdhe8192 = 260
    allFF = list(range(256, 261))

    all = allEC + allFF

    @classmethod
    def toRepr(cls, value, blacklist=None):
        """Convert numeric type to name representation"""
        if blacklist is None:
            blacklist = []
        blacklist += ['all', 'allEC', 'allFF']
        return super(GroupName, cls).toRepr(value, blacklist)


# groups forbidden by RFC 8446 section B.3.1.4
TLS_1_3_FORBIDDEN_GROUPS = frozenset().union(
    range(1, 0x17),
    range(0x1A, 0x1D),
    (0xff01, 0xff02))

