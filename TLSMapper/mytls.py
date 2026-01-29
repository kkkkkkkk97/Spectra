from __future__ import print_function
import sys
import os
import os.path
import socket
import struct
import getopt
import binascii
import copy

from http import client as httplib
from socketserver import *
from http.server import *
from http.server import SimpleHTTPRequestHandler
from tlslite.api import *
from tlslite.utils.compat import formatExceptionTrace
from tlslite.tlsrecordlayer import TLSRecordLayer
from tlslite.session import Session
from tlslite.constants import *
from tlslite.utils.cryptomath import derive_secret, getRandomBytes, HKDF_expand_label
from tlslite.utils.dns_utils import is_valid_hostname
from tlslite.utils.lists import getFirstMatching
from tlslite.errors import *
from tlslite.messages import *
from tlslite.mathtls import *
from tlslite.handshakesettings import HandshakeSettings, KNOWN_VERSIONS, CURVE_ALIASES
from tlslite.handshakehashes import HandshakeHashes
from tlslite.utils.tackwrapper import *
from tlslite.utils.deprecations import deprecated_params
from tlslite.keyexchange import KeyExchange, RSAKeyExchange, DHE_RSAKeyExchange, \
        ECDHE_RSAKeyExchange, SRPKeyExchange, ADHKeyExchange, \
        AECDHKeyExchange, FFDHKeyExchange, ECDHKeyExchange
from tlslite.handshakehelpers import HandshakeHelpers
from tlslite.utils.cipherfactory import createAESCCM, createAESCCM_8, \
        createAESGCM, createCHACHA20
from TLSMapper.helpers import SIG_ALL, RSA_SIG_ALL, AutoEmptyExtension
from tlslite.extensions import TLSExtension, RenegotiationInfoExtension, \
        ClientKeyShareExtension, StatusRequestExtension
from TLSMapper.TLSFuzzer import *
from TLSMapper.random_fuzz import *
import xml.etree.ElementTree as ET
import xml.dom.minidom
from datetime import datetime

class TLSClient(TLSRecordLayer):
    
    def __init__(self, sock, ciphersuites=None, privateKey=None, cert_chain=None, old_session=None, tlspro = None, target = ('127.0.0.1',4433)):
        TLSRecordLayer.__init__(self, sock)
        '''
        Built in a state machine
        '''
        self.target_ip = target[0]
        self.target_port = target[1]
        self.serverSigAlg = None
        self.ecdhCurve = None
        self.dhGroupSize = None
        self.extendedMasterSecret = False
        self._clientRandom = bytearray(0)
        self._serverRandom = bytearray(0)
        self.session_id = bytearray(0)
        self.next_proto = None
        self._ccs_sent = False
        self._peer_record_size_limit = None
        self._pha_supported = False
        self.sig_scheme_alg = None
        self.support_version = tlspro.version if tlspro.version is not None else (3,3)
        self.version= tlspro.version if tlspro.version is not None else (3,3)
        self.tlspro = tlspro
        # self.CH = ClientHello() #client_hello
        # self.SH = ServerHello() #server_hello
        self.CH = None #client_hello
        self.SH = None #server_hello
        self.SC = None #server_certificate
        self.SKE = None #server_key_exchange
        self.CR = None #cert_request
        self.CT = None


        self._cipherSuite = None
        self.ciphersuites = tlspro.cipher_suite
        # self.SH.cipher_suite = ciphersuites[0]

        # For key calculation
        self.premasterSecret = bytearray(0)
        self.masterSecret = bytearray(0)
        self.client_verify_data = bytearray(0)
        self.server_verify_data = bytearray(0)
        # self.prf_name = 'sha256'
        # self.prf_size = 32
        self.prf_name = tlspro.prf_name
        self.prf_size = tlspro.prf_size
        self.early_secret = bytearray(self.prf_size)
        self.handshake_secret = bytearray(self.prf_size)
        self.master_secret = bytearray(self.prf_size)
        self.sr_handshake_traffic_secret = bytearray(self.prf_size)
        self.cl_handshake_traffic_secret = bytearray(self.prf_size)
        self.exporter_master_secret = None
        self.resumption_master_secret = None
        self.cl_app_traffic = bytearray(self.prf_size)
        self.sr_app_traffic = bytearray(self.prf_size)
        self.server_finish_hs = None

        # for ext
        self.psk_only = False
        self.pre_set_extensions = None
        self.extensions = None
        self.settings = None
        self.privateKey = privateKey
        self.cert_chain = cert_chain
        self.error_cert_chain = cert_chain
        self.server_finish_received = False
        self.post_handshake = False
        self.hrr = False
        self.nst = None
        self._ch_hh = None
        self.old_session = old_session
        self.nst_received_time=None
        self.key_log_write = True
        self.key_log_file = './key_log.file'
        self.resuming=False
        self.keyUpdate_not_req = False
        self.change_cipher_debug = False
        self.resume12=False






        # for debug
        self.key_log_write = False
        self.key_log_file = None
        # self.test_handshake_hash = HandshakeHashes()

        # for fuzz
        self.fuzz_flag = tlspro.fuzz_tls[0]
        self.fuzz_log = tlspro.fuzz_tls[1]
        self.fuzz_letter = tlspro.fuzz_tls[2]
        self.RF=None
        self.LOG={'message:':tlspro.fuzz_tls[2],'fuzz_operator:':None,'recieve:':None,'time:':datetime.now().strftime("%Y-%m-%d-%H-%M-%S"),'orign:':None,'packet:':None,"all_recieve:":None}
        self.repeat = False
        self.repeat_message = None
        self.repeat_symbol = None
    #for debug
    def write_key_log(self, key_name, client_random, server_random, key):
        file = open(self.key_log_file, "a")
        strr=key_name+' '+client_random.hex() +' '+ key.hex() +'\n'
        file.write(strr)
        file.close()

    def reset_packet_buffer(self):
        pass
    
    def save_pcap(self, pcap_filename_prefix):
        pass
        
    def save_fuzz_plain(self, filename):
        xml_content = ET.tostring(self.fuzz_contents, encoding='utf-8')
        dom = xml.dom.minidom.parseString(xml_content)
        pretty_xml = dom.toprettyxml()
        with open(filename, 'w') as f:
            f.write(pretty_xml)

    def sendPCKAndRecv(self,pck,letter):
        # if letter == 'ClientHello':
        #     ch=ClientHello()
        #     ch.client_version=(3,4)
        #     # ch.cipher_suites=[]
        #     p = Parser(bytearray(pck[5:]))
        #     clh=ch.parse(p)

        self.sendpck(pck)
        re = self.process_recieve()
        return re

    def sendAndRecv(self, symbol):
        messages=[]

        # if symbol == 'repeat':
        #     symbol = self.repeat_symbol
        #     pck = self.repeat_message
        #     # print(symbol,pck)
        #     for result in self._recordLayer._recordSocket._sockSendAll(pck):
        #         pass

        # elif 'repeat' in symbol:
        #     symbol = symbol[6:]
        #     self.repeat = True
        #     self.repeat_symbol = symbol


        if symbol == 'ClientHelloDHE':
            self.ciphersuites= [CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA]
            message = self.generateClientHello()
            messages.append(message)            
        elif symbol == 'ClientHelloRSA':
            self.ciphersuites= [CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA]
            message = self.generateClientHello()
            messages.append(message)            
        elif symbol == 'ClientHello':
            message = self.generateClientHello()
            messages.append(message)
        elif symbol == 'TLS12ReClientHello1':
            message = self.generateClientHello()
            messages.append(message)
        elif symbol == 'ClientHelloTLS12':
            message = self.generateClientHelloTLS12()
            messages.append(message)
        elif symbol == 'ClientHelloTLS13':
            message = self.generateClientHelloTLS13()  
            messages.append(message)     
        elif symbol == 'ClientKeyExchange':
            message = self.generateClientKeyExchange()
            messages.append(message)
        elif symbol == 'ChangeCipherSpec':
            message = self.generateChangeCipherSpec()  
            messages.append(message)          
        elif symbol == 'Certificate':
            if self.privateKey is None or self.cert_chain is None:
                return 'NoClientCert'
            message = self.generateClientCertificate()
            messages.append(message)
        elif symbol == 'EmptyCertificate':
            message = self.generateEmptyCertificate()
            messages.append(message)
        elif symbol == 'ErrorCertificate':
            # print("!!!!!!!!!!!!!!!!!!!!!")
            message = self.generateErrorCertificate()
            messages.append(message)
            # self.generateErrorCertificate()
            # re = self.process_recieve()
            # return re
        elif symbol == 'ErrorCertificateVerify':
            message = self.generateErrorCertificateVerify()
            messages.append(message)
        elif symbol == 'EmptyCertificateVerify':
            message = self.generateEmptyCertificateVerify()
            messages.append(message)
        elif symbol == 'CertificateVerify':
            if self.privateKey is None or self.cert_chain is None:
                return 'NoClientCert'
            message = self.generateCertificateVerify()
            if not message:
                return 'SigFailed'
            messages.append(message)
            # print(message.write())
        elif symbol == 'Finish':
            message = self.generateClientFinished()
            messages.append(message)
        elif symbol == 'ApplicationData':
            message = self.generateAppData()
            messages.append(message)
        elif symbol == 'ClosureAlert':
            message = self.generateClosureAlert()
            messages.append(message)
        elif symbol == 'ErrorAlert':
            message = self.generateErrorAlert()
            messages.append(message)
        elif symbol == 'CertificateRequest':
            message = self.generateCertificateRequest()
            messages.append(message)
        elif symbol == 'TLS12ReClientHello':
            message = self.TLS12ReClientHello()
            messages.append(message)
        elif symbol == 'ClientHelloEmtyKeyShare':            
            message = self.generateClientHelloEmtyKeyShare()
            messages.append(message)
        elif symbol == 'KeyUpdate':
            message = self.generateKeyUpdate() 
            messages.append(message)
        elif symbol == 'EndOfEarlyData':
            message = self.generateEndOfEarlydata()
            messages.append(message)
            self.tlspro.SendEndofEarlyData = True
        elif symbol == 'ChangeKeyState':
            self.keystatechange()
            message = ''
            messages.append(message)
        elif symbol == 'fuzz_ClientHello':
            # self.sendpck()
            # re = self.process_recieve()
            # return re
            message = self.generatefuzz_ClientHello() 
            messages.append(message)
        elif symbol == 'fuzz_CertVerify':
            self.sendpck1()
            re = self.process_recieve()
            return re
        elif symbol == 'fuzz_ClientHello2':
            self.sendpck2()
            re = self.process_recieve()
            return re
        elif symbol == 'fuzz_ClientHello_version':
            message = self.generateFuzzClientHelloVersion()
            messages.append(message)
        elif symbol == 'fuzz_ClientHello_keyshare':
            # 默认：Y = 0
            message = self.generateFuzzClientHelloKeyShare('zero')
            messages.append(message)
        elif symbol == 'fuzz_ClientHello_keyshare_zero':
            # Y = 0 (全零)
            message = self.generateFuzzClientHelloKeyShare('zero')
            messages.append(message)
        elif symbol == 'fuzz_ClientHello_keyshare_one':
            # Y = 1
            message = self.generateFuzzClientHelloKeyShare('one')
            messages.append(message)
        elif symbol == 'fuzz_ClientHello_keyshare_max':
            # Y = p-1 (最大值)
            message = self.generateFuzzClientHelloKeyShare('max')
            messages.append(message)
        elif symbol == 'fuzz_ClientHello_keyshare_over':
            # Y > p-1 (超出范围)
            message = self.generateFuzzClientHelloKeyShare('over_prime')
            messages.append(message)
        elif symbol == 'fuzz_ClientHello_keyshare_invalid_len':
            # 错误的长度
            message = self.generateFuzzClientHelloKeyShare('invalid_length')
            messages.append(message)

        # C18: 针对特定群组的 KeyShare 测试
        # 格式: fuzz_ClientHello_keyshare_{fuzz_type}_{group}
        # fuzz_type: zero, one, max, over, invalid_len
        # group: secp256r1, secp384r1, secp521r1, x25519, x448
        elif symbol.startswith('fuzz_ClientHello_keyshare_'):
            parts = symbol.split('_')
            if len(parts) >= 5:  # fuzz_ClientHello_keyshare_{fuzz}_{group}
                fuzz_part = parts[3]
                group_name = '_'.join(parts[4:])  # 支持 secp256r1 等

                # 映射 fuzz 类型
                fuzz_map = {
                    'zero': 'zero',
                    'one': 'one',
                    'max': 'max',
                    'over': 'over_prime',
                    'invalid': 'invalid_length'
                }

                # 映射群组名称
                from tlslite.constants import GroupName
                group_map = {
                    'secp256r1': GroupName.secp256r1,
                    'secp384r1': GroupName.secp384r1,
                    'secp521r1': GroupName.secp521r1,
                    'x25519': GroupName.x25519,
                    'x448': GroupName.x448,
                    'ffdhe2048': GroupName.ffdhe2048,
                    'ffdhe3072': GroupName.ffdhe3072,
                    'ffdhe4096': GroupName.ffdhe4096
                }

                fuzz_type = fuzz_map.get(fuzz_part)
                target_group = group_map.get(group_name)

                if fuzz_type and target_group:
                    message = self.generateFuzzClientHelloKeyShare(fuzz_type, target_group)
                    messages.append(message)

        elif symbol == 'fuzz_ClientHello_comp':
            message = self.generateFuzzClientHelloComp()
            messages.append(message)

        # C20: 记录边界测试（客户端模式）
        elif symbol == 'ClientHello+Finished':
            # 合并ClientHello和Finished到同一个TLS记录
            ch = self.generateClientHello()
            # 生成一个虚拟的Finished消息（用于边界测试）
            finished = Finished(self.support_version, 32)  # 假设SHA256
            finished.verify_data = bytearray(32)  # 虚拟数据
            # 将两个消息合并发送
            self._send_merged_client_messages(ch, finished)
            return 'MergedSent'  # 特殊返回值，跳过正常的发送流程

        elif symbol == 'ClientHello+Certificate':
            # 合并ClientHello和Certificate到同一个TLS记录
            ch = self.generateClientHello()
            cert = self.generateClientCertificate() if (self.privateKey and self.cert_chain) else self.generateEmptyCertificate()
            self._send_merged_client_messages(ch, cert)
            # return 'MergedSent'
            # messages.append(ch)
            # messages.append(cert)
            # # self.test_handshake_hash.update(ch.write())
            # self.CH=ch
            # self.CT=cert

            # self._handshake_hash.update(ch.write())

            re = self.process_recieve()
            return re
        elif symbol == 'fuzz_Finished_verifydata':
            message = self.generateFuzzFinishedVerifyData()
            messages.append(message)
        elif symbol =="ResumptionClientHello":
            # self.generateResumptionClientHello()
            try:
                message = self.generateResumptionClientHello()
                messages.append(message)
            except:
                # return "NoSessionBefore"    
                return 'None'
        elif symbol == 'fuzz_empty_keyshare_zero':
            self.fuzz_empty_keyshare_zero()
            re = self.process_recieve()
            return re
        elif symbol =="ResumptionClientHelloAP":
            try:
                message = self.generateResumptionClientHelloAD()
                messages.append(message)
                message = self.generateChangeCipherSpec()
                messages.append(message)
                message = self.generateAppData()
                messages.append(message)         
                message = self.generateEndOfEarlydata()
                messages.append(message)
                # print(messages)
            except:
                return "None"
        else:
            return 'UnSupported'
        if messages[0] == None:
            return 'None'

        

        ed = False
        if symbol == 'TLS12ReClientHello':
            # Check if we have completed the initial handshake
            # Support both TLS 1.2 and TLS 1.3 -> TLS 1.2 downgrade scenarios
            # TLS 1.2 uses self.masterSecret, TLS 1.3 uses self.master_secret
            tls12_handshake_done = (self.masterSecret != bytearray(0))
            tls13_handshake_done = (self.master_secret != bytearray(self.prf_size))
            
            if (self._cipherSuite is None or 
                (not tls12_handshake_done and not tls13_handshake_done) or
                not self.server_finish_received):
                # Cannot perform TLS 1.2 renegotiation without completing initial handshake
                return 'None'
            
            # Use TLS 1.2 master secret if available, otherwise it will be empty for fresh negotiation
            masterSecret = self.masterSecret if tls12_handshake_done else bytearray(0)
            self.tlspro.cipher_suite =  [self._cipherSuite] 
            resuming = self.resume12
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            try:
                sock.connect((self.target_ip,self.target_port))
            except:
                return 'None'
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            try:            
                self.__init__(sock=sock,ciphersuites=[self._cipherSuite], privateKey=self.privateKey, cert_chain=self.cert_chain, old_session=None, tlspro = self.tlspro, target = (self.target_ip,self.target_port)) 
            except:
                return 'None'   
            self.prf_name = 'sha384' if self.ciphersuites[0] in CipherSuite.sha384PrfSuites else 'sha256'
            self.prf_size = 48 if self.ciphersuites[0] in CipherSuite.sha384PrfSuites else 32 
            self.resume12 = resuming
            self.masterSecret = masterSecret
        # or symbol == 'TLS12ReClientHello'  or symbol == 'TLS12ReClientHello1' 
        if symbol == 'ResumptionClientHello' or symbol == 'ResumptionClientHelloAP' and message != None:
            # print("!!!!!!!")
            if self.fuzz_flag == True:
                x=self.fuzz_letter
                fuzz_flag = True
            else:
                x=None
                fuzz_flag = False
            # if self.repeat == True:
            # rp = self.repeat
            # sb = self.repeat_symbol
            log_content=self.LOG
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            try:
                sock.connect((self.target_ip,self.target_port))
            except:
                return 'None'
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            session=[self.resumption_master_secret,self.nst]
            ext = self.extensions
            nst = self.nst
            SH = self.SH
            hrr = self.hrr
            resuming = self.resume12
            masterSecret = self.masterSecret
            self.tlspro.cipher_suite =  [self._cipherSuite]          
            try:            
                self.__init__(sock=sock,ciphersuites=[self._cipherSuite], privateKey=self.privateKey, cert_chain=self.cert_chain, old_session=session, tlspro = self.tlspro, target = (self.target_ip,self.target_port)) 
            except:
                return 'None'
            self.settings=HandshakeSettings().validate()
            self.tlspro.reset()
            if fuzz_flag == True and x != None:
                self.fuzz_letter = x
                self.fuzz_flag = True
                self.LOG=log_content
            self.CH = messages[0]
            self.SH =SH
            self.extensions = ext
            self.nst = nst
            self.prf_name = 'sha384' if self.ciphersuites[0] in CipherSuite.sha384PrfSuites else 'sha256'
            self.prf_size = 48 if self.ciphersuites[0] in CipherSuite.sha384PrfSuites else 32
            # self.repeat = rp
            # self.repeat_symbol = sb
            self._clientRandom = messages[0].random
            self.hrr = hrr
            self.resume12 = resuming
            self.masterSecret = masterSecret
            if symbol == 'ResumptionClientHelloAP':
                clPSK = self.CH.getExtension(ExtensionType.pre_shared_key)
                ident = clPSK.identities[0]
                psk = HandshakeHelpers.calc_res_binder_psk(
                        ident, self.old_session[0],
                        [self.old_session[1]])
                self.early_secret = secureHMAC(bytearray(self.prf_size), psk, self.prf_name)
                ed = True
                self.tlspro.SendEarlyData = True
                self.tlspro.SendEndofEarlyData = True

        # if self.repeat == True:
        #     self.repeat_message = messages
        #     self.repeat = False
        # print(messages)
        try:
            # print(self.fuzz_flag,symbol,self.fuzz_letter)
            if self.fuzz_flag == True and symbol == self.fuzz_letter:
                self.RF=RandomFuzz()
                for result in self._sendMsg(message, SF=self.RF, fuzz_flag=self.fuzz_flag, log_content=self.LOG):
                    pass
            else:
                # print("!!!!!!!!!!!!!")
                for result in self._sendMsgs(messages,ed):
                    pass
                # for result in self._sendMsg(message):
                #     pass

            self.tlspro.changemessagestate(symbol)
        except Exception as e:
            return 'SendFailed'
        # print(self.repeat_message)
        if 'ClientHello' in symbol:
            # print(messages)
            self.CH = messages[0] 
            self._clientRandom = messages[0].random
        if symbol == 'ChangeCipherSpec':
            if self.support_version <= (3,3):
                # if self.tlspro.has_to_change_write():
                self.changestate()
        if symbol == 'Finish':
            if self.support_version >= (3,4):
                # change write state
                if self.tlspro.has_to_change_write():
                    self._changeWriteState()
                # change read state
                if self.tlspro.has_to_change_read():
                    self._changeReadState()
                
            # handshake complete
            if self.server_finish_received:
                self.post_handshake = True
        if symbol =='KeyUpdate':
            if self.SH == None:
                self.SH = ServerHello()
            if self.SH.cipher_suite == None or self.SH.cipher_suite == 0:
                self.SH.cipher_suite = self.tlspro.cipher_suite[0]

            # print(self.keyUpdate_not_req)
            # if self.keyUpdate_not_req == False:
            self.cl_app_traffic,self.sr_app_traffic = self._recordLayer.calcTLS1_3KeyUpdate_reciever(
                        self.SH.cipher_suite,
                        self.cl_app_traffic,
                        self.sr_app_traffic)
            self._recordLayer.calcTLS1_3PendingState(
                self.SH.cipher_suite,
                self.cl_app_traffic,
                self.sr_app_traffic,
                ['python'])
            # self._changeReadState()
            # self._changeWriteState()

            # self._recordLayer.calcTLS1_3KeyUpdate_sender(
            #                 self.SH.cipher_suite,
            #                 self.cl_app_traffic,
            #                 self.sr_app_traffic)

        re = self.process_recieve()
        return re


    def set_extensions(self, versions=None, groups=None, sig_algs=None):
        ext = {}
        
        if self.support_version is None:
            versions = [(3, 4), (3, 3), (3, 2), (3, 1)]
        else:
            versions = [self.support_version]
        ext[ExtensionType.supported_versions] = SupportedVersionsExtension().create(versions)
        # print(groups)
        if groups is None:
            groups = [GroupName.secp256r1]
            # groups=[GroupName.x448]

        ext[ExtensionType.supported_groups] = SupportedGroupsExtension().create(groups)
        if self.support_version >= (3,4):
            key_shares = []
            ext[ExtensionType.key_share] = ClientKeyShareExtension().create(key_shares)
            if self.hrr == False:
                for group in groups:
                    key_shares.append(self._genKeyShareEntry(group, self.support_version))
        
        if sig_algs is None:
            sig_algs = RSA_SIG_ALL
            # sig_algs=[(6, 1), (5, 1), (4, 1)]

        ext[ExtensionType.signature_algorithms] = SignatureAlgorithmsExtension().create(sig_algs)
        ext[ExtensionType.signature_algorithms_cert] = SignatureAlgorithmsCertExtension().create(sig_algs)
        if self.support_version >= (3, 4):
            ext[ExtensionType.server_name]=SNIExtension().create(hostname=bytearray(b'localhost'), hostNames=None, serverNames=None)
            ext[ExtensionType.ec_point_formats] = ECPointFormatsExtension().create([0,1,2])
            # ext[ExtensionType.ec_point_formats] = ECPointFormatsExtension().create(ECPointFormat.all)

            ext[ExtensionType.cert_type] = ClientCertTypeExtension().create([CertificateType.x509])
            ext[ExtensionType.session_ticket]=TLSExtension().create(ExtensionType.session_ticket,bytearray())
            ext[ExtensionType.encrypt_then_mac]=TLSExtension().create(ExtensionType.encrypt_then_mac,bytearray())
            # ext[ExtensionType.extended_master_secret] = TLSExtension().create(ExtensionType.extended_master_secret,bytearray())

            # ext[ExtensionType.supports_npn] = AutoEmptyExtension()
            # # ext[ExtensionType.alpn] = AutoEmptyExtension()
            # ext[ExtensionType.srp] = AutoEmptyExtension()
            # ext[ExtensionType.post_handshake_auth] = AutoEmptyExtension()

            # FOR PSK
            # ext[ExtensionType.psk_key_exchange_modes] = PskKeyExchangeModesExtension().create([PskKeyExchangeMode.psk_ke])
            ext[ExtensionType.psk_key_exchange_modes] = PskKeyExchangeModesExtension().create([PskKeyExchangeMode.psk_dhe_ke, PskKeyExchangeMode.psk_ke])
            
        # ext[ExtensionType.ec_point_formats] = ECPointFormatsExtension().create(ECPointFormat.all)
        # ext[ExtensionType.session_ticket] = AutoEmptyExtension()
        # ext[ExtensionType.encrypt_then_mac] = AutoEmptyExtension()
        # ext[ExtensionType.extended_master_secret] = AutoEmptyExtension()
        # ext[ExtensionType.heartbeat] = HeartbeatExtension().create(
        #     HeartbeatMode.PEER_ALLOWED_TO_SEND)

        # ext[ExtensionType.supports_npn] = AutoEmptyExtension()
        # ext[ExtensionType.alpn] = AutoEmptyExtension()
        # ext[ExtensionType.srp] = AutoEmptyExtension()
        # ext[ExtensionType.post_handshake_auth] = AutoEmptyExtension()
        # FOR Renegotiation
        if self.support_version <= (3,3):            
            ext[ExtensionType.renegotiation_info] = None
            # ext[ExtensionType.renegotiation_info] = AutoEmptyExtension()

        self.extensions = ext

    def generate_extensions(self):
        """Convert extension generators to extension objects."""
        extensions = []
        if self.pre_set_extensions is None:
            self.set_extensions()
        else:
            self.set_extensions(versions=self.pre_set_extensions[0],
                                groups=self.pre_set_extensions[1],
                                sig_algs=self.pre_set_extensions[2])
        
        for ext_id in self.extensions:
            if self.extensions[ext_id] is not None:
                if callable(self.extensions[ext_id]):
                    extensions.append(self.extensions[ext_id])
                elif isinstance(self.extensions[ext_id], TLSExtension):
                    extensions.append(self.extensions[ext_id])
                elif self.extensions[ext_id] is AutoEmptyExtension():
                    extensions.append(TLSExtension().create(ext_id,
                                                            bytearray()))
                else:
                    raise ValueError("Bad extension, id: {0}".format(ext_id))
                continue

            if ext_id == ExtensionType.renegotiation_info:
                ext = RenegotiationInfoExtension()\
                    .create(self.client_verify_data)
            elif ext_id == ExtensionType.status_request:
                ext = StatusRequestExtension().create()
            elif ext_id in (ExtensionType.client_hello_padding,
                            ExtensionType.encrypt_then_mac,
                            ExtensionType.extended_master_secret,
                            35,  # session_ticket
                            49,  # post_handshake_auth
                            52):  # transparency_info
                ext = TLSExtension().create(ext_id, bytearray())
            else:
                raise ValueError("No autohandler for extension {0}"
                                 .format(ExtensionType.toStr(ext_id)))
            extensions.append(ext)
        return extensions
    
    # def generate_extensions_1(self):
    #     """Convert extension generators to extension objects."""
    #     extensions = []
    #     ext_dir = {}

    #     versions = [(3, 4), (3, 3)]
    #     ext_dir[ExtensionType.supported_versions] = SupportedVersionsExtension().create(versions)
    #     groups = [GroupName.secp256r1]
    #     ext_dir[ExtensionType.supported_groups] = SupportedGroupsExtension().create(groups)
    #     sig_algs = [(8,9)]
    #     sig_algs_crt = RSA_SIG_ALL
    #     # sig_algs=[(6, 1), (5, 1), (4, 1)]
    #     ext_dir[ExtensionType.signature_algorithms] = SignatureAlgorithmsExtension().create(sig_algs)
    #     ext_dir[ExtensionType.signature_algorithms_cert] = SignatureAlgorithmsCertExtension().create(sig_algs_crt)
    #     key_shares = []
    #     ext_dir[ExtensionType.key_share] = ClientKeyShareExtension().create(key_shares)
    #     for group in groups:
    #         key_shares.append(self._genKeyShareEntry(group, self.support_version))
    #     for ext_id in ext_dir:
    #         if ext_dir[ext_id] is not None:
    #             if callable(ext_dir[ext_id]):
    #                 extensions.append(ext_dir[ext_id])
    #             elif isinstance(ext_dir[ext_id], TLSExtension):
    #                 extensions.append(ext_dir[ext_id])
    #             elif ext_dir[ext_id] is AutoEmptyExtension():
    #                 extensions.append(TLSExtension().create(ext_id,
    #                                                         bytearray()))
    #             else:
    #                 raise ValueError("Bad extension, id: {0}".format(ext_id))
    #             continue

    #         if ext_id == ExtensionType.renegotiation_info:
    #             ext = RenegotiationInfoExtension()\
    #                 .create(self.client_verify_data)
    #         elif ext_id == ExtensionType.status_request:
    #             ext = StatusRequestExtension().create()
    #         elif ext_id in (ExtensionType.client_hello_padding,
    #                         ExtensionType.encrypt_then_mac,
    #                         ExtensionType.extended_master_secret,
    #                         35,  # session_ticket
    #                         49,  # post_handshake_auth
    #                         52):  # transparency_info
    #             ext = TLSExtension().create(ext_id, bytearray())
    #         else:
    #             raise ValueError("No autohandler for extension {0}"
    #                              .format(ExtensionType.toStr(ext_id)))
    #         extensions.append(ext)
    #     return extensions
    
    def generatefuzz_ClientHello(self):
        ''' session id '''
        if self.session_id == bytearray(0):
            self.session = None
            self.session_id = getRandomBytes(32)
        #client random
        client_random = bytes.fromhex(str(hex(int(time.time())))[2:]) + os.urandom(28)
        self._clientRandom = client_random
        clientHello = ClientHello()


        extensions = []
        ext_dir = {}
        versions = [(3, 4), (3, 3)]
        ext_dir[ExtensionType.supported_versions] = SupportedVersionsExtension().create(versions)
        # groups = [GroupName.secp256r1]
        groups = [GroupName.ffdhe2048]
        ext_dir[ExtensionType.supported_groups] = SupportedGroupsExtension().create(groups)
        # sig_algs = [(8,9)]
        sig_algs = RSA_SIG_ALL
        # sig_algs_crt = RSA_SIG_ALL
        # sig_algs=[]
        # sig_algs=[(2, 1)]
        # sig_algs=[(16, 16)]
        ext_dir[ExtensionType.signature_algorithms] = SignatureAlgorithmsExtension().create(sig_algs)
        # ext_dir[ExtensionType.signature_algorithms_cert] = SignatureAlgorithmsCertExtension().create(sig_algs_crt)


        key_shares = []
        ext_dir[ExtensionType.key_share] = ClientKeyShareExtension().create(key_shares)
        
        for group in groups:
            if group == GroupName.ffdhe2048:
                params = FFDHE2048
            elif group == GroupName.ffdhe3072:
                params = FFDHE3072
            elif group == GroupName.ffdhe4096:
                params = FFDHE4096
            elif group == GroupName.ffdhe6144:
                params = FFDHE6144
            else:
                assert group == GroupName.ffdhe8192
                params = FFDHE8192


            key_share=self._genKeyShareEntry(group, self.support_version)
            # key_share = KeyShareEntry().create(group,
            #                                numberToByteArray(params[1]))
            # key_share = KeyShareEntry().create(group, bytearray(b'\x00'))
            key_share.key_exchange = bytearray(len(key_share.key_exchange))
            # key_share.key_exchange = bytearray(len(key_share.key_exchange))
            # key_share.key_exchange[-1] = 0x01
            # key_share.key_exchange += bytearray(b'\x00')
            # key_share.key_exchange = bytearray([0xff] * len(key_share.key_exchange))
            key_shares.append(key_share)
            # key_shares.append(key_share)

        # key_shares = []
        # key_share = self._genKeyShareEntry(groups[0], self.support_version)
        # key_share.key_exchange += bytearray(b'\x00')
        # ext_dir[ExtensionType.key_share] = ClientKeyShareExtension().create([key_share])

        for ext_id in ext_dir:
            if ext_dir[ext_id] is not None:
                if callable(ext_dir[ext_id]):
                    extensions.append(ext_dir[ext_id])
                elif isinstance(ext_dir[ext_id], TLSExtension):
                    extensions.append(ext_dir[ext_id])
                elif ext_dir[ext_id] is AutoEmptyExtension():
                    extensions.append(TLSExtension().create(ext_id,
                                                            bytearray()))
                else:
                    raise ValueError("Bad extension, id: {0}".format(ext_id))
                continue

            if ext_id == ExtensionType.renegotiation_info:
                ext = RenegotiationInfoExtension()\
                    .create(self.client_verify_data)
            elif ext_id == ExtensionType.status_request:
                ext = StatusRequestExtension().create()
            elif ext_id in (ExtensionType.client_hello_padding,
                            ExtensionType.encrypt_then_mac,
                            ExtensionType.extended_master_secret,
                            35,  # session_ticket
                            49,  # post_handshake_auth
                            52):  # transparency_info
                ext = TLSExtension().create(ext_id, bytearray())
            else:
                raise ValueError("No autohandler for extension {0}"
                                 .format(ExtensionType.toStr(ext_id)))
            extensions.append(ext)

        if self.support_version >= (3,4):
            clientHello.create((3, 3),
                               client_random,
                               self.session_id,
                               self.ciphersuites,
                               extensions=extensions)
            # Initialize settings if not already done
            if self.settings is None:
                self.settings = HandshakeSettings().validate()
            if self.settings.pskConfigs:
                ext = PreSharedKeyExtension()
                idens = []
                binders = []
                for psk in self.settings.pskConfigs:
                    # skip PSKs with no identities as they're TLS1.3 incompatible
                    if not psk[0]:
                        continue
                    idens.append(PskIdentity().create(psk[0], 0))
                    psk_hash = psk[2] if len(psk) > 2 else 'sha256'
                    assert psk_hash in set(['sha256', 'sha384'])
                    # create fake binder values to create correct length fields
                    binders.append(bytearray(32 if psk_hash == 'sha256' else 48))

                if idens:
                    ext.create(idens, binders)
                    clientHello.extensions.append(ext)
                    # for HRR(HelloRetryRequest) case we'll need 1st CH and HRR in handshake hashes,
                    # so pass them in, truncated CH will be added by the helpers to
                    # the copy of the hashes
                    HandshakeHelpers.update_binders(clientHello,
                                                    self._handshake_hash,
                                                    self.settings.pskConfigs,
                                                    self.session.tickets if self.session else None,
                                                    self.session.resumptionMasterSecret if self.session else None)
        if self.support_version <= (3,3):
            clientHello.create(self.support_version,
                               client_random,
                               self.session_id,
                               self.ciphersuites,
                               extensions=extensions)

        # clientHello.extensions[0]=SupportedVersionsExtension().create([(3,3)])
        # print(clientHello)
        return clientHello

    def generateClientHelloTLS12(self):
        # self.version = (3,3)
        self.support_version = (3,3)
        if self.session_id == bytearray(0):
            self.session = None
            self.session_id = getRandomBytes(32)
        #client random
        client_random = bytes.fromhex(str(hex(int(time.time())))[2:]) + os.urandom(28)
        self._clientRandom = client_random
        clientHello = ClientHello()
        clientHello.create((3,3),
                               client_random,
                               self.session_id,
                               self.ciphersuites,
                               extensions=self.generate_extensions())

   
        return clientHello
    
    def generateClientHelloTLS13(self):
        # self.version = (3,4)
        self.support_version = (3,4)
        if self.session_id == bytearray(0):
            self.session = None
            self.session_id = getRandomBytes(32)
        client_random = bytes.fromhex(str(hex(int(time.time())))[2:]) + os.urandom(28)
        self._clientRandom = client_random
        self.hrr = False
        clientHello = ClientHello()
        clientHello.create(self.support_version,
                               client_random,
                               self.session_id,
                               self.ciphersuites,
                               extensions=self.generate_extensions())
        clientHello.create((3, 3),
                            client_random,
                            self.session_id,
                            self.ciphersuites,
                            extensions=self.generate_extensions())
        # Initialize settings if not already done
        if self.settings is None:
            self.settings = HandshakeSettings().validate()
        if self.settings.pskConfigs:
            ext = PreSharedKeyExtension()
            idens = []
            binders = []
            for psk in self.settings.pskConfigs:
                # skip PSKs with no identities as they're TLS1.3 incompatible
                if not psk[0]:
                    continue
                idens.append(PskIdentity().create(psk[0], 0))
                psk_hash = psk[2] if len(psk) > 2 else 'sha256'
                assert psk_hash in set(['sha256', 'sha384'])
                # create fake binder values to create correct length fields
                binders.append(bytearray(32 if psk_hash == 'sha256' else 48))

            if idens:
                ext.create(idens, binders)
                clientHello.extensions.append(ext)
                # for HRR(HelloRetryRequest) case we'll need 1st CH and HRR in handshake hashes,
                # so pass them in, truncated CH will be added by the helpers to
                # the copy of the hashes
                HandshakeHelpers.update_binders(clientHello,
                                                self._handshake_hash,
                                                self.settings.pskConfigs,
                                                self.session.tickets if self.session else None,
                                                self.session.resumptionMasterSecret if self.session else None)

   
        return clientHello
    


    def generateClientHello(self):
        ''' session id '''
        if self.session_id == bytearray(0):
            # self.session = None
            self.session_id = getRandomBytes(32)
        #client random
        client_random = bytes.fromhex(str(hex(int(time.time())))[2:]) + os.urandom(28)
        self._clientRandom = client_random
        clientHello = ClientHello()
        if self.support_version >= (3,4) :
            self.hrr = False
        if self.support_version >= (3,4):
            clientHello.create((3, 3),
                               client_random,
                               self.session_id,
                               self.ciphersuites,
                               extensions=self.generate_extensions())
            # Initialize settings if not already done
            if self.settings is None:
                self.settings = HandshakeSettings().validate()
            if self.settings.pskConfigs:
                ext = PreSharedKeyExtension()
                idens = []
                binders = []
                for psk in self.settings.pskConfigs:
                    # skip PSKs with no identities as they're TLS1.3 incompatible
                    if not psk[0]:
                        continue
                    idens.append(PskIdentity().create(psk[0], 0))
                    psk_hash = psk[2] if len(psk) > 2 else 'sha256'
                    assert psk_hash in set(['sha256', 'sha384'])
                    # create fake binder values to create correct length fields
                    binders.append(bytearray(32 if psk_hash == 'sha256' else 48))

                if idens:
                    ext.create(idens, binders)
                    clientHello.extensions.append(ext)
                    # for HRR(HelloRetryRequest) case we'll need 1st CH and HRR in handshake hashes,
                    # so pass them in, truncated CH will be added by the helpers to
                    # the copy of the hashes
                    HandshakeHelpers.update_binders(clientHello,
                                                    self._handshake_hash,
                                                    self.settings.pskConfigs,
                                                    self.session.tickets if self.session else None,
                                                    self.session.resumptionMasterSecret if self.session else None)
        if self.support_version <= (3,3):
            clientHello.create(self.support_version,
                               client_random,
                               self.session_id,
                               self.ciphersuites,
                               extensions=self.generate_extensions())

        # clientHello.extensions[0]=SupportedVersionsExtension().create([(3,3)])
        # print(clientHello)
        return clientHello
    
    def generateClientHelloEmtyKeyShare(self):
        if self.session_id == bytearray(0):
            self.session = None
            self.session_id = getRandomBytes(32)
        self.hrr=True
        client_random=bytes.fromhex(str(hex(int(time.time())))[2:])+os.urandom(28)
        clientHello = ClientHello()
        clientHello.create((3,3),
                           client_random,
                           self.session_id,
                           self.ciphersuites,
                           extensions=self.generate_extensions())
        # Initialize settings if not already done
        if self.settings is None:
            self.settings = HandshakeSettings().validate()
        if self.settings.pskConfigs:
            ext = PreSharedKeyExtension()
            idens = []
            binders = []
            for psk in self.settings.pskConfigs:
                # skip PSKs with no identities as they're TLS1.3 incompatible
                if not psk[0]:
                    continue
                idens.append(PskIdentity().create(psk[0], 0))
                psk_hash = psk[2] if len(psk) > 2 else 'sha256'
                assert psk_hash in set(['sha256', 'sha384'])
                # create fake binder values to create correct length fields
                binders.append(bytearray(32 if psk_hash == 'sha256' else 48))

            if idens:
                ext.create(idens, binders)
                clientHello.extensions.append(ext)
                # for HRR(HelloRetryRequest) case we'll need 1st CH and HRR in handshake hashes,
                # so pass them in, truncated CH will be added by the helpers to
                # the copy of the hashes
                HandshakeHelpers.update_binders(clientHello,
                                                self._handshake_hash,
                                                self.settings.pskConfigs,
                                                self.session.tickets if self.session else None,
                                                self.session.resumptionMasterSecret if self.session else None)
        return clientHello

    def generateFuzzClientHelloVersion(self):
        """
        C17: 测试ClientHello.legacy_version字段
        正常值: (3, 3) = 0x0303 (TLS 1.2)
        Fuzz: 使用(3, 2)等错误版本
        """
        if self.session_id == bytearray(0):
            self.session = None
            self.session_id = getRandomBytes(32)

        client_random = bytes.fromhex(str(hex(int(time.time())))[2:]) + os.urandom(28)
        clientHello = ClientHello()

        # 正常创建ClientHello
        clientHello.create(
            (3, 1),  # legacy_version
            client_random,
            self.session_id,
            self.ciphersuites,
            extensions=self.generate_extensions()
        )

        # FUZZ: 修改client_version字段为错误版本
        # clientHello.client_version = (3, 0)  # TLS 1.1 而非 TLS 1.2

        return clientHello

    def _send_merged_client_messages(self, msg1, msg2):
        """
        C20: 将两个客户端消息合并到同一个TLS记录中发送
        用于测试服务器是否正确验证记录边界

        :param msg1: 第一个消息（通常是ClientHello）
        :param msg2: 第二个消息（Finished或Certificate）
        """
        print(f"\n[C20-CLIENT-FUZZ] 合并两个消息到同一个TLS记录")

        # 序列化两个消息
        msg1_bytes = msg1.write()
        msg2_bytes = msg2.write()
        # print(msg2_bytes.hex())
        # msg3_bytes = msg2_bytes[0:3]+bytes.fromhex('8b')+msg2_bytes[5:]
        # msg2_bytes = msg3_bytes
        # print(dir(self.cert_chain))
        # print(self.cert_chain[0].x509List)

        print(f"  - {msg1.__class__.__name__}: {len(msg1_bytes)} bytes")
        print(f"  - {msg2.__class__.__name__}: {len(msg2_bytes)} bytes")

        # 创建TLS记录头，长度 = msg1 + msg2
        # RecordHeader3.create(version, type, length)
        from tlslite.messages import RecordHeader3
        from tlslite.constants import ContentType
        record = RecordHeader3()
        total_length = len(msg1_bytes) + len(msg2_bytes)
        record.create((3, 3), ContentType.handshake, total_length)

        # 发送：记录头 + msg1 + msg2（全部在一个TLS记录中）
        record_bytes = record.write() + msg1_bytes + msg2_bytes

        # 直接通过socket发送
        for result in self._recordLayer._recordSocket._sockSendAll(record_bytes):
            pass

        # 更新握手哈希
        self._handshake_hash.update(msg1_bytes)
        if msg1.__class__.__name__ == 'ClientHello':
            self.CH = msg1
            self._clientRandom = msg1.random

        print(f"[C20-CLIENT-FUZZ] 已发送合并记录: {len(record_bytes)} bytes")
        print(f"  - TLS Record: [Type=22][Version=0x0303][Length={total_length}]")
        print(f"  - 违规: 两个握手消息在同一个TLS记录中")

    def generateFuzzClientHelloKeyShare(self, fuzz_type='zero', target_group=None):
        """
        C18: 测试KeyShare的Y值必须在范围 1 < Y < p-1
        Fuzz策略: 测试边界值

        Args:
            fuzz_type: 模糊测试类型
                'zero' - Y = 0 (全零)
                'one' - Y = 1
                'max' - Y = p-1 (最大值)
                'over_prime' - Y > p-1 (超出范围)
                'invalid_length' - 错误的长度
            target_group: 目标群组 (None=所有群组, 或指定单个GroupName)
        """
        # my_groups = [GroupName.secp256r1,
        #       GroupName.secp384r1,
        #       GroupName.secp521r1,
        #       GroupName.x25519,
        #       GroupName.x448]

        # 定义各个curve的参数长度和prime值
        curve_params = {
            GroupName.secp256r1: {
                'length': 65,  # 0x04 + 32字节x + 32字节y (uncompressed point)
                'coord_len': 32,
                'prime': int('FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF', 16)
            },
            GroupName.secp384r1: {
                'length': 97,  # 0x04 + 48字节x + 48字节y
                'coord_len': 48,
                'prime': int('FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFF', 16)
            },
            GroupName.secp521r1: {
                'length': 133,  # 0x04 + 66字节x + 66字节y
                'coord_len': 66,
                'prime': int('01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF', 16)
            },
            GroupName.x25519: {
                'length': 32,  # 32字节的u-coordinate
                'coord_len': 32,
                'prime': 2**255 - 19
            },
            GroupName.x448: {
                'length': 56,  # 56字节的u-coordinate
                'coord_len': 56,
                'prime': 2**448 - 2**224 - 1
            },
            GroupName.ffdhe2048: {
                'length': 256,  # 2048 bits = 256 bytes
                'coord_len': 256,
                'prime': int('FFFFFFFFFFFFFFFFADF85458A2BB4A9AAFDC5620273D3CF1D8B9C583CE2D3695A9E13641146433FBCC939DCE249B3EF97D2FE363630C75D8F681B202AEC4617AD3DF1ED5D5FD65612433F51F5F066ED0856365553DED1AF3B557135E7F57C935984F0C70E0E68B77E2A689DAF3EFE8721DF158A136ADE73530ACCA4F483A797ABC0AB182B324FB61D108A94BB2C8E3FBB96ADAB760D7F4681D4F42A3DE394DF4AE56EDE76372BB190B07A7C8EE0A6D709E02FCE1CDF7E2ECC03404CD28342F619172FE9CE98583FF8E4F1232EEF28183C3FE3B1B4C6FAD733BB5FCBC2EC22005C58EF1837D1683B2C6F34A26C1B2EFFA886B423861285C97FFFFFFFFFFFFFFFF', 16)
            },
            GroupName.ffdhe3072: {
                'length': 384,  # 3072 bits = 384 bytes
                'coord_len': 384,
                'prime': int('FFFFFFFFFFFFFFFFADF85458A2BB4A9AAFDC5620273D3CF1D8B9C583CE2D3695A9E13641146433FBCC939DCE249B3EF97D2FE363630C75D8F681B202AEC4617AD3DF1ED5D5FD65612433F51F5F066ED0856365553DED1AF3B557135E7F57C935984F0C70E0E68B77E2A689DAF3EFE8721DF158A136ADE73530ACCA4F483A797ABC0AB182B324FB61D108A94BB2C8E3FBB96ADAB760D7F4681D4F42A3DE394DF4AE56EDE76372BB190B07A7C8EE0A6D709E02FCE1CDF7E2ECC03404CD28342F619172FE9CE98583FF8E4F1232EEF28183C3FE3B1B4C6FAD733BB5FCBC2EC22005C58EF1837D1683B2C6F34A26C1B2EFFA886B4238611FCFDCDE355B3B6519035BBC34F4DEF99C023861B46FC9D6E6C9077AD91D2691F7F7EE598CB0FAC186D91CAEFE130985139270B4130C93BC437944F4FD4452E2D74DD364F2E21E71F54BFF5CAE82AB9C9DF69EE86D2BC522363A0DABC521979B0DEADA1DBF9A42D5C4484E0ABCD06BFA53DDEF3C1B20EE3FD59D7C25E41D2B66C62E37FFFFFFFFFFFFFFFF', 16)
            },
            GroupName.ffdhe4096: {
                'length': 512,  # 4096 bits = 512 bytes
                'coord_len': 512,
                'prime': int('FFFFFFFFFFFFFFFFADF85458A2BB4A9AAFDC5620273D3CF1D8B9C583CE2D3695A9E13641146433FBCC939DCE249B3EF97D2FE363630C75D8F681B202AEC4617AD3DF1ED5D5FD65612433F51F5F066ED0856365553DED1AF3B557135E7F57C935984F0C70E0E68B77E2A689DAF3EFE8721DF158A136ADE73530ACCA4F483A797ABC0AB182B324FB61D108A94BB2C8E3FBB96ADAB760D7F4681D4F42A3DE394DF4AE56EDE76372BB190B07A7C8EE0A6D709E02FCE1CDF7E2ECC03404CD28342F619172FE9CE98583FF8E4F1232EEF28183C3FE3B1B4C6FAD733BB5FCBC2EC22005C58EF1837D1683B2C6F34A26C1B2EFFA886B4238611FCFDCDE355B3B6519035BBC34F4DEF99C023861B46FC9D6E6C9077AD91D2691F7F7EE598CB0FAC186D91CAEFE130985139270B4130C93BC437944F4FD4452E2D74DD364F2E21E71F54BFF5CAE82AB9C9DF69EE86D2BC522363A0DABC521979B0DEADA1DBF9A42D5C4484E0ABCD06BFA53DDEF3C1B20EE3FD59D7C25E41D2B669E1EF16E6F52C3164DF4FB7930E9E4E58857B6AC7D5F42D69F6D187763CF1D5503400487F55BA57E31CC7A7135C886EFB4318AED6A1E012D9E6832A907600A918130C46DC778F971AD0038092999A333CB8B7A1A1DB93D7140003C2A4ECEA9F98D0ACC0A8291CDCEC97DCF8EC9B55A7F88A46B4DB5A851F44182E1C68A007E5E655F6AFFFFFFFFFFFFFFFF', 16)
            }
        }

        if self.session_id == bytearray(0):
            self.session = None
            self.session_id = getRandomBytes(32)

        client_random = bytes.fromhex(str(hex(int(time.time())))[2:]) + os.urandom(28)

        # 如果指定了target_group，只生成该群组的KeyShare
        # print(target_group)
        if target_group is not None:
            groups_to_use = [target_group]
        else:
            groups_to_use = [GroupName.secp256r1]  # 默认只测试secp256r1

        # 生成指定群组的extensions
        if self.pre_set_extensions is None:
            self.set_extensions(groups=groups_to_use)
        # print(groups_to_use)
        # 先生成正常的extensions
        self.pre_set_extensions = [[(3, 4)],groups_to_use,RSA_SIG_ALL]
        extensions = self.generate_extensions()
        # print(extensions[ExtensionType.key_share].client_shares[0].private)
        # print(extensions[ExtensionType.key_share].client_shares[0].key_exchange)
        for ext in extensions:
            if hasattr(ext, 'extType') and ext.extType == ExtensionType.key_share:
                # 修改key_share entries
                if hasattr(ext, 'client_shares'):
                    for key_share in ext.client_shares:
                        # print(key_share.private,len(key_share.private))
                        # print(key_share.key_exchange,len(key_share.key_exchange))
                        group = key_share.group

                        if group not in curve_params:
                            continue

                        params = curve_params[group]

                        if fuzz_type == 'zero':
                            # Y = 0: 全零
                            # key_share.key_exchange = bytearray(params['length'])
                            if group in [GroupName.x25519, GroupName.x448]:
                                # Montgomery curves: 直接设置u-coordinate为1
                                key_share.key_exchange = bytearray(params['length'])
                            elif group in [GroupName.ffdhe2048, GroupName.ffdhe3072, GroupName.ffdhe4096]:
                                # FFDHE: 大整数为0
                                key_share.key_exchange = bytearray(params['length'])
                            else:
                                # Weierstrass curves: uncompressed point (0x04, x=1, y=1)
                                key_share.key_exchange = bytearray(params['length'])
                                key_share.key_exchange[0] = 0x04  # uncompressed point format

                        elif fuzz_type == 'one':
                            # Y = 1
                            if group in [GroupName.x25519, GroupName.x448]:
                                # Montgomery curves: 直接设置u-coordinate为1
                                key_share.key_exchange = bytearray(params['length'])
                                # print(key_share.key_exchange)
                                key_share.key_exchange[0] = 0x01
                            elif group in [GroupName.ffdhe2048, GroupName.ffdhe3072, GroupName.ffdhe4096]:
                                # FFDHE: 大整数为1（big-endian）
                                key_share.key_exchange = bytearray(params['length'])
                                key_share.key_exchange[-1] = 0x01
                            else:
                                # Weierstrass curves: uncompressed point (0x04, x=1, y=1)
                                key_share.key_exchange = bytearray(params['length'])
                                key_share.key_exchange[0] = 0x04  # uncompressed point format
                                # x = 1
                                key_share.key_exchange[params['coord_len']] = 0x01
                                # y = 1
                                key_share.key_exchange[params['coord_len'] * 2] = 0x01

                        elif fuzz_type == 'max':
                            # Y = p-1 (最大有效值)
                            prime = params['prime']
                            p_minus_1 = prime - 1

                            if group in [GroupName.x25519, GroupName.x448]:
                                # Montgomery curves
                                p_minus_1_bytes = p_minus_1.to_bytes(params['coord_len'], 'little')
                                key_share.key_exchange = bytearray(p_minus_1_bytes)
                            elif group in [GroupName.ffdhe2048, GroupName.ffdhe3072, GroupName.ffdhe4096]:
                                # FFDHE: big-endian
                                p_minus_1_bytes = p_minus_1.to_bytes(params['length'], 'big')
                                key_share.key_exchange = bytearray(p_minus_1_bytes)
                            else:
                                # Weierstrass curves: (0x04, x=p-1, y=p-1)
                                key_share.key_exchange = bytearray(params['length'])
                                key_share.key_exchange[0] = 0x04

                                # x = p-1
                                x_bytes = p_minus_1.to_bytes(params['coord_len'], 'big')
                                key_share.key_exchange[1:1+params['coord_len']] = x_bytes

                                # y = p-1
                                y_bytes = p_minus_1.to_bytes(params['coord_len'], 'big')
                                key_share.key_exchange[1+params['coord_len']:] = y_bytes

                        elif fuzz_type == 'invalid_length':
                            # 错误的长度：添加额外字节
                            original_len = len(key_share.key_exchange)
                            key_share.key_exchange = bytearray(b'\x00') * (original_len + 10)

                        elif fuzz_type == 'over_prime':
                            # Y > p-1 (超出范围)
                            prime = params['prime']
                            over_value = prime + 100

                            if group in [GroupName.x25519, GroupName.x448]:
                                over_bytes = over_value.to_bytes(params['coord_len'], 'little', signed=False)
                                key_share.key_exchange = bytearray(over_bytes)
                            elif group in [GroupName.ffdhe2048, GroupName.ffdhe3072, GroupName.ffdhe4096]:
                                # FFDHE: big-endian, 可能需要额外字节
                                try:
                                    over_bytes = over_value.to_bytes(params['length'], 'big')
                                except OverflowError:
                                    # 如果over_value太大，使用更大的长度
                                    over_bytes = over_value.to_bytes(params['length'] + 1, 'big')
                                key_share.key_exchange = bytearray(over_bytes)
                            else:
                                key_share.key_exchange = bytearray(params['length'])
                                key_share.key_exchange[0] = 0x04
                                over_bytes = over_value.to_bytes(params['coord_len'], 'big', signed=False)
                                key_share.key_exchange[1:1+params['coord_len']] = over_bytes

        clientHello = ClientHello()
        clientHello.create((3, 3), client_random, self.session_id,
                          self.ciphersuites, extensions=extensions)
        # print(clientHello.getExtension(ExtensionType.key_share).client_shares[0].private,len(clientHello.getExtension(ExtensionType.key_share).client_shares[0].private))
        # print(clientHello.getExtension(ExtensionType.key_share).client_shares[0].key_exchange,len(clientHello.getExtension(ExtensionType.key_share).client_shares[0].key_exchange))
        # print(dir(clientHello.getExtension(ExtensionType.key_share).client_shares[0]))


        return clientHello

    def generateFuzzClientHelloComp(self):
        """
        C19: 测试compression_methods必须为[0]
        Fuzz: 使用[1]等错误值
        """
        if self.session_id == bytearray(0):
            self.session = None
            self.session_id = getRandomBytes(32)

        client_random = bytes.fromhex(str(hex(int(time.time())))[2:]) + os.urandom(28)
        clientHello = ClientHello()

        # 正常创建ClientHello
        clientHello.create(
            (3, 3),
            client_random,
            self.session_id,
            self.ciphersuites,
            extensions=self.generate_extensions()
        )

        # FUZZ: 修改compression_methods字段
        clientHello.compression_methods = [1]  # 错误: 应该是[0]

        return clientHello

    def generateFuzzFinishedVerifyData(self):
        """
        Fuzzing Finished消息的verify_data字段
        测试服务器对错误verify_data的处理

        Fuzzing策略: 翻转第一个字节
        """
        self.resume12 = False
        if self.SH == None:
            self.SH = ServerHello()
        if self.SH.cipher_suite == None or self.SH.cipher_suite == 0:
            self.SH.cipher_suite = self.tlspro.cipher_suite[0]

        if self.support_version >= (3,4):
            # TLS 1.3 - 计算正确的verify_data然后fuzz
            temp = derive_secret(self.handshake_secret, bytearray(b'derived'), None, self.prf_name)
            self.master_secret = secureHMAC(temp, bytearray(self.prf_size), self.prf_name)
            self.cl_app_traffic = derive_secret(self.master_secret, bytearray(b'c ap traffic'),
                                                self.server_finish_hs, self.prf_name)
            if self.sr_app_traffic is None:
                self.sr_app_traffic = derive_secret(self.master_secret, bytearray(b's ap traffic'),
                                                    self.server_finish_hs, self.prf_name)
            self.exporter_master_secret = derive_secret(self.master_secret,
                                                        bytearray(b'exp master'),
                                                        self._handshake_hash, self.prf_name)

            self._recordLayer.calcTLS1_3PendingState(
                self.SH.cipher_suite,
                self.cl_app_traffic,
                self.sr_app_traffic,
                ['python'])

            if self.key_log_write == True:
                try:
                    self.write_key_log('CLIENT_TRAFFIC_SECRET_0', self._clientRandom, self._serverRandom,
                                       self.cl_app_traffic)
                except:
                    pass

            if self.tlspro.SendEndofEarlyData == True and self.resuming:
                self._handshake_hash.update(bytearray(b'\x05\x00\x00\x00'))

            cl_finished_key = HKDF_expand_label(self.cl_handshake_traffic_secret,
                                                b"finished", b'',
                                                self.prf_size, self.prf_name)
            cl_verify_data = secureHMAC(
                cl_finished_key,
                self._handshake_hash.digest(self.prf_name),
                self.prf_name)

            # FUZZ: 修改verify_data
            cl_verify_data = bytearray(cl_verify_data)
            cl_verify_data[0] ^= 0xFF  # 翻转第一个字节
            cl_verify_data = bytes(cl_verify_data)

            client_finished = Finished(self.support_version, self.prf_size)
            client_finished.create(cl_verify_data)

            return client_finished
        elif self.support_version <=(3,3):
            # TLS 1.2及以下 - 修改client_verify_data
            verify_data = bytearray(self.client_verify_data)
            verify_data[0] ^= 0xFF  # 翻转第一个字节
            client_finished = Finished(self.support_version).create(bytes(verify_data))
            return client_finished


    def generateClientKeyExchange(self):
        if self.CH == None or self.SH == None or self.SC == None:
            self.ciphersuites = [CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
                                    CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA]
            session_id = getRandomBytes(32)
            if self.CH == None:
                CH = ClientHello()
                client_random=bytes.fromhex(str(hex(int(time.time())))[2:])+os.urandom(28)
                CH.create((3,3),
                            client_random,
                            session_id,
                            self.ciphersuites,
                            extensions=self.generate_extensions()) 
                self.CH = CH
            
            if self.SH == None:
                SH = ServerHello()
                server_random=bytes.fromhex(str(hex(int(time.time())))[2:])+os.urandom(28)
                SH.create((3,3),
                            server_random,
                            session_id,
                            self.ciphersuites[0])
                self.SH = SH
  
            keyExchange = RSAKeyExchange(self._cipherSuite, self.CH,
                                             self.SH, None)
            if self.SC == None:
                server_cert = open('./key/server.cer', 'rb').read()
                server_cert = str(server_cert, 'utf-8')
                server_cert_chain = X509CertChain()
                server_cert_chain.parsePemList(server_cert)
                keyExchange.cipherSuite=self.ciphersuites[0]
                keyExchange.version = (3,3)
                
            
            self.premasterSecret = keyExchange.processServerKeyExchange(server_cert_chain.getEndEntityPublicKey(),
                                                                    self.SKE)
                                                                    
        else:

            if self._cipherSuite in CipherSuite.dhAllSuites:
                keyExchange = DHE_RSAKeyExchange(self._cipherSuite, self.CH,
                                                self.SH, None)
                self.premasterSecret = keyExchange.processServerKeyExchange(self.SC.cert_chain.getEndEntityPublicKey(),
                                                                   self.SKE)
           
            elif self._cipherSuite in CipherSuite.ecdhAllSuites or self._cipherSuite in CipherSuite.ecdheEcdsaSuites:
                keyExchange = ECDHE_RSAKeyExchange(self._cipherSuite, self.CH,
                                                self.SH, None,
                                                [self.ecdhCurve])
                self.premasterSecret = keyExchange.processServerKeyExchange(self.SC.cert_chain.getEndEntityPublicKey(),
                                                                   self.SKE)

            else:
                keyExchange = RSAKeyExchange(self._cipherSuite, self.CH,
                                                self.SH, None)
                self.premasterSecret = keyExchange.processServerKeyExchange(self.SC.cert_chain.getEndEntityPublicKey(),
                                                                   self.SKE)
        clientKeyExchange = keyExchange.makeClientKeyExchange()
        return clientKeyExchange
    
    def generateChangeCipherSpec(self):
        
        ccs = ChangeCipherSpec().create()
        
        return ccs 

    def generateClientCertificate(self):  
        if self.SH == None:
            certificate_type = CertificateType.x509
        else:
            certificate_type = self.SH.certificate_type
        client_certificate = Certificate(certificate_type, self.support_version)
        client_certificate.create(self.cert_chain)
        # print(client_certificate.certificate_list[0].certificate.writeBytes().hex())

        return client_certificate

    def generateEmptyCertificate(self):
        self.cert_chain = X509CertChain()
        test_cert = X509()
        test_cert.certAlg = 'rsa'
        self.cert_chain.x509List.append(test_cert)
        certificate_type = CertificateType.x509
        client_certificate = Certificate(certificate_type, self.support_version)

        client_certificate.create(self.cert_chain)
        return client_certificate
    
    def generateErrorCertificate(self):
        if self.SH == None:
            certificate_type = CertificateType.x509
        else:
            certificate_type = self.SH.certificate_type
        error_cert_chain = './key/y.pem'
        text_cert1 = str(open(error_cert_chain, 'rb').read(), 'utf-8')
        cert_chain1=X509CertChain()
        cert_chain1.parsePemList(text_cert1)
        client_certificate1 = Certificate(certificate_type, self.support_version)
        client_certificate1.create(cert_chain1)
        # print(text_cert1)
        # print(cert_chain1)
        # cert1='3082037f30820267021448ad55aed8e77613d87e4169a7aa677cb4c1659e300d06092a864886f70d01010b05003079310b312346035504061302434e310b300906035504080c025344310b300906035504070c024a4e310d300b060355040a0c0451445a5931153013060355040b0c0c7777772e746573742e636f6d310b300906035504030c024341311d301b06092a864886f70d010901160e61646d696e40746573742e636f6d3020170d3232303431393030353932315a180f32313232303332363030353932315a307d310b300906035504061302434e310b300906035504080c025344310b300906035504070c024a4e310d300b060355040a0c0451445a5931153013060355040b0c0c7777772e746573742e636f6d310f300d06035504030c06534552564552311d301b06092a864886f70d010901160e61646d696e40746573742e636f6d30820122300d06092a864886f70d01010105000382010f003082010a0282010100aa73c6f1f5b54b01793b133b2383b263ad03046a92a84aac9bc73263ccb98ed2baf76fb5b9206ce4d59f711c7dae6bb8e067b50a44ff2c6f6a16160e73ecc9895fdd9cc549af82fd0ba05e42deba68b0fe040290acf4e2c7781334d6af308f1ba977f4a6b07c4871eb482f8f95b54ca8b3befab144934069d2f6b262a0773fc00a41253087109d857ac5466a15bda3500a7e20d53529eb9d5a86149990aa277e0ac0ee8a781f666d1f10c3c0eb782687790b9dfa49bbb1f1e0231bbe7c7dbadf0c74ff2b96df8d6195f3e4d0b9892f5a493eb0fc13056accbc200c18b5656447270c07fc852e6dd15524e20d25468d5bf4da3a274176d51cfb4b3d84e4057e050203010001300d06092a864886f70d01010b0500038201010000885dd7b32b90b61a6f75c36f3cacf87a0179ef1985be0c6c73974e25acb530501842614576e17268ba30c4a7f15e5341bde33929ce0957987ff82b7419e3eae3b65f4f1fbe99ee40ca0fcd0c39efacc658670b22fc887ed75eaa5fba9405850fd6bd62621cb321efde49456bb0b7b017eac80b5a44867f700d2f6b5b3916229bf85f46799e664cfaf3d50d2e835098ee7a93f1af2df6ce387594af3ad416932af47ad80500a223e1143779e1774bbffe9c03d3d78d0599f6cf6c3c6c794f34ba7fc37c1171cf6d094b7c3a08e81e3eb83ccaa9ab6a576d2b037ee9a71208ce6d7cf823d32c295a5a490a676fbcdad15040c34ce0327d18d72d6ad69889d275'
        # x=bytes.fromhex(cert1)
        # client_certificate1.certificate_list[0].certificate.writeBytes()[:] = x
        # print(client_certificate1.certificate_list[0].certificate.writeBytes().hex())
        return client_certificate1
        # if self.SH == None:
        #     certificate_type = CertificateType.x509
        # else:
        #     certificate_type = self.SH.certificate_type
        # client_certificate1 = Certificate(certificate_type, self.support_version)

        # client_certificate1.create(copy.copy(self.error_cert_chain))
        # # print(dir(client_certificate.certificate_list[0].certificate.writeBytes()))
        # # print(client_certificate.certificate_list[0].certificate.writeBytes())
        # # pck='160303070f0b00070b0007080003833082037f30820267021448ad55aed8e77613d87e4169a7aa677cb4c1659e300d06092a864886f70d01010b05003079310b300906035504061302434e310b300906035504080c025344310b300906035504070c024a4e310d300b060355040a0c0451445a5931153013060355040b0c0c7777772e746573742e636f6d310b300906035504030c024341311d301b06092a864886f70d010901160e61646d696e40746573742e636f6d3020170d3232303431393030353932315a180f32313232303332363030353932315a307d310b300906035504061302434e310b300906035504080c025344310b300906035504070c024a4e310d300b060355040a0c0451445a5931153013060355040b0c0c7777772e746573742e636f6d310f300d06035504030c06534552564552311d301b06092a864886f70d010901160e61646d696e40746573742e636f6d30820122300d06092a864886f70d01010105000382010f003082010a0282010100aa73c6f1f5b54b01793b133b2383b263ad03046a92a84aac9bc73263ccb98ed2baf76fb5b9206ce4d59f711c7dae6bb8e067b50a44ff2c6f6a16160e73ecc9895fdd9cc549af82fd0ba05e42deba68b0fe040290acf4e2c7781334d6af308f1ba977f4a6b07c4871eb482f8f95b54ca8b3befab144934069d2f6b262a0773fc00a41253087109d857ac5466a15bda3500a7e20d53529eb9d5a86149990aa277e0ac0ee8a781f666d1f10c3c0eb782687790b9dfa49bbb1f1e0231bbe7c7dbadf0c74ff2b96df8d6195f3e4d0b9892f5a493eb0fc13056accbc200c18b5656447270c07fc852e6dd15524e20d25468d5bf4da3a274176d51cfb4b3d84e4057e050203010001300d06092a864886f70d01010b0500038201010000885dd7b32b90b61a6f75c36f3cacf87a0179ef1985be0c6c73974e25acb530501842614576e17268ba30c4a7f15e5341bde33929ce0957987ff82b7419e3eae3b65f4f1fbe99ee40ca0fcd0c39efacc658670b22fc887ed75eaa5fba9405850fd6bd62621cb321efde49456bb0b7b017eac80b5a44867f700d2f6b5b3916229bf85f46799e664cfaf3d50d2e835098ee7a93f1af2df6ce387594af3ad416932af47ad80500a223e1143779e1774bbffe9c03d3d78d0599f6cf6c3c6c794f34ba7fc37c1171cf6d094b7c3a08e81e3eb83ccaa9ab6a576d2b037ee9a71208ce6d7cf823d32c295a5a490a676fbcdad15040c34ce0327d18d72d6ad69889d27500037f3082037b3082026302141fd976b5c4e9938405599e599d6eda7d25d8c8d4300d06092a864886f70d01010b05003079310b300906035504061302434e310b300906035504080c025344310b300906035504070c024a4e310d300b060355040a0c0451445a5931153013060355040b0c0c7777772e746573742e636f6d310b300906035504030c024341311d301b06092a864886f70d010901160e61646d696e40746573742e636f6d3020170d3232303431393030353635395a180f32313232303332363030353635395a3079310b300906035504061302434e310b300906035504080c025344310b300906035504070c024a4e310d300b060355040a0c0451445a5931153013060355040b0c0c7777772e746573742e636f6d310b300906035504030c024341311d301b06092a864886f70d010901160e61646d696e40746573742e636f6d30820122300d06092a864886f70d01010105000382010f003082010a0282010100a93749ab45e64e1c1767daa2dab979c1613a6be462e586e6a28b68bb154b5a7801a18a6226644b611aec8cf317e3a2d4fb29b5291b89d5e5d262c1df109c2bf1d9bf727c3155f7b88452a09270ac8fe060b5c4429cfd6ccc2f842c6c5aaa91af2f08c85d38e02b7641e69cde074028a86f6a38422dde095254f0b705ca1d25a1576f9fb423812cae71fc2015ba6d3833b6bb529816bf953d30073bc152f3a590a0aff134e249edb552aa8ea25a25a86c71a604e2155f4d269b572a719f9abb38c6ce5c28759b298d8113b4e119c1c3501b6a88dc573a4248a6c860fcaf51833986b535b2eb1e679b12aef187a2615613c68884a3ad7c70b63ea235e5a53056a30203010001300d06092a864886f70d01010b0500038201010069e6f9ff26ffaf4ed3cf0aa053275696ab74715747b4f7827e6da4a6052e5d6bc8bfdd0bb08d31be45832e5d9ce842c9eaad568de3d360cc24b55458fb239984206dd5bb14a24afd514d6ef23ba830e64714135731049ac161b5665f8345e301ba5050160865a5d5167a9d8109412cb6ea13fefed06ebc440a68eb468215b3ecc95c33a0e5145465cc85db9e4258bb2f582758b83c86a324b850496d99c25de21bcfea0d91b777ba9dd435a3eaa692fd4d104272b12edf93464c1358fef595f33f35a1ac2a723a6e5d63e81cc0894c2ea670c694ca9fb7950bde31e2a655517a4140f430c0cf996e16fdd0dcdaa4d9b3e09673e358eb1e7e91a239f0b4627931'
        # cert1='3082037f30820267021448ad55aed8e77613d87e4169a7aa677cb4c1659e300d06092a864886f70d01010b05003079310b312346035504061302434e310b300906035504080c025344310b300906035504070c024a4e310d300b060355040a0c0451445a5931153013060355040b0c0c7777772e746573742e636f6d310b300906035504030c024341311d301b06092a864886f70d010901160e61646d696e40746573742e636f6d3020170d3232303431393030353932315a180f32313232303332363030353932315a307d310b300906035504061302434e310b300906035504080c025344310b300906035504070c024a4e310d300b060355040a0c0451445a5931153013060355040b0c0c7777772e746573742e636f6d310f300d06035504030c06534552564552311d301b06092a864886f70d010901160e61646d696e40746573742e636f6d30820122300d06092a864886f70d01010105000382010f003082010a0282010100aa73c6f1f5b54b01793b133b2383b263ad03046a92a84aac9bc73263ccb98ed2baf76fb5b9206ce4d59f711c7dae6bb8e067b50a44ff2c6f6a16160e73ecc9895fdd9cc549af82fd0ba05e42deba68b0fe040290acf4e2c7781334d6af308f1ba977f4a6b07c4871eb482f8f95b54ca8b3befab144934069d2f6b262a0773fc00a41253087109d857ac5466a15bda3500a7e20d53529eb9d5a86149990aa277e0ac0ee8a781f666d1f10c3c0eb782687790b9dfa49bbb1f1e0231bbe7c7dbadf0c74ff2b96df8d6195f3e4d0b9892f5a493eb0fc13056accbc200c18b5656447270c07fc852e6dd15524e20d25468d5bf4da3a274176d51cfb4b3d84e4057e050203010001300d06092a864886f70d01010b0500038201010000885dd7b32b90b61a6f75c36f3cacf87a0179ef1985be0c6c73974e25acb530501842614576e17268ba30c4a7f15e5341bde33929ce0957987ff82b7419e3eae3b65f4f1fbe99ee40ca0fcd0c39efacc658670b22fc887ed75eaa5fba9405850fd6bd62621cb321efde49456bb0b7b017eac80b5a44867f700d2f6b5b3916229bf85f46799e664cfaf3d50d2e835098ee7a93f1af2df6ce387594af3ad416932af47ad80500a223e1143779e1774bbffe9c03d3d78d0599f6cf6c3c6c794f34ba7fc37c1171cf6d094b7c3a08e81e3eb83ccaa9ab6a576d2b037ee9a71208ce6d7cf823d32c295a5a490a676fbcdad15040c34ce0327d18d72d6ad69889d275'
        # x=bytes.fromhex(cert1)
        # # y=bytes.fromhex(pck)
        # # # self._handshake_hash.update(y[5:])
        # # # print(self._handshake_hash._handshake_buffer.hex())
        # # # for result in self._recordLayer._recordSocket._sockSendAll(y):
        # # #     pass
        # client_certificate1.certificate_list[0].certificate.writeBytes()[:] = x
        # print(client_certificate1.certificate_list[0].certificate.writeBytes().hex())

        # return client_certificate1
    
    def generateErrorCertificateVerify(self):
        if self.support_version <= (3,3):
            self._certificate_verify_handshake_hash = self._handshake_hash.copy()
            # Initialize settings if not already done
            if self.settings is None:
                self.settings = HandshakeSettings().validate()
            valid_sig_algs = self._sigHashesToList(self.settings, self.privateKey,
                                                    self.cert_chain)
            if self.CR==None:
                self.CR=CertificateRequest(version=(3,3)).create()
                self.CR.supported_signature_algs=[(4, 3), (5, 3), (6, 3), (8, 7), (8, 8), (8, 9), (8, 10), (8, 11), (8, 4), (8, 5), (8, 6), (4, 1), (5, 1), (6, 1), (3, 3), (2, 3), (3, 1), (2, 1), (3, 2), (2, 2), (4, 2), (5, 2), (6, 2)]
            certificateVerify = KeyExchange.makeCertificateVerify(
                        self.support_version,
                        HandshakeHashes(),
                        valid_sig_algs,
                        self.privateKey,
                        self.CR,
                        self.premasterSecret,
                        self._clientRandom,
                        self._serverRandom)
            return certificateVerify
        elif self.support_version >=(3,4):
            try:
                valid_sig_algs = self.CR.supported_signature_algs
            except:
                valid_sig_algs = RSA_SIG_ALL
            availSigAlgs = self._sigHashesToList(self.settings, self.privateKey,
                                                 self.cert_chain, version=(3, 4))
            signature_scheme = getFirstMatching(availSigAlgs, valid_sig_algs)
            scheme = SignatureScheme.toRepr(signature_scheme)
            signature_scheme = getattr(SignatureScheme, scheme)

            signature_context = KeyExchange.calcVerifyBytes((3, 4), HandshakeHashes(),
                                                            signature_scheme, None, None,
                                                            None, self.prf_name, b'client')

            if signature_scheme in (SignatureScheme.ed25519, SignatureScheme.ed448):
                pad_type = None
                hash_name = "intrinsic"
                salt_len = None
                sig_func = self.privateKey.hashAndSign
                ver_func = self.privateKey.hashAndVerify
            elif signature_scheme[1] == SignatureAlgorithm.ecdsa:
                pad_type = None
                hash_name = HashAlgorithm.toRepr(signature_scheme[0])
                salt_len = None
                sig_func = self.privateKey.sign
                ver_func = self.privateKey.verify
            else:
                pad_type = SignatureScheme.getPadding(scheme)
                hash_name = SignatureScheme.getHash(scheme)
                salt_len = getattr(hashlib, hash_name)().digest_size
                sig_func = self.privateKey.sign
                ver_func = self.privateKey.verify

            signature = sig_func(signature_context,
                                 pad_type,
                                 hash_name,
                                 salt_len)
            
            if not ver_func(signature, signature_context,
                            pad_type,
                            hash_name,
                            salt_len):
                # for result in self._sendError(
                #         AlertDescription.internal_error,
                #         "Certificate Verify signature failed"):
                #     yield result
                return None
            

            certificateVerify = CertificateVerify(self.support_version)
            certificateVerify.create(signature, signature_scheme)
            return certificateVerify

    def generateCertificateVerify(self):
        if self.support_version <= (3,3):
            self._certificate_verify_handshake_hash = self._handshake_hash.copy()
            # Initialize settings if not already done
            if self.settings is None:
                self.settings = HandshakeSettings().validate()
            valid_sig_algs = self._sigHashesToList(self.settings, self.privateKey,
                                                    self.cert_chain)
            if self.CR==None:
                self.CR=CertificateRequest(version=(3,3)).create()
                self.CR.supported_signature_algs=[(4, 3), (5, 3), (6, 3), (8, 7), (8, 8), (8, 9), (8, 10), (8, 11), (8, 4), (8, 5), (8, 6), (4, 1), (5, 1), (6, 1), (3, 3), (2, 3), (3, 1), (2, 1), (3, 2), (2, 2), (4, 2), (5, 2), (6, 2)]
            certificateVerify = KeyExchange.makeCertificateVerify(
                        self.support_version,
                        self._certificate_verify_handshake_hash,
                        valid_sig_algs,
                        self.privateKey,
                        self.CR,
                        self.premasterSecret,
                        self._clientRandom,
                        self._serverRandom)
            # print(dir(certificateVerify))
            # print(certificateVerify.signature)
            # certificateVerify.signature = bytearray(0)
            return certificateVerify
        elif self.support_version >=(3,4):
            # print("!!!!!!!!!!!!!!!!!!!!!!!")
            # self.test_handshake_hash.update(self.CT.write())
            try:
                valid_sig_algs = self.CR.supported_signature_algs
            except:
                valid_sig_algs = RSA_SIG_ALL
            availSigAlgs = self._sigHashesToList(self.settings, self.privateKey,
                                                 self.cert_chain, version=(3, 4))
            signature_scheme = getFirstMatching(availSigAlgs, valid_sig_algs)
            scheme = SignatureScheme.toRepr(signature_scheme)
            signature_scheme = getattr(SignatureScheme, scheme)

            signature_context = KeyExchange.calcVerifyBytes((3, 4), self._handshake_hash,
                                                            signature_scheme, None, None,
                                                            None, self.prf_name, b'client')
            # signature_context = KeyExchange.calcVerifyBytes((3, 4), self.test_handshake_hash,
            #                                                 signature_scheme, None, None,
            #                                                 None, self.prf_name, b'client')
            # print("!!!!!!!")
            if signature_scheme in (SignatureScheme.ed25519, SignatureScheme.ed448):
                pad_type = None
                hash_name = "intrinsic"
                salt_len = None
                sig_func = self.privateKey.hashAndSign
                ver_func = self.privateKey.hashAndVerify
            elif signature_scheme[1] == SignatureAlgorithm.ecdsa:
                pad_type = None
                hash_name = HashAlgorithm.toRepr(signature_scheme[0])
                salt_len = None
                sig_func = self.privateKey.sign
                ver_func = self.privateKey.verify
            else:
                pad_type = SignatureScheme.getPadding(scheme)
                hash_name = SignatureScheme.getHash(scheme)
                salt_len = getattr(hashlib, hash_name)().digest_size
                sig_func = self.privateKey.sign
                ver_func = self.privateKey.verify

            signature = sig_func(signature_context,
                                 pad_type,
                                 hash_name,
                                 salt_len)
            
            if not ver_func(signature, signature_context,
                            pad_type,
                            hash_name,
                            salt_len):
                # for result in self._sendError(
                #         AlertDescription.internal_error,
                #         "Certificate Verify signature failed"):
                #     yield result
                return None
            

            certificateVerify = CertificateVerify(self.support_version)
            certificateVerify.create(signature, signature_scheme)
            
            return certificateVerify
    
    def generateEmptyCertificateVerify(self):
        if self.support_version <= (3,3):
            self._certificate_verify_handshake_hash = self._handshake_hash.copy()
            # Initialize settings if not already done
            if self.settings is None:
                self.settings = HandshakeSettings().validate()
            valid_sig_algs = self._sigHashesToList(self.settings, self.privateKey,
                                                    self.cert_chain)
            if self.CR==None:
                self.CR=CertificateRequest(version=(3,3)).create()
                self.CR.supported_signature_algs=[(4, 3), (5, 3), (6, 3), (8, 7), (8, 8), (8, 9), (8, 10), (8, 11), (8, 4), (8, 5), (8, 6), (4, 1), (5, 1), (6, 1), (3, 3), (2, 3), (3, 1), (2, 1), (3, 2), (2, 2), (4, 2), (5, 2), (6, 2)]
            certificateVerify = KeyExchange.makeCertificateVerify(
                        self.support_version,
                        self._certificate_verify_handshake_hash,
                        valid_sig_algs,
                        self.privateKey,
                        self.CR,
                        self.premasterSecret,
                        self._clientRandom,
                        self._serverRandom)
            # print(dir(certificateVerify))
            # print(certificateVerify.signature)
            certificateVerify.signature = bytearray(0)
            return certificateVerify
        elif self.support_version >=(3,4):
            # print("!!!!!!!!!!!!!!!!!!!!!!!")
            # self.test_handshake_hash.update(self.CT.write())
            try:
                valid_sig_algs = self.CR.supported_signature_algs
            except:
                valid_sig_algs = RSA_SIG_ALL
            availSigAlgs = self._sigHashesToList(self.settings, self.privateKey,
                                                 self.cert_chain, version=(3, 4))
            signature_scheme = getFirstMatching(availSigAlgs, valid_sig_algs)
            scheme = SignatureScheme.toRepr(signature_scheme)
            signature_scheme = getattr(SignatureScheme, scheme)

            signature_context = KeyExchange.calcVerifyBytes((3, 4), self._handshake_hash,
                                                            signature_scheme, None, None,
                                                            None, self.prf_name, b'client')
            # signature_context = KeyExchange.calcVerifyBytes((3, 4), self.test_handshake_hash,
            #                                                 signature_scheme, None, None,
            #                                                 None, self.prf_name, b'client')
            # print("!!!!!!!")
            if signature_scheme in (SignatureScheme.ed25519, SignatureScheme.ed448):
                pad_type = None
                hash_name = "intrinsic"
                salt_len = None
                sig_func = self.privateKey.hashAndSign
                ver_func = self.privateKey.hashAndVerify
            elif signature_scheme[1] == SignatureAlgorithm.ecdsa:
                pad_type = None
                hash_name = HashAlgorithm.toRepr(signature_scheme[0])
                salt_len = None
                sig_func = self.privateKey.sign
                ver_func = self.privateKey.verify
            else:
                pad_type = SignatureScheme.getPadding(scheme)
                hash_name = SignatureScheme.getHash(scheme)
                salt_len = getattr(hashlib, hash_name)().digest_size
                sig_func = self.privateKey.sign
                ver_func = self.privateKey.verify

            signature = sig_func(signature_context,
                                 pad_type,
                                 hash_name,
                                 salt_len)
            
            if not ver_func(signature, signature_context,
                            pad_type,
                            hash_name,
                            salt_len):
                # for result in self._sendError(
                #         AlertDescription.internal_error,
                #         "Certificate Verify signature failed"):
                #     yield result
                return None
            

            certificateVerify = CertificateVerify(self.support_version)
            certificateVerify.create(signature, signature_scheme)
            certificateVerify.signature = bytearray(0)
            return certificateVerify
    
    def changestate(self):
        # print(self.SH)
        if self.SH == None:
            return
        if len(self.premasterSecret) != 0 and len(self._clientRandom) !=0:
            # print("!!!!!!!")
            self.masterSecret = calc_key(self.version, self.premasterSecret,
                                        self._cipherSuite, b"master secret",
                                        client_random=self._clientRandom,
                                        server_random=self._serverRandom,
                                        output_length=48)
        else:
            # print(self.masterSecret.hex())
            if self.masterSecret != bytearray(0):
                pass
            else:
                self.masterSecret = bytearray(b'')
            if self.SH == None:
                self._cipherSuite = self.ciphersuites[0]
        label = b"client finished"
        self.version = (3,3)
        verifyData = calc_key(self.version, self.masterSecret,
                              self._cipherSuite, label,
                              handshake_hashes=self._handshake_hash,
                              output_length=12)
        # print(verifyData.hex())
        self.client_verify_data=verifyData
        if self._cipherSuite == None:
            self._cipherSuite = 49171
        self._calcPendingStates(self._cipherSuite, self.masterSecret, 
                                self._clientRandom,self._serverRandom, 
                                ['python'])
        #for no enc
        # print(self.tlspro.has_to_change_write())
        # if self.tlspro.has_to_change_write():
        self._changeWriteState()

    def keystatechange(self):
        temp = derive_secret(self.handshake_secret, bytearray(b'derived'), None, self.prf_name)
        self.master_secret = secureHMAC(temp, bytearray(self.prf_size), self.prf_name)
        self.cl_app_traffic = derive_secret(self.master_secret, bytearray(b'c ap traffic'),
                                       self.server_finish_hs, self.prf_name)
        if self.sr_app_traffic is None:
            self.sr_app_traffic = derive_secret(self.master_secret, bytearray(b's ap traffic'),
                                                self.server_finish_hs, self.prf_name)
        self.exporter_master_secret = derive_secret(self.master_secret,
                                               bytearray(b'exp master'),
                                               self._handshake_hash, self.prf_name)
        # self.resumption_master_secret = derive_secret(self.master_secret,
        #                                        bytearray(b'res master'),
        #                                        self._handshake_hash, self.prf_name)
        # print(self.SH.cipher_suite,self.cl_app_traffic, self.sr_app_traffic)
        self._recordLayer.calcTLS1_3PendingState(
            self.SH.cipher_suite,
            self.cl_app_traffic,
            self.sr_app_traffic,
            ['python'])

    def generateClientFinished(self):
        self.resume12 = False
        if self.SH == None:
            self.SH = ServerHello()
        if self.SH.cipher_suite == None or self.SH.cipher_suite == 0:
            self.SH.cipher_suite = self.tlspro.cipher_suite[0]
        if self.support_version >= (3,4):
            temp = derive_secret(self.handshake_secret, bytearray(b'derived'), None, self.prf_name)
            self.master_secret = secureHMAC(temp, bytearray(self.prf_size), self.prf_name)
            self.cl_app_traffic = derive_secret(self.master_secret, bytearray(b'c ap traffic'),
                                                self.server_finish_hs, self.prf_name)
            if self.sr_app_traffic is None:
                self.sr_app_traffic = derive_secret(self.master_secret, bytearray(b's ap traffic'),
                                                    self.server_finish_hs, self.prf_name)
            self.exporter_master_secret = derive_secret(self.master_secret,
                                                        bytearray(b'exp master'),
                                                        self._handshake_hash, self.prf_name)

            self._recordLayer.calcTLS1_3PendingState(
                self.SH.cipher_suite,
                self.cl_app_traffic,
                self.sr_app_traffic,
                ['python'])

            if self.key_log_write == True:
                try:
                    self.write_key_log('CLIENT_TRAFFIC_SECRET_0', self._clientRandom, self._serverRandom,
                                       self.cl_app_traffic)
                except:
                    pass

            # print("handshake_secret",self.handshake_secret.hex())
            # print("master_secret",self.master_secret.hex())
            # print("sr_handshake_traffic_secret",self.sr_handshake_traffic_secret.hex())
            # print("cl_handshake_traffic_secret",self.cl_handshake_traffic_secret.hex())
            # print("cl_app_traffic",self.cl_app_traffic.hex())
            # print("sr_app_traffic",self.sr_app_traffic.hex())
            # print("cl_finished_key",cl_finished_key.hex())
            #  and self.tlspro.implementation == 'WolfSSL'
            if self.tlspro.SendEndofEarlyData == True and self.resuming:
                self._handshake_hash.update(bytearray(b'\x05\x00\x00\x00'))
            cl_finished_key = HKDF_expand_label(self.cl_handshake_traffic_secret,
                                                b"finished", b'',
                                                self.prf_size, self.prf_name)
            cl_verify_data = secureHMAC(
                cl_finished_key,
                self._handshake_hash.digest(self.prf_name),
                self.prf_name)
            client_finished = Finished(self.support_version, self.prf_size)
            client_finished.create(cl_verify_data)

            return client_finished
        elif self.support_version <=(3,3):
            client_finished = Finished(self.support_version).create(self.client_verify_data)
            return client_finished
        
    def generateClosureAlert(self):
        closurealert = Alert().create(AlertDescription.close_notify, level=AlertLevel.warning)
        return closurealert
            
    def generateErrorAlert(self):
        erroralert = Alert().create(AlertDescription.decrypt_error, level=AlertLevel.fatal)
        return erroralert
    
    def generateCertificateRequest(self):
        # if self.SH == None:
        #     certificate_type = CertificateType.x509
        # else:
        #     certificate_type = self.SH.certificate_type
        # create(self, certificate_types=None, certificate_authorities=None,
        #        sig_algs=None, context=b'', extensions=None):
        extensions=[SignatureAlgorithmsExtension().create(RSA_SIG_ALL)]
        certificateRequest = CertificateRequest(self.support_version).create(certificate_types=[64, 1],extensions=extensions,certificate_authorities= [b''])
        return certificateRequest
    
    def generateEndOfEarlydata(self):
        # erroralert = Message(contentType=HandshakeType.end_of_early_data,data='0000')
        endofearlydata = EndOfEarlyData().create()
        # self._recordLayer.calcTLS1_3PendingState(
        #                             self.ciphersuites[0],
        #                             self.client_early_traffic_secret,
        #                             self.client_early_traffic_secret,
        #                             self.settings.cipherImplementations)
        # self._changeWriteState()
        return endofearlydata
            
            
    def generateAppData(self):
        # appdata = ApplicationData().create(b"GET / HTTP/1.1\r\nHost: testserver.com\r\n\r\n")
        appdata = ApplicationData().create(b"GET / HTTP/1.0\n\n") # for openssl
        # appdata = ApplicationData().create(b"GET /index.html HTTP/1.0\r\nHost:127.0.0.1\r\nUser-Agent: MatrixSSL/4.6.0-OPEN\r\nAccept: */*\r\nContent-Length: 0\r\n\r\n") # for MatrixSSL

        return appdata
    
    def ResetHandshakeHashes(self):
        self._handshake_hash = HandshakeHashes()

    def TLS12ReClientHello(self):
        # print(self.version)
        self.resume12 = True
        self.ResetHandshakeHashes()
        # self._changeReadState()
        # self._changeWriteState()
        ext_dir = {ExtensionType.renegotiation_info: None}
        ext_dir[ExtensionType.extended_master_secret] = TLSExtension().create(ExtensionType.extended_master_secret,bytearray())
        # groups = [GroupName.secp256r1, GroupName.ffdhe2048]
        # ext_dir[ExtensionType.supported_groups] = SupportedGroupsExtension() \
        #     .create(groups)
        # ext_dir[ExtensionType.signature_algorithms] = \
        #     SignatureAlgorithmsExtension().create(RSA_SIG_ALL)
        # ext_dir[ExtensionType.signature_algorithms_cert] = \
        #     SignatureAlgorithmsCertExtension().create(RSA_SIG_ALL)
        # ext = ext
        extensions = []
        # print(ext_dir)
        for ext_id in ext_dir:
            if ext_dir[ext_id] is not None:
                if callable(ext_dir[ext_id]):
                    extensions.append(ext_dir[ext_id])
                elif isinstance(ext_dir[ext_id], TLSExtension):
                    extensions.append(ext_dir[ext_id])
                elif ext_dir[ext_id] is AutoEmptyExtension():
                    extensions.append(TLSExtension().create(ext_id,
                                                            bytearray()))
                else:
                    raise ValueError("Bad extension, id: {0}".format(ext_id))
                continue

            if ext_id == ExtensionType.renegotiation_info:
                ext = RenegotiationInfoExtension()\
                    .create(bytearray())
                    # .create(self.client_verify_data)
                    
            elif ext_id == ExtensionType.status_request:
                ext = StatusRequestExtension().create()
            elif ext_id in (ExtensionType.client_hello_padding,
                            ExtensionType.encrypt_then_mac,
                            ExtensionType.extended_master_secret,
                            35,  # session_ticket
                            49,  # post_handshake_auth
                            52):  # transparency_info
                ext = TLSExtension().create(ext_id, bytearray())
            else:
                raise ValueError("No autohandler for extension {0}"
                                 .format(ExtensionType.toStr(ext_id)))
            extensions.append(ext)    
        # if self.support_version <= (3,3):
            # print(self.version)
        # session_id = b''
        session_id = self.session_id
        client_random=bytes.fromhex(str(hex(int(time.time())))[2:])+os.urandom(28)
        # extensions = self.generate_extensions()
        clientHello = ClientHello()
        clientHello.create(self.version,
                            client_random,
                            session_id,
                            self.ciphersuites,
                            extensions=extensions)


        return clientHello
    
    def sendpck(self,pck):
        # pck = bytes.fromhex('16030301080f000104080601004788173a9305ad249c3462e18d6bedf40bfd74e0c8152c533552cd9a7fec27a7246073c2c4463746cf17c11e6f1ecb25f37418067835c38f7876ab984a4eaeac174913a4fc0fddbf3f3afa48bc6586d4ee033e0973473d58d6886d92bdc99964153c872e9d3ff6a8edff08b957885d9cc86ffb4feb25fd53f2f5f7506a83dc1f1f3159e1de5eeba5df94fc4838fe8d86494d526d1a1f103d6faa732e07846a9aa765b10909c95c8f04f740e533207646e8a086e550fc0384a32d144f4af858cfe8672b7b40676d14be8957b991b47da44dfbcb50e9597c11d1a8d0edb3ff93253eb1d7e58bdfb0e9381bb6769274cb2cc1c3dceea972482918bca4c1130fd5b7')
        # print(dir(self._handshake_hash))
        self._handshake_hash.update(bytearray(pck[5:]))
        # print(self._handshake_hash._handshake_buffer.hex())
        for result in self._recordLayer._recordSocket._sockSendAll(pck):
            pass

    def fuzz_empty_keyshare_zero(self):
        pck = bytes.fromhex('160303016e0100016a030368ff2f857f4ea8b6dd60aa4271b40a39aa24259a37fe97200e08aa8d6761fa1000000a13011302c02cccaac03001000137002b0003020304000a000400020100000d001a00180601050104010301020101010804080508060809080a080b0033010601040100010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000')
        self._handshake_hash.update(bytearray(pck[5:]))
        
        y=Parser(pck[6:])
        x=ClientHello().parse(y)
        # print(x)
        self.CH = x
        for result in self._recordLayer._recordSocket._sockSendAll(pck):
            pass

        self.CH.getExtension(ExtensionType.key_share).client_shares[0].private = 1
        cl_key_share_ex = self.CH.getExtension(ExtensionType.key_share)
        # print(cl_key_share_ex)
        # print(dir(cl_key_share_ex))
        # print(dir(cl_key_share_ex.client_shares[0]))
        # print(cl_key_share_ex.client_shares[0].group,cl_key_share_ex.client_shares[0].private,cl_key_share_ex.client_shares[0].key_exchange)
        # cl_kex = next((i for i in cl_key_share_ex.client_shares
        #         if i.group == sr_kex.group), None)
        # kex = self._getKEX(sr_kex.group, self.support_version)
        # shared_sec = kex.calc_shared_key(cl_kex.private, sr_kex.key_exchange)
        # x=ClientHello()
        # x.parse(pck[5:])
        # print(dir(x))

    def sendpck1(self):
        pck = bytes.fromhex('16030300060f0000020804')
        # pck = bytes.fromhex('16030300050f00000108')
        pck = bytes.fromhex('16030300040f000000')
        pck = bytes.fromhex('160303000b0f00000708040003ac9622')
        # print(bytearray(os.urandom(3)))
        pck = bytes.fromhex('160303000b0f00000708040003')+bytearray(os.urandom(3))
        self._handshake_hash.update(bytearray(pck[5:]))
        for result in self._recordLayer._recordSocket._sockSendAll(pck):
            pass

    def sendpck2(self):
        pck = bytes.fromhex('160300002f0100002b03030000000000000000000000000000000000000000000000000000000000000000000004002f00ff0100')
        # pck = bytes.fromhex('160300010901000105030300000000000000000000000000000000000000000000000000000000000000002010a7b0908ef647a477c9e0420cd509b05b1ac94b2ef9f9802641f81fc74a611a0004130100ff010000b80033006700650018006104000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002b00050403040303000a000400020018000d000c000a08040809060305030403003200280026080b080a08090806080508040601050104010301020101010603050304030303020308080807')
        # pck = bytes.fromhex('160300002f0100002b03030000000000000000000000000000000000000000000000000000000000000000000004002f00ff01001603000046100000424104df8e20a2d6318ff8eddffc1948d2ec650ae841ed879bf6e6f5eba05292c2976031529f2b0fa3ce715b598359ee46c14d951f26be7ac52a7a8f2dfe623baae2e9')

        
        for result in self._recordLayer._recordSocket._sockSendAll(pck):
            pass
    
    # def sendpck1(self,pck):
    #     # pck = bytes.fromhex('16030301080f00010408060100b9b9301a22a4066b27b2187277eb79947293f3065a857dac0abcbe020090c0d607576a8c902f58d7d25a9a38c4e10eb06b33b87e88bab623cf24495dd8b4b2fc01a14b5dcdea3fc00775ed3babf2f9d0e3886f550d809c28582ca36a7345918459a7a384b8554bb166b862bd4eca9ca5ce33a70f5113664b83d649434ff8c7508454a5e3bb044a8a1f7b5e9aeb30731a7dee11c159f7bdeaa502f5612ad4817a6bc4737612a8b3cae16856dfce338a3cc48865fd750210daaba823d8ae77d5fe750fa8aa0dc24c9ccc78aeff6b4e2081c4662886c68878945b9e43db3c17f5e6ef7afb2acb509a03f0d6dcd09d96964563139f305320a84e5ffd6715d5d45cec')
    #     # for result in self._recordLayer._recordSocket._sockSendAll(pck):
    #         # yield result
    #     self._recordLayer._recordSocket._sockSendAll(pck)

    def generateResumptionClientHello(self):
        if self.nst != None:
            self.resumption_master_secret = derive_secret(self.master_secret,
                                                bytearray(b'res master'),
                                                self._handshake_hash, self.prf_name)
            nst=self.nst
            ident = []
            binder = []
            self._handshake_hash=HandshakeHashes()
            # nst.time is fractional but ticket time should be in ms, not s as the
            # NewSessionTicket.time is
            # ticket_time = int(time.time() * 1000 - nst.ticket_lifetime * 1000 +   nst.ticket_age_add) % 2**32
            ticket_time = int(time.time() * 1000 - self.nst_received_time +   nst.ticket_age_add) % 2**32

            ticket_iden = PskIdentity().create(nst.ticket, ticket_time)
            binder_len = self.prf_size
            ident.insert(0, ticket_iden)
            binder.insert(0, bytearray(binder_len))
            self.extensions[ExtensionType.pre_shared_key] = PreSharedKeyExtension().create(ident, binder)



            ext=[]
            for ext_id in self.extensions:
                if self.extensions[ext_id] is not None:
                        ext.append(self.extensions[ext_id])

            client_random=bytes.fromhex(str(hex(int(time.time())))[2:])+os.urandom(28)
            clientHello = ClientHello()
            self.session_id = getRandomBytes(32)

            clientHello.create((3,3),
                            client_random,
                            self.session_id,
                            self.ciphersuites,
                            extensions=ext)
            HandshakeHelpers.update_binders(
                clientHello,
                self._handshake_hash,
                (),
                [nst] if nst else None,
                self.resumption_master_secret)
            clientHello.extensions[0]=SupportedVersionsExtension().create([(3,3)])
            # clientHello.extensions.pop(3)
            # pck=clientHello.write()
            # lenbyt=len(pck)
            # x=lenbyt.to_bytes(2, byteorder='big')
            # pck=b'\x16\x03\x03'+x+pck
            # print(pck)
            # for result in self._recordLayer._recordSocket._sockSendAll(pck):
            #     pass
            # return
            # print(clientHello.extensions)
            # print(clientHello.extensions)
            # for i in range(len(clientHello.extensions)):
            #     print(i,clientHello.extensions[i])
            return clientHello
        else:
            pass
    
    def generateResumptionClientHelloAD(self):
        if self.nst != None:
            self.resumption_master_secret = derive_secret(self.master_secret,
                                                bytearray(b'res master'),
                                                self._handshake_hash, self.prf_name)
            nst=self.nst
            ident = []
            binder = []
            self._handshake_hash=HandshakeHashes()
            # nst.time is fractional but ticket time should be in ms, not s as the
            # NewSessionTicket.time is
            # ticket_time = int(time.time() * 1000 - nst.ticket_lifetime * 1000 +   nst.ticket_age_add) % 2**32
            ticket_time = int(time.time() * 1000 - self.nst_received_time +   nst.ticket_age_add) % 2**32

            ticket_iden = PskIdentity().create(nst.ticket, ticket_time)
            binder_len = self.prf_size
            ident.insert(0, ticket_iden)
            binder.insert(0, bytearray(binder_len))
            self.extensions[ExtensionType.pre_shared_key] = PreSharedKeyExtension().create(ident, binder)

            ext=[]
            for ext_id in self.extensions:
                if self.extensions[ext_id] is not None:
                        ext.append(self.extensions[ext_id])

            ext.insert(len(ext)-1,TLSExtension().create(ExtensionType.early_data,bytearray()))
            client_random=bytes.fromhex(str(hex(int(time.time())))[2:])+os.urandom(28)
            clientHello = ClientHello()
            self.session_id = getRandomBytes(32)

            clientHello.create((3,3),
                            client_random,
                            self.session_id,
                            self.ciphersuites,
                            extensions=ext)
            HandshakeHelpers.update_binders(
                clientHello,
                self._handshake_hash,
                (),
                [nst] if nst else None,
                self.resumption_master_secret)
            # clientHello.extensions[0]=SupportedVersionsExtension().create([(3,3)])
            clientHello.extensions.pop(3)

            return clientHello
        
        else:
            pass

    def generateKeyUpdate(self):
        key_update = KeyUpdate().create(KeyUpdateMessageType.update_requested)
        # key_update = KeyUpdate().create(KeyUpdateMessageType.update_not_requested)

        
        # self._changeReadState()
        # self._changeWriteState()
        return key_update       
     
    def _check_certchain_with_settings(self, cert_chain, settings):
        """
        Verify that the key parameters match enabled ones.

        Checks if the certificate key size matches the minimum and maximum
        sizes set or that it uses curves enabled in settings
        """
        #Get and check public key from the cert chain
        publicKey = cert_chain.getEndEntityPublicKey()
        cert_type = cert_chain.x509List[0].certAlg
        if cert_type == "ecdsa":
            curve_name = publicKey.curve_name
            for name, aliases in CURVE_ALIASES.items():
                if curve_name in aliases:
                    curve_name = name
                    break

            if self.version <= (3, 3) and curve_name not in settings.eccCurves:
                for result in self._sendError(
                        AlertDescription.handshake_failure,
                        "Peer sent certificate with curve we did not "
                        "advertise support for: {0}".format(curve_name)):
                    yield result
            if self.version >= (3, 4):
                if curve_name not in ('secp256r1', 'secp384r1', 'secp521r1'):
                    for result in self._sendError(
                            AlertDescription.illegal_parameter,
                            "Peer sent certificate with curve not supported "
                            "in TLS 1.3: {0}".format(curve_name)):
                        yield result
                if curve_name == 'secp256r1':
                    sig_alg_for_curve = 'sha256'
                elif curve_name == 'secp384r1':
                    sig_alg_for_curve = 'sha384'
                else:
                    assert curve_name == 'secp521r1'
                    sig_alg_for_curve = 'sha512'
                if sig_alg_for_curve not in settings.ecdsaSigHashes:
                    for result in self._sendError(
                            AlertDescription.illegal_parameter,
                            "Peer selected certificate with ECDSA curve we "
                            "did not advertise support for: {0}"
                            .format(curve_name)):
                        yield result
        elif cert_type in ("Ed25519", "Ed448"):
            if self.version < (3, 3):
                for result in self._sendError(
                        AlertDescription.illegal_parameter,
                        "Peer sent certificate incompatible with negotiated "
                        "TLS version"):
                    yield result
            if cert_type not in settings.more_sig_schemes:
                for result in self._sendError(
                        AlertDescription.handshake_failure,
                        "Peer sent certificate we did not advertise support "
                        "for: {0}".format(cert_type)):
                    yield result

        else:
            # for RSA and DSA keys
            if len(publicKey) < settings.minKeySize:
                for result in self._sendError(
                        AlertDescription.handshake_failure,
                        "Other party's public key too small: %d" %
                        len(publicKey)):
                    yield result
            if len(publicKey) > settings.maxKeySize:
                for result in self._sendError(
                        AlertDescription.handshake_failure,
                        "Other party's public key too large: %d" %
                        len(publicKey)):
                    yield result
        yield publicKey

    def _clientGetKeyFromChain(self, certificate, settings, tack_ext=None):
        #Get and check cert chain from the Certificate message
        cert_chain = certificate.cert_chain
        if not cert_chain or cert_chain.getNumCerts() == 0:
            for result in self._sendError(
                    AlertDescription.illegal_parameter,
                    "Other party sent a Certificate message without "\
                    "certificates"):
                yield result

        for result in self._check_certchain_with_settings(
                cert_chain,
                settings):
            if result in (0, 1):
                yield result
            else: break
        public_key = result

        # If there's no TLS Extension, look for a TACK cert
        if tackpyLoaded:
            if not tack_ext:
                tack_ext = cert_chain.getTackExt()
         
            # If there's a TACK (whether via TLS or TACK Cert), check that it
            # matches the cert chain   
            if tack_ext and tack_ext.tacks:
                for tack in tack_ext.tacks:
                    if not cert_chain.checkTack(tack):
                        for result in self._sendError(  
                                AlertDescription.illegal_parameter,
                                "Other party's TACK doesn't match their public key"):
                                yield result

        yield public_key, cert_chain, tack_ext


    @classmethod
    def _genKeyShareEntry(cls, group, version):
        """Generate KeyShareEntry object from randomly selected private value.
        """
        kex = cls._getKEX(group, version)
        private = kex.get_random_private_key()
        share = kex.calc_public_value(private)
        return KeyShareEntry().create(group, share, private)

    @staticmethod
    def _getKEX(group, version):
        """Get object for performing key exchange."""
        if group in GroupName.allFF:
            return FFDHKeyExchange(group, version)
        return ECDHKeyExchange(group, version)
    
    @staticmethod
    def _getPRFParams(cipher_suite):
        """Return name of hash used for PRF and the hash output size."""
        if cipher_suite in CipherSuite.sha384PrfSuites:
            return 'sha384', 48
        return 'sha256', 32

    def server_extensions_is_wrong(self, smsg_type, server_extensions):
        client_extensions = [ens.extType for ens in self.CH.extensions]
        for en in server_extensions:
            if en not in client_extensions:
                if smsg_type == HandshakeType.hello_retry_request and en == ExtensionType.cookie:
                    continue
                return True
        if ExtensionType.psk_key_exchange_modes in server_extensions:
            return True
        if ExtensionType.post_handshake_auth in server_extensions:
            return True
        return False
    
    @staticmethod
    def _curve_name_to_hash_name(curve_name):
        """Find the matching hash given the curve name, as specified in TLS 1.3."""
        if curve_name == "NIST256p":
            return "sha256"
        if curve_name == "NIST384p":
            return "sha384"
        if curve_name == "NIST521p":
            return "sha512"
        raise ValueError("Curve {0} is not allowed in TLS 1.3 "
                        "(wrong name? please use python-ecdsa names)"
                        .format(curve_name))
    

    def server_extensions_is_wrong(self, smsg_type, server_extensions):
        client_extensions = [ens.extType for ens in self.CH.extensions]
        for en in server_extensions:
            if en not in client_extensions:
                if smsg_type == HandshakeType.hello_retry_request and en == ExtensionType.cookie:
                    continue
                return True
        if ExtensionType.psk_key_exchange_modes in server_extensions:
            return True
        if ExtensionType.post_handshake_auth in server_extensions:
            return True
        return False
        
    def process_recieve(self):
        
        receive_msg = ''
        while True:
            try:
                for result in self._getMsg(ContentType.all, HandshakeType.all):
                    pass
            except Exception as e:
                break
            recordHeader, p = result
            if recordHeader.type == ContentType.change_cipher_spec:
                ccs = ChangeCipherSpec().parse(p)
                receive_msg += '-ChangeCipherSpec'
                if self.support_version <= (3,3):
                    # print(self.masterSecret,self.resuming)
                    if self.resume12 == True:
                        self._calcPendingStates(self._cipherSuite, self.masterSecret, 
                                self._clientRandom,self._serverRandom, 
                                ['python'])
                    #for no enc
                    # print(self.tlspro.has_to_change_write())
                    # if self.tlspro.has_to_change_write():
                    self._changeReadState()
            if recordHeader.type == ContentType.application_data:
                appdata = ApplicationData().parse(p)
                receive_msg += '-AppliciationData'
            if recordHeader.type == ContentType.alert:
                alert = Alert().parse(p)
                receive_msg += '-' + alert.descriptionName
            if recordHeader.type == ContentType.handshake:
                subType = p.get(1)
                # self._handshake_hash.update(p.bytes)                
                if subType == HandshakeType.client_hello:
                    # print(p.bytes)
                    self._handshake_hash.update(p.bytes)
                    receive_msg += '-ClientHello'               
                if subType == HandshakeType.key_update:
                    if p.get(2) == 0:
                        receive_msg += '-keyUpdate_not_req'
                        # print(self.keyUpdate_not_req)
                        # if self.keyUpdate_not_req == False:
                        self.cl_app_traffic,self.sr_app_traffic = self._recordLayer.calcTLS1_3KeyUpdate_sender(
                                    self.SH.cipher_suite,
                                    self.cl_app_traffic,
                                    self.sr_app_traffic)
                        self._recordLayer.calcTLS1_3PendingState(
                                    self.SH.cipher_suite,
                                    self.cl_app_traffic,
                                    self.sr_app_traffic,
                                    ['python'])
                        # self._recordLayer.calcTLS1_3KeyUpdate_reciever(
                        #             self.SH.cipher_suite,
                        #             self.cl_app_traffic,
                        #             self.sr_app_traffic)
                        # self.keyUpdate_not_req = True
                        
                    if p.get(2) == 1:
                        receive_msg += '-keyUpdate_req'
                    # if self.keyUpdate_not_req == False:
                        self._recordLayer.calcTLS1_3KeyUpdate_sender(
                                    self.SH.cipher_suite,
                                    self.cl_app_traffic,
                                    self.sr_app_traffic)                

                if subType == HandshakeType.hello_retry_request:
                    self._handshake_hash.update(p.bytes)
                    helloRetryRequest = ServerHello().parse(p)
                    server_ens = [ens.extType for ens in helloRetryRequest.extensions]
                    if self.server_extensions_is_wrong(subType, server_ens):
                        receive_msg += '-HelloRetryRequestWithWrongENs'
                    else:
                        receive_msg += '-HelloRetryRequest'

                if subType == HandshakeType.server_hello:
                    # 
                    serverHello = ServerHello().parse(p)
                    self.SH = serverHello
                    # print(serverHello)
                    if serverHello.extensions == None:
                        self.support_version = (3,3)
                        self.version = (3,3)

                    elif SrvSupportedVersionsExtension().create((3,4)) in serverHello.extensions:
                        self.support_version = (3,4)
                        self.version = (3,4)
                    else:
                        self.version = (3,3)
                        self.support_version = (3,3)
                    # print(self.support_version)
                    if self.support_version <= (3,3):
                        self._handshake_hash.update(p.bytes)
                        # print(p.bytes)

                        # print(serverHello)
                        # server_ens = [ens.extType for ens in serverHello.extensions]
                        # sr_kex = serverHello.getExtension(ExtensionType.key_share)
                        # print(dir(serverHello))
                        self.session_id = serverHello.session_id
                        # print(self.session_id)
                        self._serverRandom = serverHello.random

                        self._cipherSuite = serverHello.cipher_suite
                        self.prf_name = 'sha384' if self._cipherSuite in CipherSuite.sha384PrfSuites else 'sha256'
                        self.prf_size = 48 if self._cipherSuite in CipherSuite.sha384PrfSuites else 32
                        receive_msg += '-ServerHello'
                    elif self.support_version >= (3,4):
                        server_ens = [ens.extType for ens in serverHello.extensions]
                        sr_kex = serverHello.getExtension(ExtensionType.key_share)
                        # print(sr_kex.extType)
                        # print(sr_kex)
                        # print(dir(sr_kex))
                        # self.hrr = True
                        # if self.hrr ==True or :
                        if 'server_share' not in dir(sr_kex):
                            prf_name, prf_size = self._getPRFParams(serverHello.cipher_suite)
                            self._ch_hh = self._handshake_hash.copy()
                            ch_hash = self._ch_hh.digest(prf_name)
                            new_hh = HandshakeHashes()
                            writer = Writer()
                            writer.add(HandshakeType.message_hash, 1)
                            writer.addVarSeq(ch_hash, 1, 3)
                            new_hh.update(writer.bytes)
                            new_hh.update(p.bytes)
                            self._handshake_hash = new_hh
                            receive_msg += '-ServerHelloRetryRequest'
                            if self.tlspro.SendEarlyData == True:
                                self._changeWriteState()

                        else:
                            self._handshake_hash.update(p.bytes)
                            # self.test_handshake_hash.update(p.bytes)
                            sr_psk = serverHello.getExtension(ExtensionType.pre_shared_key)
                            self._serverRandom = serverHello.random
                            self._cipherSuite = serverHello.cipher_suite
                            self.prf_name, self.prf_size = self._getPRFParams(serverHello.cipher_suite)
                            group_is_wrong = False
                            if not sr_kex and not sr_psk:
                                # raise TLSIllegalParameterException("Server did not select PSK nor an (EC)DH group")
                                group_is_wrong = True
                            if sr_kex:
                                # print(sr_kex)
                                # prinr(sr_kex)
                                # print(dir(sr_kex))
                                sr_kex = sr_kex.server_share
                                self.ecdhCurve = sr_kex.group
                                cl_key_share_ex = self.CH.getExtension(ExtensionType.key_share)
                                # print(cl_key_share_ex.client_shares[0].group,cl_key_share_ex.client_shares[0].private,cl_key_share_ex.client_shares[0].key_exchange)

                                cl_kex = next((i for i in cl_key_share_ex.client_shares
                                            if i.group == sr_kex.group), None)
                                if cl_kex is None:
                                    # raise TLSIllegalParameterException("Server selected not advertised group.")
                                    group_is_wrong = True
                                kex = self._getKEX(sr_kex.group, self.support_version)
                                # print(cl_kex.private)
                                shared_sec = kex.calc_shared_key(cl_kex.private, sr_kex.key_exchange)
                            else:
                                shared_sec = bytearray(self.prf_size)

                            # print("shared_sec:",shared_sec.hex())
                            # print("sr_kex.key_exchange:",sr_kex.key_exchange.hex())
                            # shared_sec=bytearray(0)
                            # check server extensions
                            client_ens = [ens.extType for ens in self.CH.extensions]
                            if self.server_extensions_is_wrong(subType, server_ens) or group_is_wrong:
                                receive_msg += '-ServerHelloWithWrongENs'
                            elif sr_psk and ExtensionType.psk_key_exchange_modes not in client_ens:
                                receive_msg += '-ServerHelloWithWrongENs'                            
                            elif sr_kex and ExtensionType.key_share not in client_ens:
                                receive_msg += '-ServerHelloWithWrongENs'
                            elif sr_psk:
                                receive_msg += '-ServerHelloPSK'
                            else:
                                receive_msg += '-ServerHello'
                            # receive_msg += '-ServerHello'
                            # print(p.bytes)
                            # if server agreed to perform resumption, find the matching secret key
                            self.resuming = False
                            if sr_psk:
                                clPSK = self.CH.getExtension(ExtensionType.pre_shared_key)
                                ident = clPSK.identities[sr_psk.selected]
                                # Initialize settings if not already done
                                if self.settings is None:
                                    self.settings = HandshakeSettings().validate()
                                psk = [i[1] for i in self.settings.pskConfigs if i[0] == ident.identity]
                                if psk:
                                    psk = psk[0]
                                else:
                                    self.resuming = True
                                    psk = HandshakeHelpers.calc_res_binder_psk(
                                        ident, self.old_session[0],
                                        [self.old_session[1]])
                                    # psk = HandshakeHelpers.calc_res_binder_psk(
                                    #     ident, session.resumptionMasterSecret,
                                    #     session.tickets)
                            else:
                                psk = bytearray(self.prf_size)

                                # Early Secret
                            self.early_secret = secureHMAC(bytearray(self.prf_size), psk, self.prf_name)
                            # print(self.early_secret.hex())
                        
                            # Handshake Secret
                            temp = derive_secret(self.early_secret, bytearray(b'derived'),
                                                None, self.prf_name)
                            self.handshake_secret = secureHMAC(temp, shared_sec, self.prf_name)
                            # print(self.handshake_secret.hex())
                            # self.handshake_secret=bytes.fromhex('0f98ead138ee983dadb26c6061a269c88e2df278e2cb896c5d8111742897023a')
                            # print(self._handshake_hash._handshake_buffer.hex())

                            self.sr_handshake_traffic_secret = derive_secret(self.handshake_secret,
                                                                        bytearray(b's hs traffic'),
                                                                        self._handshake_hash,
                                                                        self.prf_name)
                            self.cl_handshake_traffic_secret = derive_secret(self.handshake_secret,
                                                                        bytearray(b'c hs traffic'),
                                                                        self._handshake_hash,
                                                                        self.prf_name)
                            # self.sr_handshake_traffic_secret = derive_secret(self.handshake_secret,
                            #                                             bytearray(b's hs traffic'),
                            #                                             self.test_handshake_hash,
                            #                                             self.prf_name)
                            # self.cl_handshake_traffic_secret = derive_secret(self.handshake_secret,
                            #                                             bytearray(b'c hs traffic'),
                            #                                             self.test_handshake_hash,
                            #                                             self.prf_name)
                            # self.test_handshake_hash.update(p.bytes)
                            # print(f"[KEY] Handshake Secret派生完成")
                            # print(f"  - Early Secret: {self.early_secret.hex()[:32]}...")
                            # print(f"  - Handshake Secret: {self.handshake_secret.hex()[:32]}...")
                            # print(f"  - Server HS Traffic: {self.sr_handshake_traffic_secret.hex()[:32]}...")
                            # print(f"  - Client HS Traffic: {self.cl_handshake_traffic_secret.hex()[:32]}...")

                            # print(self.sr_handshake_traffic_secret.hex(),self.cl_handshake_traffic_secret.hex())

                            if self.key_log_write == True:
                                try:
                                    self.write_key_log('SERVER_HANDSHAKE_TRAFFIC_SECRET', self._clientRandom, self._serverRandom,
                                            self.sr_handshake_traffic_secret)
                                    self.write_key_log('CLIENT_HANDSHAKE_TRAFFIC_SECRET', self._clientRandom, self._serverRandom,
                                            self.cl_handshake_traffic_secret)
                                except:
                                    pass

                            #WolfSSL using this
                            # Initialize settings if not already done
                            # print(self.settings.cipherImplementations)
                            if self.settings is None:
                                self.settings = HandshakeSettings().validate()
                            self._recordLayer.calcTLS1_3PendingState(
                                    self.SH.cipher_suite,
                                    self.cl_handshake_traffic_secret,
                                    self.sr_handshake_traffic_secret,
                                    self.settings.cipherImplementations)
                            # if se
                            #for no enc
                            # print(self.tlspro.has_to_change_write(),self.tlspro.has_to_change_read())
                            # if self.tlspro.has_to_change_write():
                            #     self._changeReadState()
                            #     self._changeWriteState()
                            # print(self.tlspro.has_to_change_write(),self.tlspro.has_to_change_read())
                            
                            self._changeReadState()
                            self._changeWriteState()
                    
                if subType == HandshakeType.encrypted_extensions:
                    self._handshake_hash.update(p.bytes)
                    encryptedExtensions = EncryptedExtensions().parse(p)
                    server_ens = [ens.extType for ens in encryptedExtensions.extensions]
                    if self.server_extensions_is_wrong(subType, server_ens):
                        receive_msg += '-EncryptedExtensionsWithWrongENs'
                    else:
                        receive_msg += '-EncryptedExtensions'
                # if subType == HandshakeType.certificate_request:
                #     self.CR = CertificateRequest(self.version).parse(p)
                #     receive_msg += '-CertificateRequest'  
                if subType == HandshakeType.certificate_request:
                    if self.version > (3,3):
                        self._handshake_hash.update(p.bytes)
                        self.CR = CertificateRequest(self.support_version).parse(p)
                        if self.post_handshake:
                            receive_msg += '-CertificateRequestPostHandshake' 
                        else:
                            receive_msg += '-CertificateRequest' 
                    else:
                        self._handshake_hash.update(p.bytes)
                        self.CR = CertificateRequest(self.support_version).parse(p)
                        # print(dir(self.CR))
                        # print(self.CR.certificate_request_context,self.CR.certificate_types,self.CR.extensions,self.CR.certificate_authorities)
                        receive_msg += '-CertificateRequest'  


                if subType == HandshakeType.certificate:
                    
                    if self.support_version > (3,3):
                        self._handshake_hash.update(p.bytes)
                        self.SC = Certificate(self.SH.certificate_type, self.support_version).parse(p)
                        receive_msg += '-Certificate'
                        srv_cert_verify_hh = self._handshake_hash.copy()
                    else:
                        self._handshake_hash.update(p.bytes)
                        self.SC = Certificate(CertificateType.x509, self.support_version).parse(p)
                        # print(dir(self.SC))
                        # self.SC = Certificate(self.SH.certificate_type, self.version).parse(p)
                        receive_msg += '-Certificate'
                    
                if subType == HandshakeType.certificate_verify:
                    if self.support_version >(3,3):
                        self._handshake_hash.update(p.bytes)
                        certificate_verify = CertificateVerify(self.support_version).parse(p)
                        receive_msg += '-CertificateVerify'
                        signature_scheme = certificate_verify.signatureAlgorithm
                        self.serverSigAlg = signature_scheme
                        signature_context = KeyExchange.calcVerifyBytes((3, 4),
                                                                        srv_cert_verify_hh,
                                                                        signature_scheme,
                                                                        None, None, None,
                                                                        self.prf_name, b'server')
                        # Initialize settings if not already done
                        if self.settings is None:
                            self.settings = HandshakeSettings().validate()
                        for result in self._clientGetKeyFromChain(self.SC, self.settings):
                            pass
                        publicKey, serverCertChain, tackExt = result
                        if signature_scheme in (SignatureScheme.ed25519, SignatureScheme.ed448):
                            pad_type = None
                            hash_name = "intrinsic"
                            salt_len = None
                            method = publicKey.hashAndVerify
                        elif signature_scheme[1] == SignatureAlgorithm.ecdsa:
                            pad_type = None
                            hash_name = HashAlgorithm.toRepr(signature_scheme[0])
                            matching_hash = self._curve_name_to_hash_name(
                                publicKey.curve_name)
                            if hash_name != matching_hash:
                                raise TLSIllegalParameterException(
                                    "server selected signature method invalid for the "
                                    "certificate it presented (curve mismatch)")

                            salt_len = None
                            method = publicKey.verify
                        else:
                            scheme = SignatureScheme.toRepr(signature_scheme)
                            pad_type = SignatureScheme.getPadding(scheme)
                            hash_name = SignatureScheme.getHash(scheme)
                            salt_len = getattr(hashlib, hash_name)().digest_size
                            method = publicKey.verify

                        transcript_hash = self._handshake_hash.digest(self.prf_name)
                    else:
                        self._handshake_hash.update(p.bytes)
                        certificate_verify = CertificateVerify(self.support_version).parse(p)
                        receive_msg += '-CertificateVerify'

                if subType == HandshakeType.server_key_exchange:
                    self._handshake_hash.update(p.bytes)

                    # print(self._cipherSuite,ContentType.handshake)
                    serverKeyExchange=ServerKeyExchange(
                                            cipherSuite=self._cipherSuite, version=self.support_version).parse(p)
                    # serverKeyExchange=ServerKeyExchange(HandshakeType.server_key_exchange,
                    #                         self.version).parse(p)
                    
                    self.SKE=serverKeyExchange
                    receive_msg += '-serverKeyExchange'
                    if self.support_version >= (3, 3) \
                            and (self._cipherSuite in CipherSuite.certAllSuites or
                                    self._cipherSuite in CipherSuite.ecdheEcdsaSuites) \
                            and self._cipherSuite not in CipherSuite.certSuites:
                        self.serverSigAlg = (serverKeyExchange.hashAlg,
                                    serverKeyExchange.signAlg)
                    if self._cipherSuite in CipherSuite.dhAllSuites:
                        self.dhGroupSize = numBits(serverKeyExchange.dh_p)
                    if self._cipherSuite in CipherSuite.ecdhAllSuites:
                        self.ecdhCurve = serverKeyExchange.named_curve

                if subType == HandshakeType.server_hello_done:
                    self._handshake_hash.update(p.bytes)

                    receive_msg += '-ServerHelloDone'

                if subType == HandshakeType.finished:
                    # self._handshake_hash.update(p.bytes)

                    if self.support_version >= (3,4):
                        self._handshake_hash.update(p.bytes)
                        # receive_msg += '-Finished'
                        self.server_finish_hs = self._handshake_hash.copy()      
                        self.server_finish_received = True              
                        
                        temp = derive_secret(self.handshake_secret, bytearray(b'derived'), None, self.prf_name)
                        self.master_secret = secureHMAC(temp, bytearray(self.prf_size), self.prf_name)
                        self.sr_app_traffic = derive_secret(self.master_secret, bytearray(b's ap traffic'),
                                                    self.server_finish_hs, self.prf_name)
                        self.exporter_master_secret = derive_secret(self.master_secret,
                                                            bytearray(b'exp master'),
                                                            self._handshake_hash, self.prf_name)
                        if self.key_log_write == True:
                            try:
                                self.write_key_log('EXPORTER_SECRET', self._clientRandom, self._serverRandom,
                                                self.exporter_master_secret)
                                self.write_key_log('SERVER_TRAFFIC_SECRET_0', self._clientRandom, self._serverRandom,
                                                self.sr_app_traffic)
                            except:
                                pass

                        self._recordLayer.calcTLS1_3PendingState(
                            self.SH.cipher_suite,
                            self.cl_handshake_traffic_secret,
                            self.sr_app_traffic,
                            ['python'])
                        
                        # except mebdtls
                        # self._changeReadState()

                        if self.tlspro.has_to_change_read():
                            self._changeReadState()


                        receive_msg += '-Finished'
                    else:
                        # print(p.bytes.hex())
                        self._handshake_hash.update(p.bytes)
                        self.server_finish_received = True

                        receive_msg += '-Finished'
     
                    
                if subType == HandshakeType.new_session_ticket:
                    # self._handshake_hash.update(p.bytes)
                    newSessionTicket = NewSessionTicket().parse(p)
                    self.nst=newSessionTicket
                    # print(self.nst)
                    self.nst_received_time = int(time.time() * 1000)

                    if newSessionTicket.ticket_lifetime > 604800:
                        receive_msg += '-NewSessionTicketWrongLifetime'
                    else:
                        receive_msg += '-NewSessionTicket'
                    
                if subType == HandshakeType.end_of_early_data:
                    receive_msg += '-EndofEarlyData'
                    
        return 'NoResponse' if receive_msg == '' else receive_msg.strip('-')
    
    @staticmethod
    def _sigHashesToList(settings, privateKey=None, certList=None,
                         version=(3, 3)):
        """Convert list of valid signature hashes to array of tuples"""
        certType = None
        publicKey = None
        if certList and certList.x509List:
            certType = certList.x509List[0].certAlg
            publicKey = certList.x509List[0].publicKey

        sigAlgs = []

        if not certType or certType == "Ed25519" or certType == "Ed448":
            for sig_scheme in settings.more_sig_schemes:
                if version < (3, 3):
                    # EdDSA is supported only in TLS 1.2 and 1.3
                    continue
                if certType and sig_scheme != certType:
                    continue
                sigAlgs.append(getattr(SignatureScheme, sig_scheme.lower()))

        if not certType or certType == "ecdsa":
            for hashName in settings.ecdsaSigHashes:
                # only SHA256, SHA384 and SHA512 are allowed in TLS 1.3
                if version > (3, 3) and hashName in ("sha1", "sha224"):
                    continue

                # in TLS 1.3 ECDSA key curve is bound to hash
                if publicKey and version > (3, 3):
                    curve = publicKey.curve_name
                    matching_hash = TLSConnection._curve_name_to_hash_name(
                        curve)
                    if hashName != matching_hash:
                        continue

                sigAlgs.append((getattr(HashAlgorithm, hashName),
                                SignatureAlgorithm.ecdsa))

        if not certType or certType == "dsa":
            for hashName in settings.dsaSigHashes:
                if version > (3, 3):
                    continue

                sigAlgs.append((getattr(HashAlgorithm, hashName),
                                SignatureAlgorithm.dsa))

        if not certType or certType in ("rsa", "rsa-pss"):
            for schemeName in settings.rsaSchemes:
                # pkcs#1 v1.5 signatures are not allowed in TLS 1.3
                if version > (3, 3) and schemeName == "pkcs1":
                    continue

                for hashName in settings.rsaSigHashes:
                    # rsa-pss certificates can't be used to make PKCS#1 v1.5
                    # signatures
                    if certType == "rsa-pss" and schemeName == "pkcs1":
                        continue
                    try:
                        # 1024 bit keys are too small to create valid
                        # rsa-pss-SHA512 signatures
                        if schemeName == 'pss' and hashName == 'sha512'\
                                and privateKey and privateKey.n < 2**2047:
                            continue
                        # advertise support for both rsaEncryption and RSA-PSS OID
                        # key type
                        if certType != 'rsa-pss':
                            sigAlgs.append(getattr(SignatureScheme,
                                                   "rsa_{0}_rsae_{1}"
                                                   .format(schemeName, hashName)))
                        if certType != 'rsa':
                            sigAlgs.append(getattr(SignatureScheme,
                                                   "rsa_{0}_pss_{1}"
                                                   .format(schemeName, hashName)))
                    except AttributeError:
                        if schemeName == 'pkcs1':
                            sigAlgs.append((getattr(HashAlgorithm, hashName),
                                            SignatureAlgorithm.rsa))
                        continue
        return sigAlgs




