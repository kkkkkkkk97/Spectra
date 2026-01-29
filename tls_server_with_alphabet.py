"""
TLS服务器端字母映射系统
参考客户端实现：./TLSMapper/mytls.py
参考服务器实现：./tlslite/tlsconnection.py

核心功能：
1. 接收客户端消息并转换为字母
2. 根据字母配置发送服务器响应
3. 完整的密钥派生和加密支持
4. TLS密钥日志记录（用于Wireshark解密）

密钥日志使用方法：
1. 启动服务器时指定keylog_file参数：
   python tls_server_with_alphabet.py cert.pem key.pem 4433 /tmp/tls_keys.log

2. 在Wireshark中配置：
   Edit -> Preferences -> Protocols -> TLS -> (Pre)-Master-Secret log filename
   设置为：/tmp/tls_keys.log

3. Wireshark将自动解密TLS 1.3流量
"""

from __future__ import print_function
import sys
import os
import socket
import time
from tlslite.api import *
from tlslite.tlsrecordlayer import TLSRecordLayer
from tlslite.constants import *
from tlslite.utils.cryptomath import derive_secret, getRandomBytes, HKDF_expand_label, secureHMAC
from tlslite.errors import *
from tlslite.messages import *
from tlslite.mathtls import *
from tlslite.handshakehashes import HandshakeHashes
from tlslite.keyexchange import ECDHKeyExchange, FFDHKeyExchange
from tlslite.extensions import *
from TLSMapper.helpers import SIG_ALL
from tlslite.utils.codec import Writer


class TLSServerWithAlphabet(TLSRecordLayer):
    """
    支持字母映射的TLS服务器
    """

    def __init__(self, sock, cert_file=None, key_file=None, version=(3, 4), debug=False, keylog_file=None):
        """
        初始化TLS服务器

        :param sock: socket对象
        :param cert_file: 服务器证书文件路径
        :param key_file: 服务器私钥文件路径
        :param version: TLS版本 (3,4)=TLS1.3
        :param debug: 是否启用调试输出，默认False只输出抽象符号
        :param keylog_file: 密钥日志文件路径（用于Wireshark解密），默认None不记录
        """
        TLSRecordLayer.__init__(self, sock)

        # 密钥日志文件（用于Wireshark解密TLS流量）
        self.keylog_file = keylog_file

        # 设置合理的接收超时（2秒），不是短超时立即返回
        # 参考 mytls.py 中的 sock.settimeout(0.5)
        # 服务器端使用更长的超时以等待客户端响应
        sock.settimeout(0.1)

        # 调试模式控制
        self.debug = debug

        # CRITICAL: Mark this as a SERVER (not client)
        # This ensures encryption keys are assigned correctly in calcTLS1_3PendingState()
        # Without this, the server would encrypt with CLIENT key, causing "Bad Record MAC" error
        self._recordLayer.client = False

        # TLS版本
        self.version = version
        self.support_version = version

        # 随机数和会话
        self._clientRandom = bytearray(32)
        self._serverRandom = bytearray(32)
        self.session_id = bytearray(0)

        # 握手消息存储
        self.CH = None  # ClientHello
        self.SH = None  # ServerHello
        self.client_cert = None  # 客户端证书

        # 密钥材料（参考mytls.py:82-100）
        self.prf_name = 'sha256'
        self.prf_size = 32
        self.early_secret = bytearray(self.prf_size)
        self.handshake_secret = bytearray(self.prf_size)
        self.master_secret = bytearray(self.prf_size)
        self.sr_handshake_traffic_secret = bytearray(self.prf_size)
        self.cl_handshake_traffic_secret = bytearray(self.prf_size)
        self.sr_app_traffic = bytearray(self.prf_size)
        self.cl_app_traffic = bytearray(self.prf_size)
        self.exporter_master_secret = bytearray(self.prf_size)

        # 握手哈希
        self._handshake_hash = None

        # 密码套件
        self.cipher_suite = CipherSuite.TLS_AES_128_GCM_SHA256

        # 密钥交换
        self.keyExchange = None
        if key_file is None or cert_file is None:
            self.privateKey = None
            self.cert_chain = None
            return 
        try:
            text_key = str(open(key_file, 'rb').read(), 'utf-8')
            self.privateKey = parsePEMKey(text_key, private=True,implementations=["python"])
            text_cert = str(open(cert_file, 'rb').read(), 'utf-8')
            self.cert_chain = X509CertChain()
            # print(text_cert)
            self.cert_chain.parsePemList(text_cert)
        except Exception as e:
            print(f'wrong keyfile or certfile!{e}')

        # 状态标志
        self._ccs_sent = False
        self.cert_request_sent = False

    def _debug_print(self, *args, **kwargs):
        """仅在debug模式下打印"""
        if self.debug:
            print(*args, **kwargs)

    def _write_keylog(self):
        """
        将TLS密钥写入NSS Key Log文件（Wireshark格式）

        NSS Key Log格式参考：
        https://firefox-source-docs.mozilla.org/security/nss/legacy/key_log_format/index.html

        TLS 1.3格式：
        CLIENT_HANDSHAKE_TRAFFIC_SECRET <client_random> <secret>
        SERVER_HANDSHAKE_TRAFFIC_SECRET <client_random> <secret>
        CLIENT_TRAFFIC_SECRET_0 <client_random> <secret>
        SERVER_TRAFFIC_SECRET_0 <client_random> <secret>
        EXPORTER_SECRET <client_random> <secret>
        """
        if not self.keylog_file:
            return

        try:
            client_random_hex = self._clientRandom.hex()

            with open(self.keylog_file, 'a') as f:
                # 写入握手流量密钥（如果已派生）
                if len(self.cl_handshake_traffic_secret) > 0 and self.cl_handshake_traffic_secret != bytearray(self.prf_size):
                    f.write(f"CLIENT_HANDSHAKE_TRAFFIC_SECRET {client_random_hex} {self.cl_handshake_traffic_secret.hex()}\n")
                    self._debug_print(f"[KEYLOG] Wrote CLIENT_HANDSHAKE_TRAFFIC_SECRET")

                if len(self.sr_handshake_traffic_secret) > 0 and self.sr_handshake_traffic_secret != bytearray(self.prf_size):
                    f.write(f"SERVER_HANDSHAKE_TRAFFIC_SECRET {client_random_hex} {self.sr_handshake_traffic_secret.hex()}\n")
                    self._debug_print(f"[KEYLOG] Wrote SERVER_HANDSHAKE_TRAFFIC_SECRET")

                # 写入应用流量密钥（如果已派生）
                if len(self.cl_app_traffic) > 0 and self.cl_app_traffic != bytearray(self.prf_size):
                    f.write(f"CLIENT_TRAFFIC_SECRET_0 {client_random_hex} {self.cl_app_traffic.hex()}\n")
                    self._debug_print(f"[KEYLOG] Wrote CLIENT_TRAFFIC_SECRET_0")

                if len(self.sr_app_traffic) > 0 and self.sr_app_traffic != bytearray(self.prf_size):
                    f.write(f"SERVER_TRAFFIC_SECRET_0 {client_random_hex} {self.sr_app_traffic.hex()}\n")
                    self._debug_print(f"[KEYLOG] Wrote SERVER_TRAFFIC_SECRET_0")

                # 写入导出密钥（如果已派生）
                if len(self.exporter_master_secret) > 0 and self.exporter_master_secret != bytearray(self.prf_size):
                    f.write(f"EXPORTER_SECRET {client_random_hex} {self.exporter_master_secret.hex()}\n")
                    self._debug_print(f"[KEYLOG] Wrote EXPORTER_SECRET")

        except Exception as e:
            self._debug_print(f"[!] 写入keylog失败: {e}")

    def _print_message_header(self):
        """打印双列格式的表头"""
        if not self.debug:
            print("Send              | Recv")
            print("------------------+------------------")

    def _print_message_pair(self, send_msg=None, recv_msg=None):
        """
        打印收发对照的双列格式（先发送后接收）
        Args:
            send_msg: 发送的消息(None表示-)
            recv_msg: 接收到的消息(None表示No_Resp)
        """
        if send_msg is None:
            send_msg = "-"
        if recv_msg is None:
            recv_msg = "No_Resp"

        # 格式化为固定宽度
        print(f"{send_msg:<18}| {recv_msg}")

    def receiveAndMap(self):
        """
        接收客户端消息并转换为字母
        参考：mytls.py:1759-2179 (process_recieve)

        :return: 字母列表，如 ['ClientHello'] 或 ['Certificate', 'CertificateVerify', 'Finished']
        """
        self._debug_print("[DEBUG] receiveAndMap() 开始...")
        receive_letters = []

        while True:
            self._debug_print("[DEBUG] 调用 _getMsg()...")
            try:
                for result in self._getMsg(ContentType.all, HandshakeType.all):
                    if result in (0, 1):
                        continue
                    else:
                        break
            except Exception as e:
                error_msg = str(e)
                # 异常信息映射
                if 'bad_record_mac' in error_msg.lower():
                    self._debug_print(f"[!] 接收消息异常: {e}")
                    return ['Bad_Mac_Record']
                elif 'timeout' in error_msg.lower() or 'timed out' in error_msg.lower():
                    # 超时是正常的，表示客户端还没准备好发送（可能在等待更多服务器消息）
                    # 返回空列表，而不是错误
                    self._debug_print(f"[DEBUG] 接收超时（正常），客户端暂无响应")
                    break  # 退出循环，返回已收到的消息（可能为空）
                elif 'connection' in error_msg.lower() or 'closed' in error_msg.lower():
                    self._debug_print(f"[!] 接收消息异常: {e}")
                    return ['Connection_Closed']
                else:
                    self._debug_print(f"[!] 接收消息异常: {e}")
                    return ['Error']

            # 如果 _getMsg() 返回 0 或 1，表示没有更多消息，退出循环
            if result in (0, 1):
                self._debug_print(f"[DEBUG] _getMsg() 返回 {result}，退出循环")
                break

            recordHeader, p = result
            # print(result)
            # print(dir(p),p.bytes)
            self._debug_print(f"[DEBUG] 收到消息: type={recordHeader.type}, len={recordHeader.length}")

            # 根据不同的内容类型处理（参考mytls.py:1769-2177）
            if recordHeader.type == ContentType.change_cipher_spec:
                receive_letters.append('ChangeCipherSpec')
                self._debug_print(f"[←] 收到 ChangeCipherSpec")

            elif recordHeader.type == ContentType.application_data:
                receive_letters.append('ApplicationData')
                self._debug_print(f"[←] 收到 ApplicationData ({len(p.bytes)} bytes)")

            elif recordHeader.type == ContentType.alert:
                alert = Alert().parse(p)
                alert_name = AlertDescription.toRepr(alert.description)
                receive_letters.append(alert_name)
                self._debug_print(f"[←] 收到 Alert: {alert_name}")
                if alert.level == AlertLevel.fatal:
                    break

            elif recordHeader.type == ContentType.handshake:
                subType = p.get(1)

                if subType == HandshakeType.client_hello:
                    # 接收ClientHello
                    client_hello = ClientHello().parse(p)
                    self.CH = client_hello
                    self._clientRandom = client_hello.random

                    # 更新握手哈希
                    if self._handshake_hash is None:
                        self._handshake_hash = HandshakeHashes()
                    self._handshake_hash.update(p.bytes)

                    receive_letters.append('ClientHello')
                    self._debug_print(f"[←] 收到 ClientHello")
                    self._debug_print(f"  - 版本: {client_hello.client_version}")
                    self._debug_print(f"  - 密码套件数量: {len(client_hello.cipher_suites)}")

                    # === VALIDATION SECTION ===
                    # 1. Validate cipher suites exist
                    if not client_hello.cipher_suites:
                        self._debug_print("[!] Error: Empty cipher suite list")
                        return receive_letters

                    # 2. Validate compression methods (must include 0)
                    if 0 not in client_hello.compression_methods:
                        self._debug_print("[!] Error: Missing null compression")
                        return receive_letters

                    # 3. Validate required extensions for TLS 1.3
                    ext_sv = client_hello.getExtension(ExtensionType.supported_versions)
                    if not ext_sv or (3, 4) not in ext_sv.versions:
                        self._debug_print("[!] Error: TLS 1.3 not supported by client")
                        return receive_letters

                    # 4. Validate key_share extension
                    ext_ks = client_hello.getExtension(ExtensionType.key_share)
                    if not ext_ks or not ext_ks.client_shares:
                        self._debug_print("[!] Error: Missing key_share extension")
                        return receive_letters

                    # 5. Validate signature_algorithms extension
                    ext_sig = client_hello.getExtension(ExtensionType.signature_algorithms)
                    if not ext_sig or not ext_sig.sigalgs:
                        self._debug_print("[!] Error: Missing signature_algorithms extension")
                        return receive_letters

                    # Print extension information
                    self._debug_print(f"  - 支持的版本: {ext_sv.versions}")
                    self._debug_print(f"  - 密钥交换组: {[s.group for s in ext_ks.client_shares]}")

                    # ClientHello 收到后立即返回，不继续循环等待
                    self._debug_print("[DEBUG] ClientHello处理完毕，立即返回")
                    return receive_letters

                elif subType == HandshakeType.certificate:
                    # 接收客户端证书
                
                    cert = Certificate(CertificateType.x509, self.version).parse(p)
                    self.client_cert = cert
                    self._handshake_hash.update(p.bytes)
                    receive_letters.append('Certificate')
                    self._debug_print(f"[←] 收到 Certificate (客户端)")
                    # if cert.cert_list:
                    #     self._debug_print(f"  - 证书数量: {len(cert.cert_list)}")

                elif subType == HandshakeType.certificate_verify:
                    # 接收客户端CertificateVerify
                    cert_verify = CertificateVerify(self.version).parse(p)
                    self._handshake_hash.update(p.bytes)
                    receive_letters.append('CertificateVerify')
                    self._debug_print(f"[←] 收到 CertificateVerify (客户端)")
                    self._debug_print(f"  - 签名算法: {SignatureScheme.toRepr(cert_verify.signatureAlgorithm)}")

                elif subType == HandshakeType.finished:
                    # 接收客户端Finished (在验证前不更新握手哈希)
                    handshake_hash_before_client_fin = self._handshake_hash.digest(self.prf_name)
                    finished = Finished(self.version, self.prf_size).parse(p)

                    # 验证客户端Finished (参考 tlsconnection.py)
                    cl_finished_key = HKDF_expand_label(
                        self.cl_handshake_traffic_secret,
                        b"finished",
                        b"",
                        self.prf_size,
                        self.prf_name
                    )
                    expected_verify_data = secureHMAC(
                        cl_finished_key,
                        handshake_hash_before_client_fin,
                        self.prf_name
                    )

                    # 验证
                    if finished.verify_data != expected_verify_data:
                        self._debug_print(f"[!] 警告: Finished verify_data不匹配!")
                        self._debug_print(f"  - 收到: {finished.verify_data.hex()[:64]}...")
                        self._debug_print(f"  - 期望: {expected_verify_data.hex()[:64]}...")
                    else:
                        self._debug_print(f"[✓] Finished验证成功")

                    # 验证后才更新握手哈希
                    self._handshake_hash.update(p.bytes)
                    receive_letters.append('Finished')
                    self._debug_print(f"[←] 收到 Finished (客户端)")
                    self._debug_print(f"  - Verify Data: {finished.verify_data.hex()[:32]}...")

                    # 接收到客户端Finished后立即返回,不继续等待更多消息
                    self._debug_print("[DEBUG] 客户端Finished处理完毕,立即返回")
                    return receive_letters

                else:
                    self._debug_print(f"[!] 未知握手消息类型: {subType}")

                # print(receive_letters)
        return receive_letters

    def sendResponse(self, symbol):
        """
        根据字母发送服务器响应
        参考：mytls.py:171-471 (sendAndRecv)

        支持的字母格式：
        - 'ServerHello': 正常的ServerHello
        - 'HelloRetryRequest': HRR（不包含key_share扩展，不发送CCS）
        - 'HelloRetryRequest_CCS': HRR + CCS（中间盒兼容模式）
        - 'HelloRetryRequest_KeyShare': HRR + key_share扩展（固定使用x25519组）
        - 'EncryptedExtensions': 加密扩展
        - 'Certificate': 服务器证书
        - 'CertificateVerify': 证书验证
        - 'CertificateRequest': 证书请求
        - 'Finished': 握手完成
        - 'ChangeCipherSpec': 中间盒兼容的CCS
        - 'CustomPacket': 发送自定义数据包（用于特殊测试场景）

        :param symbol: 字母，如 'ServerHello', 'Certificate', 'Finished'
        """
        self._debug_print(f"\n[→] 准备发送: {symbol}")

        # 注意：_send_xxx方法都是生成器，需要遍历它们
        if symbol == 'ServerHello':
            for _ in self._send_server_hello():
                pass

        elif symbol == 'HelloRetryRequest':
            # 默认：不包含key_share，不发送CCS
            for _ in self._send_hello_retry_request(selected_group=None, send_ccs=False):
                pass

        elif symbol == 'HelloRetryRequest_CCS':
            # HRR后发送CCS（中间盒兼容）
            for _ in self._send_hello_retry_request(selected_group=None, send_ccs=True):
                pass

        elif symbol == 'HelloRetryRequest_KeyShare':
            # HRR + key_share 扩展（固定使用 x25519 组）
            for _ in self._send_hello_retry_request(selected_group=GroupName.x25519, send_ccs=False):
                pass

        elif symbol == 'EncryptedExtensions':
            for _ in self._send_encrypted_extensions():
                pass

        elif symbol == 'CertificateRequest':
            for _ in self._send_certificate_request():
                pass

        elif symbol == 'EmptyCertificate':
            for _ in self._send_empty_certificate():
                pass

        elif symbol == 'Certificate':
            for _ in self._send_certificate():
                pass

        elif symbol == 'CertificateVerify':
            for _ in self._send_certificate_verify():
                pass

        elif symbol == 'Finished':
            for _ in self._send_finished():
                pass

        elif symbol == 'ChangeCipherSpec':
            for _ in self._send_change_cipher_spec():
                pass

        elif symbol == 'EmptyCertificateVerify':
            for _ in self._send_empty_certificate_verify():
                pass

        elif symbol == 'ApplicationData':
            for _ in self._send_Appdata():
                pass

        elif symbol == 'CustomPacket':
            # 发送自定义数据包
            self._send_pck()
            self._debug_print(f"[→] CustomPacket 已发送")

        # C18: KeyShare模糊测试变体
        elif symbol.startswith('ServerHello_FuzzKeyShare_'):
            # 提取fuzz_type: ServerHello_FuzzKeyShare_zero, ServerHello_FuzzKeyShare_one等
            fuzz_type = symbol.split('_')[-1]  # 'zero', 'one', 'max', 'over_prime', 'invalid_length'
            self._debug_print(f"[C18-TEST] ServerHello with fuzzy KeyShare (type={fuzz_type})")

            # 生成带有模糊KeyShare的ServerHello，并获取共享密钥
            sh_fuzz, shared_secret = self._generate_server_hello_fuzz_keyshare(fuzz_type)

            if sh_fuzz and shared_secret is not None:
                # 手动发送ServerHello
                sh_bytes = sh_fuzz.write()
                from tlslite.recordlayer import RecordHeader3
                record = RecordHeader3()
                record.create((3, 3), ContentType.handshake, len(sh_bytes))
                self.sock.sendall(record.write() + sh_bytes)

                # 更新握手哈希
                if self._handshake_hash is None:
                    self._handshake_hash = HandshakeHashes()
                self._handshake_hash.update(sh_bytes)

                self._debug_print(f"[→] ServerHello_FuzzKeyShare_{fuzz_type} 已发送")

                # 使用fuzzy值计算出的共享密钥进行密钥派生
                self._derive_keys_after_server_hello(shared_secret)

                # 切换到握手加密状态
                self._change_cipher_state_after_server_hello()

                self._debug_print(f"[STATE] 已使用fuzzy KeyShare派生密钥并切换加密状态")

        # C20: ServerHello和EncryptedExtensions合并到同一个TLS记录
        elif symbol == 'ServerHello_MergedWithEE':
            self._send_server_hello_merged_with_ee()
            self._debug_print(f"[→] ServerHello_MergedWithEE 已发送")

        # C20: SH+EE+CERT合并到同一个TLS记录
        elif symbol == 'ServerHello_MergedWithEE_Cert':
            self._send_server_hello_merged_with_ee_cert()
            self._debug_print(f"[→] ServerHello_MergedWithEE_Cert 已发送")

        # C20: SH+EE+CERT+CV+FIN合并到同一个TLS记录
        elif symbol == 'ServerHello_MergedWithEE_Cert_CV_Fin':
            self._send_server_hello_merged_with_ee_cert_cv_fin()
            self._debug_print(f"[→] ServerHello_MergedWithEE_Cert_CV_Fin 已发送")

        # C20: ServerHello不包含KeyShare扩展
        elif symbol == 'ServerHello_NoKeyShare':
            sh_no_keyshare = self._generate_server_hello_no_keyshare()

            # 手动发送
            sh_bytes = sh_no_keyshare.write()
            from tlslite.recordlayer import RecordHeader3
            record = RecordHeader3()
            record.create((3, 3), ContentType.handshake, len(sh_bytes))
            self.sock.sendall(record.write() + sh_bytes)

            self._debug_print(f"[→] ServerHello_NoKeyShare 已发送")

        # C20: 记录边界测试场景（原有的）
        elif symbol == 'ServerHello+EncryptedExtensions':
            # C20违规：将ServerHello和EncryptedExtensions合并到同一个TLS记录
            self._debug_print(f"[C20-TEST] 合并ServerHello和EncryptedExtensions到同一个TLS记录")

            # 步骤1: 正常生成ServerHello并派生密钥
            for _ in self._send_server_hello():
                pass

            # 步骤2: 生成EncryptedExtensions（不加密）
            ee = EncryptedExtensions().create([])

            # 步骤3: 合并发送（这里需要手动发送，不能用_sendMsg因为会加密）
            # 为了简化，使用Finished消息代替（都是明文）
            finished = Finished((3, 4), self.prf_size)
            finished.verify_data = bytearray(self.prf_size)  # 虚拟数据

            # 合并发送ServerHello和Finished到同一个记录
            self._send_merged_handshake(self.SH, finished)

        else:
            self._debug_print(f"[!] 未知字母: {symbol}")

    def sendAndRecv(self, symbol):
        """
        发送服务器消息并接收客户端响应（模仿mytls.py的sendAndRecv模式）

        参考：mytls.py:176-581
        核心流程：
        1. 生成并发送消息（带异常处理）
        2. 根据消息类型执行状态切换
        3. 接收客户端响应
        4. 返回接收到的消息列表

        :param symbol: 消息符号，如 'ServerHello', 'Certificate', 'Finished'
        :return: 接收到的消息列表，如 ['Finished'] 或 ['SendFailed']
        """
        self._debug_print(f"\n[→] 发送: {symbol}")

        # 步骤1: 发送消息（带异常处理）
        try:
            if symbol == 'ServerHello':
                for result in self._send_server_hello():
                    pass
            elif symbol.startswith('HelloRetryRequest'):
                # HelloRetryRequest后需要特殊处理
                if symbol == 'HelloRetryRequest':
                    for result in self._send_hello_retry_request(selected_group=None, send_ccs=False):
                        pass
                elif symbol == 'HelloRetryRequest_CCS':
                    for result in self._send_hello_retry_request(selected_group=None, send_ccs=True):
                        pass
                elif symbol == 'HelloRetryRequest_KeyShare':
                    for result in self._send_hello_retry_request(selected_group=GroupName.x25519, send_ccs=False):
                        pass
                else:
                    self.sendResponse(symbol)
            elif symbol == 'EncryptedExtensions':
                for result in self._send_encrypted_extensions():
                    pass
            elif symbol == 'CertificateRequest':
                for result in self._send_certificate_request():
                    pass
            elif symbol == 'Certificate':
                for result in self._send_certificate():
                    pass
            elif symbol == 'CertificateVerify':
                for result in self._send_certificate_verify():
                    pass
            elif symbol == 'Finished':
                for result in self._send_finished():
                    pass
            elif symbol == 'ChangeCipherSpec':
                for result in self._send_change_cipher_spec():
                    pass
            else:
                # 其他消息类型（如C20测试用例、C18测试用例）
                # 包括：
                # - ServerHello_FuzzKeyShare_zero/one/max/over_prime/invalid_length (C18)
                # - ServerHello_MergedWithEE (C20)
                # - ServerHello_NoKeyShare (C20)
                # - ServerHello+EncryptedExtensions (C20)
                self.sendResponse(symbol)
        except Exception as e:
            self._debug_print(f"[!] 发送失败: {e}")
            return ['SendFailed']

        self._debug_print(f"[→] {symbol} 已发送")

        # 步骤2: 根据消息类型进行状态切换
        self._handle_state_transition_after_send(symbol)

        # 步骤3: 接收客户端响应
        try:
            re = self.receiveAndMap()

            # 如果返回空列表，表示没有响应（超时，但这是正常的）
            if not re:
                self._debug_print(f"[←] 暂无响应（正常）")
            else:
                self._debug_print(f"[←] 收到响应: {'-'.join(re)}")

            # 步骤4: 根据接收到的消息进行状态切换
            if re:  # 只有在有响应时才处理状态切换
                self._handle_state_transition_after_recv(re)

            return re if re else []  # 确保返回列表
        except Exception as e:
            self._debug_print(f"[!] 接收失败: {e}")
            return ['ReceiveFailed']

    def _handle_state_transition_after_send(self, symbol):
        """
        发送消息后根据消息类型处理状态切换

        关键时机：
        - ServerHello后：切换写状态到握手加密
        - Finished后：切换读状态以接收客户端加密消息
        """
        if symbol == 'ServerHello':
            # ServerHello已经在_send_server_hello()中切换了写状态
            pass
        elif symbol == 'Finished':
            # 发送Finished后，切换读状态以接收客户端的加密消息
            # 参考 tlsconnection.py:2854
            # self._changeReadState()
            self._debug_print("[STATE] 切换读状态 - 可以接收客户端加密消息")

    def _handle_state_transition_after_recv(self, received_letters):
        """
        接收消息后根据消息类型处理状态切换

        关键时机：
        - 收到客户端Finished后：派生应用密钥并切换到应用加密
        """
        if 'Finished' in received_letters:
            # 接收到客户端Finished后，计算应用密钥
            self._derive_keys_after_finished()

            # 切换到应用流量密钥
            self._change_cipher_state_to_application()

    def _send_server_hello(self):
        """
        发送ServerHello并计算握手密钥
        参考：tlsconnection.py:2657-2734
        """
        # 生成服务器随机数
        self._serverRandom = getRandomBytes(32)
        self._debug_print(f"  - 服务器随机数: {self._serverRandom.hex()[:32]}...")
        # 选择密码套件
        client_suites = self.CH.cipher_suites
        if self.cipher_suite in client_suites:
            selected_suite = self.cipher_suite
        else:
            # 选择第一个TLS 1.3套件
            for suite in client_suites:
                if suite in CipherSuite.tls13Suites:
                    selected_suite = suite
                    break
            else:
                # 默认使用第一个
                selected_suite = client_suites[0]

        self.cipher_suite = selected_suite

        # 根据密码套件设置PRF
        if selected_suite in CipherSuite.sha384PrfSuites:
            self.prf_name = 'sha384'
            self.prf_size = 48
        else:
            self.prf_name = 'sha256'
            self.prf_size = 32

        # self._debug_print(f"  - 选择密码套件: {CipherSuite.ietfNames.get(selected_suite, hex(selected_suite))}")
        # self._debug_print(f"  - PRF: {self.prf_name}")

        # 密钥交换 - 生成服务器密钥对
        client_key_share = self.CH.getExtension(ExtensionType.key_share)
        if not client_key_share or not client_key_share.client_shares:
            self._debug_print("[!] 错误: ClientHello缺少KeyShare扩展")
            return

        # 服务器支持的群组列表
        # ECDHE: secp256r1=23, secp384r1=24, secp521r1=25, x25519=29, x448=30
        # FFDH: ffdhe2048=256, ffdhe3072=257, ffdhe4096=258, ffdhe6144=259, ffdhe8192=260
        SERVER_SUPPORTED_GROUPS = [23, 24, 25, 29, 30, 256, 257, 258, 259, 260]

        # 匹配客户端和服务器支持的群组，选择第一个匹配的
        selected_share = None
        for share in client_key_share.client_shares:
            if share.group in SERVER_SUPPORTED_GROUPS:
                selected_share = share
                break

        if selected_share is None:
            self._debug_print("[!] 错误: 客户端和服务器没有共同支持的密钥交换组")
            self._debug_print(f"  - 客户端支持: {[s.group for s in client_key_share.client_shares]}")
            self._debug_print(f"  - 服务器支持: {SERVER_SUPPORTED_GROUPS}")
            return

        group_id = selected_share.group
        self._debug_print(f"  - 密钥交换组: {GroupName.toRepr(group_id)} (ID: {group_id})")

        # 选择密钥交换方法 (参考 tlsconnection.py:1154-1158)
        if group_id in [23, 24, 25, 29, 30]:  # ECDHE groups
            self.keyExchange = ECDHKeyExchange(group_id, (3, 4))
        elif group_id in [256, 257, 258, 259, 260]:  # FFDH groups
            self.keyExchange = FFDHKeyExchange(group_id, (3, 4))
        else:
            self._debug_print(f"[!] 错误: 不支持的密钥交换组 {group_id}")
            return


        # self._recordLayer.encryptThenMAC = True

        # 生成密钥对 (参考 tlsconnection.py:1165-1167)
        private_key = self.keyExchange.get_random_private_key()
        public_key = self.keyExchange.calc_public_value(private_key)

        # 创建服务器KeyShareEntry
        from tlslite.messages import KeyShareEntry
        server_key_share = KeyShareEntry().create(group_id, public_key, private_key)
        # print(private_key)
        # 计算共享密钥 (参考 tlsconnection.py:1199-1200)
        client_pub_key = selected_share.key_exchange
        shared_sec = self.keyExchange.calc_shared_key(private_key, client_pub_key)

        self._debug_print(f"  - 共享密钥: {shared_sec.hex()[:32]}...")

        # 构建ServerHello
        serverHello = ServerHello()
        serverHello.server_version = (3, 3)  # TLS 1.3使用兼容版本
        serverHello.random = self._serverRandom
        serverHello.session_id = self.CH.session_id
        serverHello.cipher_suite = selected_suite
        serverHello.compression_method = 0

        # 添加扩展
        serverHello.extensions = []

        # supported_versions扩展
        ext_sv = SrvSupportedVersionsExtension().create((3, 4))
        serverHello.extensions.append(ext_sv)

        # key_share扩展
        ext_ks = ServerKeyShareExtension().create(server_key_share)
        serverHello.extensions.append(ext_ks)

        self.SH = serverHello

        # 发送ServerHello (_sendMsg会自动更新握手哈希)
        for result in self._sendMsg(serverHello):
            if result in (0, 1):
                yield result

        self._debug_print(f"[→] ServerHello 已发送")

        # 计算握手密钥（参考tlsconnection.py:2713-2734）
        self._derive_keys_after_server_hello(shared_sec)

        # 切换到握手加密
        self._change_cipher_state_after_server_hello()

        self._debug_print(f"[DEBUG] Hash after SH: {self._handshake_hash.digest(self.prf_name).hex()[:32]}...")

    def _send_hello_retry_request(self, selected_group=None, send_ccs=False):
        """
        发送HelloRetryRequest (HRR)
        参考：tlsconnection.py:4066-4088

        HRR 是一个特殊的 ServerHello，其 random 字段设置为 TLS_1_3_HRR
        用于请求客户端重新发送 ClientHello（例如：不同的密钥交换组）

        :param selected_group: 服务器选择的密钥交换组（如果需要客户端更换组，默认None表示不更换）
        :param send_ccs: 是否在 HRR 后发送 ChangeCipherSpec（中间盒兼容模式，默认False）
        """
        self._debug_print(f"  - 发送 HelloRetryRequest")

        # 选择密码套件（如果尚未选择）
        if not hasattr(self, 'cipher_suite') or self.cipher_suite is None:
            client_suites = self.CH.cipher_suites
            for suite in client_suites:
                if suite in CipherSuite.tls13Suites:
                    self.cipher_suite = suite
                    break
            else:
                self.cipher_suite = client_suites[0]

        # 根据密码套件设置PRF
        if self.cipher_suite in CipherSuite.sha384PrfSuites:
            self.prf_name = 'sha384'
            self.prf_size = 48
        else:
            self.prf_name = 'sha256'
            self.prf_size = 32

        self._debug_print(f"  - 密码套件: {CipherSuite.ietfNames.get(self.cipher_suite, hex(self.cipher_suite))}")

        # 构建 HRR 扩展
        hrr_extensions = []

        # 添加 supported_versions 扩展（必需）
        ext_sv = SrvSupportedVersionsExtension().create((3, 4))
        hrr_extensions.append(ext_sv)

        # 只有在明确指定了密钥交换组时，才添加 key_share 扩展
        if selected_group is not None:
            # HRR 中的 key_share 只包含 selected_group，不包含实际密钥
            ext_ks = HRRKeyShareExtension().create(selected_group)
            hrr_extensions.append(ext_ks)
            self._debug_print(f"  - 请求的密钥交换组: {GroupName.toRepr(selected_group)}")
        else:
            self._debug_print(f"  - 不包含 key_share 扩展")

        # 创建 HelloRetryRequest（实际上是特殊的 ServerHello）
        hrr = ServerHello()
        hrr.create(
            (3, 3),                    # 兼容版本（TLS 1.2）
            TLS_1_3_HRR,               # 特殊的 random 值标识这是 HRR
            self.CH.session_id,        # 回显客户端的 session_id
            self.cipher_suite,         # 选择的密码套件
            extensions=hrr_extensions
        )

        # 正确的顺序：先发送 HRR，再发送可选的 CCS
        # 参考 RFC 8446: HRR 后面可以跟 ChangeCipherSpec（中间盒兼容）
        msgs = [hrr]

        # 只有在明确要求时才发送 CCS
        if send_ccs and self.CH.session_id and not self._ccs_sent:
            ccs = ChangeCipherSpec().create()
            msgs.append(ccs)  # CCS 在 HRR 之后
            self._debug_print(f"  - HRR 之后发送 ChangeCipherSpec（中间盒兼容）")
            self._ccs_sent = True

        for result in self._sendMsgs(msgs):
            if result in (0, 1):
                yield result

        self._debug_print(f"[→] HelloRetryRequest 已发送")

        # HRR 后需要更新握手哈希
        # 创建合成的握手哈希：message_hash(CH) + HRR
        # 参考 tlsconnection.py:4051-4062
        client_hello_hash = self._handshake_hash.digest(self.prf_name)

        # 重置握手哈希
        self._handshake_hash = HandshakeHashes()

        # 添加 message_hash 消息
        writer = Writer()
        writer.add(HandshakeType.message_hash, 1)
        writer.addVarSeq(client_hello_hash, 1, 3)
        self._handshake_hash.update(writer.bytes)

        # 添加 HRR
        self._handshake_hash.update(hrr.write())

        self._debug_print(f"[DEBUG] Hash after HRR: {self._handshake_hash.digest(self.prf_name).hex()[:32]}...")
        self._debug_print(f"[NOTE] 等待客户端重新发送 ClientHello...")

    def _send_encrypted_extensions(self):
        """发送EncryptedExtensions"""
        ee = EncryptedExtensions().create([])
        # print(self._handshake_hash._handshake_buffer.hex())
        # 发送 (_sendMsg会自动更新握手哈希)
        for result in self._sendMsg(ee):
            if result in (0, 1):
                yield result

        
        self._debug_print(f"[→] EncryptedExtensions 已发送")

    def _send_certificate_request(self):
        """发送CertificateRequest"""
        
        cert_req = CertificateRequest(self.support_version).create(certificate_types=[64, 1],certificate_authorities= [b''])
        cert_req.certificate_request_context = bytearray(0)

        # 添加signature_algorithms扩展
        ext_sig = SignatureAlgorithmsExtension().create(SIG_ALL)
        cert_req.extensions = [ext_sig]

        self.cert_request_sent = True

        # 发送 (_sendMsg会自动更新握手哈希)
        for result in self._sendMsg(cert_req):
            if result in (0, 1):
                yield result

        self._debug_print(f"[→] CertificateRequest 已发送")
    
    def _send_empty_certificate(self):
        self.cert_chain = X509CertChain()
        test_cert = X509()
        test_cert.certAlg = 'rsa'
        self.cert_chain.x509List.append(test_cert)
        certificate_type = CertificateType.x509
        client_certificate = Certificate(certificate_type, self.support_version)

        client_certificate.create(self.cert_chain)
        for result in self._sendMsg(client_certificate):
            if result in (0, 1):
                yield result

        self._debug_print(f"[→] EmptyCertificate 已发送")

    def _send_certificate(self):
        """发送服务器证书"""
        # cert_msg = Certificate(CertificateType.x509, (3, 4))
        # cert_msg.certificate_request_context = bytearray(0)

        # if self.cert_chain:
        #     cert_list = []
        #     for cert in self.cert_chain.x509List:
        #         cert_entry = CertificateEntry(CertificateType.x509)
        #         cert_entry.certificate = cert.writeBytes()
        #         cert_entry.extensions = []
        #         cert_list.append(cert_entry)
        #     cert_msg.cert_list = cert_list
        # else:
        #     cert_msg.cert_list = []
        if self.SH == None:
            certificate_type = CertificateType.x509
        else:
            certificate_type = self.SH.certificate_type
        cert_msg = Certificate(certificate_type, self.support_version)
        cert_msg.create(self.cert_chain)
        # print(cert_msg.certificate_list[0].certificate.writeBytes().hex())

        # 发送 (_sendMsg会自动更新握手哈希)
        for result in self._sendMsg(cert_msg):
            if result in (0, 1):
                yield result

        self._debug_print(f"[→] Certificate 已发送")

    def _send_empty_certificate_verify(self):
        """发送CertificateVerify"""
        if not self.privateKey:
            self._debug_print("[!] 错误: 没有私钥，无法创建CertificateVerify")
            return

        cert_verify = CertificateVerify((3, 4))

        # 选择签名算法
        sig_alg = SignatureScheme.rsa_pss_rsae_sha256

        cert_verify.signatureAlgorithm = sig_alg

        # 使用 KeyExchange.calcVerifyBytes 计算签名上下文（正确的方式）
        # 这会自动处理：64个空格 + "TLS 1.3, server CertificateVerify\x00" + 握手哈希
        # 并且会对整个上下文再进行一次SHA256哈希
        from tlslite.keyexchange import KeyExchange
        signature_context = KeyExchange.calcVerifyBytes(
            (3, 4),                      # TLS 1.3版本
            self._handshake_hash,        # 握手哈希对象
            sig_alg,                     # 签名算法
            None,                        # premasterSecret (TLS 1.3不使用)
            None,                        # clientRandom (TLS 1.3不使用)
            None,                        # serverRandom (TLS 1.3不使用)
            self.prf_name,               # PRF名称
            b'server'                    # 服务器端标识
        )

        # 使用私钥签名
        try:
            signature = self.privateKey.sign(signature_context,
                                              padding='pss',
                                              hashAlg='sha256',
                                              saltLen=32)
            cert_verify.signature = bytearray(0)

            self._debug_print(f"  - 签名算法: {SignatureScheme.toRepr(sig_alg)}")
            self._debug_print(f"  - 签名上下文长度: {len(signature_context)} bytes")
            self._debug_print(f"  - 签名: {signature.hex()[:32]}...")
        except Exception as e:
            self._debug_print(f"[!] 签名失败: {e}")
            import traceback
            traceback.print_exc()
            return

        # 发送 (_sendMsg会自动更新握手哈希)
        for result in self._sendMsg(cert_verify):
            if result in (0, 1):
                yield result

        self._debug_print(f"[→] CertificateVerify 已发送")

    def _send_certificate_verify(self):
        """发送CertificateVerify"""
        if not self.privateKey:
            self._debug_print("[!] 错误: 没有私钥，无法创建CertificateVerify")
            return

        cert_verify = CertificateVerify((3, 4))

        # 选择签名算法
        sig_alg = SignatureScheme.rsa_pss_rsae_sha256

        cert_verify.signatureAlgorithm = sig_alg

        # 使用 KeyExchange.calcVerifyBytes 计算签名上下文（正确的方式）
        # 这会自动处理：64个空格 + "TLS 1.3, server CertificateVerify\x00" + 握手哈希
        # 并且会对整个上下文再进行一次SHA256哈希
        from tlslite.keyexchange import KeyExchange
        signature_context = KeyExchange.calcVerifyBytes(
            (3, 4),                      # TLS 1.3版本
            self._handshake_hash,        # 握手哈希对象
            sig_alg,                     # 签名算法
            None,                        # premasterSecret (TLS 1.3不使用)
            None,                        # clientRandom (TLS 1.3不使用)
            None,                        # serverRandom (TLS 1.3不使用)
            self.prf_name,               # PRF名称
            b'server'                    # 服务器端标识
        )

        # 使用私钥签名
        try:
            signature = self.privateKey.sign(signature_context,
                                              padding='pss',
                                              hashAlg='sha256',
                                              saltLen=32)
            cert_verify.signature = signature

            self._debug_print(f"  - 签名算法: {SignatureScheme.toRepr(sig_alg)}")
            self._debug_print(f"  - 签名上下文长度: {len(signature_context)} bytes")
            self._debug_print(f"  - 签名: {signature.hex()[:32]}...")
        except Exception as e:
            self._debug_print(f"[!] 签名失败: {e}")
            import traceback
            traceback.print_exc()
            return

        # 发送 (_sendMsg会自动更新握手哈希)
        for result in self._sendMsg(cert_verify):
            if result in (0, 1):
                yield result

        self._debug_print(f"[→] CertificateVerify 已发送")

    def _send_finished(self):
        """发送Finished"""
        finished = Finished((3, 4), self.prf_size)

        # CRITICAL: Copy hash state BEFORE computing verify_data
        # Finished verify_data is computed over CH+SH+EE+Cert+CV (without SF itself)
        hash_before_finished = self._handshake_hash.copy()
        handshake_hash = hash_before_finished.digest(self.prf_name)

        finished_key = HKDF_expand_label(
            self.sr_handshake_traffic_secret,
            b"finished",
            b"",
            self.prf_size,
            self.prf_name
        )

        verify_data = secureHMAC(
            finished_key,
            handshake_hash,
            self.prf_name
        )

        finished.verify_data = verify_data

        self._debug_print(f"  - Verify Data: {verify_data.hex()[:32]}...")
        self._debug_print(f"[DEBUG] Hash for SF verify_data: {handshake_hash.hex()[:32]}...")

        # CRITICAL: Send with update_hashes=False to prevent automatic update
        for result in self._sendMsg(finished, update_hashes=False):
            if result in (0, 1):
                yield result

        # CRITICAL: Manually update hash AFTER sending
        # This ensures hash includes SF for master secret derivation
        finished_bytes = finished.write()
        self._handshake_hash.update(finished_bytes)

        self._debug_print(f"[→] Finished 已发送")
        self._debug_print(f"[DEBUG] Hash after SF: {self._handshake_hash.digest(self.prf_name).hex()[:32]}...")

        # NOTE: 不在这里切换读状态！应该在外部调用后切换

    def _send_change_cipher_spec(self):
        """发送ChangeCipherSpec（兼容模式）"""
        ccs = ChangeCipherSpec().create()

        for result in self._sendMsg(ccs):
            if result in (0, 1):
                yield result

        self._ccs_sent = True
        self._debug_print(f"[→] ChangeCipherSpec 已发送")
    
    def _send_Appdata(self):
        appdata = ApplicationData().create(b"GET / HTTP/1.0\n\n") # for openssl

        for result in self._sendMsg(appdata):
            if result in (0, 1):
                yield result
        self._debug_print(f"[→] ApplicationData 已发送")

    def _send_merged_handshake(self, msg1, msg2):
        """
        C20: 将两个握手消息合并到同一个TLS记录中发送
        通过修改TLS记录长度字段来包含两个消息

        :param msg1: 第一个消息对象
        :param msg2: 第二个消息对象
        """
        self._debug_print(f"\n[C20-FUZZ] 合并两个消息到同一个TLS记录")

        # 序列化两个消息
        msg1_bytes = msg1.write()
        msg2_bytes = msg2.write()

        self._debug_print(f"  - {msg1.__class__.__name__}: {len(msg1_bytes)} bytes")
        self._debug_print(f"  - {msg2.__class__.__name__}: {len(msg2_bytes)} bytes")

        # 创建TLS记录头，长度 = msg1 + msg2
        # RecordHeader3.create(version, type, length)
        from tlslite.recordlayer import RecordHeader3
        record = RecordHeader3()
        total_length = len(msg1_bytes) + len(msg2_bytes)
        record.create((3, 3), ContentType.handshake, total_length)

        # 发送：记录头 + msg1 + msg2 （全部在一个TLS记录中）
        record_bytes = record.write() + msg1_bytes + msg2_bytes
        self.sock.sendall(record_bytes)

        # 更新握手哈希
        self._handshake_hash.update(msg1_bytes)
        self._handshake_hash.update(msg2_bytes)

        self._debug_print(f"[C20-FUZZ] 已发送合并记录: {len(record_bytes)} bytes")
        self._debug_print(f"  - TLS Record: [Type=22][Version=0x0303][Length={total_length}]")
        self._debug_print(f"  - 违规: 两个握手消息在同一个TLS记录中")
    
    def _send_pck(self):
        pck = bytes.fromhex('16030300320200002e03034369265a5e64e3a9933b496b1f8352fc52e6556a724c2def356c0846cc5db73b001301000006002b00020304')
        for result in self._recordLayer._recordSocket._sockSendAll(pck):
            pass



    def _generate_server_hello_no_keyshare(self):
        """
        C20: 生成不包含KeyShare扩展的ServerHello
        用于测试客户端是否验证密钥材料的存在

        :return: ServerHello消息对象（不包含key_share扩展）
        """
        self._debug_print(f"\n[C20-FUZZ] 生成不包含KeyShare的ServerHello")

        # 生成服务器随机数
        self._serverRandom = getRandomBytes(32)

        # 选择密码套件
        client_suites = self.CH.cipher_suites
        if self.cipher_suite in client_suites:
            selected_suite = self.cipher_suite
        else:
            for suite in client_suites:
                if suite in CipherSuite.tls13Suites:
                    selected_suite = suite
                    break
            else:
                selected_suite = client_suites[0]

        self.cipher_suite = selected_suite

        # 设置PRF
        if selected_suite in CipherSuite.sha384PrfSuites:
            self.prf_name = 'sha384'
            self.prf_size = 48
        else:
            self.prf_name = 'sha256'
            self.prf_size = 32

        # self._debug_print(f"  - 选择密码套件: {CipherSuite.toRepr(selected_suite)}")
        # self._debug_print(f"  - PRF: {self.prf_name}")

        # 创建ServerHello（不包含key_share扩展）
        serverHello = ServerHello()
        serverHello.create(
            version=(3, 3),  # TLS 1.2 in legacy_version
            random=self._serverRandom,
            session_id=self.CH.session_id,  # Echo回客户端的session_id
            cipher_suite=selected_suite,
            extensions=[SupportedVersionsExtension().create([(3, 4)])]  # 空扩展列表（没有key_share和supported_versions）
        )

        # 添加supported_versions扩展（TLS 1.3必需）
        # supported_versions_ext = SupportedVersionsExtension().create([(3, 4)])
        # serverHello.extensions = [supported_versions_ext]

        # 故意不添加key_share扩展

        self._debug_print(f"  [C20-FUZZ] ServerHello扩展: {[ext.__class__.__name__ for ext in serverHello.extensions]}")
        self._debug_print(f"  [WARNING] 缺少KeyShare扩展 - 违反TLS 1.3规范")
        
        self.SH = serverHello
        return serverHello

    def _generate_server_hello_fuzz_keyshare(self, fuzz_type='zero'):
        """
        生成带有模糊KeyShare的ServerHello（用于测试客户端对异常KeyShare的处理）

        参考：mytls.py:1115-1264 (generateFuzzClientHelloKeyShare)

        Args:
            fuzz_type: 模糊测试类型
                'zero' - Y = 0 (全零)
                'one' - Y = 1
                'max' - Y = p-1 (最大值)
                'over_prime' - Y > p-1 (超出范围)
                'invalid_length' - 错误的长度

        :return: (ServerHello, shared_secret) 元组
                 - ServerHello: 包含模糊KeyShare扩展的服务器Hello消息
                 - shared_secret: 使用模糊私钥计算的共享密钥（用于密钥派生）
        """
        self._debug_print(f"\n[C18-FUZZ] 生成带有模糊KeyShare的ServerHello (fuzz_type={fuzz_type})")

        # 生成服务器随机数
        self._serverRandom = getRandomBytes(32)
    
        # 选择密码套件
        client_suites = self.CH.cipher_suites
        if self.cipher_suite in client_suites:
            selected_suite = self.cipher_suite
        else:
            for suite in client_suites:
                if suite in CipherSuite.tls13Suites:
                    selected_suite = suite
                    break
            else:
                selected_suite = client_suites[0]

        self.cipher_suite = selected_suite

        # 设置PRF
        if selected_suite in CipherSuite.sha384PrfSuites:
            self.prf_name = 'sha384'
            self.prf_size = 48
        else:
            self.prf_name = 'sha256'
            self.prf_size = 32

        # self._debug_print(f"  - 选择密码套件: {CipherSuite.toRepr(selected_suite)}")

        # 获取客户端的KeyShare
        client_key_share = self.CH.getExtension(ExtensionType.key_share)
        if not client_key_share or not client_key_share.client_shares:
            self._debug_print("[!] 错误: ClientHello缺少KeyShare扩展")
            return None

        # 服务器支持的群组列表（与 _send_server_hello 保持一致）
        # ECDHE: secp256r1=23, secp384r1=24, secp521r1=25, x25519=29, x448=30
        # FFDH: ffdhe2048=256, ffdhe3072=257, ffdhe4096=258, ffdhe6144=259, ffdhe8192=260
        SERVER_SUPPORTED_GROUPS = [23, 24, 25, 29, 30, 256, 257, 258, 259, 260]

        # 匹配客户端和服务器支持的群组，选择第一个匹配的
        selected_share = None
        for share in client_key_share.client_shares:
            if share.group in SERVER_SUPPORTED_GROUPS:
                selected_share = share
                break

        if selected_share is None:
            self._debug_print("[!] 错误: 客户端和服务器没有共同支持的密钥交换组（fuzz模式）")
            self._debug_print(f"  - 客户端支持: {[s.group for s in client_key_share.client_shares]}")
            self._debug_print(f"  - 服务器支持: {SERVER_SUPPORTED_GROUPS}")
            return None

        group_id = selected_share.group
        # print("group",group_id)

        self._debug_print(f"  - 密钥交换组: {GroupName.toRepr(group_id)}")

        # 定义各个curve的参数长度和prime值
        curve_params = {
            GroupName.secp256r1: {
                'length': 65,
                'coord_len': 32,
                'prime': int('FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF', 16)
            },
            GroupName.secp384r1: {
                'length': 97,
                'coord_len': 48,
                'prime': int('FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFF', 16)
            },
            GroupName.secp521r1: {
                'length': 133,
                'coord_len': 66,
                'prime': int('01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF', 16)
            },
            GroupName.x25519: {
                'length': 32,
                'coord_len': 32,
                'prime': 2**255 - 19
            },
            GroupName.x448: {
                'length': 56,
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

        if group_id not in curve_params:
            self._debug_print(f"[!] 不支持的群组: {group_id}")
            return None

        params = curve_params[group_id]
        # 生成模糊的key_exchange值
        if fuzz_type == 'zero':
            # Y = 0: 全零
            if group_id in [GroupName.x25519, GroupName.x448]:
                # Montgomery curves: 直接设置u-coordinate为0
                fuzz_key_exchange = bytearray(params['length'])
            elif group_id in [GroupName.ffdhe2048, GroupName.ffdhe3072, GroupName.ffdhe4096]:
                # FFDHE: 大整数为0
                fuzz_key_exchange = bytearray(params['length'])
            else:
                # Weierstrass curves: uncompressed point format
                fuzz_key_exchange = bytearray(params['length'])
                fuzz_key_exchange[0] = 0x04  # uncompressed point format

        elif fuzz_type == 'one':
            # Y = 1
            if group_id in [GroupName.x25519, GroupName.x448]:
                # Montgomery curves: 设置u-coordinate为1
                fuzz_key_exchange = bytearray(params['length'])
                fuzz_key_exchange[0] = 0x01
            elif group_id in [GroupName.ffdhe2048, GroupName.ffdhe3072, GroupName.ffdhe4096]:
                # FFDHE: 大整数为1（big-endian）
                fuzz_key_exchange = bytearray(params['length'])
                fuzz_key_exchange[-1] = 0x01
            else:
                # Weierstrass curves: uncompressed point (0x04, x=1, y=1)
                fuzz_key_exchange = bytearray(params['length'])
                fuzz_key_exchange[0] = 0x04
                fuzz_key_exchange[params['coord_len']] = 0x01
                fuzz_key_exchange[params['coord_len'] * 2] = 0x01

        elif fuzz_type == 'max':
            # Y = p-1 (最大有效值)
            prime = params['prime']
            p_minus_1 = prime - 1

            if group_id in [GroupName.x25519, GroupName.x448]:
                # Montgomery curves: little-endian
                p_minus_1_bytes = p_minus_1.to_bytes(params['coord_len'], 'little')
                fuzz_key_exchange = bytearray(p_minus_1_bytes)
            elif group_id in [GroupName.ffdhe2048, GroupName.ffdhe3072, GroupName.ffdhe4096]:
                # FFDHE: big-endian
                p_minus_1_bytes = p_minus_1.to_bytes(params['length'], 'big')
                fuzz_key_exchange = bytearray(p_minus_1_bytes)
            else:
                # Weierstrass curves: (0x04, x=p-1, y=p-1)
                fuzz_key_exchange = bytearray(params['length'])
                fuzz_key_exchange[0] = 0x04
                x_bytes = p_minus_1.to_bytes(params['coord_len'], 'big')
                fuzz_key_exchange[1:1+params['coord_len']] = x_bytes
                y_bytes = p_minus_1.to_bytes(params['coord_len'], 'big')
                fuzz_key_exchange[1+params['coord_len']:] = y_bytes

        elif fuzz_type == 'length':
            # 错误的长度：添加额外字节
            fuzz_key_exchange = bytearray(params['length'] + 10)

        elif fuzz_type == 'prime':
            # Y > p-1 (超出范围)
            prime = params['prime']
            over_value = prime + 100
            if group_id in [GroupName.x25519, GroupName.x448]:
                # Montgomery curves: little-endian
                over_bytes = over_value.to_bytes(params['coord_len'], 'little')
                fuzz_key_exchange = bytearray(over_bytes)
            elif group_id in [GroupName.ffdhe2048, GroupName.ffdhe3072, GroupName.ffdhe4096]:
                # FFDHE: big-endian, 可能需要额外字节
                try:
                    over_bytes = over_value.to_bytes(params['length'], 'big')
                except OverflowError:
                    # 如果over_value太大，使用更大的长度
                    over_bytes = over_value.to_bytes(params['length'] + 1, 'big')
                fuzz_key_exchange = bytearray(over_bytes)
            else:
                # Weierstrass curves
                fuzz_key_exchange = bytearray(params['length'])
                fuzz_key_exchange[0] = 0x04
                try:
                    over_bytes = over_value.to_bytes(params['coord_len'], 'big')
                except OverflowError:
                    over_bytes = over_value.to_bytes(params['coord_len'] + 1, 'big')[:params['coord_len']]
                fuzz_key_exchange[1:1+len(over_bytes)] = over_bytes
        else:
            self._debug_print(f"[!] 未知的fuzz_type: {fuzz_type}")
            return None

        self._debug_print(f"  - 模糊KeyShare长度: {len(fuzz_key_exchange)} bytes")
        self._debug_print(f"  - 模糊KeyShare前16字节: {fuzz_key_exchange[:16].hex()}")

        # 生成模糊的私钥 (关键修改：使用fuzzy值生成私钥)
        # 注意：这些私钥值是无效的，但如果客户端接受了KeyShare，握手会继续
        if fuzz_type == 'zero':
            # 私钥 = 0 (全零)
            if group_id in [GroupName.x25519, GroupName.x448]:
                fuzz_private_key = bytearray(params['coord_len'])
            elif group_id in [GroupName.ffdhe2048, GroupName.ffdhe3072, GroupName.ffdhe4096]:
                fuzz_private_key = bytearray(params['length'])
            else:
                # Weierstrass curves: 私钥也是全零
                fuzz_private_key = bytearray(params['coord_len'])

        elif fuzz_type == 'one':
            # 私钥 = 1
            if group_id in [GroupName.x25519, GroupName.x448]:
                fuzz_private_key = bytearray(params['coord_len'])
                fuzz_private_key[0] = 0x01  # little-endian
            elif group_id in [GroupName.ffdhe2048, GroupName.ffdhe3072, GroupName.ffdhe4096]:
                fuzz_private_key = bytearray(params['length'])
                fuzz_private_key[-1] = 0x01  # big-endian
            else:
                # Weierstrass curves
                fuzz_private_key = bytearray(params['coord_len'])
                fuzz_private_key[-1] = 0x01

        elif fuzz_type == 'max':
            # 私钥 = p-1
            prime = params['prime']
            p_minus_1 = prime - 1
            if group_id in [GroupName.x25519, GroupName.x448]:
                fuzz_private_key = bytearray(p_minus_1.to_bytes(params['coord_len'], 'little'))
            elif group_id in [GroupName.ffdhe2048, GroupName.ffdhe3072, GroupName.ffdhe4096]:
                fuzz_private_key = bytearray(p_minus_1.to_bytes(params['length'], 'big'))
            else:
                fuzz_private_key = bytearray(p_minus_1.to_bytes(params['coord_len'], 'big'))

        elif fuzz_type == 'prime':
            # 私钥 > p-1 (超出范围)
            prime = params['prime']
            over_value = prime + 100
            if group_id in [GroupName.x25519, GroupName.x448]:
                try:
                    fuzz_private_key = bytearray(over_value.to_bytes(params['coord_len'], 'little'))
                except OverflowError:
                    fuzz_private_key = bytearray(over_value.to_bytes(params['coord_len'] + 1, 'little')[:params['coord_len']])
            elif group_id in [GroupName.ffdhe2048, GroupName.ffdhe3072, GroupName.ffdhe4096]:
                try:
                    fuzz_private_key = bytearray(over_value.to_bytes(params['length'], 'big'))
                except OverflowError:
                    fuzz_private_key = bytearray(over_value.to_bytes(params['length'] + 1, 'big')[:params['length']])
            else:
                try:
                    fuzz_private_key = bytearray(over_value.to_bytes(params['coord_len'], 'big'))
                except OverflowError:
                    fuzz_private_key = bytearray(over_value.to_bytes(params['coord_len'] + 1, 'big')[:params['coord_len']])

        elif fuzz_type == 'length':
            # 错误长度：使用更长的私钥
            if group_id in [GroupName.x25519, GroupName.x448]:
                fuzz_private_key = bytearray(params['coord_len'] + 10)
            elif group_id in [GroupName.ffdhe2048, GroupName.ffdhe3072, GroupName.ffdhe4096]:
                fuzz_private_key = bytearray(params['length'] + 10)
            else:
                fuzz_private_key = bytearray(params['coord_len'] + 10)

        else:
            # 默认使用全零
            fuzz_private_key = bytearray(params.get('coord_len', params['length']))

        self._debug_print(f"  - 模糊私钥长度: {len(fuzz_private_key)} bytes")
        self._debug_print(f"  - 模糊私钥前16字节: {fuzz_private_key[:16].hex()}")

        # 初始化密钥交换对象（如果尚未初始化）
        if self.keyExchange is None:
            if group_id in [23, 24, 25, 29, 30]:  # ECDHE groups
                self.keyExchange = ECDHKeyExchange(group_id, (3, 4))
            elif group_id in [256, 257, 258, 259, 260]:  # FFDH groups
                self.keyExchange = FFDHKeyExchange(group_id, (3, 4))

        # 使用模糊私钥计算共享密钥
        # 注意：即使私钥无效，calc_shared_key也会尝试计算（可能失败或产生无效结果）
        try:
            client_pub_key = selected_share.key_exchange
            shared_secret = self.keyExchange.calc_shared_key(fuzz_private_key, client_pub_key)
            self._debug_print(f"  - 共享密钥计算成功: {shared_secret.hex()[:32]}...")
        except Exception as e:
            self._debug_print(f"  [WARNING] 共享密钥计算失败: {e}")
            # 如果计算失败，使用全零共享密钥（这样握手会失败，但可以继续测试）
            if group_id in [GroupName.x25519, GroupName.x448]:
                shared_secret = bytearray(params['coord_len'])
            elif group_id in [GroupName.ffdhe2048, GroupName.ffdhe3072, GroupName.ffdhe4096]:
                shared_secret = bytearray(params['length'])
            else:
                shared_secret = bytearray(params['coord_len'])
            self._debug_print(f"  - 使用全零共享密钥: {shared_secret.hex()[:32]}...")

        # 创建服务器KeyShareEntry（使用模糊的key_exchange和私钥）
        from tlslite.messages import KeyShareEntry
        server_key_share = KeyShareEntry()
        server_key_share.group = group_id
        server_key_share.key_exchange = fuzz_key_exchange
        server_key_share.private = fuzz_private_key  # 保存模糊私钥

        # 构建ServerHello
        serverHello = ServerHello()
        serverHello.server_version = (3, 3)
        serverHello.random = self._serverRandom
        serverHello.session_id = self.CH.session_id
        serverHello.cipher_suite = selected_suite
        serverHello.compression_method = 0

        # 添加扩展
        serverHello.extensions = []

        # supported_versions扩展
        ext_sv = SrvSupportedVersionsExtension().create((3, 4))
        serverHello.extensions.append(ext_sv)

        # key_share扩展（使用模糊的KeyShare）
        ext_ks = ServerKeyShareExtension().create(server_key_share)
        serverHello.extensions.append(ext_ks)

        self.SH = serverHello

        self._debug_print(f"  [C18-FUZZ] ServerHello生成完成，包含模糊KeyShare和共享密钥")

        # 返回 ServerHello 和 shared_secret（供密钥派生使用）
        return (serverHello, shared_secret)

    def _send_server_hello_merged_with_ee(self):
        """
        C20: 将ServerHello和EncryptedExtensions合并到同一个TLS记录中发送

        参考用户描述：
        1. 生成ServerHello: sh，转为bytes类型
        2. 修改ServerHello的长度length
        3. 更新握手哈希: self._handshake_hash.update(bytearray(sh[5:]))
        4. 生成EncryptedExtensions: ee，更新哈希 ee[5:]
        5. 合并发送: for result in self._recordLayer._recordSocket._sockSendAll(sh+ee): pass

        :return: None（直接发送，不通过生成器）
        """
        self._debug_print(f"\n[C20-FUZZ] 合并ServerHello和EncryptedExtensions到同一个TLS记录")

        # 步骤1: 生成ServerHello并派生密钥（使用正常流程）
        # 生成服务器随机数
        self._serverRandom = getRandomBytes(32)
        self._debug_print(f"  - 服务器随机数: {self._serverRandom.hex()[:32]}...")

        # 选择密码套件
        client_suites = self.CH.cipher_suites
        if self.cipher_suite in client_suites:
            selected_suite = self.cipher_suite
        else:
            for suite in client_suites:
                if suite in CipherSuite.tls13Suites:
                    selected_suite = suite
                    break
            else:
                selected_suite = client_suites[0]

        self.cipher_suite = selected_suite

        # 根据密码套件设置PRF
        if selected_suite in CipherSuite.sha384PrfSuites:
            self.prf_name = 'sha384'
            self.prf_size = 48
        else:
            self.prf_name = 'sha256'
            self.prf_size = 32

        self._debug_print(f"  - 选择密码套件: {CipherSuite.ietfNames.get(selected_suite, hex(selected_suite))}")

        # 密钥交换
        client_key_share = self.CH.getExtension(ExtensionType.key_share)
        if not client_key_share or not client_key_share.client_shares:
            self._debug_print("[!] 错误: ClientHello缺少KeyShare扩展")
            return

        # 服务器支持的群组列表（与 _send_server_hello 保持一致）
        # ECDHE: secp256r1=23, secp384r1=24, secp521r1=25, x25519=29, x448=30
        # FFDH: ffdhe2048=256, ffdhe3072=257, ffdhe4096=258, ffdhe6144=259, ffdhe8192=260
        SERVER_SUPPORTED_GROUPS = [23, 24, 25, 29, 30, 256, 257, 258, 259, 260]

        # 匹配客户端和服务器支持的群组，选择第一个匹配的
        selected_share = None
        for share in client_key_share.client_shares:
            if share.group in SERVER_SUPPORTED_GROUPS:
                selected_share = share
                break

        if selected_share is None:
            self._debug_print("[!] 错误: 客户端和服务器没有共同支持的密钥交换组（merged模式）")
            self._debug_print(f"  - 客户端支持: {[s.group for s in client_key_share.client_shares]}")
            self._debug_print(f"  - 服务器支持: {SERVER_SUPPORTED_GROUPS}")
            return

        group_id = selected_share.group

        # 选��密钥交换方法
        if group_id in [23, 24, 25, 29, 30]:
            self.keyExchange = ECDHKeyExchange(group_id, (3, 4))
        elif group_id in [256, 257, 258, 259, 260]:
            self.keyExchange = FFDHKeyExchange(group_id, (3, 4))
        else:
            self._debug_print(f"[!] 错误: 不支持的密钥交换组 {group_id}")
            return

        # 生成密钥对
        private_key = self.keyExchange.get_random_private_key()
        public_key = self.keyExchange.calc_public_value(private_key)

        # 创建服务器KeyShareEntry
        from tlslite.messages import KeyShareEntry
        server_key_share = KeyShareEntry().create(group_id, public_key, private_key)

        # 计算共享密钥
        client_pub_key = selected_share.key_exchange
        shared_sec = self.keyExchange.calc_shared_key(private_key, client_pub_key)

        # 构建ServerHello
        serverHello = ServerHello()
        serverHello.server_version = (3, 3)
        serverHello.random = self._serverRandom
        serverHello.session_id = self.CH.session_id
        serverHello.cipher_suite = selected_suite
        serverHello.compression_method = 0

        # 添加扩展
        serverHello.extensions = []
        ext_sv = SrvSupportedVersionsExtension().create((3, 4))
        serverHello.extensions.append(ext_sv)
        ext_ks = ServerKeyShareExtension().create(server_key_share)
        serverHello.extensions.append(ext_ks)

        self.SH = serverHello

        # 步骤2: 将ServerHello转为bytes（包含TLS记录头）
        sh_handshake_bytes = serverHello.write()  # 握手消息（不含记录头）

        # 创建TLS记录头（正常的，用于ServerHello）
        from tlslite.recordlayer import RecordHeader3
        sh_record = RecordHeader3()
        sh_record.create((3, 3), ContentType.handshake, len(sh_handshake_bytes))
        sh_bytes = sh_record.write() + sh_handshake_bytes  # 完整的TLS记录

        self._debug_print(f"  - ServerHello记录长度: {len(sh_bytes)} bytes")

        # 步骤3: 更新握手哈希（只更新握手消息部分，不包含记录头的前5字节）
        self._handshake_hash.update(bytearray(sh_bytes[5:]))

        # 步骤4: 派生握手密钥
        self._derive_keys_after_server_hello(shared_sec)

        # 步骤5: 生成EncryptedExtensions（明文，不加密）
        ee = EncryptedExtensions().create([])
        ee_handshake_bytes = ee.write()

        # 更新握手哈希（EncryptedExtensions）
        self._handshake_hash.update(bytearray(ee_handshake_bytes))

        self._debug_print(f"  - EncryptedExtensions握手消息长度: {len(ee_handshake_bytes)} bytes")

        # 步骤6: 合并ServerHello和EncryptedExtensions到同一个TLS记录
        # C20违规：修改ServerHello的TLS记录长度，使其包含EE
        merged_length = len(sh_handshake_bytes) + len(ee_handshake_bytes)
        merged_record = RecordHeader3()
        merged_record.create((3, 3), ContentType.handshake, merged_length)

        # 合并：记录头 + ServerHello握手消息 + EE握手消息
        merged_bytes = merged_record.write() + sh_handshake_bytes + ee_handshake_bytes

        self._debug_print(f"  - 合并后的TLS记录长度: {len(merged_bytes)} bytes")
        self._debug_print(f"  [C20-FUZZ] 违规：两个握手消息在同一个TLS记录中")

        # 步骤7: 直接发送合并的记录（不加密）
        # 参考用户提供的代码：for result in self._recordLayer._recordSocket._sockSendAll(ch+ee): pass
        for result in self._recordLayer._recordSocket._sockSendAll(merged_bytes):
            pass

        self._debug_print(f"  [C20-FUZZ] 合并消息已发送")

        # 步骤8: 切换到握手加密状态
        self._change_cipher_state_after_server_hello()

    def _send_server_hello_merged_with_ee_cert(self):
        """
        C20: 将ServerHello + EncryptedExtensions + Certificate合并到同一个TLS记录中发送

        测试场景：(1) SH+EE+CERT
        """
        self._debug_print(f"\n[C20-FUZZ] 合并ServerHello + EncryptedExtensions + Certificate到同一个TLS记录")

        # 步骤1: 生成ServerHello并派生密钥（使用正常流程）
        self._serverRandom = getRandomBytes(32)

        # 选择密码套件
        client_suites = self.CH.cipher_suites
        if self.cipher_suite in client_suites:
            selected_suite = self.cipher_suite
        else:
            for suite in client_suites:
                if suite in CipherSuite.tls13Suites:
                    selected_suite = suite
                    break
            else:
                selected_suite = client_suites[0]

        self.cipher_suite = selected_suite

        # 根据密码套件设置PRF
        if selected_suite in CipherSuite.sha384PrfSuites:
            self.prf_name = 'sha384'
            self.prf_size = 48
        else:
            self.prf_name = 'sha256'
            self.prf_size = 32

        # 密钥交换
        client_key_share = self.CH.getExtension(ExtensionType.key_share)
        if not client_key_share or not client_key_share.client_shares:
            self._debug_print("[!] 错误: ClientHello缺少KeyShare扩展")
            return

        # 服务器支持的群组列表
        SERVER_SUPPORTED_GROUPS = [23, 24, 25, 29, 30, 256, 257, 258, 259, 260]

        # 匹配客户端和服务器支持的群组，选择第一个匹配的
        selected_share = None
        for share in client_key_share.client_shares:
            if share.group in SERVER_SUPPORTED_GROUPS:
                selected_share = share
                break

        if selected_share is None:
            self._debug_print("[!] 错误: 客户端和服务器没有共同支持的密钥交换组")
            return

        group_id = selected_share.group

        # 选择密钥交换方法
        if group_id in [23, 24, 25, 29, 30]:
            self.keyExchange = ECDHKeyExchange(group_id, (3, 4))
        elif group_id in [256, 257, 258, 259, 260]:
            self.keyExchange = FFDHKeyExchange(group_id, (3, 4))
        else:
            self._debug_print(f"[!] 错误: 不支持的密钥交换组 {group_id}")
            return

        # 生成密钥对
        private_key = self.keyExchange.get_random_private_key()
        public_key = self.keyExchange.calc_public_value(private_key)

        # 创建服务器KeyShareEntry
        from tlslite.messages import KeyShareEntry
        server_key_share = KeyShareEntry().create(group_id, public_key, private_key)

        # 计算共享密钥
        client_pub_key = selected_share.key_exchange
        shared_sec = self.keyExchange.calc_shared_key(private_key, client_pub_key)

        # 构建ServerHello
        serverHello = ServerHello()
        serverHello.server_version = (3, 3)
        serverHello.random = self._serverRandom
        serverHello.session_id = self.CH.session_id
        serverHello.cipher_suite = selected_suite
        serverHello.compression_method = 0

        # 添加扩展
        serverHello.extensions = []
        ext_sv = SrvSupportedVersionsExtension().create((3, 4))
        serverHello.extensions.append(ext_sv)
        ext_ks = ServerKeyShareExtension().create(server_key_share)
        serverHello.extensions.append(ext_ks)

        self.SH = serverHello

        # 步骤2: 将ServerHello转为bytes
        sh_handshake_bytes = serverHello.write()

        # 步骤3: 更新握手哈希（ServerHello）
        if self._handshake_hash is None:
            self._handshake_hash = HandshakeHashes()
        self._handshake_hash.update(bytearray(sh_handshake_bytes))

        # 步骤4: 派生握手密钥
        self._derive_keys_after_server_hello(shared_sec)

        # 步骤5: 生成EncryptedExtensions（明文，不加密）
        ee = EncryptedExtensions().create([])
        ee_handshake_bytes = ee.write()

        # 更新握手哈希（EncryptedExtensions）
        self._handshake_hash.update(bytearray(ee_handshake_bytes))

        self._debug_print(f"  - EncryptedExtensions长度: {len(ee_handshake_bytes)} bytes")

        # 步骤6: 生成Certificate（明文，不加密）
        if self.SH == None:
            certificate_type = CertificateType.x509
        else:
            certificate_type = self.SH.certificate_type
        cert_msg = Certificate(certificate_type, self.support_version)
        cert_msg.create(self.cert_chain)
        cert_handshake_bytes = cert_msg.write()

        # 更新握手哈希（Certificate）
        self._handshake_hash.update(bytearray(cert_handshake_bytes))

        self._debug_print(f"  - Certificate长度: {len(cert_handshake_bytes)} bytes")

        # 步骤7: 合并ServerHello + EncryptedExtensions + Certificate到同一个TLS记录
        from tlslite.recordlayer import RecordHeader3
        merged_length = len(sh_handshake_bytes) + len(ee_handshake_bytes) + len(cert_handshake_bytes)
        merged_record = RecordHeader3()
        merged_record.create((3, 3), ContentType.handshake, merged_length)

        # 合并：记录头 + SH + EE + Cert
        merged_bytes = merged_record.write() + sh_handshake_bytes + ee_handshake_bytes + cert_handshake_bytes

        self._debug_print(f"  - 合并后的TLS记录长度: {len(merged_bytes)} bytes")
        self._debug_print(f"  [C20-FUZZ] 违规：三个握手消息在同一个TLS记录中")

        # 步骤8: 直接发送合并的记录（不加密）
        for result in self._recordLayer._recordSocket._sockSendAll(merged_bytes):
            pass

        self._debug_print(f"  [C20-FUZZ] 合并消息已发送")

        # 步骤9: 切换到握手加密状态
        self._change_cipher_state_after_server_hello()

    def _send_server_hello_merged_with_ee_cert_cv_fin(self):
        """
        C20: 将ServerHello + EncryptedExtensions + Certificate + CertificateVerify + Finished合并到同一个TLS记录中发送

        测试场景：(2) SH+EE+CERT+CV+FIN
        """
        self._debug_print(f"\n[C20-FUZZ] 合并ServerHello + EE + Certificate + CertificateVerify + Finished到同一个TLS记录")

        # 步骤1: 生成ServerHello并派生密钥
        self._serverRandom = getRandomBytes(32)

        # 选择密码套件
        client_suites = self.CH.cipher_suites
        if self.cipher_suite in client_suites:
            selected_suite = self.cipher_suite
        else:
            for suite in client_suites:
                if suite in CipherSuite.tls13Suites:
                    selected_suite = suite
                    break
            else:
                selected_suite = client_suites[0]

        self.cipher_suite = selected_suite

        # 根据密码套件设置PRF
        if selected_suite in CipherSuite.sha384PrfSuites:
            self.prf_name = 'sha384'
            self.prf_size = 48
        else:
            self.prf_name = 'sha256'
            self.prf_size = 32

        # 密钥交换
        client_key_share = self.CH.getExtension(ExtensionType.key_share)
        if not client_key_share or not client_key_share.client_shares:
            self._debug_print("[!] 错误: ClientHello缺少KeyShare扩展")
            return

        # 服务器支持的群组列表
        SERVER_SUPPORTED_GROUPS = [23, 24, 25, 29, 30, 256, 257, 258, 259, 260]

        # 匹配客户端和服务器支持的群组
        selected_share = None
        for share in client_key_share.client_shares:
            if share.group in SERVER_SUPPORTED_GROUPS:
                selected_share = share
                break

        if selected_share is None:
            self._debug_print("[!] 错误: 客户端和服务器没有共同支持的密钥交换组")
            return

        group_id = selected_share.group

        # 选择密钥交换方法
        if group_id in [23, 24, 25, 29, 30]:
            self.keyExchange = ECDHKeyExchange(group_id, (3, 4))
        elif group_id in [256, 257, 258, 259, 260]:
            self.keyExchange = FFDHKeyExchange(group_id, (3, 4))
        else:
            self._debug_print(f"[!] 错误: 不支持的密钥交换组 {group_id}")
            return

        # 生成密钥对
        private_key = self.keyExchange.get_random_private_key()
        public_key = self.keyExchange.calc_public_value(private_key)

        # 创建服务器KeyShareEntry
        from tlslite.messages import KeyShareEntry
        server_key_share = KeyShareEntry().create(group_id, public_key, private_key)

        # 计算共享密钥
        client_pub_key = selected_share.key_exchange
        shared_sec = self.keyExchange.calc_shared_key(private_key, client_pub_key)

        # 构建ServerHello
        serverHello = ServerHello()
        serverHello.server_version = (3, 3)
        serverHello.random = self._serverRandom
        serverHello.session_id = self.CH.session_id
        serverHello.cipher_suite = selected_suite
        serverHello.compression_method = 0

        # 添加扩展
        serverHello.extensions = []
        ext_sv = SrvSupportedVersionsExtension().create((3, 4))
        serverHello.extensions.append(ext_sv)
        ext_ks = ServerKeyShareExtension().create(server_key_share)
        serverHello.extensions.append(ext_ks)

        self.SH = serverHello

        # 步骤2: 将ServerHello转为bytes
        sh_handshake_bytes = serverHello.write()

        # 步骤3: 更新握手哈希（ServerHello）
        if self._handshake_hash is None:
            self._handshake_hash = HandshakeHashes()
        self._handshake_hash.update(bytearray(sh_handshake_bytes))

        # 步骤4: 派生握手密钥
        self._derive_keys_after_server_hello(shared_sec)

        # 步骤5: 生成EncryptedExtensions
        ee = EncryptedExtensions().create([])
        ee_handshake_bytes = ee.write()
        self._handshake_hash.update(bytearray(ee_handshake_bytes))
        self._debug_print(f"  - EncryptedExtensions长度: {len(ee_handshake_bytes)} bytes")

        # 步骤6: 生成Certificate
        if self.SH == None:
            certificate_type = CertificateType.x509
        else:
            certificate_type = self.SH.certificate_type
        cert_msg = Certificate(certificate_type, self.support_version)
        cert_msg.create(self.cert_chain)
        cert_handshake_bytes = cert_msg.write()
        self._handshake_hash.update(bytearray(cert_handshake_bytes))
        self._debug_print(f"  - Certificate长度: {len(cert_handshake_bytes)} bytes")

        # 步骤7: 生成CertificateVerify
        if not self.privateKey:
            self._debug_print("[!] 错误: 没有私钥，无法创建CertificateVerify")
            return

        cert_verify = CertificateVerify((3, 4))
        sig_alg = SignatureScheme.rsa_pss_rsae_sha256
        cert_verify.signatureAlgorithm = sig_alg

        # 计算签名
        from tlslite.keyexchange import KeyExchange
        signature_context = KeyExchange.calcVerifyBytes(
            (3, 4),
            self._handshake_hash,
            sig_alg,
            None,
            None,
            None,
            self.prf_name,
            b'server'
        )

        try:
            signature = self.privateKey.sign(signature_context,
                                              padding='pss',
                                              hashAlg='sha256',
                                              saltLen=32)
            cert_verify.signature = signature
        except Exception as e:
            self._debug_print(f"[!] 签名失败: {e}")
            return

        cv_handshake_bytes = cert_verify.write()
        self._handshake_hash.update(bytearray(cv_handshake_bytes))
        self._debug_print(f"  - CertificateVerify长度: {len(cv_handshake_bytes)} bytes")

        # 步骤8: 生成Finished
        finished = Finished((3, 4), self.prf_size)
        hash_before_finished = self._handshake_hash.copy()
        handshake_hash = hash_before_finished.digest(self.prf_name)

        finished_key = HKDF_expand_label(
            self.sr_handshake_traffic_secret,
            b"finished",
            b"",
            self.prf_size,
            self.prf_name
        )

        verify_data = secureHMAC(
            finished_key,
            handshake_hash,
            self.prf_name
        )

        finished.verify_data = verify_data
        finished_handshake_bytes = finished.write()
        # 注意：Finished哈希在发送后才更新，这里暂不更新
        self._debug_print(f"  - Finished长度: {len(finished_handshake_bytes)} bytes")

        # 步骤9: 合并所有消息到同一个TLS记录
        from tlslite.recordlayer import RecordHeader3
        merged_length = (len(sh_handshake_bytes) + len(ee_handshake_bytes) +
                        len(cert_handshake_bytes) + len(cv_handshake_bytes) +
                        len(finished_handshake_bytes))
        merged_record = RecordHeader3()
        merged_record.create((3, 3), ContentType.handshake, merged_length)

        # 合并：记录头 + SH + EE + Cert + CV + Fin
        merged_bytes = (merged_record.write() + sh_handshake_bytes + ee_handshake_bytes +
                       cert_handshake_bytes + cv_handshake_bytes + finished_handshake_bytes)

        self._debug_print(f"  - 合并后的TLS记录长度: {len(merged_bytes)} bytes")
        self._debug_print(f"  [C20-FUZZ] 违规：五个握手消息在同一个TLS记录中")

        # 步骤10: 直接发送合并的记录（不加密）
        for result in self._recordLayer._recordSocket._sockSendAll(merged_bytes):
            pass

        self._debug_print(f"  [C20-FUZZ] 合并消息已发送")

        # 步骤11: 更新Finished哈希（发送后）
        self._handshake_hash.update(finished_handshake_bytes)

        # 步骤12: 切换到握手加密状态
        self._change_cipher_state_after_server_hello()

    def _derive_keys_after_server_hello(self, shared_sec):
        """
        在ServerHello后计算握手密钥
        参考：tlsconnection.py:2713-2734
        """
        self._debug_print(f"\n[KEY] 开始密钥派生...")

        # 调试：打印握手哈希
        self._debug_print(f"[DEBUG] 握手哈希（用于密钥派生）: {self._handshake_hash.digest(self.prf_name).hex()[:64]}...")

        # 密钥派生流程 (参考 tlsconnection.py:2712-2726)
        # 1. Early Secret（无PSK时使用零）
        psk = bytearray(self.prf_size)
        secret = bytearray(self.prf_size)  # 初始化为零
        secret = secureHMAC(secret, psk, self.prf_name)
        self.early_secret = secret

        # 2. Handshake Secret
        secret = derive_secret(secret, bytearray(b'derived'), None, self.prf_name)
        secret = secureHMAC(secret, shared_sec, self.prf_name)
        self.handshake_secret = secret

        # 3. 握手流量密钥
        self.sr_handshake_traffic_secret = derive_secret(
            secret,
            bytearray(b's hs traffic'),
            self._handshake_hash,
            self.prf_name
        )
        self.cl_handshake_traffic_secret = derive_secret(
            secret,
            bytearray(b'c hs traffic'),
            self._handshake_hash,
            self.prf_name
        )

        self._debug_print(f"[KEY] Handshake Secret派生完成")
        self._debug_print(f"  - Early Secret: {self.early_secret.hex()[:32]}...")
        self._debug_print(f"  - Handshake Secret: {self.handshake_secret.hex()[:32]}...")
        self._debug_print(f"  - Server HS Traffic: {self.sr_handshake_traffic_secret.hex()[:32]}...")
        self._debug_print(f"  - Client HS Traffic: {self.cl_handshake_traffic_secret.hex()[:32]}...")

        # 写入握手密钥到keylog文件
        self._write_keylog()

    def _derive_keys_after_finished(self):
        """
        在接收客户端Finished后计算应用密钥
        参考：tlsconnection.py (Master Secret derivation)
        """
        self._debug_print(f"\n[KEY] 开始应用密钥派生...")

        # 1. Master Secret (参考 tlsconnection.py:2712-2717)
        temp = derive_secret(self.handshake_secret, bytearray(b'derived'), None, self.prf_name)
        self.master_secret = secureHMAC(temp, bytearray(self.prf_size), self.prf_name)

        # 2. 应用流量密钥
        self.cl_app_traffic = derive_secret(
            self.master_secret,
            bytearray(b'c ap traffic'),
            self._handshake_hash,
            self.prf_name
        )
        self.sr_app_traffic = derive_secret(
            self.master_secret,
            bytearray(b's ap traffic'),
            self._handshake_hash,
            self.prf_name
        )

        # 3. Exporter Master Secret
        self.exporter_master_secret = derive_secret(
            self.master_secret,
            bytearray(b'exp master'),
            self._handshake_hash,
            self.prf_name
        )

        self._debug_print(f"[KEY] Application Secret派生完成")
        self._debug_print(f"  - Master Secret: {self.master_secret.hex()[:32]}...")
        self._debug_print(f"  - Client App Traffic: {self.cl_app_traffic.hex()[:32]}...")
        self._debug_print(f"  - Server App Traffic: {self.sr_app_traffic.hex()[:32]}...")

        # 写入应用密钥到keylog文件
        self._write_keylog()

    def _change_cipher_state_after_server_hello(self):
        """
        ServerHello后切换到握手加密
        参考：tlsconnection.py:2728-2734
        """
        # print(self.SH.cipher_suite)
        # print(self.cipher_suite)
        self._recordLayer.calcTLS1_3PendingState(
            self.cipher_suite,
            self.cl_handshake_traffic_secret,
            self.sr_handshake_traffic_secret,
            ['python']
        )
        # print(self._handshake_hash._handshake_buffer.hex())
        # self._changeReadState()
        self._changeWriteState()
        self._changeReadState()
        self._debug_print("[STATE] 切换到握手加密（写状态）- 服务器现在可以发送加密消息")

    def _change_cipher_state_after_server_finished(self):
        """发送Finished后切换读密钥"""
        self._changeReadState()
        self._debug_print("[STATE] 切换到握手加密（读状态）- 服务器现在可以接收客户端的加密消息")

    def _change_cipher_state_to_application(self):
        """接收客户端Finished后切换到应用密钥"""
        self._recordLayer.calcTLS1_3PendingState(
            self.cipher_suite,
            self.cl_app_traffic,
            self.sr_app_traffic,
            ['python']
        )
        self._changeWriteState()
        # self._changeReadState()
        self._debug_print("[STATE] 切换到应用流量密钥")

    def run_handshake_loop(self, message_sequence):
        """
        执行握手循环（使用sendAndRecv模式）

        参考：mytls.py 的交替发送接收模式
        核心改进：
        1. 每发送一个消息立即接收响应（交替进行）
        2. 状态切换根据消息类型，不依赖"是否最后一条消息"
        3. 使用合理超时，不是短超时立即接收

        :param message_sequence: 服务器发送的消息序列，如 ['ServerHello', 'Certificate', 'Finished']
        """
        # Debug模式: 打印阶段标记
        self._debug_print("\n" + "="*70)
        self._debug_print("TLS服务器握手开始")
        self._debug_print("="*70)

        # 非Debug模式: 打印双列表头
        self._print_message_header()

        # 步骤1: 接收ClientHello
        self._debug_print("\n[阶段1] 等待ClientHello...")
        client_letters = self.receiveAndMap()

        if self.debug:
            print(f"[←] 收到客户端消息: {'-'.join(client_letters) if client_letters else '(无)'}")
        else:
            # 第一行：还没发送消息，但收到了ClientHello
            recv_msg = '-'.join(client_letters) if client_letters else "No_Resp"
            self._print_message_pair(send_msg="-", recv_msg=recv_msg)

        if 'ClientHello' not in client_letters:
            self._debug_print("[!] 错误: 未收到ClientHello")
            return

        # 步骤2: 交替发送接收（每发送一个消息立即接收响应）
        self._debug_print(f"\n[阶段2] 交替发送接收模式: {' -> '.join(message_sequence)}")

        recv_list = []  # 存储所有收发记录

        for idx, symbol in enumerate(message_sequence):
            # 特殊处理：HelloRetryRequest后需要接收新的ClientHello
            if symbol.startswith('HelloRetryRequest'):
                # 发送HRR（不接收响应，因为客户端会发送新的ClientHello）
                self._debug_print(f"\n[发送] {symbol}")
                try:
                    if symbol == 'HelloRetryRequest':
                        for result in self._send_hello_retry_request(selected_group=None, send_ccs=False):
                            pass
                    elif symbol == 'HelloRetryRequest_CCS':
                        for result in self._send_hello_retry_request(selected_group=None, send_ccs=True):
                            pass
                    elif symbol == 'HelloRetryRequest_KeyShare':
                        for result in self._send_hello_retry_request(selected_group=GroupName.x25519, send_ccs=False):
                            pass
                    else:
                        self.sendResponse(symbol)
                except Exception as e:
                    self._debug_print(f"[!] 发送HRR失败: {e}")
                    if not self.debug:
                        self._print_message_pair(send_msg=symbol, recv_msg="SendFailed")
                    return

                # 打印HRR发送（不接收响应）
                if not self.debug:
                    self._print_message_pair(send_msg=symbol, recv_msg="No_Resp")

                # 接收新的ClientHello
                self._debug_print(f"\n[接收] 等待新的ClientHello...")
                client_letters = self.receiveAndMap()

                if self.debug:
                    print(f"[←] 收到客户端消息: {'-'.join(client_letters) if client_letters else '(无)'}")
                else:
                    recv_msg = '-'.join(client_letters) if client_letters else "No_Resp"
                    self._print_message_pair(send_msg="-", recv_msg=recv_msg)

                if 'ClientHello' not in client_letters:
                    self._debug_print("[!] 错误: 未收到新的ClientHello")
                    return

                recv_list.append((symbol, client_letters))
                continue

            # 普通消息：使用sendAndRecv模式（发送+接收）
            self._debug_print(f"\n[发送+接收] {symbol}")
            response = self.sendAndRecv(symbol)

            # 存储收发记录
            recv_list.append((symbol, response))

            # 打印输出
            if self.debug:
                self._debug_print(f"[完成] {symbol} -> {'-'.join(response) if response else '(无)'}")
            else:
                # 空列表表示没有响应（No_Resp），而不是错误
                if not response:
                    recv_msg = "No_Resp"
                else:
                    recv_msg = '-'.join(response)
                self._print_message_pair(send_msg=symbol, recv_msg=recv_msg)

            # 检查是否有真正的错误（SendFailed, ReceiveFailed, Error等）
            if response and ('SendFailed' in response or 'ReceiveFailed' in response or 'Error' in response):
                self._debug_print(f"[!] 错误: {symbol} 处理失败")
                return

        self._debug_print("\n" + "="*70)
        self._debug_print("握手完成！")
        self._debug_print("="*70 + "\n")


def main():
    """主函数：启动TLS服务器"""
    import sys

    if len(sys.argv) < 3:
        print("用法: python tls_server_with_alphabet.py <cert_file> <key_file> [port] [keylog_file]")
        print("\n示例:")
        print("  python tls_server_with_alphabet.py ./key/server.cer ./key/deserver.key")
        print("  python tls_server_with_alphabet.py ./key/server.cer ./key/deserver.key 4433")
        print("  python tls_server_with_alphabet.py ./key/server.cer ./key/deserver.key 4433 /tmp/tls_keys.log")
        print("\n说明:")
        print("  keylog_file: 可选，密钥日志文件路径（用于Wireshark解密）")
        sys.exit(1)

    cert_file = sys.argv[1]
    key_file = sys.argv[2]
    port = int(sys.argv[3]) if len(sys.argv) > 3 else 4433
    keylog_file = sys.argv[4] if len(sys.argv) > 4 else None

    # 创建监听socket
    listen_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listen_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listen_sock.bind(('0.0.0.0', port))
    listen_sock.listen(5)

    print(f"\n{'='*70}")
    print(f"TLS服务器启动")
    print(f"  - 监听地址: 0.0.0.0:{port}")
    print(f"  - 证书: {cert_file}")
    print(f"  - 私钥: {key_file}")
    if keylog_file:
        print(f"  - 密钥日志: {keylog_file}")
    print(f"{'='*70}\n")
    print("等待客户端连接...\n")

    while True:
        try:
            client_sock, client_addr = listen_sock.accept()
            print(f"\n[+] 接受来自 {client_addr} 的连接\n")

            # 创建TLS服务器实例
            server = TLSServerWithAlphabet(
                client_sock,
                cert_file=cert_file,
                key_file=key_file,
                version=(3, 4),
                keylog_file=keylog_file,  # 传入密钥日志文件路径
                # debug = True
            )

            # 配置消息序列（正常TLS 1.3握手）
            message_sequence = [
                # 'HelloRetryRequest_KeyShare',
                'ServerHello',
                'EncryptedExtensions',
                'CertificateRequest',
                'Certificate',
                'CertificateVerify',
                'Finished'
            ]

            # 执行握手
            try:
                server.run_handshake_loop(message_sequence)

                # 握手后可以接收应用数据
                print("\n[*] 等待应用数据...")
                app_letters = server.receiveAndMap()
                if app_letters:
                    print(f"[←] 收到应用层消息: {'-'.join(app_letters)}")

            except Exception as e:
                print(f"\n[!] 握手错误: {e}")
                import traceback
                traceback.print_exc()

            finally:
                client_sock.close()
                print(f"\n[-] 关闭连接: {client_addr}\n")

        except KeyboardInterrupt:
            print("\n\n[*] 服务器关闭")
            break
        except Exception as e:
            print(f"\n[!] 错误: {e}")
            import traceback
            traceback.print_exc()


if __name__ == '__main__':
    main()
