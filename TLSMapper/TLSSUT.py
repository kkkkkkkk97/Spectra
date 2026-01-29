import subprocess
from TLSMapper.mytls import *
import time,datetime,json
import colorama
from colorama import Fore
from operator import methodcaller
from aalpy.base import SUL
# from fuzzing.LTLfSUT import *
# from LTLf.TLS13LTLfFormulas import *
from TLSMapper.TLSProtocol import *
import signal

all_alert=[
    'close_notify', 
    'unexpected_message', 
    'bad_record_mac', 
    'decryption_failed', 
    'record_overflow', 
    'decompression_failure', 
    'handshake_failure', 
    'no_certificate', 
    'bad_certificate', 
    'unsupported_certificate', 
    'certificate_revoked', 
    'certificate_expired', 
    'certificate_unknown', 
    'illegal_parameter', 
    'unknown_ca', 
    'access_denied', 
    'decode_error', 
    'decrypt_error', 
    'export_restriction', 
    'protocol_version', 
    'insufficient_security', 
    'internal_error', 
    'inappropriate_fallback', 
    'user_canceled', 
    'no_renegotiation', 
    'missing_extension', 
    'unsupported_extension', 
    'certificate_unobtainable', 
    'unrecognized_name', 
    'bad_certificate_status_response', 
    'bad_certificate_hash_value', 
    'unknown_psk_identity', 
    'certificate_required', 
    'no_application_protocol', 
]

class TLSSUT(SUL):
    def __init__(self, keyfile=None, certfile=None, ciphersuites=None, target_cmd=None, TLSpro = None):
        super().__init__()
        self.load_key_and_cert(keyfile, certfile)
        self.ciphersuites = ciphersuites
        self.TLS_client=None
        self.target_cmd = target_cmd
        self.target_process = None
        self.target_ip = None
        self.target_port = None
        self.TLSpro = TLSpro
    
    def load_key_and_cert(self, keyfile, certfile):
        if keyfile is None or certfile is None:
            self.privateKey = None
            self.cert_chain = None
            return 
        try:
            text_key = str(open(keyfile, 'rb').read(), 'utf-8')
            self.privateKey = parsePEMKey(text_key, private=True,implementations=["python"])
            text_cert = str(open(certfile, 'rb').read(), 'utf-8')
            self.cert_chain = X509CertChain()
            # print(text_cert)
            self.cert_chain.parsePemList(text_cert)
        except Exception as e:
            print(f'wrong keyfile or certfile!{e}')
        
    def reset(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.5)
        # print(self.TLSpro.target)
        if self.TLSpro.target is None:
            sock.connect(('127.0.0.1',4433))
        else:
            try:
                sock.connect(self.TLSpro.target)
            except:
                print("server cannot start")
                # return 'None'

        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        self.TLSpro.reset()
        self.TLS_client = TLSClient(sock, ciphersuites=self.ciphersuites, privateKey=self.privateKey, cert_chain=self.cert_chain, tlspro=self.TLSpro,target = self.TLSpro.target)
        self.TLS_client.pre_set_extensions=self.TLSpro.pre_set_extensions
        self.TLS_client.settings=HandshakeSettings().validate()
        return True

    def process_query(self, letter):
        response = self.TLS_client.sendAndRecv(letter)
        if self.TLS_client.fuzz_flag == True and letter == self.TLS_client.fuzz_letter:
            self.TLS_client.LOG['recieve:']=response
            # print(self.TLS_client.LOG)
            # json_str = json.dumps(self.TLS_client.LOG)
            # with open(self.TLS_client.fuzz_log, 'a', encoding='utf-8') as f:
            #     f.write(json_str + '\n')
        if response in ['UnSupported', 'SendFailed', 'SigFailed', 'NoClientCert']:
            return 'None'
        return response
     
    def pre(self):
        if self.TLSpro.implementation == 'OpenSSL':
            import os
            current_dir = os.getcwd()
            my_env = os.environ.copy()
            my_env['LD_LIBRARY_PATH'] = f"{my_env.get('LD_LIBRARY_PATH', '')}:{current_dir}/openssl-gcov"
            # print(current_dir,my_env)

        if self.target_cmd:
            # self.target_process = subprocess.Popen(self.target_cmd, shell=False, stdin=None, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=my_env)
            # print(self.target_cmd)
            try:
                if self.TLSpro.implementation == 'OpenSSL':
                    # self.target_process = subprocess.Popen(self.target_cmd, shell=False, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=my_env)
                    self.target_process = subprocess.Popen(self.target_cmd, shell=False, stdin=None, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=my_env)

                else:
                    self.target_process = subprocess.Popen(self.target_cmd, shell=False, stdin=None, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

                # self.target_process = subprocess.Popen(self.target_cmd, shell=False, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=my_env)

                # self.target_process = subprocess.Popen(self.target_cmd, shell=False, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=my_env)
            except:
                print("cannot start server")

        time.sleep(0.1)
        # time.sleep(10)
        
        self.reset()
    

    def post(self):


        self.stepclose('ClosureAlert')
        self.stepclose('ClosureAlert')

        # if self.target_cmd is not None:
        #     self.target_process.communicate()

        if self.target_process:
            self.target_process.send_signal(signal.SIGINT)
            self.target_process.wait()
            self.target_process.terminate()
            self.target_process.wait()
   
    
    def step(self, letter):
        response = self.process_query(letter)
        print(f'{letter} | {response}')
        return response
    def step_early_terminate(self,letter):
        response = 'None'
        print(f'{letter} | {response}')
        return 'None'

    
    def stepclose(self, letter):
        response = self.process_query(letter)
        return response
    
    def check_connection(self):
        retcode = self.target_process.poll()
        if retcode is None:
            print("Server is still running.")
        else:
            print(f"Server exited with code {retcode}.")
        if retcode is not None:
            out, err = self.target_process.communicate()
            print("stdout:", out.decode())
            print("stderr:", err.decode())
    
    def query(self, word):
        print(f'current query : {word}')
        self.pre()
        out = []
        early_terminate = False
        resumption_encountered = False
        if len(word) == 0:
            out = [self.step(None)]
        else:
            for letter in word:
                # if not early_terminate and letter == "ClosureAlert":
                #     # response = "NoResponse"
                #     # out.append("NoResponse")
                #     early_terminate = True
                # print(early_terminate)
                if letter == 'ResumptionClientHelloAP' or letter == 'ResumptionClientHello':
                        resumption_encountered = True
                        early_terminate = False
                if early_terminate:
                    response = self.step_early_terminate(letter)
                    out.append(response)
                else:   
                    response = self.step(letter)
                    out.append(response)
                    list_resp = response.split('-')
                    common_elements = set(list_resp) & set(all_alert)
                    if common_elements:
                        early_terminate = True
                    if letter == 'ClosureAlert':
                        early_terminate = True
                    if letter == 'ResumptionClientHelloAP' or letter == 'ResumptionClientHello':
                        if response == 'None':
                           early_terminate = True
        # print(self.TLS_client.fuzz_flag) 
        if self.TLS_client.fuzz_flag == True:
            # print('-'.join(out))
            # print(self.TLS_client.LOG)
            self.TLS_client.LOG['all_recieve:'] = '|'.join(out)
            json_str = json.dumps(self.TLS_client.LOG)
            with open(self.TLS_client.fuzz_log, 'a', encoding='utf-8') as f:
                f.write(json_str + '\n')            
        self.post()
        self.num_queries += 1
        self.num_steps += len(word)
        self.performed_steps_in_query = self.num_steps
        print('*'*100)
        return out
    
    def query_packet(self, word, pck, alp):
        # print
        print(f'current query : {word}')
        self.pre()
        out = []
        for letter in word:
            if letter != alp:
                response = self.process_query(letter)    
            else:
                response = self.TLS_client.sendPCKAndRecv(pck,letter)
            out.append(response)
            print(f'{letter} | {response}')
        print('*'*100)
        return out

    def query_old(self, word):
        
        print(f'current query : {word}')
        self.pre()
        if len(word) == 0:
            out = [self.step(None)]
        else:
            out = [self.step(letter) for letter in word]
        self.post()
        self.num_queries += 1
        self.num_steps += len(word)
        self.performed_steps_in_query = self.num_steps
        print('*'*100)
        return out
    
    def fuzz_step(self, letter:str):
        self.TLS_client.fuzz_mode = True
        fletter = f'{letter}*'
        response = self.process_query(letter)
        self.TLS_client.fuzz_mode = False
        print(f'{letter} | {response}')
        return fletter, response
    
    def replay_fuzz_step(self, letter:str):
        print(letter)
        if '*' in letter:
            self.TLS_client.fuzz_replay_mode = True
            rletter = letter.replace('*', '')
            response = self.process_query(rletter)
        else:
            response = self.process_query(letter)
        self.TLS_client.fuzz_replay_mode = False
        print(f'{letter} | {response}')
        return letter, response
    
    # def save_pcap(self, name): 
    #     self.TLS_client.save_pcap(name)
        
    # def save_fuzz_contents(self, name):   
    #     xml_content = ET.tostring(self.TLS_client.fuzz_contents, encoding='utf-8').decode('utf-8')
    #     dom = xml.dom.minidom.parseString(xml_content)
    #     pretty_xml = dom.toprettyxml()
    #     with open(name, 'w') as f:
    #         f.write(pretty_xml)
        
    # def read_fuzz_contents(self, name):
    #     tree = ET.parse(name)
    #     self.TLS_client.fuzz_replay_content = tree.getroot()
            
    # def sut_to_ltl_map(self, symbol_name, is_request:bool):
    #     symbol = Symbol(symbol_name, is_request)
    #     return tls_sut_to_ltl_map(symbol).name
    
    # def ltl_to_sut_map(self, symbol_name):
    #     return tls_ltl_to_sut_map(symbol_name)
        

