from __future__ import print_function
import sys
import os
import os.path
import socket
import struct
import getopt
import binascii
import random
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

#------------------------------------------------------------
# Chooses an item from a list defined as:
# [(item_1,prob_1), (item_2,prob_2),... ,(item_n,prob_n)]
# where prob_i is the probability of choosing item_i
#------------------------------------------------------------
def weighted_choice(items):
    weight_total = sum((item[1] for item in items))
    n = random.uniform(0, weight_total)
    for item, weight in items:
        if n < weight:
            return item
        n = n - weight
    return item

def rand_ByteEnumField(enumeration=[]):
   if len(enumeration) == 0:
      return random.randint(0, 255)
   else:
      return random.choice(list(enumeration))
      
def rand_FieldLenField():
   if random.randint(0,1) == 0:
      return 0
   else:
      return random.randint(1,5000)

def rand_ShortEnumField(enumeration=[]):
   if len(enumeration) == 0:
      return random.randint(0,65535)
   else:
      return random.choice(list(enumeration))
   
def rand_IntEnumField(enumeration=[]):
   if len(enumeration) == 0:
      return random.randint(0,2147483647)
   else:
      return random.choice(list(enumeration))

def rand_StrLenField(data):
   if len(data) <= 1:
      return data
   bit = random.randint(0,2)
   if bit == 0:
      index = random.randint(0,len(data)-2)
      data = data[:index] + os.urandom(1) + data[index+1:]
   elif bit == 1:
      index = random.randint(0,len(data)-2)
      data = data[:index] + b'\x00' + data[index+1:]
   elif bit == 2:
      data = data + os.urandom(random.randint(0,100))
   elif bit == 3:
      data = b'\x00'
   return data

def rand_IntField(a=0, b=5000):
   return random.randint(a, b)

def generate_random_bytes(length):
   return bytes(random.randint(0, 255) for _ in range(length))

def string_to_list(s):
   s = s.replace('[', '').replace(']', '').replace(' ', '')
   lst = s.split(',')
   return lst

def string_to_tuple(s):
   s = s.replace('(', '').replace(')', '').replace(' ', '')
   lst = s.split(',')
   return tuple(map(int, lst)) 

def convert_string_to_type(s):
    type_map = {
        'int': int,
        'tuple': string_to_tuple,
        'list': string_to_list
    }
    
    for type_name, converter in type_map.items():
        try:
            result = converter(s)
            if isinstance(result, type_map[type_name]):
                return result
        except:
            continue
    
    return None
         
#------------------------------------------------------------
# The functions to fuzz specific type messages
#------------------------------------------------------------
def fuzzClientHello(ch: ClientHello, t=None, value=None):
   t = weighted_choice([('random', 0), ('sid', 0.5), ('cipher', 0.5), ('compress', 0.5), ('extensions', 0.5)]) if t is None else t
   if t == 'random':
      ch.random = rand_StrLenField(ch.random)
      v = None
   elif t == 'sid':
      ch.session_id = rand_StrLenField(ch.random)
      v = None
   elif t == 'cipher':
      random.shuffle(ch.cipher_suites)
      v = None
   elif t == 'compress':
      ch.compression_methods = [random.randint(1, 255)] if not isinstance(value, int) else value
      v = ch.compression_methods
   elif t == 'extensions':
      index = random.randint(0, len(ch.extensions)-1) if not isinstance(value, int) else value
      if ch.extensions[index].extType == ExtensionType.supported_versions:
         return None, None
      ch.extensions.remove(ch.extensions[index])
      v = index
   else:
      return None, None
   return t, v
         
def fuzzChangeCipherSpec(ccs: ChangeCipherSpec, ftype=None, value=None):
   while ccs.type == 1:
      ccs.type = random.randint(0, 255) if not isinstance(value, int) else value
      v = ccs.type
   return None, v

def fuzzClientCertificate(cert: Certificate, ftype=None, value=None):
   return None, None

def fuzzClientCertificateVerify(cv: CertificateVerify, ftype=None, value=None):
   t = weighted_choice([ ('alg', 0.5), ('sig',0.5)]) if ftype is None else ftype
   if t == 'alg':
      cv.signatureAlgorithm = random.choice(RSA_SIG_ALL) if not isinstance(value, tuple) else value
      v = cv.signatureAlgorithm
   elif t == 'sig':
      cv.signature = rand_StrLenField(cv.signature)
      v = None
   return t, v

def fuzzClientFinished(cf: ClientFinished, ftype=None, value=None):
   cf.verify_data = rand_StrLenField(cf.verify_data)
   return None, None

def fuzzClosureAlert(closurealert: Alert, ftype=None, value=None):
   t = weighted_choice([ ('lev', 0.5), ('des',0.5)])
   if t == 'lev':
      closurealert.level = AlertLevel.fatal
      v = closurealert.level
   elif t == 'des':
      closurealert.description = AlertDescription.user_canceled
      v = closurealert.description
   return t, v

def fuzzErrorAlert(erroralert: Alert, ftype=None, value=None):
   t = weighted_choice([ ('lev', 0.1), ('des',0.8)])
   if t == 'lev':
      erroralert.level = AlertLevel.warning
      v = erroralert.level
   elif t == 'des':
      alert_description_list = [value for name, value in vars(AlertDescription).items() if isinstance(value, int)]
      erroralert.description = random.choice(list(alert_description_list)) if not isinstance(value, int) else value
      v = erroralert.description
   return t, v
      
def fuzzApplicationData(ad: ApplicationData, ftype=None, value=None):
   return None, None

def fuzzGeneric(msg, ftype=None, value=None):
   return None, None

fuzz_func = {
   'ClientHello' : fuzzClientHello,
   'ChangeCipherSpec' : fuzzChangeCipherSpec,
   'Certificate' : fuzzClientCertificate,
   'CertificateVerify' : fuzzClientCertificateVerify,
   'Finish' : fuzzClientFinished,
   'ApplicationData' : fuzzApplicationData,
   'ClosureAlert' : fuzzClosureAlert,
   'ErrorAlert' : fuzzErrorAlert,
}   

class TLS_fuzzer:
   
   def __init__(self):
      pass
   
   def fuzzMessage(self, messageType, message, ftype=None, value=None):
      rvalue = convert_string_to_type(value)
      t, v = fuzz_func.get(messageType, fuzzGeneric)(message, ftype, rvalue)
      return t, v
   
   