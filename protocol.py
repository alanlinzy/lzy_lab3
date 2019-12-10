import logging
import time
import asyncio
import datetime
import random
import os
import binascii#?
import bisect#?
import hashlib
from random import randrange
from playground.network.packet import PacketType
from playground.network.packet.fieldtypes import UINT8, UINT32, STRING, BUFFER, LIST
from playground.network.packet.fieldtypes.attributes import Optional
from playground.network.common import StackingProtocolFactory, StackingProtocol, StackingTransport

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, rsa, padding
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import PublicFormat, Encoding, load_pem_public_key,load_pem_private_key
from cryptography import x509
from poop.protocol import POOP
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

logger = logging.getLogger("playground.__connector__." + __name__)
from os.path import dirname, abspath
path = dirname(dirname(abspath(__file__)))
# pakcet part

class CrapPacketType(PacketType):#milestone2 packet
    DEFINITION_IDENTIFIER = "crap"
    DEFINITION_VERSION = "1.0"

class HandshakePacket(CrapPacketType):
    DEFINITION_IDENTIFIER = "crap.handshakepacket"
    DEFINITION_VERSION = "1.0"

    NOT_STARTED = 0
    SUCCESS     = 1
    ERROR       = 2

    FIELDS = [
               ("status", UINT8),
	       ("nonce", UINT32({Optional:True})),
	       ("nonceSignature", BUFFER({Optional:True})),
               ("signature", BUFFER({Optional:True})),
               ("pk", BUFFER({Optional:True})),
               ("cert", BUFFER({Optional:True})),
               ("certChain", LIST(BUFFER, {Optional:True}))
           ]

class DataPacket(CrapPacketType):
    DEFINITION_IDENTIFIER = "crap.datapacket"
    DEFINITION_VERSION = "1.0"

    FIELDS = [
               ("data", BUFFER),
           ]
    
class ErrorPacket(CrapPacketType):
    DEFINITION_IDENTIFIER = "crap.errorpacket"
    DEFINITION_VERSION = "1.0"
    FIELDS = [
           ("message", STRING)
        ]

#transport
class CRAPTransport(StackingTransport):
    def connect_protocol(self,protocol):
        self.protocol =protocol
    def write(self,data):
        self.protocol.data_enc(data)


# tls handshake part
class CRAP(StackingProtocol):
    def __init__(self,mode):
        super().__init__()
        self.mode = mode
        self.higher_transport = None
        self.deserializer = CrapPacketType.Deserializer()
        self.status = "LISTEN"
        self.nonce = random.randrange(1000000,9999999)
        

    def connection_made(self, transport):
        print("connection made crap")
        self.transport = transport
        self.higher_transport = CRAPTransport(transport)
        self.higher_transport.connect_protocol(self)
        r = int(input("Enter testing rule number: "))
        if r == 0:
            self.make_key()
            print("makekey")
        else:
            self.load_key(r)
            print("test rule" + str(r))
        
        if self.mode == "client":
            print("client init")
            try:
                pktstatus = 0
                pkt = HandshakePacket(status=pktstatus, pk=self.public_bytes(self.public_key,"pk"), signature=self.signature, cert=self.public_bytes(self.certificate,"cert"),nonce=self.nonce)
                self.transport.write(pkt.__serialize__())
                print("send packet")
                self.status = "HS_SENT"
                print("client handshake sent")
            except Exception as e:
                print(e)
            
    def send_error_handshake_pkt(self):
        print("error packet!")
        pkt = HandshakePacket(status=2)
        self.transport.write(pkt.__serialize__())


    def make_key(self):
        self.private_key = ec.generate_private_key(ec.SECP384R1(), default_backend())
        
        self.public_key = self.private_key.public_key()

        self.signing_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
    
        self.verification_key = self.signing_key.public_key()
        try:
            with open(path + "/keyfiles/team2_key.pem", "rb") as f:
                self.team2_signing_key = load_pem_private_key(f.read(), password=None, backend=default_backend())
                self.team2_verification_key = self.signing_key.public_key()
                self.team2_verification_key_bytes = self.team2_verification_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
            with open(path + "/keyfiles/20194_root_cert.pem", "rb") as f:
                self.root_cert = x509.load_pem_x509_certificate(f.read(), default_backend())
                self.root_public_key = self.root_cert.public_key()
                
            with open(path + "/keyfiles/team2_cert.pem", "rb") as f:
                self.team2_certification_bytes = f.read()
                self.team2_cert = x509.load_pem_x509_certificate(self.team2_certification_bytes, default_backend())
        except Exception as e:
            print(e)

        #self.issuer_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend()) #team2 key
        #certificate
        self.certificate = self.generate_cert(self.generate_subject(u'20194.2.56.78'),self.team2_cert.subject,self.verification_key,self.team2_signing_key)#something I need check which key to use
        
        self.signature = self.signing_key.sign(self.public_bytes(self.public_key,"pk"), padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),hashes.SHA256())
    def load_key(r):
        if rule == 1:
            print("Testing rule #1: Fake Root Cert")
            self.rule1()
            return
        elif rule == 2:
            print("Testing rule #2: Fake team2 key")
            self.rule2()
            return
        elif rule == 3:
            print("Testing rule #3: Unmatching Playground Address")
            self.rule3()
            return
        elif rule == 4:
            print("Testing rule #4: Unmatching certChain and cert")
            self.rule4()
            return
        else:
            print("What Rule?")
            return

        
    def public_bytes(self,thesubject,check = ""):
        if check == "pk":
            return thesubject.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
        elif check == "cert":
            return thesubject.public_bytes(Encoding.PEM)
        else:
            print("can't byte!")
            print(str(thesubject))
            return

    def data_received(self,buffer):
        #print("recive packets!")
        self.deserializer.update(buffer)
        for pkt in self.deserializer.nextPackets():
            #self.printpkt(pkt)
            if pkt.DEFINITION_IDENTIFIER == HandshakePacket().DEFINITION_IDENTIFIER:
                self.handshake_pkt_recv(pkt)
            elif pkt.DEFINITION_IDENTIFIER == DataPacket().DEFINITION_IDENTIFIER:
                self.data_pkt_recv(pkt)
            elif pkt.DEFINITION_IDENTIFIER == ErrorPacket().DEFINITION_IDENTIFIER:
                print("error:")
                print(pkt.message)
            else:
                print("wrong packet!")

                
    def handshake_pkt_recv(self,pkt):
        if pkt.status == 2:
            print("ERROR PACKET")
            #self.transport.close()
        
        elif self.status == "LISTEN":# server get the first packet
            if pkt.cert and pkt.pk and pkt.signature:
                if pkt.status == 0:
                    print(self.root_public_key)
                    print("recvive client's first handshake packet")
                    self.peer_verikey = x509.load_pem_x509_certificate(pkt.cert, default_backend()).public_key()
                    self.peer_public_key = load_pem_public_key(pkt.pk, backend=default_backend())
                    if self.verify_signature(pkt) and self.verify_chain(pkt.certChain) and self.verify_cert(pkt.cert):
                        #verify
                        # verify the signiature  fail: send error else:pass
                        # generate its own ECDH public key
                    
                        nonce_sig = self.generate_signature(self.signing_key, pkt.nonce)
                 
                        #self.shared_key = self.private_key.exchange(ec.ECDH(), load_pem_public_key(pkt.pk, backend=default_backend()))
                        #self.derived_key = self.get_derived_key(self.shared_key)
                        #self.generate_communicatekey(self.shared_key)
                        #self.higherProtocol().connection_made(self.higher_transport)
                        
                        pktstatus = 1 
                        sendpkt = HandshakePacket(status=pktstatus,nonceSignature=nonce_sig,pk=self.public_bytes(self.public_key,"pk"),
                                                  signature=self.signature, cert=self.public_bytes(self.certificate,"cert"),nonce=self.nonce,certChain=[self.team2_certification_bytes])
                        self.transport.write(sendpkt.__serialize__())
                        print("send server first packet")
                        self.status = "HS_SENT"
                        return
                    else:
                        self.send_error_handshake_pkt()
                        #self.higherProtocol().connection_lost(None)
                        #self.transport.close()
                        return
                elif pkt.status == 1:
                    print("handshake packet status shouldn't be 1 when the server status is LISTEN")
                    self.send_error_handshake_pkt()
                    return
            else:
                print("miss handshake field")
                self.send_error_handshake_pkt()
                return
        elif self.status == "HS_SENT":#client and server already sent the first packet
            print("HS_SENT")
            if pkt.status == 1:
                if self.mode == "client":
                    print("client handshake made")
                    self.peer_verikey = x509.load_pem_x509_certificate(pkt.cert, default_backend()).public_key()
                    self.peer_public_key = load_pem_public_key(pkt.pk, backend=default_backend())
                    if self.verify_signature(pkt) and self.verify_nonce(pkt) and self.verify_chain(pkt.certChain) and self.verify_cert(pkt.cert):
                        print("verify nonce and signature")
                        self.shared_key = self.private_key.exchange(ec.ECDH(), self.peer_public_key )
                        self.derived_key = self.get_derived_key(self.shared_key)

                        nonce_sig = self.generate_signature(self.signing_key, pkt.nonce)
    
                        sendpkt = HandshakePacket(status=1, nonceSignature=nonce_sig)
                        self.transport.write(pkt.__serialize__())
                        self.status = "ESTABILISHED"
                        self.generate_communicatekey(self.shared_key)
                        self.higherProtocol().connection_made(self.higher_transport)
                        print("sent 2 packet")
                    else:
                        self.send_error_handshake_pkt()
                        return
                else:
                    if self.verify_nonce(pkt):
                        self.shared_key = self.private_key.exchange(ec.ECDH(), self.peer_public_key)
                        self.derived_key = self.get_derived_key(self.shared_key)
                        print("server handshake made")
                        self.status = "ESTABILISHED"
                        self.generate_communicatekey(self.shared_key)
                        self.higherProtocol().connection_made(self.higher_transport)
                    else:
                        self.send_error_handshake_pkt()
                        return
    
        else:
            self.send_error_handshake_pkt()
            return
                
    def data_pkt_recv(self,pkt):
        print("send data packet")
        # encrypt (key, plaintext, associated_data) -> (iv, ciphertext, encryptor.tag)
        # decrypt  (key, associated_data, iv, ciphertext, tag) -> decryptor.update(ciphertext) + decryptor.finalize()
        if self.status == "ESTABILISHED":
            plaintext = self.data_dec(pkt.data)
            self.higherProtocol().data_received(plaintext)
        else:
            self.printpkt(pkt)
            plaintext = self.data_dec(pkt.data)
            self.data_enc(plaintext)
            print(plaintext)
            #self.send_error_handshake_pkt()
            return
            

    def generate_signature(self,sign_key,nonce):
        #print("generate sign")
        #if type(nonce) != bytes:
         #   nonce = bytes(nonce)
        return sign_key.sign(str(nonce).encode('ASCII'), padding.PSS(mgf=padding.MGF1(hashes.SHA256()),salt_length=padding.PSS.MAX_LENGTH),hashes.SHA256())

    def verify_nonce(self,pkt):

        try:
            self.peer_verikey.verify(pkt.nonceSignature, str(self.nonce).encode('ASCII'), padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
            print("nonce!")
            return True
        except Exception as e :
            print(e)
            return False
        
    def verify_signature(self,pkt):
        #print("verify signature")
        try:
            #cert_to_verify = x509.load_pem_x509_certificate(pkt.cert, default_backend())
            #self.peer_public_key = load_pem_public_key(pkt.pk, default_backend())
            #self.peer_cert_public_key = cert_to_verify.public_key()
            #self.issuer_public_key = ec.generate_private_key(ec.SECP384R1(), default_backend()).public_key()
            #self.issuer_public_key.verify(cert_to_verify.signature,cert_to_verify.tbs_certificate_bytes,padding.PKCS1v15(),cert_to_verify.signature_hash_algorithm,)
            #self.peer_cert_public_key.verify(pkt.signature, pkt.cert, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())#4 but 5 given
            self.peer_verikey.verify(pkt.signature, pkt.pk, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
            print("signature!")
            return True
        except Exception as e :
            print(e)
            return False
        
    def verify_cert(self,cert):
        #print("verify cert")
        try:
            cert_to_verify = x509.load_pem_x509_certificate(cert, default_backend())
            self.peer_root_verikey.verify(cert_to_verify.signature, cert_to_verify.tbs_certificate_bytes, padding.PKCS1v15(), cert_to_verify.signature_hash_algorithm)
            print("cert!")
            return True
        except Exception as e:
            print(e)
            return False

    def verify_chain(self,chain):
        #print("verify chain")
        for c in range(len(chain)):
            cert_to_verify = x509.load_pem_x509_certificate(chain[c], default_backend())
            try:
                self.root_public_key.verify(cert_to_verify.signature, cert_to_verify.tbs_certificate_bytes, padding.PKCS1v15(), cert_to_verify.signature_hash_algorithm)
                self.peer_root_verikey = cert_to_verify.public_key()
                print("chain!")
                return True
            except Exception as e:
                print(e)
                return False
        
    def generate_subject(self, common_name):
        return x509.Name([
            x509.NameAttribute(x509.NameOID.COUNTRY_NAME, u"US"),#"US"
            x509.NameAttribute(x509.NameOID.STATE_OR_PROVINCE_NAME, u"Maryland"),# "Maryland"
            x509.NameAttribute(x509.NameOID.LOCALITY_NAME, u"Baltimore"),# "Baltimore"
            x509.NameAttribute(x509.NameOID.ORGANIZATION_NAME, u"JHU"),#"JHU"
            x509.NameAttribute(x509.NameOID.COMMON_NAME, common_name),
        ])

    def generate_cert(self, subject, issuer, cert_public_key, issuer_sign_key):
        return x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            cert_public_key
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.datetime.utcnow()
        ).not_valid_after(
            datetime.datetime.utcnow() + datetime.timedelta(days=10)
        ).add_extension(
            x509.SubjectAlternativeName([x509.DNSName(u"20194.2")]),
            critical=False,
        ).sign(issuer_sign_key, hashes.SHA256(), default_backend())
    
    def get_derived_key(self,shared_key):
        return HKDF(algorithm=hashes.SHA256(),length=32,salt=None,info=b'handshake data',backend=default_backend()).derive(shared_key)

    def generate_communicatekey(self,shared_secret):
        hash1 = self.digest_hash(shared_secret)
        hash2 = self.digest_hash(hash1)
        hash3 = self.digest_hash(hash2)
        if self.mode == "client":
            self.iv = hash1[0:12]
            self.peer_iv = hash1[12:24]
            self.enc_key = hash2[0:16]
            self.dec_key = hash3[0:16]
        else:
            self.iv = hash1[12:24]
            self.peer_iv = hash1[0:12]
            self.enc_key = hash3[0:16]
            self.dec_key = hash2[0:16]

    def digest_hash(self,data):
        tep = hashlib.sha256()
        tep.update(data)
        return tep.digest()
        
    def data_enc(self,data):#no
        print("enc")
        scheme = AESGCM(self.enc_key)
        ciphertext = scheme.encrypt(self.iv, data, None)
        self.transport.write(DataPacket(data=ciphertext).__serialize__())
        self.iv = (int.from_bytes(self.iv, "big")+1).to_bytes(12,"big")#?
        print("fin enc")
    
    def data_dec(self,data):#no
        print("dec")
        scheme = AESGCM(self.dec_key)
        plaintext = scheme.decrypt(self.peer_iv, data, None)
        self.peer_iv = (int.from_bytes(self.peer_iv, "big")+1).to_bytes(12,"big")
        print("fin dec")
        return plaintext
        
    def printpkt(self,pkt):  # try to print packet content
        print("--------------------")
        for f in pkt.FIELDS:
            fname = f[0]
            print(str(fname) + ": " + str(pkt._fields[fname]._data))
        print("--------------------")
        return
    def connection_lost(self, exc):
        print("connection lost")
        self.higherProtocol().connection_lost(exc)


    
    def rule1(self):
        # Fake Root key to produce new team2_cert and self.cert
        self.private_key = ec.generate_private_key(
            ec.SECP384R1(), default_backend())
        
        self.public_key = self.private_key.public_key()
        self.public_key_bytes = self.public_key.public_bytes(
            Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
        self.signing_key = rsa.generate_private_key(
            public_exponent=65537, key_size=2048, backend=default_backend())
        self.verification_key = self.signing_key.public_key()
        with open("/home/student_20194/.playground/connectors/lab3_keyfiles/rule1/team2_key.pem", "rb") as f:
            self.team2_signing_key = load_pem_private_key(f.read(), password=None, backend=default_backend())
            self.team2_verification_key = self.signing_key.public_key()
            self.team2_verification_key_bytes = self.team2_verification_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
        with open("/home/student_20194/.playground/connectors/lab3_keyfiles/rule1/root_cert.pem", "rb") as f:
            self.root_cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            self.root_pubk = self.root_cert.public_key()
        with open("/home/student_20194/.playground/connectors/lab3_keyfiles/rule1/team2_cert.pem", "rb") as f:
            self.team2_certification_bytes = f.read()
            self.team2_cert = x509.load_pem_x509_certificate(self.team2_certification_bytes, default_backend())
        one_day = datetime.timedelta(1, 0, 0)
        builder = x509.CertificateBuilder()
        builder = builder.public_key(self.verification_key)

        if rule == 3:
            builder = builder.subject_name(
                x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, u'20194.2.12.34'), ]))
        else:
            builder = builder.subject_name(
                x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, u'20194.2.57.98'), ]))
        builder = builder.issuer_name(self.team2_cert.subject)
        builder = builder.serial_number(x509.random_serial_number())
        builder = builder.not_valid_before(datetime.datetime.today() - one_day)
        builder = builder.not_valid_after(
            datetime.datetime.today() + (one_day * 30))
        self.cert = builder.sign(private_key=self.team2_signing_key,
                                 algorithm=hashes.SHA256(), backend=default_backend())
        self.certification_bytes = self.cert.public_bytes(Encoding.PEM)
        self.signature = self.signing_key.sign(self.public_key_bytes, padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())

    def rule2(self):
        # Fake Root key to produce new team2_cert and self.cert
        self.private_key = ec.generate_private_key(
            ec.SECP384R1(), default_backend())
        self.public_key = self.private_key.public_key()
        self.public_key_bytes = self.public_key.public_bytes(
            Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
        with open("/home/student_20194/.playground/connectors/lab3_keyfiles/rule2/20194.2.57.98_key.pem", "rb") as f:
            self.signing_key = load_pem_private_key(f.read(), password=None, backend=default_backend())
            self.verification_key = self.signing_key.public_key()
        with open("/home/student_20194/.playground/connectors/lab3_keyfiles/rule2/team2_key.pem", "rb") as f:
            self.team2_signing_key = load_pem_private_key(f.read(), password=None, backend=default_backend())
            self.team2_verification_key = self.signing_key.public_key()
            self.team2_verification_key_bytes = self.team2_verification_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
        with open("/home/student_20194/.playground/connectors/crap_aht/final_keyfile/20194_root_cert.pem", "rb") as f:
            self.root_cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            self.root_pubk = self.root_cert.public_key()
        with open("/home/student_20194/.playground/connectors/crap_aht/final_keyfile/team2_cert.pem", "rb") as f:
            self.team2_certification_bytes = f.read()
            self.team2_cert = x509.load_pem_x509_certificate(self.team2_certification_bytes, default_backend())
        one_day = datetime.timedelta(1, 0, 0)
        builder = x509.CertificateBuilder()
        builder = builder.public_key(self.verification_key)
        builder = builder.subject_name(
            x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, u'20194.2.57.98'), ]))
        builder = builder.issuer_name(self.team2_cert.subject)
        builder = builder.serial_number(x509.random_serial_number())
        builder = builder.not_valid_before(datetime.datetime.today() - one_day)
        builder = builder.not_valid_after(
            datetime.datetime.today() + (one_day * 30))
        self.cert = builder.sign(private_key=self.team2_signing_key,
                                 algorithm=hashes.SHA256(), backend=default_backend())
        self.certification_bytes = self.cert.public_bytes(Encoding.PEM)
        self.signature = self.signing_key.sign(self.public_key_bytes, padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())

    def rule3(self):
        # Wrong Playground Address
        self.private_key = ec.generate_private_key(
            ec.SECP384R1(), default_backend())
        self.public_key = self.private_key.public_key()
        self.public_key_bytes = self.public_key.public_bytes(
            Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
        self.signing_key = rsa.generate_private_key(
            public_exponent=65537, key_size=2048, backend=default_backend())
        self.verification_key = self.signing_key.public_key()
        with open("/home/student_20194/.playground/connectors/crap_aht/final_keyfile/team2_key.pem", "rb") as f:
            self.team2_signing_key = load_pem_private_key(f.read(), password=None, backend=default_backend())
            self.team2_verification_key = self.signing_key.public_key()
            self.team2_verification_key_bytes = self.team2_verification_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
        with open("/home/student_20194/.playground/connectors/crap_aht/final_keyfile/20194_root_cert.pem", "rb") as f:
            self.root_cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            self.root_pubk = self.root_cert.public_key()
        with open("/home/student_20194/.playground/connectors/crap_aht/final_keyfile/team2_cert.pem", "rb") as f:
            self.team2_certification_bytes = f.read()

            self.team2_cert = x509.load_pem_x509_certificate(self.team2_certification_bytes, default_backend())
        with open("/home/student_20194/.playground/connectors/lab3_keyfiles/rule2/20194.2.57.98_cert.pem", "rb") as f:
            self.certification_bytes = f.read()
            self.cert = x509.load_pem_x509_certificate(self.certification_bytes, default_backend())
            self.team2_cert = x509.load_pem_x509_certificate(self.team2_certification_bytes, default_backend())
        self.signature = self.signing_key.sign(self.public_key_bytes, padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())

    def rule4(self):
        # Unmatching certchain and final cert
        self.private_key = ec.generate_private_key(
            ec.SECP384R1(), default_backend())
        self.public_key = self.private_key.public_key()
        self.public_key_bytes = self.public_key.public_bytes(
            Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)

        with open("/home/student_20194/.playground/connectors/lab3_keyfiles/rule4/20194.2.57.98_key.pem", "rb") as f:
            self.signing_key = load_pem_private_key(f.read(), password=None, backend=default_backend())
            self.verification_key = self.signing_key.public_key()
        with open("/home/student_20194/.playground/connectors/lab3_keyfiles/rule4/team4_key.pem", "rb") as f:
            self.team2_signing_key = load_pem_private_key(f.read(), password=None, backend=default_backend())
            self.team2_verification_key = self.signing_key.public_key()
            self.team2_verification_key_bytes = self.team2_verification_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
        with open("/home/student_20194/.playground/connectors/crap_aht/final_keyfile/20194_root_cert.pem", "rb") as f:
            self.root_cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            self.root_pubk = self.root_cert.public_key()
        with open("/home/student_20194/.playground/connectors/lab3_keyfiles/rule4/team4_cert.pem", "rb") as f:
            self.team2_certification_bytes = f.read()
            self.team2_cert = x509.load_pem_x509_certificate(self.team2_certification_bytes, default_backend())

        with open("/home/student_20194/.playground/connectors/lab3_keyfiles/rule4/20194.2.57.98_cert.pem", "rb") as f:
            print("load team4 signed team2 cert")
            self.certification_bytes = f.read()
            self.cert = x509.load_pem_x509_certificate(self.certification_bytes, default_backend())
            self.team2_cert = x509.load_pem_x509_certificate(self.team2_certification_bytes, default_backend())
        self.signature = self.signing_key.sign(self.public_key_bytes, padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())



folder = "keyfiles/"

def main():
    team2_key_path  = folder + "team2_key.pem"
    team2_pubk_path = folder + "team2_pubk.pem"
    team2_CSR_path  = folder + "team2_CSR.pem"
    team2_key = generate_RSA_key()
    with open(team2_key_path ,"wb")  as f:
        f.write(pemfy_private_key(team2_key))
    with open(team2_pubk_path, "wb") as f:
        f.write(pemfy_public_key(team2_key.public_key()))
    generate_CSR(team2_key, folder + "team2_CSR.pem", "20194.2", "20194.2")

def generate_CSR(key , path,common_name, DNSName, country_name = "US", state_name = "Maryland", locality_name = "Baltimore", organization_name = "JHU"):
    csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, country_name),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, state_name),
        x509.NameAttribute(NameOID.LOCALITY_NAME, locality_name),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization_name),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])).add_extension(
        x509.SubjectAlternativeName([
            # Describe what sites we want this certificate for.
            x509.DNSName(DNSName)#20194.2
        ]),
        critical = False,
    ).sign(key, hashes.SHA256(), default_backend())

    with open(path,"wb") as f: 
        f.write(csr.public_bytes(serialization.Encoding.PEM))

def pemfy_private_key(key): 
    return key.private_bytes(
        encoding             = serialization.Encoding.PEM,
        format               = serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm = serialization.NoEncryption()
    )

def pemfy_public_key(public_key):
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM, 
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

def generate_RSA_key(): 
    return rsa.generate_private_key(
        public_exponent = 65537,
        key_size        = 2048,
        backend         = default_backend()
    )



CRAPClientFactory = StackingProtocolFactory.CreateFactoryType(
    lambda: POOP(mode="client"), lambda: CRAP(mode="client"))

CRAPServerFactory = StackingProtocolFactory.CreateFactoryType(
    lambda: POOP(mode="server"), lambda: CRAP(mode="server"))


'''
iv, ciphertext, tag = encrypt(
    key,
    b"a secret message!",
    b"authenticated but not encrypted payload"
)

print(decrypt(
    key,
    b"authenticated but not encrypted payload",
    iv,
    ciphertext,
    tag
))
'''






