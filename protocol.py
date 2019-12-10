
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dh, dsa, rsa, ec, padding
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key, Encoding, PublicFormat
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography import x509
from cryptography.x509.oid import NameOID
import datetime
import random
import binascii
import hashlib
import bisect
import sys, os
from ..poop.protocol import POOP

logger = logging.getLogger("playground.__connector__." + __name__)

logger = logging.getLogger("playground.__connector__." + __name__)

class CrapPacketType(PacketType):
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

class CRAPTransport(StackingTransport):
    def connect_protocol(self, protocol):
        self.protocol = protocol

    def write(self, data):
        self.protocol.encrypt_and_send(data)

class ErrorHandleClass():
    def handleException(self, e):
        print(e)

class CRAP(StackingProtocol):
    def __init__(self, mode):
        super().__init__()
        self._mode = mode
        self.status = 0
        self.higher_transport = None
        self.deserializer = CrapPacketType.Deserializer(
            errHandler=ErrorHandleClass())

    def connection_made(self, transport):
        print("Currently Running aht's Crap Scanner.")
        print("{} CRAP: connection made".format(self._mode))
        self.transport = transport
        self.higher_transport = CRAPTransport(transport)
        self.higher_transport.connect_protocol(self)
        self.status = "LISTEN"
        r = int(input("Enter testing rule number: "))
        self.scanner_load_key(r)
        #self.load_key_file() 

        if self._mode == "client":
            print("Sending initial crypto handshake packet.")
            self.nonce = random.randrange(10**7, 10**8-1)
            pkt = HandshakePacket(status=0, pk=self.public_key_bytes,
                                  signature=self.signature, nonce=self.nonce, cert=self.certification_bytes, certChain = [self.team2_certification_bytes])
            self.transport.write(pkt.__serialize__())
            self.status = "KEY_SENT"

    def data_received(self, buffer):
        self.deserializer.update(buffer)
        for pkt in self.deserializer.nextPackets():
            pkt_type = pkt.DEFINITION_IDENTIFIER
            if pkt_type == "crap.errorpacket":
                print("CRAP Recv ERROR message: {}".format(pkt.message))
                continue
            if pkt_type == "crap.handshakepacket":
                self.handshake_pkt_recv(pkt)
                continue
            elif pkt_type == "crap.datapacket":
                self.data_pkt_recv(pkt)
                continue
            else:
                print("CRAP received unknown type of packet: {}".format(pkt_type))
                continue

    def load_key_file(self):
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

    def scanner_load_key(self, rule):
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


    def extract_key(self, pkt):

        self.peer_verification_key = x509.load_pem_x509_certificate(
                    pkt.cert, default_backend()).public_key()
        self.peer_public_bytes = pkt.pk
        self.peer_public_key = load_pem_public_key(
                    pkt.pk, backend=default_backend())
        return

    def verify_cert_chain(self, certChain, public_key):
        while len(certChain) > 0:
            cert_to_verify = x509.load_pem_x509_certificate(
                    certChain[0], default_backend())
            try:
                public_key.verify(cert_to_verify.signature, cert_to_verify.tbs_certificate_bytes, padding.PKCS1v15(), cert_to_verify.signature_hash_algorithm)
            except:
                self.transport.write(HandshakePacket(status=2).__serialize__())
                self.transport.close()
                return
            public_key = cert_to_verify.public_key()
            certChain = certChain[1:]
        print("certChain verified!")
        return public_key

    def verify_cert(self, cert, public_key):
        #HERE: check whether the playground address is correct

        cert = x509.load_pem_x509_certificate(
                    cert, default_backend())
        try:
            public_key.verify(cert.signature, cert.tbs_certificate_bytes, padding.PKCS1v15(), cert.signature_hash_algorithm)
        except:
            print("cert verification FAILED")
            self.transport.write(HandshakePacket(status=2).__serialize__())
            self.transport.close()
            return
        print("cert verified!")

    def verify_sig(self, pkt, verification_key):
        try:
            verification_key.verify(pkt.signature, pkt.pk, padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
        except:
            print("signature verification FAILED")
            self.transport.write(HandshakePacket(status=2).__serialize__())
            self.transport.close()
            return


    def verify_noncesig(self, pkt, public_key, verification_key):
        try:
            verification_key.verify(pkt.nonceSignature, public_key, padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
        except:
            print("nonce signature verification FAILED")
            self.transport.write(HandshakePacket(status=2).__serialize__())
            self.transport.close()
            return

    def hash_from(self, data):
        m = hashlib.sha256()
        m.update(data)
        return m.digest()

    def data_encrypt_init(self, shared_secret, client):
        hash1 = self.hash_from(shared_secret)
        hash2 = self.hash_from(hash1)
        hash3 = self.hash_from(hash2)
        self.iv = hash1[:12] if client else hash1[12:24]
        self.peer_iv = hash1[12:24] if client else hash1[:12]
        self.enc_key = hash2[:16] if client else hash3[:16]
        self.dec_key = hash3[:16] if client else hash2[:16]



    def data_pkt_recv(self, pkt):
        aesgcm = AESGCM(self.dec_key)
        plain_text = aesgcm.decrypt(self.peer_iv, pkt.data, None)
        self.higherProtocol().data_received(plain_text)
        self.peer_iv = (int.from_bytes(self.peer_iv, "big")+1).to_bytes(12,"big")

    def encrypt_and_send(self, data):
        aesgcm = AESGCM(self.enc_key)
        cipher_text = aesgcm.encrypt(self.iv, data, None)
        self.transport.write(DataPacket(data=cipher_text).__serialize__())
        self.iv = (int.from_bytes(self.iv, "big")+1).to_bytes(12,"big")

    def handshake_pkt_recv(self, pkt):
        if pkt.status == 2:
            print("CRAP recv error pkt. Drop connection.")
            self.transport.close()
            self.higherProtocol().connection_lost(None)
            return
        elif self.status == "LISTEN":
            if pkt.status == 0:
                self.peer_root_verification_key = self.verify_cert_chain(pkt.certChain, self.root_pubk)

                self.verify_cert(pkt.cert, self.peer_root_verification_key)
                self.extract_key(pkt)
                self.verify_sig(pkt,self.peer_verification_key)
                self.shared_secret = self.private_key.exchange(ec.ECDH(), load_pem_public_key(self.peer_public_bytes, backend=default_backend()))
                self.nonceSignature = self.signing_key.sign(str(pkt.nonce).encode('ASCII'), padding.PSS(mgf=padding.MGF1(
                    hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
                self.nonce = random.randrange(10**7, 10**8-1)
                pkt = HandshakePacket(status=1, pk=self.public_key_bytes, signature=self.signature,
                                      nonce=self.nonce, nonceSignature=self.nonceSignature, cert=self.certification_bytes, certChain=[self.team2_certification_bytes])
                self.transport.write(pkt.__serialize__())
                self.status = "KEY_SENT"
                return
            else:
                self.transport.write(HandshakePacket(status=2).__serialize__())
                self.higherProtocol().connection_lost(None)
                self.transport.close()
                return



        elif self.status == "KEY_SENT":
            if pkt.status == 1:
                # success
                if self._mode == "client":
                    self.peer_root_verification_key = self.verify_cert_chain(pkt.certChain, self.root_pubk)
                    self.verify_cert(pkt.cert, self.peer_root_verification_key)
                    self.extract_key(pkt)
                    self.verify_sig(pkt, self.peer_verification_key)
                    self.verify_noncesig(pkt, str(self.nonce).encode('ASCII'), self.peer_verification_key)
                    self.shared_secret = self.private_key.exchange(ec.ECDH(), load_pem_public_key(pkt.pk, backend=default_backend()))
                    self.nonceSignature = self.signing_key.sign(str(pkt.nonce).encode('ASCII'), padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),hashes.SHA256())
                    pkt = HandshakePacket(status=1, nonceSignature=self.nonceSignature)
                    self.transport.write(pkt.__serialize__())
                    self.status = "ESTABLISHED"
                    print("CRAP client handshake success!")
                    self.data_encrypt_init(self.shared_secret, True)
                    self.higherProtocol().connection_made(self.higher_transport)


                elif self._mode == "server":
                    self.verify_noncesig(pkt, str(self.nonce).encode('ASCII'), self.peer_verification_key)
                    self.status = "ESTABLISHED"
                    print("CRAP server handshake success!")
                    self.data_encrypt_init(self.shared_secret, False)
                    self.higherProtocol().connection_made(self.higher_transport)
            else:
                self.transport.write(HandshakePacket(status=2).__serialize__())
                return
        else:
            print("recvive a handshake packet when connect ESTABLISHED")
            self.transport.close()
            return

CRAPClientFactory = StackingProtocolFactory.CreateFactoryType(
    lambda: POOP(mode="client"), lambda: CRAP(mode="client"))

CRAPServerFactory = StackingProtocolFactory.CreateFactoryType(
    lambda: POOP(mode="server"), lambda: CRAP(mode="server"))


