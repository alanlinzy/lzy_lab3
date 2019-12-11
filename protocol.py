import random
from poop.protocol import POOP
from ..crypto_manager import *
from playground.network.packet.fieldtypes.attributes import Optional
from playground.network.packet.fieldtypes import UINT8, UINT32, STRING, BUFFER, LIST
from playground.network.packet import PacketType
from playground.network.common import StackingProtocolFactory, StackingProtocol, StackingTransport
from random import randrange
import asyncio
import time
import logging
from cryptography.hazmat.backends import default_backend
import os

# logger = logging.getLogger("playground.__connector__." + __name__).debug
logger = print

# rule check
selected_rule_num = None

folder = "/home/student_20194/.playground/connectors/keyfiles/"
domain = "20194.2.57.98"

team2_cert_pem_path  = folder + "team2_cert.pem"
domain_key_pem_path  = folder + domain +"_key.pem"
domain_cert_pem_path = folder + domain + "_cert.pem"
root_pubk_pem_path   = folder + "20194_root_pubk.pem"

def printx(string):
    print(string.center(80, '-')+'\n')

def printError(string):
    print(string.center(80, '!')+'\n')

def set_rule(num):
    if num == None:
        return
    global folder
    global domain
    global team2_cert_pem_path
    global domain_key_pem_path
    global domain_cert_pem_path
    global root_pubk_pem_path

    printx( "Rule " + str(num) + " mode!")

    if num == 1:
        folder       = "/home/student_20194/.playground/connectors/lab3_keyfiles/rule1/"
        team2_cert_pem_path  = folder + "team2_cert.pem"
        domain_key_pem_path  = folder + domain +"_key.pem"
        domain_cert_pem_path = folder + domain + "_cert.pem"
        root_pubk_pem_path   = folder + "root_pubk.pem"
    elif num == 2:
        folder       = "/home/student_20194/.playground/connectors/lab3_keyfiles/rule2/"
        domain_key_pem_path  = folder + domain +"_key.pem"
        domain_cert_pem_path = folder + domain + "_cert.pem"
    elif num == 3:
        domain = "20194.2.11.09"
        folder = "/home/student_20194/.playground/connectors/lab3_keyfiles/rule3/"
        domain_key_pem_path  = folder + domain +"_key.pem"
        domain_cert_pem_path = folder + domain + "_cert.pem"
    elif num == 4:
        folder       = "/home/student_20194/.playground/connectors/lab3_keyfiles/rule4/"
        team2_cert_pem_path  = folder + "team4_cert.pem"
        domain_key_pem_path  = folder + domain +"_key.pem"
        domain_cert_pem_path = folder + domain + "_cert.pem"
    else:
        printError("Rule not found, use normal mode")

set_rule(selected_rule_num)

def print_pkt(pkt):
    logger("-----------")
    for f in pkt.FIELDS:
        f_name = f[0]
        logger(str(f_name) + ": " + str(pkt._fields[f_name]._data))
    logger("-----------")
    return


class CrapPacketType(PacketType):
    DEFINITION_IDENTIFIER = "crap"
    DEFINITION_VERSION = "1.0"


class HandshakePacket(CrapPacketType):
    DEFINITION_IDENTIFIER = "crap.handshakepacket"
    DEFINITION_VERSION = "1.0"
    NOT_STARTED = 0
    SUCCESS = 1
    ERROR = 2
    FIELDS = [
        ("status", UINT8),
        ("nonce", UINT32({Optional: True})),
        ("nonceSignature", BUFFER({Optional: True})),
        ("signature", BUFFER({Optional: True})),
        ("pk", BUFFER({Optional: True})),
        ("cert", BUFFER({Optional: True})),
        ("certChain", LIST(BUFFER, {Optional: True}))
    ]


class DataPacket(CrapPacketType):
    DEFINITION_IDENTIFIER = "crap.datapacket"
    DEFINITION_VERSION = "1.0"
    FIELDS = [
        ("data", BUFFER),
    ]


class ErrorPacket(CrapPacketType):
    DEFINITION_IDENTIFIER = "crap.errorpacket”"
    DEFINITION_VERSION = "1.0"
    FIELDS = [
        ("message", STRING),
    ]
class CRAPTransport(StackingTransport):
    def connect_protocol(self, protocol):
        self.protocol = protocol

    def write(self, data):
        self.protocol.higher_protocol_send_data(data)

    def close(self):
        self.protocol.transport.close()
        printx("app close connection")
class ErrorHandleClass():
    def handleException(self, e):
        printError(e)

class CRAP(StackingProtocol):
    def __init__(self, mode):
        super().__init__()
        printx("{} CRAP xjm lab3 init".format(mode))
        self._mode            = mode
        self.status           = 0
        self.higher_transport = None

        self.deserializer = CrapPacketType.Deserializer(errHandler=ErrorHandleClass())
        self.man          = Crypto_manager()

        # TODO: fix this
        self.nonce         = random.randrange(1000)
        self.key           = self.man.generate_EC_key()
        self.shared_secret = None
        with open(root_pubk_pem_path, "rb") as file:
            self.CA_pubk = self.man.unpemfy_public_key(file.read())
        # get cert and generate signature
        with open(domain_key_pem_path, "rb") as f:
            self.sign_key = self.man.unpemfy_private_key(f.read())
        with open(team2_cert_pem_path, "rb") as f:
            team2_cert_pem = f.read()
        with open(domain_cert_pem_path, "rb") as f:
            team2_56_78_cert_pem = f.read()
            self.cert_pem_list   = [team2_cert_pem]
            self.cert_pem        = team2_56_78_cert_pem
            self.cert            = self.man.unpemfy_cert(team2_56_78_cert_pem)
            self.sig_on_EC_pubk  = self.man.generate_RSA_signature(
                self.sign_key,
                self.man.pemfy_public_key(self.key.public_key())
            )

    def connection_made(self, transport):
        printx("{} CRAP: connection made".format(self._mode))
        self.transport        = transport
        self.higher_transport = CRAPTransport(transport)
        self.higher_transport.connect_protocol(self)

        if self._mode == "client":  # client send first packet
           pkt = HandshakePacket(
               status    = 0,
               pk        = self.man.pemfy_public_key(self.key.public_key()),
               signature = self.sig_on_EC_pubk,
               certChain = self.cert_pem_list,
               cert      = self.cert_pem,
               nonce     = self.nonce)
           self.send_pkt(pkt)
           logger("CRAP: client sent first pkt")
    def send_error_handshake_pkt(self):
        pkt = HandshakePacket(status=2)
        self.send_pkt(pkt)

    def send_pkt(self, pkt):
        self.transport.write(pkt.__serialize__())

    def increment_byte(self, input_bytes):
        return (int.from_bytes(input_bytes, "big")+1).to_bytes(12, "big")

    def higher_protocol_send_data(self, data):
        try:
            ct      = self.man.AESGCM_enc(self.enc, self.iv, data)
            self.iv = self.increment_byte(self.iv)
        except Exception as e:
            printError("ERROR: when aesgcm enc")
        self.send_pkt(DataPacket(data = ct))

    def handle_data_pkt(self, pkt):
        try:
            pt = self.man.ASEGCM_dec(self.dec, self.peer_iv, pkt.data)
        except Exception as e:
            printError("ERROR data pkt aesgcm dec")
        self.peer_iv = self.increment_byte(self.peer_iv)
        self.higherProtocol().data_received(pt)

    def handshake_success(self):
        self.shared_secret = self.man.get_EC_derived_key(
            self.key,
            self.peer_EC_pubk
        )
        hash1        = self.man.hash(self.shared_secret)
        hash2        = self.man.hash(hash1)
        hash3        = self.man.hash(hash2)
        self.iv      = hash1[:12]
        self.peer_iv = hash1[12:24]
        self.enc     = hash2[:16]
        self.dec     = hash3[:16]
        if self._mode == "server":
            self.enc, self.dec     = self.dec,     self.enc
            self.iv , self.peer_iv = self.peer_iv, self.iv
        self.status = "SUCCESS"
        printx("{} CRAP: handshake success, shared key generated".format(self._mode))
        self.higherProtocol().connection_made(self.higher_transport)
    def handle_handshake_pkt(self, pkt):
        # check unexpected pkt
        if pkt.status == 2:
            self.handshake_fail("BUG CRAP: recv a error handshake pkt")
        elif self.status == "SUCCESS":
            self.handshake_fail("BUG CRAP: recv a handshake pkt when status is SUCCESS")

        if self._mode == "client":
            self.verify_pkt_certs_and_sig(pkt)
            self.verify_pkt_nonce(pkt)
            self.send_pkt(HandshakePacket(
                status         = 1,
                nonceSignature = self.man.generate_RSA_signature(self.sign_key, pkt.nonce))
            )
            self.handshake_success()
        elif self._mode == "server":
            # two cases
            if pkt.status == 0:
                self.verify_pkt_certs_and_sig(pkt)
                logger("{} CRAP: prepare send challenge response".format(self._mode))
                self.send_pkt(HandshakePacket(
                    status         = 1,
                    nonceSignature = self.man.generate_RSA_signature(self.sign_key, pkt.nonce),
                    pk             = self.man.pemfy_public_key(self.key.public_key()),
                    signature      = self.sig_on_EC_pubk,
                    certChain      = self.cert_pem_list,
                    cert           = self.cert_pem,
                    nonce          = self.nonce)
                )
                logger("{} CRAP: sent challenge response".format(self._mode))
            else:
                self.verify_pkt_nonce(pkt)
                self.handshake_success()
    def data_received(self, buffer):
        logger("{} CRAP: recv a buffer".format(self._mode))
        self.deserializer.update(buffer)

        for pkt in self.deserializer.nextPackets():
            pkt_name = pkt.DEFINITION_IDENTIFIER
            if not pkt_name:
                printError("{} CRAP recv pkt with no pkt name".format(self._mode))
            if pkt_name == HandshakePacket().DEFINITION_IDENTIFIER:
                self.handle_handshake_pkt(pkt)
            elif pkt_name == DataPacket().DEFINITION_IDENTIFIER:
                self.handle_data_pkt(pkt)
            elif pkt_name == ErrorPacket().DEFINITION_IDENTIFIER:
                printError("{} CRAP recv a error pkt ".format(self._mode))
                printError(pkt.message)
            else:
                printError("BUG! ERROR CRAP: unexpected pkt name: {}".format(pkt_name))

    def verify_pkt_certs_and_sig(self, pkt):
        peer_domain = self.transport.get_extra_info("peername")[0]
        pkt_EC_pubk = self.man.unpemfy_public_key(pkt.pk)
        try:
            # 1. verify cert and domain, then trust cert_pubk
            # TODO: the case more than one in cert chain
            middle_cert = self.man.unpemfy_cert(pkt.certChain[0])
            self.man.verify_cert(self.CA_pubk, middle_cert)
            middle_cert_pubk = self.man.get_public_key_from_cert(middle_cert)
            pkt_cert = self.man.unpemfy_cert(pkt.cert)
            self.man.verify_cert(middle_cert_pubk, pkt_cert)
            pkt_cert_pubk = self.man.get_public_key_from_cert(pkt_cert)
            logger("{} CRAP: passed cert verify".format(self._mode))

            pkt_domain = self.man.get_subject_common_name_from_cert(pkt_cert)
            if(peer_domain != pkt_domain):
                self.handshake_fail("{} CRAP HANDSHAKE ERROR: failed verify domain: peer_domain: {} pkt_domain {}".format(self._mode,peer_domain, pkt_domain))
                return
            logger("{} CRAP: passed domain verify".format(self._mode))

            # 2. verify sig, then trust pkt_EC_pubk(pkt.pk)
            # TODO: define date
            self.man.verify_RSA_signature(pkt_cert_pubk, pkt.signature, pkt.pk)
        except Exception as e:
            self.handshake_fail("{} CRAP HANDSHAKE ERROR: exception when verifying cert or sig it says: \"{}\"".format(self._mode, e))
        logger("{} CRAP: passed sig verify".format(self._mode))
        # 3. save peer's cert_pubk and EC_pubk
        self.peer_cert_pubk = pkt_cert_pubk
        self.peer_EC_pubk   = pkt_EC_pubk

    def verify_pkt_nonce(self, pkt):
        try:
            self.man.verify_RSA_signature(
                self.peer_cert_pubk,
                pkt.nonceSignature,
                self.nonce
            )
        except Exception as e:
            self.handshake_fail("{} CRAP HANDSHAKE ERROR: exception when verifying nonce it says: \"{}\"".format(self._mode, e))
        logger("{} CRAP: passed nonce verify".format(self._mode))

    def handshake_fail(self, error_msg):
        printError(error_msg)
        self.send_error_handshake_pkt()
        self.close_connection(error_msg)

    def close_connection(self, msg):
        self.higherProtocol().connection_lost(msg)
        # TODO: bug, this not working?
        self.transport.close()

    def connection_lost(self, exc):
        logger("{} CRAP connection lost. Shutting down higher layer.".format(self._mode))
        self.higherProtocol().connection_lost(exc)


CRAPClientFactory = StackingProtocolFactory.CreateFactoryType(
    lambda: POOP(mode="client"),
    lambda: CRAP(mode="client")
)

CRAPServerFactory = StackingProtocolFactory.CreateFactoryType(
    lambda: POOP(mode="server"),
    lambda: CRAP(mode="server")
)


