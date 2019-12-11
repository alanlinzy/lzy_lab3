import sys
sys.path.insert(1, '../BitPoints-Bank-Playground3/src/')
from autograder_lab2_packets import *
# from escape_room_006 import EscapeRoomGame
from escape_room_010 import EscapeRoomGame
from class_packet import *
import datetime
import random
import string
import asyncio
import time
import os
from playground.network.packet import PacketType
from CipherUtil import loadCertFromFile
from BankCore import LedgerLineStorage, LedgerLine
from OnlineBank import BankClientProtocol, OnlineBankConfig
import playground
import getpass


# NOTE: local pkts and files


E6_STRS = ["look mirror",
           "get hairpin",
           'unlock chest with hairpin',
           'open chest',
           'look in chest',
           'get hammer in chest',
           "hit flyingkey with hammer",
           "get key",
           "unlock door with key",
           "open door"]

# bank params
BANK_CERT_FILE_NAME = "20194_online_bank.cert"
MY_UNAME = "zlin32"
MY_ACCOUNT = "zlin32_account"
AMOUNT = 10
TEST_UNAME = "test"  # TODO:make sure of this

# for formatting print
FL = 7
SL = 20
TL = 20


def printx(string):
    print(string.center(80, '-')+'\n')


def printError(string):
    print(string.center(80, '!')+'\n')


class BankManager:
    def __init__(self):
        bankconfig = OnlineBankConfig()
        self.bank_addr = bankconfig.get_parameter("CLIENT", "bank_addr")
        self.bank_port = int(bankconfig.get_parameter("CLIENT", "bank_port"))
        # bank_stack = bankconfig.get_parameter("CLIENT", "stack", "default")
        self.bank_username = bankconfig.get_parameter("CLIENT", "username")
        self.certPath = os.path.join(
            bankconfig.path(), BANK_CERT_FILE_NAME)
        self.bank_cert = loadCertFromFile(self.certPath)
        self.bank_client = None

    async def connectToBank(self):
        if self.bank_client == None:
            self.setBankClient()
        await playground.create_connection(
            lambda: self.bank_client,
            self.bank_addr,
            self.bank_port,
            family='crap_xjm'
        )
        printx("bank manager connected to bank with username: {}".format(
            self.bank_client._BankClientProtocol__loginName))

    def setBankClient(self):
        password = getpass.getpass(
            "Enter password for {}: ".format(self.bank_username))
        self.bank_client = BankClientProtocol(
            self.bank_cert, self.bank_username, password)

    async def transfer(self, src, dst, amount, memo):
        # 0. connect to bank
        await self.connectToBank()
        # 1. bank_client login
        try:
            await self.bank_client.loginToServer()
        except Exception as e:
            printError("Login error. {}".format(e))
            return (None, None)

        # 2. bank_client swtch account
        try:
            await self.bank_client.switchAccount(MY_ACCOUNT)
        except Exception as e:
            printError(
                "Could not set source account as {} because {}".format(src, e))
            return (None, None)

        # 3. get transfer result
        try:
            result = await self.bank_client.transfer(dst, amount, memo)
        except Exception as e:
            printError("Could not transfer because {}".format(e))
            return (None, None)

        return (result.Receipt, result.ReceiptSignature)

    def receipt_verify(self, receipt_bytes, signature_bytes, dst, amount, memo):
        self.bank_client = BankClientProtocol(
            self.bank_cert, self.bank_username, "testpass")
        # self.setBankClient()
        if not self.bank_client.verify(receipt_bytes, signature_bytes):
            # TODO: this func is not working as execpted
            printError("Bad receipt. Not correctly signed by bank")
            return False

        ledger_line = LedgerLineStorage.deserialize(receipt_bytes)
        if ledger_line.getTransactionAmount(dst) != amount:
            printError("Invalid amount. Expected {} got {}".format(
                amount, ledger_line.getTransactionAmount(dst)))
            return False
        elif ledger_line.memo(dst) != memo:
            printError("Invalid memo. Expected {} got {}".format(
                memo, ledger_line.memo()))
            return False
        printx('confirmed a receipt')
        return True


class DataHandler:
    def __init__(self, transport):
        self.t = transport
        self.deserializer = PacketType.Deserializer()

    def printTimeAndPeerName(self):
        peername = self.t._extra["peername"]
        print("time: {}, peername: {}:{}".format(
            str(datetime.datetime.now()), peername[0], peername[1]))

    def sendPkt(self, pkt):
        pktBytes = pkt.__serialize__()
        self.t.write(pktBytes)
        print("sent:".ljust(FL)+pkt.DEFINITION_IDENTIFIER)
        self.printPkt(pkt)

    def sendPktNoPrint(self, pkt):
        pktBytes = pkt.__serialize__()
        self.t.write(pktBytes)

    def recvPktSaveFile(self, data):
        """This is for exercise 10 eavesdrop part, record every eavesdrop pkt and save in file

        Arguments:
            data {data} -- directly from data_received()

        Returns:
            [type] -- [description]
        """
        self.deserializer.update(data)
        pkts = []
        sub_pkts = []
        for pkt in self.deserializer.nextPackets():
            self.printRecvSave(pkt.DEFINITION_IDENTIFIER)
            self.printPktSave(pkt)
            if pkt.DEFINITION_IDENTIFIER.startswith("apps.bank."):
                self.printPktSavePasswd(pkt)
            pkts.append(pkt)

        return pkts

    def printRecvSave(self, string):
        """Print a 'send:' to indicate something is received

        Arguments:
            string {string} -- printed string
        """
        txtFile = open('./static/e10_dump_data.txt', 'a+')
        print('recv:'.ljust(FL)+string, file=txtFile)

    def printPktSavePasswd(self, pkt):
        """A helper func for recvPktSaveFile

        Arguments:
            pkt {playground pkt} -- 
        """
        txtFile = open('./static/e10_dump_data_passwd.txt', 'a+')
        print(pkt.DEFINITION_IDENTIFIER, file=txtFile)
        for field in pkt.FIELDS:
            fName = field[0]
            print("".ljust(FL)+fName.ljust(SL) +
                  str(pkt._fields[fName]._data), file=txtFile)
        print('\n', file=txtFile)

    def printPktSave(self, pkt):
        """A helper func for recvPktSaveFile

        Arguments:
            pkt {playground pkt} -- 
        """
        for field in pkt.FIELDS:
            fName = field[0]
            txtFile = open('./static/e10_dump_data.txt', 'a+')
            print("".ljust(FL)+fName.ljust(SL) +
                  str(pkt._fields[fName]._data), file=txtFile)
        print('\n', file=txtFile)

    def recvPkt(self, data):
        """ Return and print pkts translated from data

        Arguments:
            data {data} -- 

        Returns:
            pkt -- the translated pkt
        """
        self.deserializer.update(data)
        pkts = []
        for pkt in self.deserializer.nextPackets():
            print('recv:'.ljust(FL)+pkt.DEFINITION_IDENTIFIER)
            self.printPkt(pkt)
            pkts.append(pkt)
        return pkts

    def getPktsFromData(self,data):
        self.deserializer.update(data)
        pkts= []
        for pkt in self.deserializer.nextPackets():
            pkts.append(pkt)
        return pkts

    def printPkt(self, pkt):
        """Print a packet

        Arguments:
            pkt {pkt} -- 
        """
        for field in pkt.FIELDS:
            fName = field[0]
            print("".ljust(FL)+fName.ljust(SL) +
                  str(pkt._fields[fName]._data))
        print('\n')
