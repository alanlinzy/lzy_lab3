import asyncio
import sys
import playground
import time
from threading import Timer
import datetime
import random
import string
# NOTE: local pkts and files
from cmdHandler import printx, DataHandler, BankManager, printError
# from escape_room_006 import EscapeRoomGame
from escape_room_010 import EscapeRoomGame
from autograder_lab2_packets import *
from class_packet import *


# from playground.common.logging import EnablePresetLogging, PRESET_VERBOSE
# EnablePresetLogging(PRESET_VERBOSE)

PORT_NUM = 2222
TIME_OUT = 60

# bank params
MY_ACCOUNT = "wli71_account"
AMOUNT = 10


class ServerProtocol(asyncio.Protocol):
    def connection_made(self, transport):
        self.transport = transport
        self.dataHandler = DataHandler(transport)
        self.peername = self.transport.get_extra_info('peername')
        printx('Connection from:{}'.format(self.peername))
        self.game = EscapeRoomGame(output=self.sendGameResPkt)
        self.game.create_game()
        self.payStatus = False
        self.bankManager = BankManager()
        self.timer = None
        self.tasks = []

    def data_received(self, data):
        self.resetTimer()
        self.dataHandler.printTimeAndPeerName()
        pkts = self.dataHandler.recvPkt(data)
        for pkt in pkts:
            self.data_received_helper(pkt)
        if self.game.status == "escaped":
            self.payStatus = False  # NOTE: here prevent user play multiple times
            printx('Student server side finished!')

    def data_received_helper(self, pkt):
        pktID = pkt.DEFINITION_IDENTIFIER
        # 1: respond to game init pkt, ask payment
        if pktID == GameInitPacket.DEFINITION_IDENTIFIER:
            self.unique_id = self.generateRandomString()
            self.dataHandler.printTimeAndPeerName()
            self.dataHandler.sendPkt(create_game_require_pay_packet(
                self.unique_id, MY_ACCOUNT, AMOUNT))

        # 2: respond to game payment response pkt, confirm payment and start game
        elif pktID == GamePayPacket.DEFINITION_IDENTIFIER:
            receipt, receipt_sig = process_game_pay_packet(pkt)
            if(True):
                # TODO: fix this
                # if(self.bankManager.receipt_verify(receipt,receipt_sig,MY_ACCOUNT,AMOUNT,self.unique_id)):
                printx("payment confirmed")
                self.payStatus = True
                self.game.start()
                for a in self.game.agents:
                    self.tasks.append(asyncio.create_task(a))
            else:
                printError("client's payment confirm failed")

        # 3: respond to game command pkt, send game response
        elif pktID == GameCommandPacket.DEFINITION_IDENTIFIER:
            if self.game.status != "playing":
                printError(
                    "client tried to play the game while status is not playing")
                return
            elif self.payStatus == False:
                printError(
                    "client tried to play game before the payment is confirmed!")
                return
            else:
                self.game.command(pkt.command)
                time.sleep(0.25)
                return
        else:
            printError("unknown pkt:" + pktID)

    def generateRandomString(self, stringLength=10):
        """ Generate a unique ID (a random string of fixed length)
        """
        return ''.join(random.choice(string.ascii_lowercase) for i in range(stringLength))

    def sendGameResPkt(self, string):
        """ Server as game's output, so pass this to the game
        """
        self.dataHandler.printTimeAndPeerName()
        pkt = create_game_response(string, self.game.status)
        self.dataHandler.sendPkt(pkt)

    def resetTimer(self):
        if self.timer != None:
            self.timer.cancel()
        self.timer = Timer(TIME_OUT, lambda: self.cancleTasks())
        self.timer.start()
        # sys.stdout.flush()  # for output.txt, otherwise will print when program ends

    def cancleTasks(self):
        # tell client the transport is closed
        self.dataHandler.sendPkt(GameResponsePacket(
            response="{},You didn't response in the past {} seconds, please reconnect again".format(self.peername, TIME_OUT),status = self.game.status))
        self.transport.close()
        for task in self.tasks:
            task.cancel()
        printx("{}, timer is up, server transport close".format(
            self.peername[0]))


def main(args):
    loop = asyncio.get_event_loop()
    coro = playground.create_server(
        ServerProtocol, "localhost", PORT_NUM,family = "lzy_crap")
    server = loop.run_until_complete(coro)

    printx('Servering on{}'.format(server.sockets[0].getsockname()))
    # loop.set_debug(1)
    try:
        loop.run_forever()
    except KeyboardInterrupt:
        pass

    server.close()
    loop.run_until_complete(server.wait_closed())
    loop.close()


if __name__ == '__main__':
    main(sys.argv[1:])
