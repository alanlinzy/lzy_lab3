import asyncio
import playground
import sys

from autograder_lab2_packets import *
from cmdHandler import *
from class_packet import *
# from playground.common.logging import EnablePresetLogging, PRESET_DEBUG
# EnablePresetLogging(PRESET_DEBUG)

IPADDR = "localhost"
PORT = 2222
# bank params
TEST_UNAME = "test"  # TODO:make sure of this
MY_UNAME = "wli71"
MY_ACCOUNT = "wli71_account"


class ClientProtocol(asyncio.Protocol):
    def __init__(self, loop, firstPkt=None):
        self.loop = loop
        self.firstPkt = firstPkt
        self.bankManager = BankManager()

    def connection_made(self, transport):
        self.transport = transport
        self.dataHandler = DataHandler(transport)
        printx("Connection made!")
        if(self.firstPkt != None):
            self.dataHandler.sendPkt(self.firstPkt)
        asyncio.get_event_loop().add_reader(sys.stdin,
                                            lambda: self.dataHandler.sendPktNoPrint(GameCommandPacket(command=input('>>'))))

    def data_received(self, data):
        pkts = self.dataHandler.getPktsFromData(data)
        for pkt in pkts:
            asyncio.create_task(self.data_received_helper(pkt))

    async def data_received_helper(self, pkt):
        pktID = pkt.DEFINITION_IDENTIFIER
        # 1: respond to auto grade submit pkt, request start game
        if pktID == AutogradeTestStatus.DEFINITION_IDENTIFIER:
            self.dataHandler.printPkt(pkt)
            if pkt.client_status == 1:
                return
            self.dataHandler.sendPkt(create_game_init_packet(TEST_UNAME))

        # 2: respond to game payment request, make payment
        elif pktID == GameRequirePayPacket.DEFINITION_IDENTIFIER:
            self.dataHandler.printPkt(pkt)
            id, account, amount = process_game_require_pay_packet(pkt)
            user_answer = input(
                "the amount you need to pay is {}, to confirm, enter \'y\', enter anything else to cancle:".format(amount))
            if(user_answer != 'y'):
                printx("the payment is cancled!")
            else:
                receipt, receipt_sig = await self.bankManager.transfer(MY_ACCOUNT, account, amount, id)
                if(receipt == None or receipt_sig == None):
                    printError(
                        "the bank transaction is not successful, so the process stopped")
                else:
                    self.dataHandler.sendPkt(
                        create_game_pay_packet(receipt, receipt_sig))

        # 3: respond to game response, send game cmd
        elif pktID == GameResponsePacket.DEFINITION_IDENTIFIER:
            print(":" + pkt.response)
            # NOTE: this part's function is replaced by loop.add_reader()
            return

        else:
            printx("unknown pkt recived:" + pktID)

    def connection_lost(self, exc):
        printx('The server closed the connction')
        printx('Stop the event loop')
        self.loop.stop()

def main(args):
    loop = asyncio.get_event_loop()
    # IPADDR = input("input the server address:")
    # PORT = input("input the server port:")

    firstPkt = create_game_init_packet("test")
    coro = playground.create_connection(lambda: ClientProtocol(loop=loop, firstPkt=firstPkt),
                                        IPADDR, PORT)  # for E5
    loop.run_until_complete(coro)
    loop.run_forever()
    loop.close()


if __name__ == "__main__":
    main(sys.argv[1:])
