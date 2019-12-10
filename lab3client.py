import asyncio
import playground
import sys

from cmdHandler import *
from class_packet import *
from autograder_lab2_packets import *
# from playground.common.logging import EnablePresetLogging, PRESET_DEBUG
# EnablePresetLogging(PRESET_DEBUG)

# IP param
TEAM_NUM = 2 # todo: change this is enough
IP_ADDR  = "localhost"
PORT     = 2222

# bank params
USER_NAME_INIT_PKT = "test" # TODO:make sure of this
MY_UNAME           = "zlin32"
MY_ACCOUNT         = "zlin32_account"


def set_server_info(team):
    global IP_ADDR
    global PORT

    if team == 1:
        IP_ADDR = "20194.1.1.200"
        PORT    = 12345
    elif team == 2:
        IP_ADDR = "localhost"
        PORT    = 2222
    elif team == 3:
        IP_ADDR = "20194.3.6.9"
        PORT    = 333
    elif team == 4:
        IP_ADDR = "20194.4.4.4"
        PORT    = 8666
    elif team == 5:
        IP_ADDR = "20194.5.20.30"
        PORT    = 8989
    elif team == 6:
        IP_ADDR = "20194.6.20.30"
        PORT    = 16666
    elif team == 9:
        IP_ADDR = "20194.9.1.1"
        PORT    = 7826
    else:
        printError("No such team number in record, connect to team2 server")
        IP_ADDR = "localhost"
        PORT    = 2222



class ClientProtocol(asyncio.Protocol):
    def __init__(self, loop, firstPkt=None,mode = "client"):
        self.loop = loop
        self.firstPkt = firstPkt
        self.bankManager = BankManager()

    def connection_made(self, transport):
        self.transport   = transport
        self.dataHandler = DataHandler(transport)
        self.peer_domain = self.transport.get_extra_info("peername")[0]
        self.peer_port   = self.transport.get_extra_info("peername")[1]
        print("App Connection made to {}:{}".format(self.peer_domain, self.peer_port))

        if(self.firstPkt != None):
            self.dataHandler.sendPkt(self.firstPkt)

        asyncio.get_event_loop().add_reader(sys.stdin,lambda: self.dataHandler.sendPktNoPrint(GameCommandPacket(command=input('>>'))))



    def send_init_game(self):
        self.dataHandler.sendPkt(create_game_init_packet(USER_NAME_INIT_PKT))
    def send_game_cmd(self):
        self.dataHandler.sendPkt(GameCommandPacket(command="look"))

    def data_received(self, data):
        pkts = self.dataHandler.getPktsFromData(data)
        for pkt in pkts:
            asyncio.create_task(self.data_received_helper(pkt))

    async def data_received_helper(self, pkt):
        pktID = pkt.DEFINITION_IDENTIFIER
        # 1: respond to game payment request, make payment
        if pktID == GameRequirePayPacket.DEFINITION_IDENTIFIER:
            self.dataHandler.printPkt(pkt)
            # todo: play this
            # self.no_pay()
            # return
            id, account, amount = process_game_require_pay_packet(pkt)
            user_answer = input(
                "the amount you need to pay is {}, to confirm, enter \'y\', enter anything else to cancle:".format(amount))
            if(user_answer != 'y'):
                printx("the payment is cancled!")
            else:
                receipt, receipt_sig = await self.bankManager.transfer(MY_ACCOUNT, account, amount, id)
                if(receipt == None or receipt_sig == None):
                    printError("the bank transaction is not successful, so the process stopped")
                else:
                    self.dataHandler.sendPkt(create_game_pay_packet(receipt, receipt_sig))

        # 2: respond to game response, send game cmd
        elif pktID == GameResponsePacket.DEFINITION_IDENTIFIER:
            print(":" + pkt.response)
            # NOTE: this part's function is replaced by loop.add_reader()
            return

        else:
            print("unknown pkt recived:" + pktID)

    def connection_lost(self, exc):
        print('The server closed the connction, now stop the event loop')
        self.loop.stop()

        
def main(args):
    team_num = int(input("team number: "))
    set_server_info(team_num)
  
    loop = asyncio.get_event_loop()
    firstPkt = create_game_init_packet(USER_NAME_INIT_PKT)
    coro = playground.create_connection(lambda: ClientProtocol(loop=loop, firstPkt=firstPkt),
                                                        IP_ADDR, PORT, family="lzy_crap")  # for E5
    loop.run_until_complete(coro)
    loop.run_forever()
    loop.close()



if __name__ == "__main__":
    main(sys.argv[1:])
