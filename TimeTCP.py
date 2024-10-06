import logging

logging.getLogger("scapy").setLevel(logging.CRITICAL)

import socket

from scapy.packet import Raw
from scapy.supersocket import StreamSocket
from datetime import datetime


class TimeTCP:
    TIMEOUT = 2
    NTP_EPOCH = 2208988800

    def __init__(self, time_server):
        self.time_server = time_server
        self.answer = 0
        self.dt = None

    def request(self):
        try:
            sck = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sck.settimeout(2)
            sck.connect((self.time_server, 37))
            stream = StreamSocket(sck, Raw)
            p = stream.sr1(Raw(""))
            self.answer = int.from_bytes(p.load)
            self.answer -= TimeTCP.NTP_EPOCH
            self.dt = datetime.fromtimestamp(self.answer)
        except socket.error:
            self.answer = "Timeout"
        finally:
            sck.close()

    def __str__(self):
        return "UDP Time from: " + self.time_server + " is " + str(self.dt)


def main():
    t_tcp = TimeTCP("jh-hera.dynv6.net")
    t_tcp.request()
    print(t_tcp)


if __name__ == "__main__":
    main()
