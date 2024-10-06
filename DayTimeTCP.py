import logging

logging.getLogger("scapy").setLevel(logging.CRITICAL)

import socket

from scapy.packet import Raw
from scapy.supersocket import StreamSocket


class DayTimeTCP:
    TIMEOUT = 2

    def __init__(self, daytime_server):
        self.daytime_server = daytime_server
        self.answer = "n.a."

    def request(self):
        try:
            sck = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sck.settimeout(2)
            sck.connect((self.daytime_server, 13))
            stream = StreamSocket(sck, Raw)
            p = stream.sr1(Raw(""))
            self.answer = p.load.decode("UTF-8")
        except socket.error:
            self.answer = "Timeout"
        finally:
            sck.close()

    def __str__(self):
        return "TCP Daytime from: " + self.daytime_server + " is " + self.answer


def main():
    dt_tcp = DayTimeTCP("jh-hera.dynv6.net")
    dt_tcp.request()
    print(dt_tcp)


if __name__ == "__main__":
    main()
