import logging

logging.getLogger("scapy").setLevel(logging.CRITICAL)

from scapy.layers.inet import UDP, IP
from scapy.sendrecv import sr1
from scapy.packet import Raw

# Version 1.0


class DayTimeUDP:
    TIMEOUT = 2

    def __init__(self, daytime_server):
        self.daytime_server = daytime_server
        self.answer = "n.a."

    def request(self):
        raw = Raw("\n")
        udp = UDP(dport=13)
        ip = IP(dst=self.daytime_server)
        message = ip / udp / raw
        p = sr1(message, timeout=DayTimeUDP.TIMEOUT)
        if p is not None:
            self.answer = p.payload.payload.load.decode("UTF-8")
        else:
            self.answer = "timeout."

    def __str__(self):
        return "UDP Daytime from: " + self.daytime_server + " is " + self.answer


def main():
    dt_udp = DayTimeUDP("jh-hera.dynv6.net")
    dt_udp.request()
    print(dt_udp)


if __name__ == "__main__":
    main()
