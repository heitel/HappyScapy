
import logging

logging.getLogger("scapy").setLevel(logging.CRITICAL)

from datetime import datetime
from scapy.layers.inet import UDP, IP
from scapy.sendrecv import sr1
from scapy.packet import Raw

# Version 1.0


class TimeUDP:
    TIMEOUT = 2
    NTP_EPOCH = 2208988800

    def __init__(self, time_server):
        self.time_server = time_server
        self.answer = 0
        self.dt = None

    def request(self):
        raw = Raw("\n")
        udp = UDP(dport=37)
        ip = IP(dst=self.time_server)
        message = ip / udp / raw
        p = sr1(message, timeout=TimeUDP.TIMEOUT)
        if p is not None:
            self.answer = int.from_bytes(p.payload.payload.load)
            self.answer -= TimeUDP.NTP_EPOCH
            self.dt = datetime.fromtimestamp(self.answer)
        else:
            self.answer = "timeout."

    def __str__(self):
        return "UDP Time from: " + self.time_server + " is " + str(self.dt)


def main():
    server = ["time-a-g.nist.gov", "jh-hera.dynv6.net"]
    for s in server:
        t_udp = TimeUDP(s)
        t_udp.request()
        print(t_udp)


if __name__ == "__main__":
    main()
