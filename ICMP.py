import logging

logging.getLogger("scapy").setLevel(logging.CRITICAL)
from datetime import datetime
from scapy.packet import Raw
from scapy.layers.inet import ICMP, IP
from scapy.sendrecv import sr1


class ICMPClient:
    def __init__(self, host, count):
        self.host = host
        self.ip_host = "n.a."
        self.diff = 0
        self.count = count

    def request(self):
        for i in range(0, self.count):
            raw = Raw("A" * 18)
            icmp = ICMP(seq=i)
            ip = IP(dst=self.host)
            message = ip / icmp / raw
            # message.show()
            start = datetime.now()
            p = sr1(message, verbose=False, timeout=2)
            end = datetime.now()
            diff = (end - start).microseconds / 1000
            # p.show()
            self.ip_host = p.src
            self.diff = diff
            print(self)

    def __str__(self):
        return f"Antwort von {self.ip_host} Dauer: {self.diff:.2f} ms"


def main():
    icmpClient = ICMPClient("94.130.171.193", 5)
    icmpClient.request()


if __name__ == "__main__":
    main()
