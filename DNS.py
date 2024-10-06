import logging

logging.getLogger("scapy").setLevel(logging.CRITICAL)

from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import UDP, IP
from scapy.sendrecv import sr1


class DNSClient:
    def __init__(self, req, server):
        self.req = req
        self.server = server
        self.answer = "n.a."

    def request(self):
        dns = DNS(rd=1, qd=DNSQR(qtype="A", qname=self.req))
        udp = UDP(dport=53)
        ip = IP(dst=self.server)
        message = ip / udp / dns
        p = sr1(message, timeout=2)
        #p.show()
        if p is not None:
            ans = p.payload.payload.an
            if ans is not None:
                self.answer = ans.rdata

    def __str__(self):
        return f"{self.req} = {self.answer} sagt: {self.server}"


def main():
    dnsClient = DNSClient("jh-hera.dynv6.net", "one.one.one.one.")
    dnsClient.request()
    print(dnsClient)


if __name__ == "__main__":
    main()
