import logging


logging.getLogger("scapy").setLevel(logging.CRITICAL)

from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import UDP, IP
from scapy.layers.inet6 import ICMPv6EchoRequest, IPv6

import socket
import time
from scapy.layers.l2 import ARP, Ether
from scapy.sendrecv import sendp, AsyncSniffer, sr1


class Host:
    NOT_AVAILABLE = "n./a."

    def __init__(self, mac, ip, name):
        self.mac = mac
        self.ip = ip
        self.ipv6 = Host.NOT_AVAILABLE
        self.name = name

    def __str__(self):
        return f"{self.mac:<20}\t{self.ip:>20}\t{self.ipv6:>32}\t{self.name}"


class DiscoverNeighbors:
    def __init__(self, ip_net):
        self.ip_net = ip_net
        self.neighbors = dict()

    def discover(self):
        t = AsyncSniffer(filter="arp and arp[7]==2")
        t.start()
        arp = ARP(pdst=self.ip_net)
        ether = Ether(dst="FF:FF:FF:FF:FF:FF")
        message = ether / arp
        sendp(message)
        time.sleep(1)
        t.stop()

        socket.timeout(1)
        if t.results is not None:
            for p in t.results:
                mac = p[ARP].hwsrc
                ip = p[ARP].psrc
                name = Host.NOT_AVAILABLE
                try:
                    name = socket.gethostbyaddr(ip)[0]
                except socket.herror:
                    pass

                host = Host(mac, ip, name)
                self.neighbors[mac] = host
                # p.show()

            print("Anzahl der Hosts: ", len(t.results))

        self.update_lla()


    def update_lla(self):
        t = AsyncSniffer(filter="icmp6 and ip6[40]==129")
        t.start()
        icmpv6 = ICMPv6EchoRequest()
        ipv6 = IPv6(dst="ff02::1")
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        message = ether / ipv6 / icmpv6
        sendp(message)
        time.sleep(1)
        t.stop()
        if t.results is not None:
            for p in t.results:
                mac = p[Ether].src
                ipv6 = p[IPv6].src
                host = self.neighbors[mac]
                host.ipv6 = ipv6
                # print(f"{mac}, {ipv6}")

    def __str__(self):
        erg = ""
        for key, host in self.neighbors.items():
            erg += str(host) + "\n"

        return f"Neighbors in {self.ip_net}\n{erg}\nAnzahl der Host:{len(self.neighbors)}"


def main():
    dn = DiscoverNeighbors("192.168.0.0/24")
    dn.discover()
    print(dn)

    DNSClient()


if __name__ == "__main__":
    main()
