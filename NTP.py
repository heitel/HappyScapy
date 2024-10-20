import locale
import logging
import math
from datetime import datetime

logging.getLogger("scapy").setLevel(logging.CRITICAL)

from scapy.layers.inet import UDP, IP
from scapy.layers.ntp import NTP
from scapy.sendrecv import sr1


class NTPClient:
    NTP_EPOCH = 2208988800
    DATE_FORMAT = "%A %d-%m-%Y %H:%M:%S.%f"

    def __init__(self, ntp_server):
        self.ntp_server = ntp_server
        self.stratum = None
        self.precision = None
        self.delay = None
        self.sent = None
        self.dtServer = None

    def request(self):
        ntp = NTP()
        udp = UDP(dport=123)
        ip = IP(dst=self.ntp_server)
        message = ip / udp / ntp
        p = sr1(message, timeout=2)
        #p.show()
        if p is not None:
            self.stratum = p.payload.payload.stratum
            self.precision = p.payload.payload.precision
            self.delay = p.payload.payload.delay
            self.sent = p.payload.payload.sent
            fractional, seconds = math.modf(self.sent)
            ts = seconds - NTPClient.NTP_EPOCH
            microseconds = int(fractional * 1e6)
            self.dtServer = datetime.fromtimestamp(ts)
            self.dtServer = self.dtServer.replace(microsecond=microseconds)

    def __str__(self):
        return f"{self.ntp_server} liefert: {self.dtServer.strftime(NTPClient.DATE_FORMAT)}\n\
Stratum: {self.stratum}\nPrecision: {self.precision} ms\nDelay: {self.delay}"



def main():
    locale.setlocale(locale.LC_ALL, 'de_DE')
    ntpClient = NTPClient("de.pool.ntp.org") #ptbtime1.ptb.de
    ntpClient.request()
    print(ntpClient)

    dt = datetime.now()
    print("Local Time:", dt.strftime(NTPClient.DATE_FORMAT))
    now = dt.timestamp()
    if ntpClient is not None:
        diff = now - ntpClient.sent + NTPClient.NTP_EPOCH
        print("Differenz: ", diff, "s")


if __name__ == "__main__":
    main()
