#!/usr/bin/env python 
from scapy.all import sniff
from scapy.packet import *
from scapy.fields import *
from scapy.layers.inet import TCP

def parse(pkt): return pkt.show()
def parse2(pkt): return pkt.sprintf("{IP:%IP.src% -> %IP.dst%\n}{Raw:%Raw.load%\n}")

def main():
    sniff(iface="lo", filter="port 8180", prn=parse, store=False)

if __name__ == '__main__':
    main()
