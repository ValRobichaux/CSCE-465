#!/usr/bin/env python3

from scapy.all import *

def print_pkt(pkt):
	pkt.show()


interfaces = ['br-11ccd7f3cf1d','br-334fd5f10716','enp0s3','lo']

pkt = sniff(iface = interfaces, filter='dst net 128.230.0.0/16', prn=print_pkt)

