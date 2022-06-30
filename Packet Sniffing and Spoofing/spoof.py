from scapy.all import * 

a = IP()
a.src = '1.1.1.1'
a.dst = '10.0.2.15'
send(a/ICMP())
ls(a)