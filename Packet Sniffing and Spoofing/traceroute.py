from scapy.all import *

inRoute = True
i = 1

while inRoute:
	a = IP(dst = '8.8.8.8', ttl = i)
	response = sr1(a/ICMP(),timeout = 7, verbose=0)

	if response is None :
		print(f"{i} Req time out.")

	elif response.type == 0:
		print(f"{i} {response.src}")
		inRoute = False

	else: 
		print(f"{i} {response.src}")

	i = i + 1