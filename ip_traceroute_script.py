import argparse
import ipaddress
import scapy.all as scapy
import time
parser = argparse.ArgumentParser(description="IP tracerouting python script")
parser.add_argument('-t','--target_ip_address',help='Target IP Address to be tracerouted')
parser.add_argument('-m','--max_hop_limit',type=int, help='max hop limit')

print("program will require sudo or admin privileges")
## get the arguments
args = parser.parse_args()
target_ip_address = args.target_ip_address
max_hop_limit = args.max_hop_limit



## validate ip address
def is_valid_ip(address):
	try:
		ipaddress.ip_address(address)
		return True
	except ValueError:
		return False

if(is_valid_ip(target_ip_address)== False):
	print("invalid ip address")
	exit(1)

# TTL initialiization
TTL = 1
print("IP Traceroute start.....")
T1 = time.time()
while ( TTL <= max_hop_limit):
	ICMP_PKT =scapy.IP(dst=target_ip_address,ttl=TTL,)/scapy.ICMP()			#ICMP Packet = IP header + ICMP Header
	ans = scapy.sr1(ICMP_PKT,timeout=3,retry=1,verbose=False)					# snd ICMP Packet
	## valid response is received
	if(isinstance(ans,type(None))) == False:
		## ICMP TTL expiried
		if (ans[1].type == 11 and ans[1].code ==0):
			print("router",ans[0].src,"|TTL:",TTL)
			TTL+=1
		# ICMP echo reply
		if(ans[1].type==0):
			print("router",target_ip_address,"| TTL:", TTL)
			break
	# if no responce
	else:
		print("Unknown router", "| TTL", TTL)
		TTL += 1

T2 = time.time()
print("ip tracerouting done in", T1 - T2 , "seconds")


