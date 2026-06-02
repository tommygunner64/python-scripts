#!/usr/bin/python3

import scapy.all as scapy # pip3 install scapy 
import time
import argparse

parser = argparse.ArgumentParser(description="arp scanner")
parser.add_argument('-n', '--network_to_be_scanned', help = 'enter the network to be scanned')
parser.add_argument('-i', '--network_interface', help =' interface used to scan the network wlp3s0 for wifi card ')

args = parser.parse_args()

network = args.network_to_be_scanned
interface = args.network_interface

if network == None:
	print("error program requires argument")
	exit(1)

if interface == None:
	print("error program requires argument")
	exit(1)

# construct the ARP Echo Request Packets
ether_req      = scapy.Ether()					#ether header
ether_req.dst  ='ff:ff:ff:ff:ff:ff'			# broadcast MAC Address
arp_req        = scapy.ARP()                       # ARP header 
arp_req.pdst   = network		    #set the ip address or the LAN subnet to be scanned
ARP_Request_PKT = ether_req/arp_req 		#complete arp packet
print("ARP Echo Request Packet Construction Complete")

# scanning the LAN
T1_SCAN_START=time.time()		                         # get the current time
print("Scan Started")
ans = scapy.srp(ARP_Request_PKT,timeout=1,retry=1,verbose=False,iface=interface,inter=0.005)[0]


T2_SCAN_Complete = time.time()	             # get the current time when the scan  is finished
print("time needed for the scan",T2_SCAN_Complete - T1_SCAN_START,"seconds")
# get the live hosts
for snd, rcv in ans:
	print("live host",rcv[0].psrc)

	#snd,rcv