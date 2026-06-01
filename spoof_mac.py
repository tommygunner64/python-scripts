#!/usr/bin/python3
import random
import subprocess
import argparse
import sys

parser = argparse.ArgumentParser(description = "mac spoofer")
parser.add_argument("-i", "--network_interface", help= "network interface to be used (wlp3s0: wifi card) ") 				# network interface to be used 
	
	## get interface to use

args = parser.parse_args()
network_interface = args.network_interface

print ("--------------------------------------------------------------------------------")
print ("spoof your mac because your sketchy")
	## if no argument passed print help
if len(sys.argv) == 1:
	parser.print_help(sys.stderr)
	sys.exit(1)

	#generate a new mac address

random_mac = [0x00, 0x50, 0x56, random.randint(0x00,0x7f), random.randint(0x00,0xff),random.randint(0x00,0xff) ] # the first 3 octets are hardcoded as vmware 
mac_addr   = ":".join(map(lambda x:"%02x"%x, random_mac))

print ("New Mac Address:", mac_addr)

	# old mac address:
print("old mac address:")
subprocess.call(["ip","link", "show", network_interface])

	# change the mac of NIC
	# step 1 : disconnect from the LAN : ifdown<nic name>
subprocess.call(["sudo", "ip","link","set" ,"down" ,network_interface])

	#step 2 : deactivate the NIC
subprocess.call(["sudo","ip","link","set",network_interface,"down"])

	# step 3 : change mac address
subprocess.call(["sudo","ip","link","set",network_interface,"address",mac_addr])

	# step 4 : activate again the MAC address:
subprocess.call(["sudo","ip","link","set",network_interface,"up"])

print("new mac address:")
	# step 5 : check the new mac address
subprocess.call(["sudo","ip","link","show",network_interface])

	## need to connect again to the LAN








