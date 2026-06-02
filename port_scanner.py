import argparse
import ipaddress
import scapy.all as scapy
import socket
import sys
import queue
import threading
## get arguments

parser = argparse.ArgumentParser(description="port scanner")
parser.add_argument("-i", "--network_interface",help="network interface to be used")			# network interface
parser.add_argument("-t","--target_ip_address",help= "IP address to can its ports")				# target ip address
parser.add_argument("-p","--scan_ports", help ="ports to be scanned")							#ports to be scanned
parser.add_argument("-s","--scan_type", help="scan_type,syn_scan, ack_scan,fin_scan,xmas_scan,tcp_connect_scan")	# type of port scan


args = parser.parse_args()
network_interface = args.network_interface
target_ip_address = args.target_ip_address
scan_ports = args.scan_ports
scan_type = args.scan_type

	## if no argument passed print help
if len(sys.argv) == 1:
	parser.print_help(sys.stderr)
	print(" ")
	print("required arguments: network interface to use (wlsp0 for wifi card) target ip to be scanned ipv4 ports to be scanned and scan type")
	print(" ")
	sys.exit(1)

print(network_interface, target_ip_address, scan_ports, scan_type)




# validating ip address
def is_valid_ip(address):
	try:
		ipaddress.ip_address(address)
		return True
	except ValueError:
		return False

if(is_valid_ip(target_ip_address)== False):
	print("Error invalid IP address")
	exit(1)

# validating ports
scan_ports_range_1 = scan_ports.split(",")				# scan_ports = 21,22,80 ==> scan_ports_range_1 = [21 22 80]
scan_ports_range_2 = []


	
for element in scan_ports_range_1:
	
	if "-" in element:
			scan_range = element.split("-")
			start = int(scan_range [0])
			stop = int(scan_range [1])
	
			for number in range(start, stop +1):
				scan_ports_range_2.append(number)
			continue
	try:
		element = int(element)							# convert to integer
		if element > 0 and element <= 65535:				# valid port
			scan_ports_range_2.append(element)
		
		

		else:
			print("invalid port", element)
			exit(1)
			print("port number must be between 0 and 65535")
	except:
		print("port number must be between 0 and 65535")
		exit(1)

def threader():
	while not q.empty():
		port = q.get()
		if scan_type == "SYN_SCAN":
			SYN_SCAN()
		elif scan_type == "ACK_SCAN":
			ACK_SCAN()
		elif scan_type == "FIN_SCAN":
			FIN_SCAN()
		elif scan_type == "xmas_scan":
			XMAS_SCAN()
		elif scan_type == "TCP_CONNECT_SCAN":
			TCP_CONNECT_SCAN()
		q.task_done()


num_threads = input(f"number of threads: ")
q = queue.Queue()
for port in scan_ports_range_2:
	q.put(port)

for thread in range(int(num_threads)):
	threading.Thread(target=threader).start()

print(scan_ports_range_2)

#validating scan type
if scan_type not in ["syn_scan","ack_scan","fin_scan","xmas_scan","tcp_connect_scan"]:
	print("invalid scanning technique")
	exit(1)

def SYN_SCAN(network_interface, target_ip_address, target_port):
	## syn packet construction
	syn_pkt = scapy.IP(dst=target_ip_address)/scapy.TCP(dport=target_port, flags='S')
	# send the syn packet
	response = scapy.sr1(syn_pkt, timeout=1,verbose=False,iface=network_interface)
	if response and response.haslayer(scapy.TCP):
		if response[scapy.TCP].flags == 'SA': ## port is open
			print(target_port, "open")
		elif response[scapy.TCP].flags == 'RA'or response[TCP].flags == 'R': # port is closed
			print(target_port , "closed")
	else:
		print(target_port, "filtered")
	print()

if scan_type =="syn_scan" :
	print("#################### starting syn scan.....")
	for index, scan_port in enumerate(scan_ports_range_2):
		SYN_SCAN(network_interface, target_ip_address, scan_port)

def ACK_SCAN(network_interface, target_ip_address, target_port):
	## ack packet construction
	ack_pkt = scapy.IP(dst=target_ip_address)/scapy.TCP(dport=target_port, flags='A')
	# send the ack packet
	response = scapy.sr1(ack_pkt, timeout=1,verbose=False,iface=network_interface)
	if response and response.haslayer(scapy.TCP):
		if response[scapy.TCP].flags == 'RA'or response[scapy.TCP].flags == 'R': # port is unfiltered
			print(target_port , "unfiltered")
	else:
		print(target_port, "filtered")
	print()
if scan_type =="ack_scan" :
	print("#################### starting ack scan.....")
	for index, scan_port in enumerate(scan_ports_range_2):
		ACK_SCAN(network_interface, target_ip_address, scan_port)

def FIN_SCAN(network_interface, target_ip_address, target_port):
	## fin packet construction
	fin_pkt = scapy.IP(dst=target_ip_address)/scapy.TCP(dport=target_port, flags='F')
	# send the fin packet
	response = scapy.sr1(fin_pkt, timeout=1,verbose=False,iface=network_interface)
	if response and response.haslayer(scapy.TCP):
		if response[scapy.TCP].flags == 'RA'or response[scapy.TCP].flags == 'R': # port is closed
			print(target_port , "closed")
	else:
		print(target_port, "open | filtered")
	print()

if scan_type =="fin_scan" :
	print("#################### starting fin scan.....")
	for index, scan_port in enumerate(scan_ports_range_2):
		FIN_SCAN(network_interface, target_ip_address, scan_port)

def XMAS_SCAN(network_interface, target_ip_address, target_port):
	## xmas packet construction: FIN PUSH URG enabled
	xmas_pkt = scapy.IP(dst=target_ip_address)/scapy.TCP(dport=target_port, flags='FPU')
	# send the xmas packet
	response = scapy.sr1(xmas_pkt, timeout=1,verbose=False,iface=network_interface)
	if response and response.haslayer(scapy.TCP):
		if response[scapy.TCP].flags == 'RA'or response[scapy.TCP].flags == 'R': # port is closed
			print(target_port , "closed")
	else:
		print(target_port, "open | filtered")
	print()

if scan_type =="xmas_scan" :
	print("#################### starting xmas scan.....")
	for index, scan_port in enumerate(scan_ports_range_2):
		XMAS_SCAN(network_interface, target_ip_address, scan_port)

def TCP_CONNECT_SCAN(destination_ip,destination_port):
	client_socket = socket.socket(socket.AF_INET,socket.SOCK_STREAM)	# construct a TCP Socket
	try:
		# establish a full tcp connection with the port you want to scan
		client_socket.connect((destination_ip,destination_port))
		print(destination_port, "open")
		client_socket.close 		#close the connection
	except:
		# port is closed
		print(destination_port, "closed")


if scan_type =="tcp_connect_scan" :
	print("#################### starting tcp connect scan.....")
	for index, scan_port in enumerate(scan_ports_range_2):
		TCP_CONNECT_SCAN( target_ip_address, scan_port)








