#!/usr/bin/python3

import ipaddress
import subprocess
import queue
import threading
import time

def scan_ip_address():	
	while not q.empty():							# check if there is more IP Addresses in the queue, otherwise exit if the queue is empty.
		ip = q.get()							# get an ip address from the queue using the method get
		command = "ping -c 1 -w 1 {}".format(ip)
		process = subprocess.run(command,
			shell = True,						# use a real shell
			stdout=subprocess.PIPE,				# send standard output to a pipe
			stderr=subprocess.PIPE,				# send standard errors to a pipe
		)	

		# check exit code to discover if a given ip aderess is reachable or not
		if process.returncode == 0:
			print("ip adress is reachable:", ip)

		else:
			print("ip adress is not reachable:", ip)
		q.task_done()								# indicate that the thread has finished processing the ip addresses

network = input(f"network to be scanned:")
num_threads = input(f" number of threads:")
start_time = time.time()
print(f"starting scan:")
print("---------------------------------------------------------------------")
try:
	IP_Adresses = ipaddress.IPv4Network(network)							# get all IP Address inside the network
	#initilize queue object that will be used by threads: (threads will get IP addresses from the queue)
	q = queue.Queue()
	# fill the queue with ip addresses
	for ip in IP_Adresses:
		q.put(ip)			# the function put() will add an ip address to the queue in every iteration of the for loop

	for thread in range(int(num_threads)):
		threading.Thread(target=scan_ip_address).start()	#create and start a new thread that will execute the function scan_ip_address

	# wait for all the ip addresses in the queue have been processed 
	q.join()
except Exception as e:
	print("Exception:", e)
print(f"Execution time: {time.time() - start_time}")
