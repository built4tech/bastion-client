#! /usr/bin/env python3
# -*- coding: latin-1 -*-

from common.logger import logger, os
from common.WebSvr import WebService, requests
import argparse
import time
import nmap
import threading
import queue
import traceback, sys
import json

q_Pending_Hosts  = queue.Queue()
q_Finished_Hosts = queue.Queue()

#GLOBALS
HEARTBEAT_VALUE = 300
NUM_WORKER_THREADS = 1
signal = False
waitingfornmap = False

# Constant
PATH = '/usr/local/share/wifi-connect/ui/'

def get_hosts(myWebSvr):
	while True:
		data = myWebSvr.getHosts2Enrich()

		if data['action'] == 'failed':
			logger.error(data['message'])
			# Si existe un problema de comunicación 
			# esperamos 30 segundos y volvemos a intentar
			time.sleep(30)
		else:
			return data['value']


def get_vendor(mac):
	url = "https://api.macvendors.com/%s"

	try:
		r = requests.get(url % mac, verify=False)    
	except Exception as e:
		return({'action' : 'failed', 'message' : 'Error getting vendor: %s'%e})

	if r.status_code == 200:
		return_data = {'action' : 'successful', 'message': r.text}

	else:
		return_data = {'action' : 'failed', 'message': r.text}

	return return_data

def get_services(ip):
	
	services = None
	
	try:
		nm = nmap.PortScanner()
		services = nm.scan(hosts=ip, arguments='-T4 -F')
	except:
		pass

	ports = []

	if services:
		try:
			ports = [key for key in services['scan'][ip]['tcp'].keys()]
		except:
			pass

	return ports

def manage_pending_hosts():
	global q_Pending_Hosts
	global q_Finished_Hosts
	global waitingfornmap

	while True:
		entry = q_Pending_Hosts.get()

		if entry is None:
			break

		mac 	 = entry['mac']
		ip  	 = entry['ip']
		vendor 	 = ''
		services = []

		data = get_vendor(mac)

		if data['action'] == 'successful':
			vendor = data['message']
		else:
			vendor = "Unknown"

		waitingfornmap = True
		services = get_services(ip)
		waitingfornmap = False

		if not signal:
			q_Finished_Hosts.put({'mac':mac, 'ip':ip, 'vendor':vendor, 'services': services})        

		q_Pending_Hosts.task_done()

def manage_finished_hosts(myWebSvr):
	global q_Finished_Hosts

	while True:
		entry = q_Finished_Hosts.get()

		if entry is None:
			break

		payload = {'vendor': entry['vendor'], 'services': json.dumps(entry['services'])}

		mac =  entry['mac']
		data = myWebSvr.enrich(mac, payload)

		if data['action'] == 'failed':
			logger.error(data['message'])
		else:
			logger.info(data['message'])

		q_Finished_Hosts.task_done()


def parseargs():
	'''
	Description: Function in charge of the CLI parameters
	Input:       No input
	Output:      Parsed arguments
	'''
	description = 'Network Monitor - Enriching function'
	prog = 'enriching.py'
	usage = 'sudo python3 enriching.py [-t Token]'
	epilog = 'Carlos Munoz (carlos.munoz.garrido@outlook.com)\n%(prog)s 1.0 (09/04/2020)'	

	parser = argparse.ArgumentParser(epilog=epilog, usage=usage, prog=prog, description=description, formatter_class=argparse.RawTextHelpFormatter)

	mon_group = parser.add_argument_group("Monitor parameters")

	arg_help = "Bastion Token"
	mon_group.add_argument('-t', required=False, default = None, action='store', dest='token', help=arg_help, metavar="")

	parser.add_argument('--version', action='version', version='Carlos Munoz (carlos.munoz.garrido@outlook.com)\n%(prog)s 1.0 (09/04/2020)')

	return parser.parse_args()


def main():
	global q_Pending_Hosts
	global q_Finished_Hosts
	global signal
	

	# Getting CLI parameters ********************************************
	option = parseargs()

	token = option.token

	if not token:
		try:
			with open(PATH + 'bast_creeds.txt', "r") as f:
				line = f.readline()
				token = line.strip()
		except Exception as e:
			logger.error("MONITOR - Error Getting token from file")
			os.sys.exit()

	if token == None or token == "":
		logger.error("MONITOR - Token cannot be blank")
		os.sys.exit()
    # *********************************************************************


	# ********************************************************************
	myWebSvr = WebService(token)

	# Check ping **********************************************************
	# Avoid to move forward untill the ping is obtained
	while True:
		ping = myWebSvr.ping()
		if ping['action'] == "successful": break
		logger.error(ping)
		time.sleep(5)
	logger.info(ping)
	# *********************************************************************   

	# Check if Token is valid *********************************************
	token_validation = myWebSvr.check_token()
	if token_validation['action'] == 'failed':
		logger.error(token_validation)
		os.sys.exit()
	logger.info(token_validation)  
    # *********************************************************************

	# Thread initialization for new hosts found **************************
	pending_hosts_threads = []
	for i in range(NUM_WORKER_THREADS):
		t = threading.Thread(target=manage_pending_hosts)
		pending_hosts_threads.append(t)
		t.setDaemon(True)
		t.start()
    # ********************************************************************

    # Thread initialization for new hosts found **************************
	finished_hosts_threads = []
	for i in range(NUM_WORKER_THREADS):
		t = threading.Thread(target=manage_finished_hosts, args=(myWebSvr,))
		finished_hosts_threads.append(t)
		t.setDaemon(True)
		t.start()
    # ********************************************************************


    # Continous loop *****************************************************

	try:
		while True:
			hosts = get_hosts(myWebSvr)
			for each_host in hosts:
				q_Pending_Hosts.put({'mac':each_host['mac'], 'ip':each_host['current_ip']})

			time.sleep(HEARTBEAT_VALUE)
	except KeyboardInterrupt:
		logger.info('Keyboard interrupt received. Stopping enriching app')


	signal = True

	
	with q_Pending_Hosts.mutex:
		q_Pending_Hosts.queue.clear()

	with q_Finished_Hosts.mutex:
		q_Finished_Hosts.queue.clear()


	for i in range(NUM_WORKER_THREADS):
		q_Pending_Hosts.put(None)
		q_Finished_Hosts.put(None) 

	while True:
		if not waitingfornmap:
			for t in pending_hosts_threads:
				t.join()

			for t in finished_hosts_threads:
				t.join()
			break
			time.sleep(5)
    # ********************************************************************


if __name__ == "__main__":
    main()