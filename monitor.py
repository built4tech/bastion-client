#! /usr/bin/env python3
# -*- coding: latin-1 -*-

import argparse
import socket
import ipaddress
import time
import threading
import json
import os

from scapy.all import *

from common.logger import logger
from common.WebSvr import WebService

try:
    import queue
except ImportError:
    import Queue as queue

# Colas
q_DB = queue.Queue()
q_ALERT = queue.Queue()

# Global variables
myWebSvr = ''   
HEARTBEAT_VALUE = 300
NUM_WORKER_THREADS = 1
host_cache = {}
signal = False

# Constant
PATH = '/usr/local/share/wifi-connect/ui/'

class Utils():
      
    @classmethod
    def get_LocalSubnet(self):
        # Esta funcion comprueba la IP local y devuelve su subred considerando siempre una clase C
        # el motivo es que va a realizar un escaneo agresivo y no queremos que analice muchos equipos
        
        data = None
        try:
        
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 53))
            localIP = s.getsockname()[0]
            s.close()
            
            data = str(ipaddress.ip_network(localIP+'/255.255.255.0', strict=False))
            
        except:
            pass
        
        return data

 
        
def active_Scan(subnet):

    ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=subnet), timeout=4, verbose=False)

    collection = []
    for snd, rcv in ans:
        result = rcv.sprintf(r"%ARP.psrc% %Ether.src%").split()
        collection.append(result)
        
    return collection

def arp_monitor_callback(pkt):
    collection = []
    if ARP in pkt and pkt[ARP].op in (1,2): #who-has or is-at
        mac = pkt.hwsrc
        current_ip = pkt.psrc
        collection.append([current_ip, mac])
        check_new_hosts(collection)
        

def pasive_scan():
    sniff(prn=arp_monitor_callback, filter="arp", store=0, stop_filter=stopfilter)
    
def stopfilter(x):
    if signal:
        return True
    else:
        return False

    
def check_new_hosts(hosts):
    global host_cache
    
    current_time = time.time()
    
    for host in hosts:
        mac = host[1]
        current_ip  = host[0]
        if mac not in host_cache:
            host_cache.update({mac:[current_ip, current_time]})
            logger.info('MONITOR - New host %s found'%mac) 
            # q_DB.put({mac:[current_ip, current_time]})
            q_DB.put({mac:[current_ip]})
            # Aqui alimentamos el modulo de notificaciones en relacion a la identificacion de un nuevo host
            
        else:
            if host_cache[mac][0] != current_ip:
                logger.info('MONITOR - Host %s has changed ip from %s to %s'%(mac,host_cache[mac][0], current_ip))
                host_cache.update({mac:[current_ip, current_time]})
                #q_DB.put({mac:[current_ip, current_time]})
                q_DB.put({mac:[current_ip]})
                # Alimentamos notificaciones descubrimiento de una MAC que ha cambiado de IP
            else:
                # Se trata de un host existente cuya IP no ha cambiado, aun así lo gestionamos para que la hora
                # de la ultima vez que se ha visto quede actualizada
                # La siguiente condicion intenta evitar que el ńumero de updates contra la BBDD sea muy alto
                # compruebo que hayan pasado 60 segundos desde la ultima actualizacion
                if current_time - host_cache[mac][1] > 60:
                    logger.info('MONITOR - Host %s seen again, updating last_time seen value'%mac)
                    host_cache.update({mac:[current_ip, current_time]})
                    #q_DB.put({mac:[current_ip, current_time]})
                    q_DB.put({mac:[current_ip]})
                
def manage_new_founds():
  
    while True:
        entry = q_DB.get()
        if entry is None:
            break
        
        mac = list(entry.keys())[0]
        current_ip = entry[mac][0]

        '''
        current_time = entry[mac][1]

        string_time = repr(current_time).split('.')[0]
        # Aunque en la siguiente linea igualemos first_time y last_time y pueda tratarse de un equipo visto con 
        # anterioridad el Web Service controla si es un nuevo registro o un registro existente y si es 
        # existente ignora el campo first_time manteniendo la fecha de la primera vez eu fue vistro
        payload = {'mac': mac, 'current_ip': current_ip, 'first_time_seen': string_time, 'last_time_seen': string_time}
        '''

        payload = {'mac': mac, 'current_ip': current_ip}

        data = myWebSvr.upload(payload)

        if data['action'] == 'failed':
            logger.error(data)
        else:
            logger.info(data)

        q_DB.task_done()

def parseargs():
    '''
    Description: Function in charge of the CLI parameters
    Input:       No input
    Output:      Parsed arguments
    '''
    description = 'Network Monitor'
    prog = 'monitor.py'
    usage = 'sudo python3 monitor.py [-t Token]'
    epilog = 'Carlos Munoz (carlos.munoz.garrido@outlook.com)\n%(prog)s 1.0 (28/10/2018)'

    parser = argparse.ArgumentParser(epilog=epilog, usage=usage, prog=prog, description=description, formatter_class=argparse.RawTextHelpFormatter)

    mon_group = parser.add_argument_group("Monitor parameters")

    arg_help = "Bastion Token"
    mon_group.add_argument('-t', required=False, default = None, action='store', dest='token', help=arg_help, metavar="")

    parser.add_argument('--version', action='version', version='Carlos Munoz (carlos.munoz.garrido@outlook.com)\n%(prog)s 1.0 (09/04/2020)')

    return parser.parse_args()


def main():
    global signal
    global myWebSvr
    
    # Getting CLI parameters ********************************************
    option = parseargs()

    token     = option.token

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
    threads = []
    for i in range(NUM_WORKER_THREADS):
        t = threading.Thread(target=manage_new_founds)
        threads.append(t)
        t.setDaemon(True)
        t.start()
    # ********************************************************************
    
    # Starting active scanner ********************************************
    last_time = time.time()
    my_Subnet = Utils.get_LocalSubnet()
    
    if my_Subnet:
        logger.info('MONITOR - initiating active hosts discovery')
        hosts = active_Scan(my_Subnet)
        check_new_hosts(hosts)
    else:
        logger.error('MONITOR - error getting local sub-net, omitting active scan ')
    # ********************************************************************

    # Iniciamos monitorizacion pasiva ************************************
    t_sniff = threading.Thread(target=pasive_scan)
    t_sniff.setDaemon(True)
    t_sniff.start()
    # ********************************************************************
    
    # ********************************************************************
    # Continuous loop, to force an active scan every 300 seconds (default#
    # value, and allow passive scan to monitor for ever until Keyboard   #
    # interruption will be detected                                      #
    try:
        while True:
            time.sleep(1)
            current_time = time.time()
            if current_time - last_time > HEARTBEAT_VALUE:
                # By default every 300 seconds the active scan is launched                  
                last_time = time.time()
                if my_Subnet:
                    logger.info('MONITOR - initiating active hosts discovery')
                    hosts = active_Scan(my_Subnet)
                    check_new_hosts(hosts)
                else:
                    logger.error('MONITOR - error getting local sub-net, omitting active scan ')
                    my_Subnet = Utils.get_LocalSubnet()
                    
                
    except KeyboardInterrupt:
        logger.info('Keyboard interrupt received. Stopping threads')
        signal = True
        t_sniff.join()
        
        for i in range(NUM_WORKER_THREADS):
            q_DB.put(None)        
            
        for t in threads:
            t.join()
    # ********************************************************************
      
    
    
if __name__ == "__main__":
    main()
    
    
