#/usr/bin/env python
#-*-coding: utf-8 -*-

"""
Based on https://github.com/Hacklabmed/dhcp-server-scapy
"""
#FIXME:  reuse constants and class from dhcpclient

__author__ = "duy <duy at rhizoma dot tk>"
__copyright__ = "GPL v3"

from scapy.all import *
from netaddr import IPNetwork
import sys
import threading
import argparse

ip_pool=[]
iterator = iter(ip_pool)

# for debugging
#CLIENT_PORT= 8001
#SERVER_PORT= 8000
SERVER_PORT = 67
CLIENT_PORT = 68

#FIXME: move to config file
server_ip="192.168.0.1"
server_mac="00:01:02:03:04:05"
subnet_mask="255.255.255.0"
router="192.168.0.1"

def getResponse():
    print "Waiting for response..."
    sniff(filter= "udp and (port %s or %s)" % \
                    (SERVER_PORT,  CLIENT_PORT),
            prn=genThreads, iface=conf.iface)

def genThreads(packet): 
    print "Creating threads"
    thread = threading.Thread(target=handleResponse, args=(packet,)) 
    thread.daemon = True 
    thread.start()

def handleResponse(packet):
    dhcp = False
    print 'Received packet'
    if packet.getlayer('BOOTP'):
        dhcp = True
    else: 
        if packet.getlayer('Raw'):
            packet[Raw] = BOOTP(packet[Raw].load)
            dhcp = True
    if dhcp:
        print packet.show()
        # discover
        if packet[DHCP].options[0][1]== 1:
            print "Received discover"
            print 'Cient MAC:', packet[Ether].src

            client_ip = str(getNextIP()) 
            print "Client ip: ",  client_ip
            if client_ip == "end": 
                print "No more addresses."
                return 

            #  Create DHCP OFFER
            dhcp_offer = (
                Ether(src=server_mac,dst=packet[Ether].src)/
                IP(src=server_ip,dst=client_ip)/
                UDP(sport=SERVER_PORT,dport=CLIENT_PORT)/
                BOOTP(op=2,yiaddr=client_ip,siaddr=server_ip,giaddr='0.0.0.0',
                    xid=packet[BOOTP].xid)/
                DHCP(options=[
                    ('message-type','offer'),
                    ('subnet_mask', subnet_mask),
                    ('server_id',server_ip),
                    ('lease_time',1800),
                    ('domain','localdomain'),
                    ('name_server',server_ip),
                    'end'
                ])
            )
            sendp(dhcp_offer)
            print 'Sent offer: ',dhcp_offer.summary()

        #request
        if packet[DHCP].options[0][1]== 3:
            print 'Received request'
            print 'Client MAC:', packet[Ether].src

            client_ip=packet[DHCP].options[2][1]

            packet_ACK= (
                Ether(src=server_mac,dst=packet[Ether].src)/
                IP(src=server_ip,dst=client_ip)/
                UDP(sport=67,dport=68)/
                BOOTP(op=2,yiaddr=client_ip,siaddr=server_ip,giaddr='0.0.0.0',
                    xid=packet[BOOTP].xid)/
                DHCP(options=[
                    ('message-type','ack'),
                    ('subnet_mask','255.255.255.0'),
                    ('server_id',server_ip),
                    ('lease_time',1800),
                    ('domain','localdomain'),
                    ('name_server',server_ip),
                    'end'
                ])
            )
            sendp(packet_ACK)
            print 'Sent ACK: ',packet_ACK.summary()


def setIPPool(ip_range): 
    #FIXME: don't use global
    global ip_pool
    global iterator
    print "Setting ip pool"
    i = ip_range.find("-")
    try:    
        if i != -1: 
            ip_pool = list(iter_iprange(ip_range[0:i],ip_range[i+1:]))
        else: 
            #FIXME: calculate in a better way, 
            # [2,-1] to exclude network, router and broadcast ips 
            ip_pool = list(IPNetwork(ip_range))[2:-1]
    except (AddrFormatError, ValueError): 
        print "Error, ip range not valid"
        exit()        
    iterator = iter(ip_pool)
    
def getNextIP():
    print "Getting next ip"
    try:
        return iterator.next()
    except StopIteration:
        return "end"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('interface', nargs='?', 
        help='interface to listen DHCP requests' )
    parser.add_argument('iprange', nargs='?', 
        help='IP range in the form x.x.x.x/24 or x.x.x.x-y.y.y.y' )
    args = parser.parse_args()
    if not args.interface:
        args.interface = 'wlan0'
    if not args.iprange: 
        args.iprange = "192.168.0.1/24"
    conf.iface = args.interface
    conf.checkIPaddr = False
    conf.verb = False

    setIPPool(args.iprange) 
    getResponse()

if __name__ == "__main__":
    main()

