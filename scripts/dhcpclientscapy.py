#! /usr/bin/env python
# vim:ts=4:sw=4:expandtab  2 
# -*- coding: utf-8 -*-

'''
Based on https://github.com/mortnerDHCPv4v6
'''

# TODO:
# * refactor
# * read conf from dhclient.conf
# * daemonize
# * requests in loop
# * send renew according to renew time
# * implement release
# * implement nak case
# FIXME:
# * build package with most common BOOTP/DCHCP options
 
__author__ = "duy <duy at rhizoma dot tk>"
__copyright__ = "GPL v3"

from scapy.all import *
import random
import ipaddr
from time import sleep
import subprocess
import argparse

# for debugging
#CLIENT_PORT= 8001
#SERVER_PORT= 8000
CLIENT_PORT= 68
SERVER_PORT= 67
BROADCAST_ADDR = '255.255.255.255'
META_ADDR = '0.0.0.0'
BROADCAST_MAC = 'ff:ff:ff:ff:ff:ff'

MAX_DHCP_LEASE = 1500
LEASE_TIME = 43200 # 7776000
# "subnet_mask", "router", "name_server", "domain"
PARAM_REQ_LIST = '\x01\x03\x06\x0fw\xfc'# \x1c3

INIT_STATE = 0
BOUND_STATE = 1
RENEW_STATE  = 2
REBIND_STATE = 3
REBOOT_STATE = 4
TIMEOUT_STATE = 5

RENEW_TIME_ON_LEASE = 1.0/2
REBIND_TIME_ON_LEASE = 7.0/8

class Limits:
    XID_MIN = 1
    XID_MAX = 900000000


def randomHostname(length=8, charset=None):
        charset = charset or string.ascii_uppercase + string.digits
        return ''.join(random.choice(charset) for x in range(length))


def genXid():
    return random.randint(Limits.XID_MIN, Limits.XID_MAX)



class DHCPv4Client(object):

    def __init__(self, iface,  server_port=None, client_port=None,  server_ip=None,  
                        server_mac=None, hostname=None):
        self.iface = iface
        
        self.state = INIT_STATE
        self.renew_time = 0
        self.rebind_time = 0

        self.server_port = server_port or SERVER_PORT
        self.client_port = client_port or CLIENT_PORT

        self.server_ip = server_ip or BROADCAST_ADDR
        self.server_mac = server_mac or BROADCAST_MAC

        self.client_ip = META_ADDR
        _, client_mac = get_if_raw_hwaddr(self.iface)
        self.client_mac = client_mac

        self.hostname = hostname or randomHostname()
        self.client_xid = genXid()
        
        # FIXME: when server xid is used?
        self.server_xid = None
        self.server_id = None
        self.response_server_ip = None
        self.response_server_mac = None

        self.client_ip_offered = None
        self.subnet_mask = None
        self.offered_ip = None
        self.lease_time = None
        self.router = None
        self.name_server = None
        self.domain = None
        self.options = []

        self.callbacks = {}
        self.history = []


    def __str__(self):
        return self.__repr__()

    def __repr__(self):
        return """DHCPv4 Client
        
        Interface: %sp
        Verbosity: %s
        
        Client Configuration:                |      Server
        -------------------------------------|------------------------------
        IP        =        %-20s      %-20s
        HWAddr    =        %-20s      %-20s
        
        Hostname  =        %-20s              
        MASK      =        %-20s
        
        xID       =        %-20s      %-20s
        
        
        
        DHCP Specific
        --------------------
        serverID  =        %-20s
        Options   =        %-20s
        
        
        Registered Callbacks
        --------------------
        %s

        History
        --------------------
        %s
        """ % (conf.iface, conf.verb,
               self.client_ip,
               self.server_ip,
               self.client_mac,
               self.server_mac,
               self.hostname,
               self.subnet_mask,
               self.client_xid,
               self.server_xid,
               self.server_id,
               repr(self.options),
               self.callbacks,
               self.history)

    def register_callback(self, hook, func):
        self.callbacks[hook] = func

    def exec_callback(self, hook, args):
        self.track_history("Hook:" + str(hook))
        if self.callbacks.has_key(hook):
            self.callbacks[hook]()

    def track_history(self, name=None):
        from inspect import stack
        name = name or stack()[1][3]
        self.history.append(name)


    def genDiscover(self):
        dhcp_discover = (
            Ether(src=str2mac(self.client_mac), dst=self.server_mac) /
            IP(src=self.client_ip, dst=self.server_ip) /
            UDP(sport=self.client_port, dport=self.server_port) /
            BOOTP(chaddr=[self.client_mac], xid=self.client_xid) /
            DHCP(options=[
                ("message-type", "discover"),
                ("param_req_list", PARAM_REQ_LIST), 
                ("max_dhcp_size", MAX_DHCP_LEASE),
                ("client_id", self.client_mac),
                ("lease_time", LEASE_TIME),  
                ("hostname", self.hostname),
                "end"
            ])
        )
        return dhcp_discover


    def genRequest(self):
        dhcp_req = (
            Ether(src=str2mac(self.client_mac), dst=self.server_mac) /
            IP(src=self.client_ip, dst=self.server_ip) /
            UDP(sport=self.client_port, dport=self.server_port) /
            BOOTP(chaddr=[self.client_mac], xid=self.client_xid) /
            DHCP(options=[
                ("message-type", "request"),
                ("param_req_list", PARAM_REQ_LIST),
                ("max_dhcp_size", MAX_DHCP_LEASE),
                ("client_id", self.client_mac),
                ("requested_addr", self.client_ip_offered),  # obtained from discover
                ("server_id", self.server_id),  # obtained from discover
                ("hostname", self.hostname),
                "end"
            ])
        )
        return dhcp_req



    def genRelease(self):
        dhcp_release = (
            Ether(src=str2mac(self.client_mac), dst=self.server_mac) /
            IP(src=self.client_ip, dst=self.server_ip) /
            UDP(sport=self.client_port, dport=self.server_port) /
            BOOTP(chaddr=[self.client_mac], xid=self.client_xid) /
            DHCP(options=[
                ("message-type", "release"), 
                ("server_id", self.server_id),  # obtained from discover
                ("client_id", self.client_mac),
                "end"
            ])
        )
        return dhcp_release


    def parseOffer(self, packet):
        print 'Parsing offer'
        print packet.show()
        self.response_server_ip =  packet[IP].src
        self.response_server_mac = packet[Ether].src
        self.server_id = packet[BOOTP].siaddr
        #FIXME: xid has to match the initial xid
        # packet[BOOTP].xid
        # FIXME: chaddr has to match client_mac
        # str2mac(packet[BOOTP].chaddr)
        # FIXME: check if yiaddr  match current client ip or requested ip
        self.client_ip_offered = packet[BOOTP].yiaddr
        
        for option in packet[DHCP].options:
            if type(option) == tuple:
                if option[0] == 'subnet_mask':
                    self.subnet_mask = option[1]
                if option[0] == 'router':
                    self.router = option[1]
                if option[0] == 'domain':
                    self.domain = option[1]
                if option[0] == 'name_server':
                    self.name_server = option[1]
                if option[0] == 'lease_time':
                    self.lease_time = option[1]

    def parseACK(self, packet):
        print "Parsing ACK"
        print packet.show()
        # FIXME: check these fields match current ones?
        #self.response_server_ip =  packet[IP].src
        #self.response_server_mac = packet[Ether].src
        #self.server_id = packet[BOOTP].siaddr
        #FIXME: xid has to match the initial xid
        # packet[BOOTP].xid
        # FIXME: chaddr has to match client_mac
        # str2mac(packet[BOOTP].chaddr)
        # FIXME: check if yiaddr  match current client ip or requested ip
        self.client_ip_offered = packet[BOOTP].yiaddr
        
        #FIXME: check these options match offered ones?
        for option in packet[DHCP].options:
            if type(option) == tuple:
                if option[0] == 'subnet_mask':
                    self.subnet_mask = option[1]
                if option[0] == 'router':
                    self.router = option[1]
                if option[0] == 'domain':
                    self.domain = option[1]
                if option[0] == 'name_server':
                    self.name_server = option[1]
                if option[0] == 'lease_time':
                    self.lease_time = option[1]

    def isOffer(self, packet):
        if DHCP in packet and DHCPTypes[packet[DHCP].options[0][1]] == 'offer':
            return True
        return False

    def isNAK(self, packet):
        if DHCP in packet and DHCPTypes[packet[DHCP].options[0][1]] == 'nak':
            return True
        return False

    def isACK(self, packet):
        if DHCP in packet and DHCPTypes[packet[DHCP].options[0][1]] == 'ack':
            return True
        return False

    def sendDiscover(self):
        packet = self.genDiscover()
        self.track_history()
        print packet.show()
        sendp(packet)
        print "Sent discover"

    def sendRequest(self):
        packet = self.genRequest()
        self.track_history()
        print packet.show()
        sendp(packet)
        print "Sent request"


    def setAddr(self):
        print "Setting address"
        #FIXME: subprocess.call to really set ip, route, nameserver
        set_ip = "ip addr add local %s netmask %s dev %s" % \
            (self.client_ip_offered,  self.subnet_mask, self.iface)
        set_route = "route add default gw %s" % self.router
        #FIXME: set nameserver with resolvconf if installed
        print set_ip
        print set_route
        #subprocess.call([set_ip])
        #subprocess.call([set_route])

    def handleResponse(self, packet):  
        print "Handling response"
        if self.isOffer(packet):
            print "Offer detected"
            self.parseOffer(packet)
            self.sendRequest()
        if self.isACK(packet):
            print "ACK detected"
            self.parseACK(packet)
            self.setAddr()
            self.state = BOUND_STATE
            self.renew_time = self.lease_time * RENEW_TIME_ON_LEASE
            self.rebind_time = self.lease_time * REBIND_TIME_ON_LEASE
            print "Sleeping for % secs." % self.renew_time
            sleep(self.renew_time)
            self.state = RENEW_STATE
            self.sendRequest()
            
        if self.isNAK(packet):
            print "NAK detected"
            # FIXME: implement

    def getResponse(self, timeout=3, tries=1):
        #FIXME: server_port is src and client_port is dst
        sniff(filter="udp and (port %s or %s)" % \
                    (self.server_port,  self.client_port),
                prn=self.handleResponse, store=0,  iface=conf.iface)

def main():
    # FIXME: add support for several ifaces
    parser = argparse.ArgumentParser()
    parser.add_argument('interface', nargs='?', 
        help='interface to configure with DHCP' )
    args = parser.parse_args()
    if not args.interface:
        args.interface = 'wlan0'
    conf.iface = args.interface
    conf.checkIPaddr = False
    conf.verb = False

    c = DHCPv4Client(args.interface)
    #FIXME: if interface has already and address, send request with that address 
    # instead of discover?
    c.sendDiscover()
    c.getResponse()
    print c

if __name__ == "__main__":
    main()
