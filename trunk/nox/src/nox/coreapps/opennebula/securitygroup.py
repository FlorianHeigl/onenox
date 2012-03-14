import logging
import re

log = logging.getLogger('nox.coreapps.tutorial.opennebula')

from nox.lib.core import TP_DST, TP_SRC, NW_PROTO, NW_SRC, NW_DST, NW_SRC_N_WILD, NW_DST_N_WILD
from nox.lib.packet.packet_utils import ipstr_to_int
from nox.lib.packet.ipv4 import ipv4

class SecurityGroup():

    def __init__(self, n, i):
        self.__name  = n
        self.__id    = i
        self.__rules = []
        
    def name(self):
        return self.__name

    def id(self):
        return self.__id

    def rules(self):
        return self.__rules

    def addRule(self, r):
        self.__rules.append(r)

    def removeRule(self,r):
        for rule in self.__rules:
            if rule.isEqual(r):
                self.__rules.remove(rule)
                break

    def __str__(self):
        toString = "ID: %d Name: %s\n" %(self.__id, self.__name)
        for rule in self.__rules:
            toString += str(rule)
        return toString 

class Rule():

    def __init__(self, proto, fromPort, toPort, ipRange):
        self.__protocol = proto
        self.__fromPort = int(fromPort)
        self.__toPort   = int(toPort)
        self.__ipRange  = ipRange.lstrip().rstrip()

        self.__flows = []
        self.__createFlows()

    def __str__(self,):
        return "Rule: %s %d %d %s\n" % ( self.__protocol, self.__fromPort, self.__toPort, self.__ipRange )

    def isEqual(self, r):
        return (
            self.__protocol == r.__protocol and\
            self.__fromPort == r.__fromPort and\
            self.__toPort   == r.__toPort   and\
            self.__ipRange  == r.__ipRange
        )

    def protocol(self):
        return self.__protocol

    def fromPort(self):
        return self.__fromPort

    def toPort(self):
        return self.__toPort

    def ipRange(self):
        return self.__ipRange

    def getFlows(self):
        return self.__flows

    def __createFlowsFromIpRange(self, flows):
        # Ip is 0.0.0.0
        if self.__ipRange == "0.0.0.0":
            log.error("Rule from 0.0.0.0")
            self.__flows = flows
            return

        # Ip addr range 192.168.2.1-196.168.2.5
        m = re.match('((\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3}))([ ]*\-[ ]*)((\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3}))$', self.__ipRange)
        if m != None:
            log.error("IP Range Rule")
            startIp = m.groups()[1:5]
            endIp   = m.groups()[7:11]
            for s4 in range(int(startIp[3]), int(endIp[3])+1):
                for flow in flows:
                    f = flow.copy()
                    f[NW_SRC] = ".".join([startIp[0],startIp[1],startIp[2],str(s4)])
                    log.error(f[NW_SRC])
                    self.__flows.append(f)
                
    
        # Ip addr block using full NetMask 192.168.2.1/255.255.255.0 
        m = re.match('((\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3}))(/)((\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3}))$', self.__ipRange)
        if m != None:
            log.error("IP Netmask rule")
            ip = m.groups()[0]
            netmask = int_to_bits(ipstr_to_int(m.groups()[6]))
            for flow in flows:
                f = flow.copy()
                f[NW_SRC] = ip 
                f[NW_SRC_N_WILD] = 32 - netmask 
                self.__flows.append(f)

            return

        # Ip addr block using CIDR 192.168.2.1/24
        m = re.match('(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/(\d{1,2})$', self.__ipRange)
        if m != None:
            log.error("IP CIDR Block rule")
            ip = m.group(1)
            cidr = m.group(2)
            for flow in flows:
                flow[NW_SRC] = ip
                flow[NW_SRC_N_WILD] = 32 - int(cidr)
                self.__flows.append(flow)

            return

        # Single IP address
        if (re.match('\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', self.__ipRange) != None):
            for flow in flows:
                flow[NW_SRC] = self.__ipRange
                self.__flows.append(flow)

            return

    def __createFlows(self):
        if self.__protocol == "icmp":
            self.__noxproto = ipv4.ICMP_PROTOCOL
            flows = self.__createIcmpFlows()
        else:
            if self.__protocol == "tcp":
                self.__noxproto = ipv4.TCP_PROTOCOL
            else:
                self.__noxproto = ipv4.UDP_PROTOCOL
            flows = self.__createL4Flows()
        
        self.__createFlowsFromIpRange(flows)
            
    def __createL4Flows(self):
        flows = []
        for port in range(self.__fromPort, self.__toPort+1):
            flow = {}
            flow[TP_DST] = port
            flow[NW_PROTO] = self.__noxproto 
            flows.append(flow)

        return flows

    def __createIcmpFlows(self):
        flows = []
        flow = {}
        flow[TP_DST] = self.__toPort
        flow[TP_SRC] = self.__fromPort
        flow[NW_PROTO] = self.__noxproto 
        flows.append(flow)

        return flows


# Returns number of bits set to 1 in an integer 
# Based on the Hamming Weight Algorithm that was translated 
# into python on stackoverflow.com/questions/4912523/python-network-cidr-calculations
def int_to_bits(num):
    num -= (num >> 1) & 0x55555555
    num = ((num >> 2) & 0x33333333) + (num & 0x33333333)
    num = ((num >> 4) + num) & 0x0f0f0f0f
    num += num >> 8
    num += num >> 16
    return num & 0x0000003f
