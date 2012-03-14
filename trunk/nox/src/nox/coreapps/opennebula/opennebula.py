# Tutorial Controller
# Starts as a hub, and your job is to turn this into a learning switch.

import logging

from nox.lib.core import *
import nox.lib.openflow as openflow
from nox.lib.packet.ethernet import ethernet, ETHER_ANY, ETHER_BROADCAST
from nox.lib.packet.icmp import icmp,echo,TYPE_ECHO_REQUEST
from nox.lib.packet.vlan import vlan
from nox.lib.packet.ipv4 import ipv4
from nox.lib.packet.arp import arp
from nox.lib.packet.packet_utils import mac_to_str, mac_to_int, ipstr_to_int, ip_to_str, octstr_to_array
from array import *

from SimpleXMLRPCServer import SimpleXMLRPCServer
from SimpleXMLRPCServer import SimpleXMLRPCRequestHandler
from subprocess import Popen,PIPE 
from nox.coreapps.opennebula.securitygroup import *
import threading

IDLE_TIMEOUT = 60
HARD_TIMEOUT = 60
SG_PRIORITY  = openflow.OFP_DEFAULT_PRIORITY+10
SG_DROP_PRIORITY  = openflow.OFP_DEFAULT_PRIORITY+5


log = logging.getLogger('nox.coreapps.tutorial.opennebula')

class RequestHandler(SimpleXMLRPCRequestHandler):
    rpc_paths = ('/RPC2',)

class Instance():
    def __init__(self, privateIp, privateMac, groupsHash=None, dpid=None, port=None):
        self.privateIp  = privateIp
        self.privateMac = privateMac
        self.groups     = {}

        self.dpid = dpid 
        self.port = port

        self.outgoingFlows = []
        self.incomingFlows = []

        if groupsHash != None:
            if type(groupsHash) is dict:
                self.groups = groupsHash

    def removeIncomingFlow(self, flow):
        try:
            for f in self.incomingFlows:
                match = True 
                for key in f:
                    if not key in flow:
                        break
                    if f[key] != flow[key]:
                        match = False
                        break
                if match:
                    log.error("Removing incoming flow %s" % (repr(f)))
                    self.incomingFlows.remove(f)
                    return

        except Exception as e: 
            log.error("removingIncomingFlow: "+str(e))
            return str(e)

class ElasticIp():
    def __init__(self, elasticIp, privateIp, privateMac, dpid=None, port=None, vlanId=None, gatewayIp=None):
        self.elasticIp = elasticIp
        self.privateIp = privateIp
        self.privateMac = privateMac
        self.vlanId = vlanId
        self.gatewayIp = gatewayIp
        self.dpid = dpid 
        self.port = port

        self.outgoingFlows = []
        self.incomingFlows = []

class SwitchDataStructure():

    def __init__(self, dpid):
        self.dpid = dpid
        # Maps MAC addrs to switch port numbers
        self.MacToPortMap = {} 
        # Maps IP addr to MAC addr
        self.IpToMacMap = {}
        # Maps MAC addr to IP addr
        self.MacToIpMap = {}

class opennebula(Component):

    def __init__(self, ctxt):
        Component.__init__(self, ctxt)
        
        self.__initDataStructures()

        self.xmlrpc_server = SimpleXMLRPCServer(("", 8000),
                            requestHandler=RequestHandler)
        self.xmlrpc_server.register_introspection_functions()
        self.xmlrpc_server.register_function(self.DumpGroupInstance)
        self.xmlrpc_server.register_function(self.AssociateAddress)
        self.xmlrpc_server.register_function(self.DisassociateAddress)
        self.xmlrpc_server.register_function(self.GetElasticIpMap)
        self.xmlrpc_server.register_function(self.GetElasticIpReverseMap)
        self.xmlrpc_server.register_function(self.GetSwitchesMap)
        self.xmlrpc_server.register_function(self.RunInstance)
        self.xmlrpc_server.register_function(self.TerminateInstance)
        self.xmlrpc_server.register_function(self.AuthorizeSecurityGroupIngress)
        self.xmlrpc_server.register_function(self.RevokeSecurityGroupIngress)
        self.xmlrpc_thread = threading.Thread(target=self.xmlrpc_server.serve_forever)
        self.xmlrpc_thread.start()

    def DumpGroupInstance(self, id):
        if id in self.groupsInstancesMap:
            return repr(self.groupsInstancesMap[id])
        else:
            return "None"

    def GetElasticIpMap(self):
        return self.ElasticIpMap
    def GetElasticIpReverseMap(self):
        return self.ElasticIpReverseMap
    def GetSwitchesMap(self):
        switches = []
        for dpid in self.SwitchesMap.keys():
            switches.append(mac_to_str(dpid))
        return switches

    def AuthorizeSecurityGroupIngress(self, sgid, protocol, fromPort, toPort, ipRange): 
        log.error("AuthorizeSecurityGroupIngress %s %s %s %s %s" % (sgid, protocol, fromPort, toPort, ipRange))

        if str(sgid) in self.groupsInstancesMap:

            instances = self.groupsInstancesMap[str(sgid)]
            for privateIp in instances:
                log.error("Updating instance %s" %(privateIp))
                instance = self.instances[privateIp]
                group = instance.groups[str(sgid)]
                group.addRule(Rule(protocol, fromPort, toPort, ipRange))
                flows = group.rules()[-1].getFlows()
                for flow in flows: 
                    actions = []

                    flow[core.DL_TYPE] = ethernet.IP_TYPE
                    flow[core.DL_DST]  = instance.privateMac
                    flow[core.NW_DST]  = instance.privateIp 

                    log.error("Installing flow "+repr(flow))
                    actions.append([openflow.OFPAT_OUTPUT, [0, int(instance.port)]])

                    self.install_datapath_flow( instance.dpid, flow, openflow.OFP_FLOW_PERMANENT, openflow.OFP_FLOW_PERMANENT, actions, None, SG_PRIORITY, None, None)

                    instance.incomingFlows.append(flow)

        return 'SUCCESS'

    def RevokeSecurityGroupIngress(self, sgid, protocol, fromPort, toPort, ipRange): 
        log.error("RevokeSecurityGroupIngress %s %s %s %s %s" % (sgid, protocol, fromPort, toPort, ipRange))

        if str(sgid) in self.groupsInstancesMap:
            try:
                instances = self.groupsInstancesMap[str(sgid)]
                for privateIp in instances:
                    log.error("Updating instance %s" %(privateIp))
                    instance = self.instances[privateIp]
                    group = instance.groups[str(sgid)]
                    rule = Rule(protocol, fromPort, toPort, ipRange)
                    group.removeRule(rule)
                    for flow in rule.getFlows(): 
                        flow[core.DL_TYPE] = ethernet.IP_TYPE
                        flow[core.DL_DST]  = instance.privateMac
                        flow[core.NW_DST]  = instance.privateIp 

                        log.error("Removing flow "+repr(flow))
                        self.delete_datapath_flow(instance.dpid, flow) 
                        instance.removeIncomingFlow(flow)

            except Exception as e: 
                log.error(e)
                return str(e)

        return 'SUCCESS'


    def TerminateInstance(self, privateIp):
        if not privateIp in self.instances:
            return 'SUCCESS'

        instance = self.instances[privateIp]

        try:
            for flow in instance.incomingFlows:
                log.error("Removing incoming flow for Instance %s" % (privateIp))
                self.delete_datapath_flow(instance.dpid, flow) 
        
            for flow in instance.outgoingFlows:
                log.error("Removing outgoing flow for Instance %s" % (privateIp))
                self.delete_datapath_flow(instance.dpid, flow) 

            del self.instances[privateIp]

        except Exception as e: 
            log.error(e)
            return str(e)

        return 'SUCCESS'

    def RunInstance(self, privateIp, privateMac, switchDpid, port, groupsHash):
        switchDpid = switchDpid.rstrip()
        log.error("RunInstance method (%s,%s)" %(privateIp, privateMac))
        log.error(repr(groupsHash))

        # Insert colons into MAC string 
        mac = [switchDpid[i:i+2] for i in range(0,len(switchDpid),2)]
        mac = ':'.join(mac)
        # Convert MAC string to int 
        dpid = mac_to_int(octstr_to_array(mac))

        log.error("OVS info (%s, %s)" %(mac, port))

        groupsDict = {}
        for groupHash in groupsHash:
            group = SecurityGroup(groupHash["name"], 
                                  groupHash["id"])
            for rule in groupHash["rules"]:
                log.error(repr(rule))
                group.addRule(Rule(rule[0], rule[1], rule[2], rule[3]))

            groupsDict[str(group.id())] = group
            self.__associateGroupInstance(group.id(), privateIp)

        instance = Instance(privateIp, privateMac, groupsDict)
        self.instances[privateIp] = instance 

        log.error("Instance is on switch "+mac_to_str(dpid))
        instance.dpid = dpid
        instance.port = port 

        result = self.installSecurityGroupFlows(instance, dpid)
        log.error(result)

        return result 
        
    def installSecurityGroupFlows(self, instance, dpid):
        if dpid in self.SwitchesMap: 
            try:
                self.installDefaultSecurityGroupFlows(instance)
                self.installIncomingSecurityGroupFlows(instance)
            except Exception as e: 
                log.error("Exception installing Security Flows: "+str(e))
                return str(e)

            return 'SUCCESS'
        else:
            return "FAIL: Flows not installed because switch "+str(mac_to_str(dpid))+" is not registered."

    def installDefaultSecurityGroupFlows(self, instance):
        log.error("Installing default security group flows")
        sw = self.SwitchesMap[instance.dpid]
        
        flow = {}
        actions = []

        flow[core.DL_TYPE] = ethernet.IP_TYPE
        flow[core.DL_DST]  = instance.privateMac 
        flow[core.NW_DST]  = instance.privateIp 

        self.install_datapath_flow( instance.dpid, flow, openflow.OFP_FLOW_PERMANENT, openflow.OFP_FLOW_PERMANENT, actions, None, SG_DROP_PRIORITY, None, None)

        instance.incomingFlows.append(flow)


    def installIncomingSecurityGroupFlows(self, instance):
        log.error("Installing Incoming security group flows")
        sw = self.SwitchesMap[instance.dpid]
        
        for gid in instance.groups:
            for rule in instance.groups[gid].rules():
                for flow in rule.getFlows():
                    actions = []

                    flow[core.DL_TYPE] = ethernet.IP_TYPE
                    flow[core.DL_DST]  = instance.privateMac
                    flow[core.NW_DST]  = instance.privateIp 

                    log.error("Installing rule "+repr(flow))
                    actions.append([openflow.OFPAT_OUTPUT, [0, int(instance.port)]])

                    self.install_datapath_flow( instance.dpid, flow, openflow.OFP_FLOW_PERMANENT, openflow.OFP_FLOW_PERMANENT, actions, None, SG_PRIORITY, None, None)

                    instance.incomingFlows.append(flow)


    def AssociateAddress(self, elasticIp, privateIp, privateMac, switchDpid, ovsPort, vlanId=None, gatewayIp=None):
        log.error("Associating E %s with P %s" % (elasticIp, privateIp))

        # Check if Elastic IP is already installed 
        if elasticIp in self.InstalledElasticIps:
            log.error("EIP is already installed...removing")
            self.DisassociateAddress(elasticIp)

        # Check if Private IP already has Elastic IP associated with it
        if privateIp in self.ElasticIpReverseMap:
            log.error("Private IP is already associated...removing")
            oldElasticIp = self.ElasticIpReverseMap[privateIp]
            self.DisassociateAddress(oldElasticIp)

        # Insert colons into MAC string 
        mac = [switchDpid[i:i+2] for i in range(0,len(switchDpid),2)]
        mac = ':'.join(mac)
        # Convert MAC string to int 
        dpid = mac_to_int(octstr_to_array(mac))

        eip = ElasticIp(elasticIp, privateIp, privateMac, dpid, ovsPort, vlanId, gatewayIp)

        # Attempt to install flows 
        result = self.installElasticIpFlows(eip, dpid)

        # Save address if flows were installed
        if result == 'SUCCESS':
            self.ElasticIpMap[elasticIp] = privateIp
            self.ElasticIpReverseMap[privateIp] = elasticIp
            self.InstalledElasticIps[elasticIp] = eip
          
        return result 

    def installElasticIpFlows(self, eip, dpid):
        if dpid in self.SwitchesMap: 
            try:
                self.installIncomingElasticIpFlows(eip)
                self.installOutgoingElasticIpFlows(eip)
            except Exception as e: 
                log.error(e)
                return str(e)

            return 'SUCCESS'
        else:
            return "FAIL: Flows not installed because switch "+str(mac_to_str(dpid))+" is not registered."

    def installOutgoingElasticIpFlows(self, eip):
        sw = self.SwitchesMap[eip.dpid]
        try:
            gatewayMac  = sw.IpToMacMap[eip.gatewayIp]
            gatewayPort = sw.MacToPortMap[gatewayMac]
        except KeyError:
            raise Exception("FAIL: Unable to install Outgoing flows. Unknown Gateway MAC or Port Number")

        log.debug("Outgoing Gateway MAC: %s" % (gatewayMac))
        log.debug("Outgoing Gateway Port: %s" % (gatewayPort))

        flow = {}
        actions = []

        flow[core.DL_TYPE] = ethernet.IP_TYPE
        flow[core.NW_SRC]  = eip.privateIp 
        flow[core.IN_PORT] = int(eip.port)

        actions.append([openflow.OFPAT_SET_NW_SRC, eip.elasticIp])
        actions.append([openflow.OFPAT_SET_DL_SRC, mac_to_str(eip.dpid)])
        actions.append([openflow.OFPAT_SET_DL_DST, gatewayMac])
        actions.append([openflow.OFPAT_OUTPUT, [0, gatewayPort]])

        self.install_datapath_flow( eip.dpid, flow, openflow.OFP_FLOW_PERMANENT, openflow.OFP_FLOW_PERMANENT, actions, None, SG_PRIORITY, None, None)
        eip.outgoingFlows.append(flow)

    def installIncomingElasticIpFlows(self, eip):
        sw = self.SwitchesMap[eip.dpid]
        try:
            gatewayMac  = sw.IpToMacMap[eip.gatewayIp]
            gatewayPort = sw.MacToPortMap[gatewayMac]
        except KeyError:
            raise Exception("FAIL: Unable to install Incoming flows. Unknown Gateway MAC or Port Number")

        flow = {}
        actions = []

        flow[core.DL_TYPE] = ethernet.IP_TYPE
        flow[core.NW_DST]  = eip.elasticIp 
        flow[core.IN_PORT] = gatewayPort

        actions.append([openflow.OFPAT_SET_NW_DST, eip.privateIp])
        actions.append([openflow.OFPAT_SET_DL_SRC, mac_to_str(eip.dpid)])
        actions.append([openflow.OFPAT_SET_DL_DST, eip.privateMac])
        actions.append([openflow.OFPAT_STRIP_VLAN])
        actions.append([openflow.OFPAT_OUTPUT, [0, int(eip.port)]])

        self.install_datapath_flow( eip.dpid, flow, openflow.OFP_FLOW_PERMANENT, openflow.OFP_FLOW_PERMANENT, actions, None, SG_PRIORITY, None, None)
        eip.incomingFlows.append(flow)

    def DisassociateAddress(self, elasticIp):
        log.error("Disassociating E %s" % (elasticIp))

        if elasticIp in self.InstalledElasticIps:
            eip = self.InstalledElasticIps[elasticIp]

            result = self.removeElasticIpFlows(elasticIp)

            if result == 'SUCCESS':
                del self.ElasticIpMap[elasticIp]
                del self.ElasticIpReverseMap[eip.privateIp]
                del self.InstalledElasticIps[elasticIp]
            
            return result 
        else:
            log.error("E %s was not installed" % (elasticIp))
            return 'SUCCESS'

    def removeElasticIpFlows(self, elasticIp):
        try:
            self.removeIncomingElasticIpFlows(elasticIp)
            self.removeOutgoingElasticIpFlows(elasticIp)
        except Exception as e: 
            log.error(e)
            return str(e)

        return 'SUCCESS'

    def removeIncomingElasticIpFlows(self, elasticIp):
        eip = self.InstalledElasticIps[elasticIp]
        for flow in eip.incomingFlows:
            log.error("Removing incoming flow for EIP %s" % (elasticIp))
            self.delete_datapath_flow(eip.dpid, flow) 
    
    def removeOutgoingElasticIpFlows(self, elasticIp):
        eip = self.InstalledElasticIps[elasticIp]
        for flow in eip.outgoingFlows:
            log.error("Removing outgoing flow for EIP %s" % (elasticIp))
            self.delete_datapath_flow(eip.dpid, flow) 

    def __associateGroupInstance(self, id, ip):
        log.error("Associating Instance %s with group %d" %(ip,id))
        if str(id) in self.groupsInstancesMap:
            self.groupsInstancesMap[str(id)].append(ip)
        else:
            self.groupsInstancesMap[str(id)] = [ip]


    def __initDataStructures(self):
        self.SwitchesMap = {}

        self.instances = { }
        self.groupsInstancesMap = { }
        self.ElasticIpMap = { }
        self.ElasticIpReverseMap = { }
        self.InstalledElasticIps = { }

    def learnAndForward(self, dpid, inport, packet, buf, bufid):
        # Convert src MAC addr to string
        mac_src = mac_to_str(packet.src)
        # Convert dest MAC addr to string
        mac_dst = mac_to_str(packet.dst)

        log.debug("mac_src is %s" % (mac_src))       

        # Get Switch data structure 
        sw = self.SwitchesMap[dpid]

        # Learn the port for the source MAC addr
        sw.MacToPortMap[mac_src] = inport

        iph = packet.find('ipv4')
        if iph != None:
            srcip = ip_to_str(iph.srcip)
            sw.IpToMacMap[srcip] = mac_src

        #if destination MAC of the packet is known:
        if mac_dst in sw.MacToPortMap:
            outport = sw.MacToPortMap[mac_dst]

            flow = extract_flow(packet)
            flow[core.IN_PORT] = inport
            actions = [[openflow.OFPAT_OUTPUT, [0, outport]]]
            
            # install flow rule on the switch 
            self.install_datapath_flow( dpid, flow, IDLE_TIMEOUT, HARD_TIMEOUT, actions, bufid, openflow.OFP_DEFAULT_PRIORITY, inport, buf)

            # Check if src ip is one of the instances with a security group
            if iph!=None:
                if srcip in self.instances:
                    log.error("INSTALLING RELATED INCOMING FLOW FOR INSTANCE %s" %(srcip))
                    # Need to install temp rule for reply packets 
                    replyFlow = flow.copy()
                    replyFlow[core.IN_PORT] = outport
                    replyFlow[core.DL_DST] = flow[core.DL_SRC]
                    replyFlow[core.DL_SRC] = flow[core.DL_DST]
                    replyFlow[core.NW_DST] = flow[core.NW_SRC]
                    replyFlow[core.NW_SRC] = flow[core.NW_DST]
                    replyFlow[core.TP_DST] = flow[core.TP_SRC]
                    replyFlow[core.TP_SRC] = flow[core.TP_DST]
                    actions = [[openflow.OFPAT_OUTPUT, [0, inport]]]
                    log.error("%s" %(repr(replyFlow)))                    

                    # install flow rule on the switch 
                    self.install_datapath_flow( dpid, replyFlow, IDLE_TIMEOUT, HARD_TIMEOUT, actions, None, SG_PRIORITY, None, None)

        else:
            # flood packet out everything but the input port
            self.send_openflow(dpid, bufid, buf, openflow.OFPP_FLOOD, inport)

    def sendArpReply(self, dpid, inport, packet):
        arph = packet.find('arp')
        targetIp = ip_to_str(arph.protodst)

        log.error("Replying to ARP Request on port "+str(inport))
        # Create ARP Reply packet 
        replyh = arp()
        # Use the Switch's ID as the MAC address
        replyh.hwsrc = octstr_to_array(mac_to_str(dpid))
        replyh.hwdst = arph.hwsrc
        replyh.hwlen = arph.hwlen
        replyh.opcode = arp.REPLY
        replyh.protolen = arph.protolen
        replyh.protosrc = arph.protodst
        replyh.protodst = arph.protosrc

        replyPkt = ethernet()

        old_vlanh = packet.find('vlan')
        if old_vlanh != None:
            log.debug("ARP Packet is VLAN Tagged with id "+str(old_vlanh.id))
            vlanh = vlan()
            vlanh.id = old_vlanh.id
            vlanh.set_payload(replyh)
            vlanh.eth_type = ethernet.ARP_TYPE
  
        # Create Ethernet packet
        replyPkt.src = replyh.hwsrc
        replyPkt.dst = packet.src

        if old_vlanh != None:
            replyPkt.type = ethernet.VLAN_TYPE
            replyPkt.set_payload(vlanh)
        else:
            replyPkt.type = ethernet.ARP_TYPE
            replyPkt.set_payload(replyh) 

        log.debug("ETH pkt %s" % str(replyPkt))

        actions = [[openflow.OFPAT_OUTPUT, [0, inport]]]

        # Send ARP reply packet out on port it was recvd on  
        #self.send_openflow_packet(dpid, replyPkt.tostring(), actions, inport) 
        self.send_openflow_packet(dpid, replyPkt.tostring(), inport, openflow.OFPP_LOCAL) 

        return CONTINUE


    def packet_in_callback(self, dpid, inport, reason, len, bufid, packet):
        """Packet-in handler""" 
        if not packet.parsed:
            log.debug('Ignoring incomplete packet')
        else:
            arph = packet.find('arp')
            if arph != None:
                log.debug("FOUND ARP PACKET")
                log.debug("ARP SRC: %s" % (ip_to_str(arph.protosrc)))
                log.debug("ARP DST: %s" % (ip_to_str(arph.protodst)))

                # ARP Packet
                if arph.opcode == arp.REQUEST:
                    # ARP Request 
                    # Get target IP address
                    targetIp = ip_to_str(arph.protodst)
                
                    log.debug("Found ARP Request for IP "+targetIp)
                    # Check if target IP is an Elastic IP 
                    if targetIp in self.ElasticIpMap:
                        log.error("Replying to ARP Request for IP "+targetIp)
                        return self.sendArpReply(dpid, inport, packet)
                elif arph.opcode == arp.REPLY:
                    targetIp = ip_to_str(arph.protosrc)
                    log.debug("FOUND ARP Reply from IP "+targetIp)
#
            # If packet is not an ARP request for an Elastic IP, then send it 
            # to the learning switch
            self.learnAndForward(dpid, inport, packet, packet.arr, bufid)    

        return CONTINUE

    def datapath_join_callback(self, dpid, stats):
        log.error("Registering switch %s" % (mac_to_str(dpid)))
        self.SwitchesMap[dpid] = SwitchDataStructure(dpid)

    def datapath_leave_callback(self, dpid):
        log.error("Switch %s has left" %(mac_to_str(dpid)))
        if dpid in self.SwitchesMap:
            del self.SwitchesMap[dpid]


    def install(self):
        self.register_for_packet_in(self.packet_in_callback)
        self.register_for_datapath_join(self.datapath_join_callback)
        self.register_for_datapath_leave(self.datapath_leave_callback)
    
    def getInterface(self):
        return str(opennebula)

def getFactory():
    class Factory:
        def instance(self, ctxt):
            return opennebula(ctxt)

    return Factory()
