from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.revent import *
from pox.lib.util import dpidToStr
from pox.lib.addresses import EthAddr
from collections import namedtuple
import os
''' New imports here ... '''
import csv
import argparse
from pox.lib.packet.ethernet import ethernet, ETHER_BROADCAST
from pox.lib.addresses import IPAddr
import pox.lib.packet as pkt
from pox.lib.packet.arp import arp
from pox.lib.packet.ipv4 import ipv4
from pox.lib.packet.icmp import icmp

log = core.getLogger()
priority = 50000

l2config = "l2firewall.config"
l3config = "l3firewall.config"


class Firewall (EventMixin):

	def __init__ (self,l2config,l3config):
		self.listenTo(core.openflow)
		#self.disbaled_MAC_pair = [] # Shore a tuple of MAC pair which will be installed into the flow table of each switch.

                # Anti-spoofing Port Security.
                # 
                # Set SpoofingTable as a dict() which uses the source MAC address as key, and an array of the IP address and source
                # switch port as value.
                #
                # For example:
                #
                #   SpoofingTable = {
                #      # src MAC address     src IP          dst IP          src OVS port
                #      "00:00:00:00:00:0a": ["192.168.2.10", "192.168.2.30", "1"],
                #      "00:00:00:00:00:0b": ["192.168.2.20", "192.168.2.10", "2"],
                #      "00:00:00:00:00:0c": ["192.168.2.30", "192.168.2.40", "3"]
                #   }
                #
                # In this way, it is possible to identify if a MAC address had already used an IP, and block it as required by the
                # Lab's algorithm.
                #
                # To implement the "Bonus Points" and also address MAC address spoofing, it is necessary to traverse the Dict
                # through the values until the source port is found again.  When we see that the same port ha originated different
                # MAC addresses, it means they have been spoofed (or the user has attached a cascading switch, which is practically
                # the same and a target for Port Security to block).
                # 
                # The same mechanism can be found to identify users that have spoofed _both_ IP addresses and MAC addresses, which
                # would be the most advanced mitigation possible for this lab.
                #
                # The dict "BlockedTable" is identical to SpoofingTable (except it doesn't stop a switch port) but represents
                # combinations of attackers that have already been blocked and the flow has been saved to CSV - this is to avoid
                # writing them multiple times in the l3firewall file.

                self.SpoofingTable = dict ()    # Corrispondence of MAC addresses with IPs and ports
                self.BlockedTable = dict ()     # Table of blocked attacks
#                self.fw_blocked_macs = list()   # Blocked MAC addresses
#                self.fw_blocked_ips  = list()   # Blocked IP addresses

		'''
		Read the CSV file
		'''
		if l2config == "":
			l2config="l2firewall.config"
			
		if l3config == "":
			l3config="l3firewall.config" 
		with open(l2config, 'rb') as rules:
			csvreader = csv.DictReader(rules) # Map into a dictionary
			for line in csvreader:
				# Read MAC address. Convert string to Ethernet address using the EthAddr() function.
                                if line['mac_0'] != 'any':
				    mac_0 = EthAddr(line['mac_0'])
                                else:
                                    mac_0 = None

                                if line['mac_1'] != 'any':
        				mac_1 = EthAddr(line['mac_1'])
                                else:
                                    mac_1 = None
				# Append to the array storing all MAC pair.
				self.disbaled_MAC_pair.append((mac_0,mac_1))

		with open(l3config) as csvfile:
			log.debug("Reading log file !")
			self.rules = csv.DictReader(csvfile)
			for row in self.rules:
				log.debug("Saving individual rule parameters in rule dict !")
				prio = row['priority']
				s_mac = row['src_mac']
				d_mac = row['dst_mac']
				s_ip = row['src_ip']
				d_ip = row['dst_ip']
				s_port = row['src_port']
				d_port = row['dst_port']
				nw_proto = row['nw_proto']
				print "src_ip, dst_ip, src_port, dst_port", s_ip,d_ip,s_port,d_port
                                # Add to firewall rules in memory
				log.debug("Keep firewall rules in memory")
                                if s_mac != "any" and d_mac == "any" and s_ip == "any" and d_ip != "any" and s_port == "any" and d_port == "any" and nw_proto == "any":
                                    self.SpoofingTable [s_mac] = [s_ip, d_ip, 'any']
                                if s_mac == "any" and d_mac == "any" and s_ip != "any" and d_ip != "any" and s_port == "any" and d_port == "any" and nw_proto == "any":
                                    self.SpoofingTable [s_mac] = [s_ip, d_ip, 'any']
                                # Install OVS flow
                                #self.installFlow(event, prio, s_mac, d_mac, s_ip, d_ip, s_port, d_port, nw_proto)

		log.debug("Enabling Firewall Module")

	def replyToARP(self, packet, match, event):
		r = arp()
		r.opcode = arp.REPLY
		r.hwdst = match.dl_src
		r.protosrc = match.nw_dst
		r.protodst = match.nw_src
		r.hwsrc = match.dl_dst
		e = ethernet(type=packet.ARP_TYPE, src = r.hwsrc, dst=r.hwdst)
		e.set_payload(r)
		msg = of.ofp_packet_out()
		msg.data = e.pack()
		msg.actions.append(of.ofp_action_output(port=of.OFPP_IN_PORT))
		msg.in_port = event.port
		event.connection.send(msg)

	def allowOther(self, event, action=None):
                log.debug ("Execute allowOther")
		msg = of.ofp_flow_mod()
		match = of.ofp_match()
		#action = of.ofp_action_output(port = of.OFPP_NORMAL)
		msg.actions.append(action)
		event.connection.send(msg)

	def installFlow(self, event, offset, srcmac, dstmac, srcip, dstip, sport, dport, nwproto):
                log.debug ("Execute installFlow")
		msg = of.ofp_flow_mod()
		match = of.ofp_match()
		if(srcip != None):
			match.nw_src = IPAddr(srcip)
		if(dstip != None):
			match.nw_dst = IPAddr(dstip)	
                if(nwproto):
                        match.nw_proto = int(nwproto)
		match.dl_src = srcmac
		match.dl_dst = dstmac
		match.tp_src = sport
		match.tp_dst = dport
		match.dl_type = pkt.ethernet.IP_TYPE
		msg.match = match
		msg.hard_timeout = 0
		msg.idle_timeout = 200
                #msg.actions.append(None)
                if priority + offset <= 65535:
                    msg.priority = priority + offset		
                else:
                    msg.priority = 65535

		event.connection.send(msg)

	def replyToIP(self, packet, match, event):
                log.debug ("Execute replyToIP")
		srcmac = str(match.dl_src)
		dstmac = str(match.dl_src)
		sport = str(match.tp_src)
		dport = str(match.tp_dst)
		nwproto = str(match.nw_proto)

                with open(l3config) as csvfile:
                    log.debug("Reading log file !")
                    self.rules = csv.DictReader(csvfile)
                    for row in self.rules:
                        prio = row['priority']
                        srcmac = row['src_mac']
                        dstmac = row['dst_mac']
                        s_ip = row['src_ip']
                        d_ip = row['dst_ip']
                        s_port = row['src_port']
                        d_port = row['dst_port']
                        nw_proto = row['nw_proto']
                        
                        log.debug("You are in original code block ...")
                        srcmac1 = EthAddr(srcmac) if srcmac != 'any' else None
                        dstmac1 = EthAddr(dstmac) if dstmac != 'any' else None
                        s_ip1 = s_ip if s_ip != 'any' else None
                        d_ip1 = d_ip if d_ip != 'any' else None
                        s_port1 = int(s_port) if s_port != 'any' else None
                        d_port1 = int(d_port) if d_port != 'any' else None
                        prio1 = int(prio) if prio != None else priority
                        if nw_proto == "tcp":
                            nw_proto1 = pkt.ipv4.TCP_PROTOCOL
                        elif nw_proto == "icmp":
                            nw_proto1 = pkt.ipv4.ICMP_PROTOCOL
                            s_port1 = None
                            d_port1 = None
                        elif nw_proto == "udp":
                            nw_proto1 = pkt.ipv4.UDP_PROTOCOL
                        else:
                            nw_proto1 = None
                            #log.debug("PROTOCOL field is mandatory, Choose between ICMP, TCP, UDP")
                        print (prio1, srcmac1, dstmac1, s_ip1, d_ip1, s_port1, d_port1, nw_proto1)
                        self.installFlow(event, prio1, srcmac1, dstmac1, s_ip1, d_ip1, s_port1, d_port1, nw_proto1)

                #self.allowOther(event)

	def _handle_ConnectionUp (self, event):
		''' Add your logic here ... '''

		'''
		Iterate through the disbaled_MAC_pair array, and for each
		pair we install a rule in each OpenFlow switch
		'''
		self.connection = event.connection

		#for (source, destination) in self.disbaled_MAC_pair:

                for spoofmac, spoofvalues in self.SpoofingTable.items():

                        srcmac = spoofmac
                        srcip = spoofvalues[0]
                        dstip = spoofvalues[1]
                        log.debug ('Loading blocked flows: srcmac=%s, srcip=%s, dstip=%s' %
                                (str(srcmac), str(srcip), str(dstip)))
			#print source,destination
			message = of.ofp_flow_mod()     # OpenFlow massage. Instructs a switch to install a flow
			match = of.ofp_match()          # Create a match
                        if srcmac == 'any':
                            match.dl_src = None         # Source MAC
                        else:
                            match.dl_src = srcmac       # Source MAC
                        if srcip == 'any':
                            match.nw_src = None         # Source IP address
                        else:
                            match.nw_src = IPAddr(srcip)    # Source IP address
                        if dstip == 'any':
                            match.nw_dst = None         # Destination IP address
                        else:
                            match.nw_dst = IPAddr(dstip)    # Destination IP address
			message.priority = 65535 # Set priority (between 0 and 65535)
                        match.dl_type = ethernet.IP_TYPE
			message.match = match			
                        #message.actions.append(None)
			event.connection.send(message) # Send instruction to the switch

		log.debug("Firewall rules installed on %s", dpidToStr(event.dpid))

        def addRuleToCSV(self, srcmac='any', srcip='any', dstip='any'):
            
            log.debug("Entered addRuleToCSV")

            # Check if the rule is not already saved
            # If not, add to firewall rules in memory and then in the CSV file

            to_add = True
            for spoofmac, spoofvalues in self.BlockedTable.items():
                if spoofmac == str(srcmac) and spoofvalues[0] == str(srcip) and spoofvalues[1] == str(dstip):
                    log.debug("No need to write log file - entry already present")
                    to_add = False
                    break

            if to_add: 
                self.BlockedTable [str(srcmac)] = [str(srcip), str(dstip)]
                # Open in append mode
                with open(l3config, 'a') as csvfile:
                    log.debug("Writing log file !")

                    csvwriter = csv.DictWriter(csvfile, fieldnames=[
                        'priority','src_mac','dst_mac','src_ip','dst_ip','src_port','dst_port','nw_proto',])
                    log.debug("Saving individual rule parameters in rule dict !")
                    csvwriter.writerow({
                        'priority': 32768,
                        'src_mac' : str(srcmac),
                        'dst_mac' : 'any',
                        'src_ip'  : str(srcip),
                        'dst_ip'  : str(dstip),
                        'src_port': 'any',
                        'dst_port': 'any',
                        'nw_proto': 'any',
                        })
                    log.debug("Saved: srcip=%s dstip=%s srcmac=%s" % (str(srcip), str(dstip), str(srcmac)))

        def verifyPortSecurity(self, packet, match=None, event=None):

            log.debug("Into verifyPortSecurity")

            srcmac = None
            srcip = None
            dstip = None

            if packet.type == packet.IP_TYPE:
                ip_packet = packet.payload
                if ip_packet.srcip == None or ip_packet.dstip == None:
                    log.debug("Packet meaningless for Port Security (likely IPv6)")
                    return True
                if packet.src not in self.SpoofingTable:        # MAC address is not in the spoofing table. Checking IP address
                    for spoofmac, spoofvalues in self.SpoofingTable.items():
                        # IP already present with another MAC address: MAC spoofing!
                        # This is the most "advanced" case (Bonus Point) for this Lab.
                        if str(spoofvalues[0]) == str(ip_packet.srcip):
                            log.debug("*** MAC spoofing attempt! IP %s already present for MAC %s and port %s, Requested: from %s on port %s ***" %
                                (str(ip_packet.srcip), str(spoofmac), str(spoofvalues[1]), str(packet.src), str(event.port)))
                            #self.addRuleToCSV (str(spoofmac), str(ip_packet.srcip))
                            # Block the source/destination IP address for any MAC, to protect the victim
                            srcmac = None
                            srcip = str(ip_packet.srcip)
                            dstip = str(ip_packet.dstip)
                            self.addRuleToCSV ('any', srcip, dstip)
                            #return False
                    # The flow is a new legitimate one. Adding it to the table and allowing the packet.
                    self.SpoofingTable [packet.src] = [ip_packet.srcip, ip_packet.dstip, event.port]
                    log.debug("Adding Port Security entry: %s, %s, %s, %s" %
                        (str(packet.src), str(ip_packet.srcip), str(ip_packet.dstip), str(event.port)))
                    return True
                else:                                           # MAC address is already in the spoofing table. Checking the cases.
                    # The identical entry is present in the table. This probably means, OVS has expired the flow and it is representing.
                    # In this case the flow is okay.
                    if self.SpoofingTable.get(packet.src) == [ip_packet.srcip, ip_packet.dstip, event.port]:
                        log.debug("Port Security entry already present: %s, %s, %s, %s" %
                            (str(packet.src), str(ip_packet.srcip), str(ip_packet.dstip), str(event.port)))
                        return True
                    else:
                        # The MAC address is present, but either the port or the source IP are different. Checking which case.
                        #
                        newip = self.SpoofingTable.get(packet.src)[0]
                        newport = self.SpoofingTable.get(packet.src)[1]
                        # First: flow has a different IP address for the same MAC.  This is the "basic" DDoS case for this lab.
                        # This is an IP Spoofing attack and the packet needs to be blocked.
                        if newip != ip_packet.srcip:
                            log.debug("*** IP spoofing attempt! MAC %s already present for: IP %s on port %s; Requested: %s on port %s ***" %
                                (str(packet.src), str(newip), str(newport), str(ip_packet.dstip), str(event.port)))
                            # Block the MAC address
                            #self.addRuleToCSV (str(packet.src), str(ip_packet.srcip), str(ip_packet.dstip))
                            srcmac = str(packet.src)
                            srcip = None
                            dstip = str(ip_packet.dstip)
                            self.addRuleToCSV (srcmac, 'any', dstip)
                            #return False
                        # Second: flow has been seen on a different port. This is likely a routing or spanning tree problem,
                        # more hardly an attack. Without better knowledge of the topology, we need to allow the flow for this lab.
                        if newport != event.port:
                            log.debug("*** Port has changed for the same MAC address: new port %s, MAC %s: it was IP %s on port %s], Requested: %s ***" %
                                (str(newport), str(packet.src), str(ip_packet.srcip), str(event.port), str(ip_packet.dstip)))
                            return True

                        log.debug("You should never get here. If you do, I did something wrong!")

                        # Future extension: count refused packet at the switch port level, and evaluate a threshold.
                        # Over the threshold, block the port altogether to save the rest of the environment
                        return True

            if packet.type == packet.ARP_TYPE:
                log.debug("ARP security - for future extension")
                return True

            srcmac = srcmac
            dstmac = None
            sport = None
            dport = None
            nwproto = str(match.nw_proto)

            log.debug("verifyPortSecurity - installFlow")
            self.installFlow(event, 32768, srcmac, None, srcip, dstip, None, None, nw_proto)

            return False


	def _handle_PacketIn(self, event):

		packet = event.parsed
		match = of.ofp_match.from_packet(packet)

		if(match.dl_type == packet.ARP_TYPE and match.nw_proto == arp.REQUEST):

		    self.replyToARP(packet, match, event)

		if(match.dl_type == packet.IP_TYPE):

                    # Verify Port Security before processing further
                    if self.verifyPortSecurity(packet, match, event):
                        log.debug("No Attack detected - flow to be allowed")
                    else:
                        log.debug("Attack detected - flow to be blocked")

		    #ip_packet = packet.payload
		    #print "Ip_packet.protocol = ", ip_packet.protocol
		    #if ip_packet.protocol == ip_packet.TCP_PROTOCOL:
		#	log.debug("TCP it is !")
   
		    self.replyToIP(packet, match, event)


def launch (l2config="l2firewall.config",l3config="l3firewall.config"):
	'''
	Starting the Firewall module
	'''
	parser = argparse.ArgumentParser()
	parser.add_argument('--l2config', action='store', dest='l2config',
					help='Layer 2 config file', default='l2firewall.config')
	parser.add_argument('--l3config', action='store', dest='l3config',
					help='Layer 3 config file', default='l3firewall.config')
	core.registerNew(Firewall,l2config,l3config)
