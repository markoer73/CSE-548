#!/bin/bash

#################################################################################
#            									#
# rc.firewall - Initial SIMPLE IP Firewall script for Linux and iptables        #
#   										#
# 02/17/2020  Created by Dijiang Huang ASU SNAC Lab    		    		#
# updated 05/12/2021								#
# updated 05/30/2021 - Marco Ermini		  				#
#################################################################################
#                                                                               #
#                                                                               #
# Configuration options, these will speed you up getting this script to         #
# work with your own setup.                                                     #
#                                                                               #
# your LAN's IP range and localhost IP. /24 means to only use the first 24      #
# bits of the 32 bit IP address. the same as netmask 255.255.255.0              #
#                                                                               #
#                                                                               # 
#################################################################################
#
# 1. Configuration options.
# NOTE that you need to change the configuration based on your own network setup.
# The defined alias and variables allow you to manage and update the entire 
# configurations easily, and more readable :-)
#
# Lab Network Topology
#
# ---------              ----------------               
# |Client |__Client_NET__|Gateway/Server |
# ---------              ----------------              
#                            |
#                            |Internet           
#                            |              ________ 
#                        ----------        /        \
#                        |Host PC |________|Internet|
#                        ----------        \________/ 
#                        
#

# Used for debug
set -x

# Allow web access to the Client (for Ubuntu updates)
export Client_Allowed_Web="Y"

# Allow web access to the Gateway (for Ubuntu updates)
export GW_Allowed_Web="Y"

####
# 1.1. Internet ip address
# 
#
Internet_IP="10.0.1.1"
Internet_IP_RANGE="10.0.1.0/24"
Internet_BCAST_ADRESS="10.0.1.255"
Internet_IFACE="enp0s8"

####
# 1.2 Client network configuration.
#
#

#
# IP addresses of the client-side network
#
Client_NET_IP="10.0.2.1"
Client_NET_IP_RANGE="10.0.2.0/24"
Client_NET_BCAST_ADRESS="10.0.2.255"
Client_NET_IFACE="enp0s3"


#
# IP aliases for the server (server's IP address)
#
LO_IFACE="lo"
LO_IP="127.0.0.1"
WEB_IP_ADDRESS="127.0.0.1"
#IP aliases for NATed services (this is the GW's ip on client network)
NAT_WEB_IP_ADDRESS="10.0.2.1"

#
# DNS Addresses
#
DNS1="208.67.222.222"
DNS2="208.67.220.220"

####
# 1.4 IPTables Configuration.
#
IPTABLES="/sbin/iptables"


#######################################################
#                                                     #
# 2. Module loading.                                  #
#                                                     #
#######################################################
#
# Needed to initially load modules
#
/sbin/depmod -a	 

#
# flush iptables
#
$IPTABLES -F 
$IPTABLES -X 
$IPTABLES -F -t nat

#####
# 2.1 Required modules
#

/sbin/modprobe ip_tables
/sbin/modprobe ip_conntrack
/sbin/modprobe iptable_filter
/sbin/modprobe iptable_mangle
/sbin/modprobe iptable_nat
/sbin/modprobe ipt_LOG
/sbin/modprobe ipt_limit
/sbin/modprobe ipt_state

#####
# 2.2 Non-frequently used modules
#

#/sbin/modprobe ipt_owner
#/sbin/modprobe ipt_REJECT
#/sbin/modprobe ipt_MASQUERADE
#/sbin/modprobe ip_conntrack_ftp
#/sbin/modprobe ip_conntrack_irc
#/sbin/modprobe ip_nat_ftp

###########################################################################
#
# 3. /proc set up.
#

#
# 3.1 Required proc configuration
#

#
# Enable ip_forward, this is critical since it is turned off as defaul in 
# Linux.
#
echo "1" > /proc/sys/net/ipv4/ip_forward

#
# 3.2 Non-Required proc configuration
#

#
# Dynamic IP users:
#
#echo "1" > /proc/sys/net/ipv4/ip_dynaddr

###########################################################################
#
# 4. rules set up.
#

# The kernel starts with three lists of rules; these lists are called firewall
# chains or just chains. The three chains are called INPUT, OUTPUT and FORWARD.
#
# The chains are arranged like so:
#
#                     _____
#                    /     \
#  -->[Routing ]--->|FORWARD|------->
#     [Decision]     \_____/        ^
#          |                        |
#          v                       ____
#         ___                     /    \
#        /   \                   |OUTPUT|
#       |INPUT|                   \____/
#        \___/                      ^
#          |                        |
#           ----> Local Process ----
#
# 1. When a packet comes in (say, through the Ethernet card) the kernel first 
#    looks at the destination of the packet: this is called `routing'.
# 2. If it's destined for this box, the packet passes downwards in the diagram, 
#    to the INPUT chain. If it passes this, any processes waiting for that 
#    packet will receive it. 
# 3. Otherwise, if the kernel does not have forwarding enabled, or it doesn't 
#    know how to forward the packet, the packet is dropped. If forwarding is 
#    enabled, and the packet is destined for another network interface (if you 
#    have another one), then the packet goes rightwards on our diagram to the 
#    FORWARD chain. If it is ACCEPTed, it will be sent out. 
# 4. Finally, a program running on the box can send network packets. These 
#    packets pass through the OUTPUT chain immediately: if it says ACCEPT, then 
#    the packet continues out to whatever interface it is destined for. 
#


#####
# 4.1 Filter table
#

#
# 4.1.1 Set policies
#

#
# Set default policies for the INPUT, FORWARD and OUTPUT chains
#

# Whitelist (Whitelist is preferred)
$IPTABLES -P INPUT DROP
$IPTABLES -P OUTPUT DROP
$IPTABLES -P FORWARD DROP

# Blacklist
#$IPTABLES -P INPUT ACCEPT
#$IPTABLES -P OUTPUT ACCEPT
#$IPTABLES -P FORWARD ACCEPT

#
# 4.1.2 Create user-specified chains
#

#
# Example of creating a chain for bad tcp packets
#

#$IPTABLES -N bad_tcp_packets

#
# Create separate chains for allowed (whitelist), ICMP, TCP and UDP to traverse
#

#$IPTABLES -N allowed
#$IPTABLES -N tcp_packets
#$IPTABLES -N udp_packets
#$IPTABLES -N icmp_packets

#
# In the following 4.1.x, you can provide individual user-specified rules


#
# 4.1.3 Example of create content in user-specified chains (bad_tcp_packets)
#

#
# bad_tcp_packets chain
#

#$IPTABLES -A bad_tcp_packets -p tcp --tcp-flags SYN,ACK SYN,ACK -m state --state NEW -j REJECT --reject-with tcp-reset 
#$IPTABLES -A bad_tcp_packets -p tcp ! --syn -m state --state NEW -j LOG --log-prefix "New not syn:"
#$IPTABLES -A bad_tcp_packets -p tcp ! --syn -m state --state NEW -j DROP

#
# 4.1.4 Example of allowed chain (allow packets for initial TCP or already established TCP sessions)
#

#$IPTABLES -A allowed -p TCP --syn -j ACCEPT
#$IPTABLES -A allowed -p TCP -m state --state ESTABLISHED,RELATED -j ACCEPT
#$IPTABLES -A allowed -p TCP -j DROP


#####
# 4.2 FORWARD chain
#

#
# Provide your forwarding rules below
#

# example of checking bad tcp packets
#$IPTABLES -A FORWARD -p tcp -j bad_tcp_packets

# Allow http traffic from client network to server network
#$IPTABLES -A FORWARD -i $Client_NET_IFACE -o $Internet_IFACE -j ACCEPT

# Allow internet traffic to HTTP/HTTPS for the client - used for Ubuntu updates.
# 
if [ "$Client_Allowed_Web" == "Y" ]; then
	$IPTABLES -A FORWARD -p TCP  -i $Client_NET_IFACE -o $Internet_IFACE ! -d $Client_NET_IP --dport 80  -j ACCEPT
	$IPTABLES -A FORWARD -p TCP  -i $Client_NET_IFACE -o $Internet_IFACE --dport 443 -j ACCEPT
fi
# Allows ping to some DNS servers
$IPTABLES -A FORWARD -p ICMP -i $Client_NET_IFACE -o $Internet_IFACE -d 8.8.8.8 -j ACCEPT
$IPTABLES -A FORWARD -p ICMP -i $Client_NET_IFACE -o $Internet_IFACE -d $DNS1 -j ACCEPT
$IPTABLES -A FORWARD -p ICMP -i $Client_NET_IFACE -o $Internet_IFACE -d $DNS2 -j ACCEPT
# Allows DNS resolution
$IPTABLES -A FORWARD -p UDP  -i $Client_NET_IFACE -o $Internet_IFACE --dport 53 -d $DNS1 -j ACCEPT
$IPTABLES -A FORWARD -p UDP  -i $Client_NET_IFACE -o $Internet_IFACE --dport 53 -d $DNS2 -j ACCEPT
$IPTABLES -A FORWARD -p UDP  -i $Client_NET_IFACE -o $Internet_IFACE --sport 53 -s $DNS1 -j ACCEPT
$IPTABLES -A FORWARD -p UDP  -i $Client_NET_IFACE -o $Internet_IFACE --sport 53 -s $DNS2 -j ACCEPT
# Allows return packets from established connections
$IPTABLES -A FORWARD -o $Client_NET_IFACE -i $Internet_IFACE -m state --state RELATED,ESTABLISHED -j ACCEPT
# Logging
$IPTABLES -A FORWARD -j LOG --log-prefix SKIPPED-FORWARD-

# example of using allowed
#$IPTABLES -A FORWARD -p tcp -j allowed


#####
# 4.3 INPUT chain
#

#
# Provide your input rules below to allow web traffic from client
#

# Allows loopback traffic resolution
$IPTABLES -A INPUT -i lo -j ACCEPT
$IPTABLES -A INPUT -i lo -s 127.0.0.0/8 -j ACCEPT
$IPTABLES -A INPUT ! -i lo -s 127.0.0.0/8 -j REJECT
# Allows SYN and return packets from established connections
$IPTABLES -A INPUT -p TCP --syn -j ACCEPT
$IPTABLES -A INPUT -p TCP -m state --state ESTABLISHED,RELATED -j ACCEPT
# Allows loopback and client host to connect to the local web server on the Gateway
$IPTABLES -A INPUT -p TCP  --dport 80  -i $LO_IFACE         -d $WEB_IP_ADDRESS -j ACCEPT
$IPTABLES -A INPUT -p TCP  --dport 80  -i $Client_NET_IFACE -d $Client_NET_IP -j ACCEPT

# Allow traffic to HTTP/HTTPS for the Gateway - used for Ubuntu updates.
# 
if [ "$GW_Allowed_Web" == "Y" ]; then
	$IPTABLES -A INPUT -p TCP  -i $Internet_IFACE --sport 80  -j ACCEPT
	$IPTABLES -A INPUT -p TCP  -i $Internet_IFACE --sport 443 -j ACCEPT
fi
# Allows ping to some DNS servers
$IPTABLES -A INPUT -p ICMP -i $Internet_IFACE -s 8.8.8.8 -j ACCEPT
$IPTABLES -A INPUT -p ICMP -i $Internet_IFACE -s $DNS1 -j ACCEPT
$IPTABLES -A INPUT -p ICMP -i $Internet_IFACE -s $DNS2 -j ACCEPT
# Generally allows ping to the Gateway from the client, and from the gateway towards the internet
$IPTABLES -A INPUT -p ICMP --icmp-type echo-request -i $Client_NET_IFACE -d $Client_NET_IP -j ACCEPT
$IPTABLES -A INPUT -p ICMP --icmp-type echo-request -i $LO_IFACE         -d $WEB_IP_ADDRESS -j ACCEPT
# Allows loopback ping
$IPTABLES -A INPUT -p ICMP --icmp-type echo-request -i $LO_IFACE         -d $LO_IP -j ACCEPT
$IPTABLES -A INPUT -p ICMP --icmp-type echo-reply   -i $LO_IFACE         -d $LO_IP -j ACCEPT
# Allows DNS traffic
$IPTABLES -A INPUT -p UDP  -i $Internet_IFACE --sport 53 -s $DNS1 -j ACCEPT
$IPTABLES -A INPUT -p UDP  -i $Internet_IFACE --sport 53 -s $DNS2 -j ACCEPT
$IPTABLES -A INPUT -p UDP  --dport 53 -d $DNS1 -j ACCEPT
$IPTABLES -A INPUT -p UDP  --dport 53 -d $DNS2 -j ACCEPT
# Logging
$IPTABLES -A INPUT -j LOG --log-prefix DROPPED-INGRESS-

#####
# 4.3 OUTPUT chain
#

#
# Provide your output rules below to allow web traffic (port 80) go back to client
#
# Fixes loopback on output chain
$IPTABLES -A OUTPUT -o $LO_IFACE -j ACCEPT
$IPTABLES -A OUTPUT -o $LO_IFACE -s 127.0.0.0/8 -j ACCEPT
# Allows SYN and return packets from established connections
$IPTABLES -A OUTPUT -p TCP  -m state --state ESTABLISHED,RELATED    -j ACCEPT
# Allows DNS traffic
$IPTABLES -A OUTPUT -p UDP  --sport 53 -d 127.0.0.53        		-j ACCEPT
$IPTABLES -A OUTPUT -p UDP  --sport 53 -d $DNS1    					-j ACCEPT
$IPTABLES -A OUTPUT -p UDP  --sport 53 -d $DNS2    					-j ACCEPT
$IPTABLES -A OUTPUT -p UDP  --dport 53 -d $DNS1    					-j ACCEPT
$IPTABLES -A OUTPUT -p UDP  --dport 53 -d $DNS2    					-j ACCEPT
# Allows client and loopback to reach web server on the gateway
$IPTABLES -A OUTPUT -p TCP  --sport 80 -o $Client_NET_IFACE -j ACCEPT
$IPTABLES -A OUTPUT -p TCP  --sport 80 -o $LO_IFACE         -j ACCEPT
# Allows ping, both outgoing and incoming, on the gateway
$IPTABLES -A OUTPUT -p ICMP --icmp-type echo-reply -j ACCEPT
$IPTABLES -A OUTPUT -p ICMP --icmp-type echo-request -j ACCEPT
# Allow traffic to HTTP/HTTPS for the Gateway - used for Ubuntu updates.
# 
if [ "$GW_Allowed_Web" == "Y" ]; then
	$IPTABLES -A OUTPUT -p TCP  --dport 80  -o $Internet_IFACE  -j ACCEPT
	$IPTABLES -A OUTPUT -p TCP  --dport 443 -o $Internet_IFACE  -j ACCEPT
fi
# Logging
$IPTABLES -A OUTPUT -j LOG --log-prefix DROPPED-EGRESS-

# example Allowed ping message back to client 

#$IPTABLES -A OUTPUT -p icmp -j ACCEPT

#####################################################################
#                                                                   #
# 5. NAT setup                                                      #
#                                                                   #
#####################################################################

#####
# 5.1  PREROUTING chain. (No used in this lab)
#
#
# Provide your NAT PREROUTING rules (packets come into your private domain)
#

#
# Example of enable http to internal web server behind the firewall (port forwarding)
#

# web 
# not used in this lab
#$IPTABLES -t nat -A PREROUTING -p tcp -d $NAT_WEB_IP_ADDRESS --dport 80 -j DNAT --to $WEB_IP_ADDRESS


#####
# 5.2 POSTROUTING chain.
#
#
# Provide your NAT PREROUTING rules (packets go to the internet domain)
# Add your own rule below to only allow ping from client to 8.8.8.8 on internet

# Example: Allow client node to access to all Internet using masquerade

#$IPTABLES -t nat -A POSTROUTING -o $Internet_IFACE -j MASQUERADE

# Allows client to ping some DNS servers
$IPTABLES -t nat -A POSTROUTING -p icmp -o $Internet_IFACE -d 8.8.8.8 -j MASQUERADE
$IPTABLES -t nat -A POSTROUTING -p icmp -o $Internet_IFACE -d $DNS1 -j MASQUERADE
$IPTABLES -t nat -A POSTROUTING -p icmp -o $Internet_IFACE -d $DNS2 -j MASQUERADE
# Allows client DNS resolution
$IPTABLES -t nat -A POSTROUTING -p udp -o $Internet_IFACE -d $DNS1 -j MASQUERADE
$IPTABLES -t nat -A POSTROUTING -p udp -o $Internet_IFACE -d $DNS2 -j MASQUERADE
# Allow internet traffic to HTTP/HTTPS for the client - used for Ubuntu updates.
# 
if [ "$Client_Allowed_Web" == "Y" ]; then
	$IPTABLES -t nat -A POSTROUTING -p tcp -o $Internet_IFACE --dport 80 -j MASQUERADE
	$IPTABLES -t nat -A POSTROUTING -p tcp -o $Internet_IFACE --dport 443 -j MASQUERADE
fi
# Logging
$IPTABLES -t nat -A POSTROUTING -j LOG --log-prefix NO-MASQUERADE-MATCH-

