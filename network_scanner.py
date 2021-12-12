#!/usr/bin/env python

# scapy is a python program that allow the user to send, sniff and dissect and forge network packets
# The capability allows constructing tools that can probe, scan or attack/A powerful interactive packet
# manipulation program
import scapy.all as scapy


def scan_network(ip):
    # set var and create an ARP packet object
    # use scapy to create an ARP object that represent as an ARP Packet
    # list of all options scapy.ls(scapy.ARP())
    arp_request = scapy.ARP(pdst=ip)  # this class will print a summary of the object just created
    print(arp_request.summary())


scan_network('10.0.0.1')
