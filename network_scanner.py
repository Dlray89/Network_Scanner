#!/usr/bin/env python

# scapy is a python program that allow the user to send, sniff and dissect and forge network packets
# The capability allows constructing tools that can probe, scan or attack/A powerful interactive packet
# manipulation program
import scapy.all as scapy


def scan_network(ip):
    # set var and create an ARP packet object
    # use scapy to create an ARP object that represent as an ARP Packet
    # list of all options from scapy using scapy.ls(scapy.ARP())/ Ether(MAC)= scapy.ls(scapy.Ether())
    # .summary() will provide a small summary about what's going on.

    arp_request = scapy.ARP(pdst=ip)  # set IP field
    # print(arp_request.summary())

    # create an eth frame that will send to the broadcast mac address
    # data and networks is always sent using the mac address
    # the source mac and des mac is set in the ethernet frame

    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    # combine packets
    # append using /
    arp_request_broadcast = broadcast/arp_request
    print(arp_request_broadcast.summary())
    arp_request_broadcast.show()





scan_network('10.0.0.1')
