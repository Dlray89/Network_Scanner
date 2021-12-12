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
    # combine packets by using / to append together
    arp_request_broadcast = broadcast / arp_request

    # send arp_request_broadcast packet into the network.
    # srp() allow us to send packets with a customer Ether layer
    # set up timeout
    answered, unanswered = scapy.srp(arp_request_broadcast, timeout=1)  # this will return a response from two list
    print(answered.summary(), unanswered.summary())


scan_network('10.0.0.1/24')
