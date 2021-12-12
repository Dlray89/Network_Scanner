#!/usr/bin/env python

# scapy is a python program that allow the user to send, sniff and dissect and forge network packets
# The capability allows constructing tools that can probe, scan or attack/A powerful interactive packet
# manipulation program
import scapy.all as scapy


def scan_network(ip):
    # this function takes IP ranges Specifying  many IP in the same line
    scapy.arping(ip)


scan_network('10.0.0.1/24')
