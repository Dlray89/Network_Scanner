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
    # srp() allows sending packets with a custom Ether layer
    # set up timeout
    # this will return a response from two list
    # print(answered_list.summary())
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    # create empty list
    client_list = []
    # iterate over the answered_list
    for element in answered_list:
        # parse the values are being capture in the list
        # view list of properties using .show()
        # --------------------------------------
        # set up dictionary and add keys and values
        client_dict = {"IP Address": element[1].psrc, "MAC Address": element[1].hwsrc}
        # append dictionary to the main list (client_list)
        client_list.append(client_dict)
    return client_list


def print_results(results_list):
    # added escape keys for better format
    print("IP\t\tMAC ADDRESS\n------------------------------------------")
    # iterate through client list and print
    for client in results_list:
        print(client["IP Address"] + "\t" + client["MAC Address"])


scan_results = scan_network('10.0.0.1/24')
print_results(scan_results)
