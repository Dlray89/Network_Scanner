#!/usr/bin/env python


import scapy.all as scapy
import optparse


# set up terminal responses
def get_arguments():
    parser = optparse.OptionParser()
    parser.add_option('-t', "--target", dest="target", help='Choice a Target IP / IP Range')
    (options, arguments) = parser.parse_args()
    return options


def scan_network(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    client_list = []

    for element in answered_list:
        client_dict = {"IP Address": element[1].psrc, "MAC Address": element[1].hwsrc}

        client_list.append(client_dict)
    return client_list


def print_results(results_list):
    print("IP\t\tMAC ADDRESS\n------------------------------------------")
    for client in results_list:
        print(client["IP Address"] + "\t" + client["MAC Address"])


option = get_arguments()
scan_results = scan_network(option.target)
print_results(scan_results)
