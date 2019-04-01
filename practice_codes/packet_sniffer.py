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

def process_sniffed_data(packet):
    if not packet.haslayer(http.HTTPRequest):
        return
    print(packet.show())

options = get_options()

sniff(options.interface)
