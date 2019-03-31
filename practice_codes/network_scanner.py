# Usage: network_scanner.py [options]
# 
# Options:
#   -h, --help            show this help message and exit
#   -t TARGET, --target=TARGET
#                         Target IP / IP Range
#


import scapy.all as scapy
import optparse


def get_option():
    parser = optparse.OptionParser()

    parser.add_option("-t","--target", dest="target",default="10.0.2.1/24", help="Target IP / IP Range")
    (options , arguments) = parser.parse_args()
    return options

def scan(ip):
    arp_request = scapy.ARP(pdst=ip)                    #network layer
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")        #data-link layer
    arp_request_broadcast = broadcast/arp_request       #physical layer
    answered_list = scapy.srp(arp_request_broadcast,timeout=1,verbose=False)[0]
    
    clients = []

    for answer in answered_list:
        client_dict = {"ip" : answer[1].psrc , "mac" : answer[1].hwsrc}
        clients.append(client_dict)
    return clients

def print_result(result):
    
    print("\n---------------------------------------------------------\n")
    print("IP\t\t\tMAC Address")
    print("\n---------------------------------------------------------\n")
    for client in result:
        print(client["ip"] + "\t\t" + client["mac"])
    print("\n")

options = get_option()
scan_result = scan(options.target)
print_result(scan_result)
