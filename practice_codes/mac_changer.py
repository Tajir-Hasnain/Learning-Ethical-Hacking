# Usage: mac_changer.py [options]
#
# run with python mac_changer.py -< option > < value >
# Options:
#   -h, --help            show this help message and exit
#   -i INTERFACE, --interface=INTERFACE
#                         Interface to change its MAC address
#   -m NEW_MAC, --mac=NEW_MAC
#                         New MAC address
#   --reset=RESET         (type "python mac_changer.py -i <interface name>
#                         --reset true")  Reset to default MAC address
#

import subprocess
import optparse
import re
import sys

def change_mac(interface,new_mac):
    print("[+] Changing MAC adress")

    subprocess.call(["ifconfig",interface,"down"])
    subprocess.call(["ifconfig",interface,"hw","ether",new_mac])
    subprocess.call(["ifconfig",interface,"up"])


def get_options():
    parser = optparse.OptionParser()
    parser.add_option("-i","--interface",dest="interface",help="Interface to change its MAC address")
    parser.add_option("-m","--mac",dest="new_mac",help="New MAC address")
    
    parser.add_option("--reset", dest="reset",help="(type \"python mac_changer.py -i <interface name> --reset true\")\n Reset to default MAC address")

    (options,arguments) = parser.parse_args()

    return options

def reset_mac(interface):
    subprocess.call(["macchanger","-p", interface])

def get_mac(interface):
    ifconfig_result = subprocess.check_output(["ifconfig" , interface])
    mac_address = re.search(r"\w\w:\w\w:\w\w:\w\w:\w\w:\w\w" , ifconfig_result)

    if mac_address:
        return mac_address.group(0)
    else:
        print("[-] Could not read MAC address")

options = get_options()

if get_mac(options.interface) == options.new_mac:
    print("[-] new MAC address is similar to the current MAC address")
    sys.exit(0)

if options.interface and options.new_mac:
    change_mac(options.interface, options.new_mac)
    cur_mac = get_mac(options.interface)
    if cur_mac == options.new_mac:
        print("[+] Changed MAC address to " + cur_mac)
    
elif options.reset and options.interface:
    reset_mac(options.interface)
