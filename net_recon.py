from scapy.all import *

import sys
import socket


# Help function
def help():
    raise SystemExit(f"Usage: {sys.argv[0]} [-i] [interface-name] [-a] | [-p] \n\noptions:\n-i interface-name, --iface interface-name\t[specify interface name]\n-a, --active\t[launch tool in active mode]\n-p, --passive\t[launch tool in passive mode]")



# Passive scan functionality
def passive_scan(iface):
    def arp_display(pkt):
        if pkt[ARP].op == 2: #is-at (response)
            print(f"{pkt[ARP].psrc} {pkt[ARP].hwsrc}")

    #sniff and filter only arp traffic
    sniff(iface=iface, filter="arp", prn=arp_display, store=1)


# active scan
def active_scan(iface):
    #Getting interface ip address
    ip = get_if_addr(iface)
    print(f"The ip address of {iface}: {ip}" )
    
    # Getting gateway
    #gw = conf.route.route(ip)
    net = ip[:ip.rfind('.')+1] + '*'
    # Assuming the netwwork is /24
    ans,unans=sr(IP(dst=net)/ICMP())
    ans.summary()



# Main function
def main():
    # Reading command line arguments and options
    opts = [opt for opt in sys.argv[1:] if opt.startswith("-")]
    args = [arg for arg in sys.argv[1:] if not arg.startswith("-")]

    # Checking for necessary arguments
    if (len(opts) > 2) | (len(args) > 1):
        help()

    elif ("-p" in opts) | ("--passive" in opts):
        if ("-i" in opts) | ("--iface" in opts):
            # call passive_scan with given interface
            passive_scan(args[0])
        else:
            help()
            
    elif ("-a" in opts) | ("--active" in opts):
        if ("-i" in opts) | ("--iface" in opts):
            # call active_scan with given interfac
            active_scan(args[0])
        else:
            help()

    else:
        help()

# start the program
main()