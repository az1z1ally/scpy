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
            return f"{pkt[ARP].psrc} {pkt[ARP].hwsrc}"

    #sniff and filter only arp traffic
    sniff(iface=iface, filter="arp", prn=arp_display, store=1)


# active scan
def active_scan(iface):
    # Assuming the network is /24
    online_host = []
    TIMEOUT = 2
    conf.verb = 0
    for ip in range(0, 255):
        packet = IP(dst="192.168.0." + str(ip), ttl=20)/ICMP()
        reply = sr1(packet, timeout=TIMEOUT)
        if not (reply is None):
           online_host.append[reply.dst]

    print(online_host)


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