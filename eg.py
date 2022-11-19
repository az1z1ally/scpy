#from scapy.all import *

import sys
import os 
import time

# https://www.geeksforgeeks.org/command-line-arguments-in-python/

def main():
    opts = [opt for opt in sys.argv[1:] if opt.startswith("-")]
    args = [arg for arg in sys.argv[1:] if not arg.startswith("-")]

    if "-c" in opts:
        print(" ".join(arg.capitalize() for arg in args))
    elif "-u" in opts:
        print(" ".join(arg.upper() for arg in args))
    elif "-l" in opts:
        print(" ".join(arg.lower() for arg in args))
    else:
        raise SystemExit(f"Usage: {sys.argv[0]} (-c | -u | -l) <arguments>...")


# https://realpython.com/python-command-line-arguments/

from argparse import ArgumentParser

parser = ArgumentParser()
parser.add_argument("-f", "--file", dest="filename",
                    help="write report to FILE", metavar="FILE")
parser.add_argument("-q", "--quiet",
                    action="store_false", dest="verbose", default=True,
                    help="don't print status messages to stdout")

args = parser.parse_args()



# --------------------------- Refs ----------------------------
# https://thepacketgeek.com/scapy/sniffing-custom-actions/part-1/    --- sniff arp


# https://0xbharath.github.io/art-of-packet-crafting-with-scapy/network_recon/host_discovery/index.html  -- Must read
# https://www.geeksforgeeks.org/network-scanning-using-scapy-module-python/   -- Network scanning to find connected hosts usimg scapy.ARP()
import scapy.all as scapy
  
request = scapy.ARP()
  
request.pdst = 'x'
broadcast = scapy.Ether()
  
broadcast.dst = 'ff:ff:ff:ff:ff:ff'
  
request_broadcast = broadcast / request
clients = scapy.srp(request_broadcast, timeout = 1)[0]
for element in clients:
    print(element[1].psrc + "      " + element[1].hwsrc)
Here x = Network range. For example x = 192.168.1.1/24, 172.16.5.1/16 etc

# https://santandergto.com/en/guide-using-scapy-with-python/  --scapy basics must read


# https://mpostument.medium.com/packet-sniffer-with-scapy-part-3-a895ce7e9cb
# https://www.thepythoncode.com/article/building-arp-spoofer-using-scapy
# https://www.geeksforgeeks.org/python-program-find-ip-address/
# https://cdn.ttgtmedia.com/rms/pdf/MPNS_CH5.pdf

# https://youtu.be/cqfgYxLT4lo

# https://gist.github.com/mgeeky/a360e4a124ddb9ef6a9ac1557b47d14c  --- ping sweep ICMP
# https://stackoverflow.com/questions/7541056/pinging-an-ip-range-with-scapy
#!/usr/bin/python
from scapy.all import *

TIMEOUT = 2
conf.verb = 0
for ip in range(0, 256):
    packet = IP(dst="192.168.0." + str(ip), ttl=20)/ICMP()
    reply = sr1(packet, timeout=TIMEOUT)
    if not (reply is None):
         print reply.dst, "is online"
    else:
         print "Timeout waiting for %s" % packet[IP].dst


# https://stackoverflow.com/questions/24196932/how-can-i-get-the-ip-address-from-a-nic-network-interface-controller-in-python
# https://www.tutorialspoint.com/python-program-to-find-the-ip-address-of-the-client
