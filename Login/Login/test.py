from scapy.all import *

import sys
import argparse
import requests
import re
from time import sleep


# Help function
def help():
    raise SystemExit(f"Usage: {sys.argv[0]} [-t] [ip addreses file] [-p] [ports to scan] [-a] [username] [-f] [password file] \n\nOptions:\n-t\t[Filename for a file containing a list of IP addresses]\n-p\t[Ports to scan on the target host]\n-u\t[username]\n-f\t[Filename for a file containing a list of passwords]\n\nExample:\n/net_attack.py -t my_ip_list.txt -p 22,23,25,80 -u admin -f my_password_list.txt\n\n./net_attack.py -t ip_list.txt -p 22 -u root -f passwords.txt")


# Read the content of the file into a list   --https://www.pythontutorial.net/python-basics/python-read-text-file/
def read_ip_list(ip_file):
    ip_list = []
    
    # declaring the regex pattern for IP addresses 
    pattern =re.compile(r'''((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)''')

    # loop through the file object and append each ip_address in the passed file in ip_list
    try:
        with open(ip_file) as f:
            for line in f:
                line = line.strip()

                # Check for valid ip address pattern & extract only ip addresses  --- ref https://www.geeksforgeeks.org/extract-ip-address-from-file-using-python/
                result = pattern.search(line)
                if result is None:
                    continue
                
                ip_list.append(line)
    except:
        raise SystemExit(f'The [{ip_file}] is not found. Please provide a valid file path!')


    # Check if we have atleast one ip address
    if len(ip_list) < 1:
        raise SystemExit(f'The [{ip_file}] does\'nt contain IP addresses, use the file with ip addresses.')   
    return ip_list



# Verify connectivity
 # https://gist.github.com/az1z1ally/d072f39846fce5b11a8bf88bf68ee596
def is_reachable(ip):
    reply = sr1(IP(dst=ip)/ICMP(), timeout=1, iface=conf.iface, verbose=0)

    if not reply:
        return False

    if int(reply.getlayer(ICMP).type) == 0 and int(reply.getlayer(ICMP).code) == 0:
        return True



# Port Scan
# https://resources.infosecinstitute.com/topic/port-scanning-using-scapy/
# https://dev.to/powerexploit/syn-stealth-scan-with-power-of-python-scapy-58aj
# https://gist.github.com/mic159/c7133509af81dad409b79b8c4838f4bd
# https://community.f5.com/t5/technical-forum/tcp-3-way-handshake-vs-tcp-half-open/td-p/263887

# Reset the connection to stop half-open connections from pooling up
def reset_half_open(ip, ports):
    sr(IP(dst=ip)/TCP(dport=ports, flags='AR'), timeout=1, verbose=0)


def scan_port(ip, ports):
    # Set all ports to none initially
    results = {port:None for port in ports}

    to_reset = [] # List to store half open connection
    p = IP(dst=ip)/TCP(dport=ports, flags='S')  # Forging SYN packet
    answers, un_answered = sr(p, timeout=1, verbose=0)  # Send the packets
    for req, resp in answers:
        if not resp.haslayer(TCP):
            continue
        tcp_layer = resp.getlayer(TCP)
        if tcp_layer.flags == 0x12:  # checking for 'SA' flag -> tcp_layer.flags == 'SA'
            to_reset.append(tcp_layer.sport)
            results[tcp_layer.sport] = True
        elif tcp_layer.flags == 0x14:
            results[tcp_layer.sport] = False

    # Bulk reset ports
    reset_half_open(ip, to_reset)
    print(f'{ip}\'s return the following results where True:[port is opened], False:[port is close] & None:[not a TCP port].')
    return results
    


# start the program
def main():
    print('############################# WELCOME TO NET ATTACK #############################\n')
    sleep(5)
    print('If I see an error I will definetly complain. Let\'s start analyzing.\n\n')
    sleep(3)

    # Reading command line arguments and options
    opts = [opt for opt in sys.argv[1:] if opt.startswith("-")]
    args = [arg for arg in sys.argv[1:] if not arg.startswith("-")]

    print(args)
    print(opts)

    # Checking for necessary arguments
    if (len(opts) < 4) | (len(args) < 4):
        help()

    if not (("-t" in opts) & ("-p" in opts) & ("-u" in opts) & ("-f" in opts)):
        help()

    # Read ip addresses file and store each ip address in a ip_list variable
    ip_list = read_ip_list(args[0])
    print(f'Passed IP list:\n{ip_list}\n')

    # Loop through ip_list to verify connectivity and remove unreachable IPs
    for ip in ip_list:
        if is_reachable(ip):
            continue
        else:
            ip_list.remove(ip)

    print(f'The active IP addresses are:\n {ip_list}\n')
    sleep(5) # sleep for 5 seconds then continue

    print('########################## Now, we are going to scan the ports. #############################\n')
    sleep(5)
    print('Start Scaning......\n')
    sleep(3)

    # Parsing ports passed in the command and return their integer value
    ports = args[1].split(',')
    ports =[int(port) for port in ports]
    print(f'The following ports were passed on the command.\n{ports}\n')

    # Loop through the ports and return open ports(services)
    resp = scan_port(ip_list[1], ports)
    sleep(3)
    print(f'{resp}\n')

    for port in resp.keys():
        if resp[port]==True:
            print(f'{port} is opened')
        else:
            print(f'{port} is closed')

    # Getting only opened ports

    # Performing Bruteforce on the services
    print('############################### Now Lets\'s Bruteforce ##########################')
    sleep(5)

    for port in resp.keys():
        # Check if 23 is open to perform bruteforce_telnet().
        if port == 23 & resp[port] == 23:
            pass
            # bruteforce_telnet(ip, port, username, password_list_filename)


# Start the script
main()