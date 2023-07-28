import argparse

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

def help():
    parser.print_help()
    raise SystemExit()

# Read arguments from command line
try:
    args = parser.parse_args()
except:
    help()


print(args.ip_list_file, args.username)