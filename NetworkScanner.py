#!/usr/bin/python3

import os, sys, socket, platform, errno, argparse
from datetime import datetime
from subprocess import Popen, PIPE

class Target:
    def __init__(self, network_ip, target_octet):
        self.network_ip = network_ip
        self.target_octet = target_octet
        
    def pingSweep():
        # Simple ping scanner that allows to pick a network segment, machine to scan (from single to range of 255)
        # Can be used in a quick mode to send only one packet or in full mode to send 5 packet for each request.

        try:

            #--- Get users OS type ---#
            os_type = '-n' if platform.system().lower() == 'windows' else '-c'

            quick_scan = input("Quick scan? [y/n] : ")
            scan_type = '1' if quick_scan == 'y' else '5'
            
            single_scan = input("Scan a single host? [y/n] : ")

            if single_scan == 'y':

                last_octet = user_target.target_octet if user_target.target_octet != None else input("Enter last octet of the host address : ")

                ip_address = user_target.network_ip + '.' + last_octet

                print(f"Scanning {ip_address}")
                subprocess = Popen(['ping', os_type, scan_type, ip_address], stdin=PIPE, stdout=PIPE, stderr=PIPE)
                stdout, stderr = subprocess.communicate(input=None) 

                #--- Decode PIPEs ---#
                std_output = stdout.decode('utf8')
                std_error = stderr.decode('utf8')

                #--- if error encountered, print the error out, else print the reply ---#
                for error in std_error:
                    print(error)
                else:
                    print(std_output)

            else:

                start_range = int(input("Enter start range (Between 0-255) : "))     
                end_range = int(input("Enter end range (Between 0-255 : ")) + 1

                #--- For each ip in the range, make a ping sweep ---#
                for ip in range(start_range, end_range):
                    ip_address = user_target.network_ip + '.' + str(ip)

                    print(f"Scanning {ip_address}")
                    subprocess = Popen(['ping', os_type, scan_type, ip_address], stdin=PIPE, stdout=PIPE, stderr=PIPE)
                    stdout, stderr = subprocess.communicate(input=None) 

                    #--- Decode PIPEs ---#
                    std_output = stdout.decode('utf8')
                    std_error = stderr.decode('utf8')

                    #--- if error encountered, print the error out, else print the reply ---#

                    if b'host unreachable' in stdout:
                        print("Host Unreachable...")

                    elif b'timed out' in stdout:
                        print("Request timed out...")

                    else:
                        print(f"ECHO_REPLY from {ip_address} \n")
                        print(f"Full reply message: {std_output}")

        # If interrupted 
        except KeyboardInterrupt:
            print("You pressed Ctrl+C")
            sys.exit()

    def portScan():

        common_ports = [
            20, 21, 22, 23, 25, 
            50, 51, 53, 67, 68, 
            69, 80, 110, 115, 119, 
            123, 135, 136, 137, 138, 
            139, 143, 161, 162, 179, 
            194, 389, 443, 445, 636, 
            989, 990, 1433, 3306, 3389, 
            5632, 5900
        ]


        def startScan():
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                result = sock.connect_ex((user_target.network_ip + '.' + user_target.target_octet, port_number))

                #--- Resolve port number to name ---#
                try:
                    port_name = socket.getservbyport(port_number)
                except socket.error as error:
                    port_name = 'Unknown name'
                    pass
                
                if result == 0:
                    print(f"{port_name} on port {port_number} is: Open")
                else:
                    print(f"{port_name} on port {port_number} is: Closed")
                    print("Reason:", errno.errorcode[result])
                    sock.close()

            # If interrupted 
            except KeyboardInterrupt:
                print("You pressed Ctrl+C")
                sys.exit()
            # If Host is wrong
            except socket.gaierror:
                print('Hostname could not be resolved. Exiting')
                sys.exit()
            # If server is down
            except socket.error:
                print("Couldn't connect to server")
                sys.exit()    


        single_port_scan = input("Scan single port? [y/n]")
        if single_port_scan == 'y':
            port_number = int(input("Enter port to scan: "))

            print("Scanning host: ", user_target.network_ip + '.' + user_target.target_octet)
            #--- start timer ---#
            t1 = datetime.now()
            startScan()
        else:
            multi_port_scan = input("Scan only common ports? [y/n]")
            if multi_port_scan == 'n':
                print("Scanning all 65535 ports.")
                print("Scanning host: ", user_target.network_ip + '.' + user_target.target_octet)

                #--- start timer ---#
                t1 = datetime.now()

                for port in range(0, 65536):
                    print(f"Checking port {port}...")
                    port_number = port
                    startScan()
            else:
                all_common_scan = input("Scan all 1024 common ports? [y/n]")

                if all_common_scan == 'y':

                    print("Scanning common ports.")
                    print("Scanning host: ", user_target.network_ip + '.' + user_target.target_octet)

                    #--- start timer ---#
                    t1 = datetime.now()
                    for port in range(0, 1025):
                        print(f"Checking port {port}...")
                        port_number = port

                        startScan()
                else:

                    for port in common_ports:
                        print(f"Checking port {port}...")
                        port_number = port

                        startScan()

        #get current Time as t2
        t2 = datetime.now()
        #total Time required to Scan
        total =  t2 - t1
        # Time for port scanning 
        print('Port Scanning Completed in: ', total)
    

    def ipDomain():

        ip_address = parsed_args.network_ip + '.' + parsed_args.target_octet
        try:
            result = socket.gethostbyaddr(ip_address)
            print(result)
            print(socket.getaddrinfo(result, socket.SOCK_STREAM))

        except socket.error as error:
            print(str(error))
            print("Connection error")
            sys.exit()
    

    def domainIP():

        domain_name = parsed_args.domain_name
        result = socket.gethostbyname_ex(domain_name)
        print(result)

#--- Defines all command line arguments and stores the output in parsed_args
parser = argparse.ArgumentParser(description='Network Scanner')

# Main arguments

parser.add_argument("-network_ip", dest="network_ip", help="Specify network segment [Example: 192.168.56]", required=False)
parser.add_argument("-target_octet", dest="target_octet", help="Specify target octet [Example: 56]", required=False)
parser.add_argument("-domain_name", dest="domain_name", help="Specify domain name [Example: www.google.com", required=False)

#parser.add_argument("-ping", help="Ping a host or a range of hosts", required=False)
#parser.add_argument("-port_scan", help="Scan ports on a target machine", required=False)
#parser.add_argument("-resolve_ip", help="Resolve ip address to a domain name", required=False)

FUNCTION_MAP = {'ping': Target.pingSweep, 'port_scan': Target.portScan, 'resolve_ip': Target.ipDomain, 'resolve_domain': Target.domainIP}

parser.add_argument('command', choices=FUNCTION_MAP.keys())

parsed_args = parser.parse_args()

func = FUNCTION_MAP[parsed_args.command]

user_target = Target(parsed_args.network_ip, parsed_args.target_octet)

func()