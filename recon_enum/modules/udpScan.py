#from modules.imports import *
import subprocess
import modules.utility_functions

def udpScan(ip_address):
    print(bcolors.HEADER + "INFO: Detected UDP on " + ip_address + bcolors.ENDC)
    UDPSCAN = "nmap -Pn -A -sC -sU -T 5 --top-ports 150 -oN '../reports/%s/udp_%s.nmap' %s"  % (ip_address, ip_address, ip_address)
    print(bcolors.HEADER + UDPSCAN + bcolors.ENDC)
    udpscan_results = subprocess.check_output(UDPSCAN, shell=True)
    print(bcolors.OKGREEN + "INFO: RESULT BELOW - Finished with UDP-Nmap scan for " + ip_address + bcolors.ENDC)
    print(udpscan_results.decode())
    write_to_file(ip_address,"udpscan",udpscan_results)
    UNICORNSCAN = "unicornscan -mU -r 1000000 -I %s > ../reports/%s/unicorn_udp_%s.txt" % (ip_address, ip_address, ip_address)
    unicornscan_results = subprocess.check_output(UNICORNSCAN, shell=True)
    print(bcolors.OKGREEN + "INFO: CHECK FILE - Finished with UNICORNSCAN for " + ip_address + bcolors.ENDC)
    return