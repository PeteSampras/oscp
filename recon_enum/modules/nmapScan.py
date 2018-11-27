import subprocess
from modules.utility_functions import *
import multiprocessing
from multiprocessing import Process, Queue, Manager

def nmapScan(ip_address,scan_type,return_dict):
    ip_address = ip_address.strip()
    print(bcolors.OKGREEN + "INFO: Running general TCP/UDP nmap scans for " + ip_address + bcolors.ENDC)
    # STEALTH FIN SCAN
    if scan_type=='STEALTH':
        TCPSCAN = "nmap -sF -p- %s -oN '../reports/%s/%s.nmap'"  % (ip_address, ip_address, ip_address)
    # PASSIVE SYN SCAN
    if scan_type=='PASSIVE':
        TCPSCAN = "nmap -sS -O -p- %s -oN '../reports/%s/%s.nmap'"  % (ip_address, ip_address, ip_address)
    # FULL SCAN
    if scan_type=='ACTIVE' or scan_type=='ALL':
        TCPSCAN = "nmap -sV -O -p- %s -oN '../reports/%s/%s.nmap'"  % (ip_address, ip_address, ip_address)
    print(bcolors.HEADER + TCPSCAN + bcolors.ENDC)
    results = subprocess.check_output(TCPSCAN, shell=True)
    print(bcolors.OKGREEN + "INFO: RESULT BELOW - Finished with BASIC Nmap-scan for " + ip_address + bcolors.ENDC)
    print(results.decode())
    write_to_file(ip_address, "portscan", results)
    # set ip = results in dict
    return_dict[ip_address] = results