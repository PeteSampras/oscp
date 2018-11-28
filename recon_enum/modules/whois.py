import subprocess
from modules.utility_functions import *

def dig(ip_address):
    print(bcolors.HEADER + "INFO: Starting dig scan for " + ip_address + bcolors.ENDC)
    WHOISSCAN = "whois " + ip_address
    print(bcolors.HEADER + WHOISSCAN + bcolors.ENDC)
    results_whois = subprocess.check_output(DIGSCAN, shell=True)
    print(bcolors.OKGREEN + "INFO: RESULT BELOW - Finished with whois request for " + ip_address + bcolors.ENDC)
    this=results_whois.decode().replace("<<-","")
    print(this)
    write_to_file(ip_address, "whois", this)
    print(bcolors.OKGREEN + "INFO: nmap scan still in progress.. " + ip_address + bcolors.ENDC)
    return