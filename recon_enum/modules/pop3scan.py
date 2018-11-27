import subprocess
from modules.utility_functions import *

def pop3Scan(ip_address, port):
    print(bcolors.HEADER + "INFO: Detected POP3 on " + ip_address + ":" + port  + bcolors.ENDC)
    connect_to_port(ip_address, port, "pop3")
    POP3SCAN = "nmap -sV -Pn -p %s --script=pop3-brute,pop3-capabilities,pop3-ntlm-info -oN '../reports/%s/pop3_%s.nmap' %s" % (port, ip_address, ip_address, ip_address)
    print(bcolors.HEADER + SSHSCAN + bcolors.ENDC)
    results_pop3 = subprocess.check_output(POP3SCAN, shell=True)
    print(bcolors.OKGREEN + "INFO: RESULT BELOW - Finished with POP3-Nmap-scan for " + ip_address + bcolors.ENDC)
    print(results_pop3.decode())
    return