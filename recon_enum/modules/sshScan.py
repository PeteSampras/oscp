import subprocess
from modules.utility_functions import *

def sshScan(ip_address, port):
    print(bcolors.HEADER + "INFO: Detected SSH on " + ip_address + ":" + port  + bcolors.ENDC)
    connect_to_port(ip_address, port, "ssh")
    SSHSCAN = "nmap -sV -Pn -p %s --script=ssh-auth-methods,ssh-hostkey,ssh-run,sshv1 -oN '../reports/%s/ssh_%s.nmap' %s" % (port, ip_address, ip_address, ip_address)
    print(bcolors.HEADER + SSHSCAN + bcolors.ENDC)
    results_ssh = subprocess.check_output(SSHSCAN, shell=True)
    print(bcolors.OKGREEN + "INFO: RESULT BELOW - Finished with SSH-Nmap-scan for " + ip_address + bcolors.ENDC)
    print(results_ssh.decode())
    write_to_file(ip_address, "ssh-connect", results_ssh)
    return