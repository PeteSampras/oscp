import subprocess
from modules.utility_functions import *

def smbNmap(ip_address, port):
    print("INFO: Detected SMB on " + ip_address + ":" + port)
    smbNmap = "nmap --script=smb-enum-shares,smb-ls,smb-enum-users,smb-mbenum,smb-os-discovery,smb-security-mode,smb-vuln-cve2009-3103,smb-vuln-ms06-025,smb-vuln-ms07-029,smb-vuln-ms08-067,smb-vuln-ms10-054,smb-vuln-ms10-061,smb-vuln-regsvc-dos %s -oN ../reports/%s/smb_%s.nmap" % (ip_address, ip_address, ip_address)
    smbNmap_results = subprocess.check_output(smbNmap, shell=True)
    print(bcolors.OKGREEN + "INFO: RESULT BELOW - Finished with SMB-Nmap-scan for " + ip_address + bcolors.ENDC)
    print(smbNmap_results.decode())
    return