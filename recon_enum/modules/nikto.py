import subprocess
from modules.utility_functions import *

def nikto(ip_address, port, url_start):
    print(bcolors.HEADER + "INFO: Starting nikto scan for " + ip_address + bcolors.ENDC)
    NIKTOSCAN = "nikto -h %s://%s -o ../reports/%s/nikto-%s-%s.txt" % (url_start, ip_address, ip_address, url_start, ip_address)
    print(bcolors.HEADER + NIKTOSCAN + bcolors.ENDC)
    results_nikto = subprocess.check_output(NIKTOSCAN, shell=True)
    print(bcolors.OKGREEN + "INFO: RESULT BELOW - Finished with NIKTO-scan for " + ip_address + bcolors.ENDC)
    print(results_nikto.decode())
    write_to_file(ip_address, "nikto", results_nikto)
    return