from modules.imports import *

def dirb(ip_address, port, url_start, wordlist="/usr/share/wordlist/dirb/big.txt, /usr/share/wordlist/dirb/vulns/cgis.txt"):
    print(bcolors.HEADER + "INFO: Starting dirb scan for " + ip_address + bcolors.ENDC)
    DIRBSCAN = "dirb %s://%s:%s %s -o ../reports/%s/dirb-%s.txt -r" % (url_start, ip_address, port, ip_address, ip_address, wordlist)
    print(bcolors.HEADER + DIRBSCAN + bcolors.ENDC)
    results_dirb = subprocess.check_output(DIRBSCAN, shell=True)
    print(bcolors.OKGREEN + "INFO: RESULT BELOW - Finished with dirb scan for " + ip_address + bcolors.ENDC)
    print(results_dirb.decode())
    write_to_file(ip_address, "dirb", results_dirb)
    return