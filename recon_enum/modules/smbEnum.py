from modules.imports import *

def smbEnum(ip_address, port):
    print("INFO: Detected SMB on " + ip_address + ":" + port)
    enum4linux = "enum4linux -a %s > ../reports/%s/enum4linux_%s 2>/dev/null" % (ip_address, ip_address, ip_address)
    enum4linux_results = subprocess.check_output(enum4linux, shell=True)
    print(bcolors.OKGREEN + "INFO: CHECK FILE - Finished with ENUM4LINUX-Nmap-scan for " + ip_address + bcolors.ENDC)
    print(enum4linux_results.decode())
    return