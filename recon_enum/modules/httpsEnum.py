import subprocess
from modules.utility_functions import *
import multiprocessing
from multiprocessing import Process, Queue

def httpsEnum(ip_address, port):
    print(bcolors.HEADER + "INFO: Detected https on " + ip_address + ":" + port + bcolors.ENDC)
    print(bcolors.HEADER + "INFO: Performing nmap web script scan for " + ip_address + ":" + port + bcolors.ENDC)

    dirb_process = multiprocessing.Process(target=dirb, args=(ip_address,port,"https"))
    dirb_process.start()
    nikto_process = multiprocessing.Process(target=nikto, args=(ip_address,port,"https"))
    nikto_process.start()

    SSLSCAN = "sslscan %s:%s >> ../reports/%s/ssl_scan_%s" % (ip_address, port, ip_address, ip_address)
    print(bcolors.HEADER + SSLSCAN + bcolors.ENDC)
    ssl_results = subprocess.check_output(SSLSCAN, shell=True)
    print(bcolors.OKGREEN + "INFO: CHECK FILE - Finished with SSLSCAN for " + ip_address + bcolors.ENDC)

    HTTPSCANS = "nmap -sV -Pn  -p %s --script=http-vhosts,http-userdir-enum,http-apache-negotiation,http-backup-finder,http-config-backup,http-default-accounts,http-methods,http-method-tamper,http-passwd,http-robots.txt,http-devframework,http-enum,http-frontpage-login,http-git,http-iis-webdav-vuln,http-php-version,http-robots.txt,http-shellshock,http-vuln-cve2015-1635 -oN ../reports/%s/%s_http.nmap %s" % (port, ip_address, ip_address, ip_address)
    print(bcolors.HEADER + HTTPSCANS + bcolors.ENDC)
    https_results = subprocess.check_output(HTTPSCANS, shell=True)
    print(bcolors.OKGREEN + "INFO: RESULT BELOW - Finished with HTTPS-scan for " + ip_address + bcolors.ENDC)
    print(https_results.decode())
    return