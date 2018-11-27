import subprocess
from modules.utility_functions import *
import multiprocessing
from multiprocessing import Process, Queue

def httpEnum(ip_address, port):
    print(bcolors.HEADER + "INFO: Detected http on " + ip_address + ":" + port + bcolors.ENDC)
    print(bcolors.HEADER + "INFO: Performing nmap web script scan for " + ip_address + ":" + port + bcolors.ENDC)

    dirb_process = multiprocessing.Process(target=dirb, args=(ip_address,port,"http"))
    dirb_process.start()
    nikto_process = multiprocessing.Process(target=nikto, args=(ip_address,port,"http"))
    nikto_process.start()

    CURLSCAN = "curl -I http://"+str(ip_address)
    print(bcolors.HEADER + CURLSCAN + bcolors.ENDC)
    curl_results = subprocess.check_output(CURLSCAN, shell=True)
    write_to_file(ip_address, "curl", curl_results)
    HTTPSCAN = "nmap -sV -Pn -p %s --script=http-vhosts,http-userdir-enum,http-apache-negotiation,http-backup-finder,http-config-backup,http-default-accounts,http-methods,http-method-tamper,http-passwd,http-robots.txt,http-devframework,http-enum,http-frontpage-login,http-git,http-iis-webdav-vuln,http-php-version,http-robots.txt,http-shellshock,http-vuln-cve2015-1635 -oN ../reports/%s/%s_http.nmap %s" % (port, ip_address, ip_address, ip_address)
    print(bcolors.HEADER + HTTPSCAN + bcolors.ENDC)

    http_results = subprocess.check_output(HTTPSCAN, shell=True)
    print(bcolors.OKGREEN + "INFO: RESULT BELOW - Finished with HTTP-SCAN for " + ip_address + bcolors.ENDC)
    print(http_results.decode())

    return