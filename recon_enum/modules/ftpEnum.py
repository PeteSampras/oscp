import subprocess
from modules.utility_functions import *
from ftplib import FTP

def ftpEnum(ip_address, port):
    print(bcolors.HEADER + "INFO: Detected ftp on " + ip_address + ":" + port  + bcolors.ENDC)
    connect_to_port(ip_address, port, "ftp")
    FTPSCAN = "nmap -sV -Pn -p %s --script=ftp-anon,ftp-bounce,ftp-libopie,ftp-proftpd-backdoor,ftp-vsftpd-backdoor,ftp-vuln-cve2010-4221 -oN '../reports/%s/ftp_%s.nmap' %s" % (port, ip_address, ip_address, ip_address)
    print(bcolors.HEADER + FTPSCAN + bcolors.ENDC)
    results_ftp = subprocess.check_output(FTPSCAN, shell=True)
    print(bcolors.OKGREEN + "INFO: RESULT BELOW - Finished with FTP-Nmap-scan for " + ip_address + bcolors.ENDC)
    # print results_ftp
    write_to_file(ip_address, "ftp-scan", results_ftp)
    # see if we can download them with default creds
    ftp = FTP(ip_address)
    ftp.login()
    ftp_files = ftp.nlst()
    for files in ftp_files:
        print("Downloading..."+ files)
        ftp.retrbinary("RETR "+files,open("../reports/" + ip_address + "/ftp_files/"+files,'wb').write)
        ftp.close()

    #FTPGET = "wget ftp://%s:21/ -o '../reports/%s/ftp_%s.html'" % (ip_address, port, ip_address, ip_address)
    #print(bcolors.HEADER + FTPGET + bcolors.ENDC)
    #results_ftp = subprocess.check_output(FTPGET, shell=True)
    #print(bcolors.OKGREEN + "INFO: RESULT BELOW - Finished with FTP-wget for " + ip_address + bcolors.ENDC)
    return