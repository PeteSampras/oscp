from modules.imports import *

def smtpEnum(ip_address, port):
    print(bcolors.HEADER + "INFO: Detected smtp on " + ip_address + ":" + port  + bcolors.ENDC)
    connect_to_port(ip_address, port, "smtp")
    SMTPSCAN = "nmap -sV -Pn -p %s --script=smtp-commands,smtp-enum-users,smtp-vuln-cve2010-4344,smtp-vuln-cve2011-1720,smtp-vuln-cve2011-1764 %s -oN ../reports/%s/smtp_%s.nmap" % (port, ip_address, ip_address, ip_address)
    print(bcolors.HEADER + SMTPSCAN + bcolors.ENDC)
    smtp_results = subprocess.check_output(SMTPSCAN, shell=True)
    print(bcolors.OKGREEN + "INFO: RESULT BELOW - Finished with SMTP-scan for " + ip_address + bcolors.ENDC)
    print(smtp_results.decode())
    # write_to_file(ip_address, "smtp", smtp_results)
    return