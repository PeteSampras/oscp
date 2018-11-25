import subprocess
import modules.utility_functions
import multiprocessing
from multiprocessing import Process, Queue
import re

def nmapScan(ip_address,scan_type,udp=False):
    ip_address = ip_address.strip()
    print(bcolors.OKGREEN + "INFO: Running general TCP/UDP nmap scans for " + ip_address + bcolors.ENDC)
    # STEALTH FIN SCAN
    if scan_type=='STEALTH':
        TCPSCAN = "nmap -sF -p- %s -oN '../reports/%s/%s.nmap'"  % (ip_address, ip_address, ip_address)
    # PASSIVE SYN SCAN
    if scan_type=='PASSIVE':
        TCPSCAN = "nmap -sS -O -p- %s -oN '../reports/%s/%s.nmap'"  % (ip_address, ip_address, ip_address)
    # FULL SCAN
    if scan_type=='ACTIVE' or scan_type=='ALL':
        TCPSCAN = "nmap -sV -O -p- %s -oN '../reports/%s/%s.nmap'"  % (ip_address, ip_address, ip_address)
    print(bcolors.HEADER + TCPSCAN + bcolors.ENDC)
    results = subprocess.check_output(TCPSCAN, shell=True)
    print(bcolors.OKGREEN + "INFO: RESULT BELOW - Finished with BASIC Nmap-scan for " + ip_address + bcolors.ENDC)
    print(results.decode())
    write_to_file(ip_address, "portscan", results)

    # UDP SCAN GOES HERE BUT LETS COMMENT IT OUT FOR NOW AND MOVE IT BELOW LATER
    if udp==False:
        
        udpScan.udpScan(ip_address)
    # udpScan(ip_address)

    lines = results.split(b"\n")
    serv_dict = {}
    for line in lines:
        ports = []
        line = str(line.decode('UTF-8').strip())
        if ("tcp" in line) and ("open" in line) and not ("Discovered" in line):
            # print line
            while "  " in line:
                line = line.replace("  ", " ")
            linesplit= line.split(" ")
            service = linesplit[2] # grab the service name

            port = line.split(" ")[0] # grab the port/proto
            # print port
            if service in serv_dict:
                ports = serv_dict[service] # if the service is already in the dict, grab the port list

            ports.append(port)
            # print ports
            serv_dict[service] = ports # add service to the dictionary along with the associated port(2)
    # stop here for now if stealth or passive
    if scan_type=='STEALTH' or 'PASSIVE':
        return
   # go through the service dictionary to call additional targeted enumeration functions
    for serv in serv_dict:
        ports = serv_dict[serv]
        if re.search(r"http[^s]", serv):
            for port in ports:
                port = port.split("/")[0]
                multProc(httpEnum.httpEnum, ip_address, port)
        elif re.search(r"https|ssl", serv):
            for port in ports:
                port = port.split("/")[0]
                multProc(httpsEnum.httpsEnum, ip_address, port)
        elif "smtp" in serv:
            for port in ports:
                port = port.split("/")[0]
                multProc(smtpEnum.smtpEnum, ip_address, port)
        elif "ftp" in serv:
            for port in ports:
                port = port.split("/")[0]
                multProc(ftpEnum.ftpEnum, ip_address, port)
        elif ("microsoft-ds" in serv) or ("netbios-ssn" == serv):
            for port in ports:
                port = port.split("/")[0]
                multProc(smbEnum.smbEnum, ip_address, port)
                multProc(smbNmap.smbNmap, ip_address, port)
        elif "ms-sql" in serv:
            for port in ports:
                port = port.split("/")[0]
                multProc(mssqlEnum.mssqlEnum, ip_address, port)
        elif "ssh" in serv:
            for port in ports:
                port = port.split("/")[0]
                multProc(sshScan.sshScan, ip_address, port)
        # this snmp doesnt even exist
        elif "snmp" in serv:
            for port in ports:
               port = port.split("/")[0]
               multProc(snmpEnum.snmpEnum, ip_address, port)

    return