from modules.imports import *

# nmap has to be after all the other functions since it calls them. 
# Otherwise call functions need to be exported from this function.
def nmapScan(ip_address):
    ip_address = ip_address.strip()
    print(bcolors.OKGREEN + "INFO: Running general TCP/UDP nmap scans for " + ip_address + bcolors.ENDC)

    # FULL SCAN
    TCPSCAN = "nmap -sV -O -p- %s -oN '../reports/%s/%s.nmap'"  % (ip_address, ip_address, ip_address)
    # PARTIAL SCAN
    #TCPSCAN = "nmap -sV -O %s -oN '../reports/%s/%s.nmap'"  % (ip_address, ip_address, ip_address)
    print(bcolors.HEADER + TCPSCAN + bcolors.ENDC)
    results = subprocess.check_output(TCPSCAN, shell=True)
    print(bcolors.OKGREEN + "INFO: RESULT BELOW - Finished with BASIC Nmap-scan for " + ip_address + bcolors.ENDC)
    print(results.decode())
    write_to_file(ip_address, "portscan", results)

    # UDP SCAN GOES HERE BUT LETS COMMENT IT OUT FOR NOW AND MOVE IT BELOW LATER
    #p = multiprocessing.Process(target=udpScan, args=(ip_address,))
    #p = multiprocessing.Process(target=udpScan, args=(scanip,))
    #p.start()
    # multi process is screwing up. let's do it single core.
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

   # go through the service dictionary to call additional targeted enumeration functions
    for serv in serv_dict:
        ports = serv_dict[serv]
        if re.search(r"http[^s]", serv):
            for port in ports:
                port = port.split("/")[0]
                multProc(httpEnum, ip_address, port)
        elif re.search(r"https|ssl", serv):
            for port in ports:
                port = port.split("/")[0]
                multProc(httpsEnum, ip_address, port)
        elif "smtp" in serv:
            for port in ports:
                port = port.split("/")[0]
                multProc(smtpEnum, ip_address, port)
        elif "ftp" in serv:
            for port in ports:
                port = port.split("/")[0]
                multProc(ftpEnum, ip_address, port)
        elif ("microsoft-ds" in serv) or ("netbios-ssn" == serv):
            for port in ports:
                port = port.split("/")[0]
                multProc(smbEnum, ip_address, port)
                multProc(smbNmap, ip_address, port)
        elif "ms-sql" in serv:
            for port in ports:
                port = port.split("/")[0]
                multProc(mssqlEnum, ip_address, port)
        elif "ssh" in serv:
            for port in ports:
                port = port.split("/")[0]
                multProc(sshScan, ip_address, port)
        elif "snmp" in serv:
            for port in ports:
               port = port.split("/")[0]
               multProc(snmpEnum, ip_address, port)

    return