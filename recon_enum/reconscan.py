#!/usr/bin/env python
import time
import multiprocessing
from multiprocessing import Process, Queue, Manager
import subprocess
import sys
import argparse
from modules.utility_functions import multProc as mp,write_to_file as w2f,bcolors, replace_file as rf
from modules.configure import configure_scan
import modules.dig as dig
import modules.dirb as dirb
import modules.ftpEnum as ftpEnum
import modules.httpEnum as httpEnum
import modules.httpsEnum as httpsEnum
import modules.mssqlEnum as mssqlEnum
import modules.nikto as nikto
import modules.nmapScan as nmapScan
import modules.pop3scan as pop3scan
import modules.smbEnum as smbEnum
import modules.smbNmap as smbNmap
import modules.smtpEnum as smtpEnum
import modules.sshScan as sshScan
import modules.udpScan as udpScan

start = time.time()

if __name__=='__main__':
    if len(sys.argv) < 2: # no args passed, print help and exit
        function = str(sys.argv[0])
        subprocess.call('python', '{}', '-h'.format(function))
        sys.exit()

    parser = argparse.ArgumentParser(prog='Recon scan',
                                    add_help=False,
                                    description='A multi-process service scanner')
    # configuration
    configure_scan(parser)
 
    args= parser.parse_args()
    # setup a dictionary for nmap return values to scan
    #manager = multiprocessing.Manager()
    #return_dict = manager.dict()
    return_dict={}
    # now we perform scans
    for ip in args.ip:
        # do a dig first regardless of mode
        p = multiprocessing.Process(target=dig.dig, args=(ip,))
        p.start()
        # now do the appropriate nmap for mode type
        nmapScan.nmapScan(ip,args.mode,return_dict,)
        #p = multiprocessing.Process(target=nmapScan.nmapScan, 
        #                            args=(ip,args.mode,return_dict,))
        #p.start()
        # UDP SCAN GOES HERE BUT LETS COMMENT IT OUT FOR NOW AND MOVE IT BELOW LATER
        if args.udp==False: 
            udpScan.udpScan(ip_address)
        
        results = return_dict[ip]
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
        if args.mode=='STEALTH' or args.mode=='PASSIVE':
            print("Scan complete")
            sys.exit()
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


