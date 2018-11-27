#!/usr/bin/env python
import time
import multiprocessing
from multiprocessing import Process, Queue
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

    # now we perform scans
    for ip in args.ip:
        # do a dig first regardless of mode
        p = multiprocessing.Process(target=dig.dig, args=(ip,))
        p.start()
        # now do the appropriate nmap for mode type
        p = multiprocessing.Process(target=nmapScan.nmapScan, args=(ip,args.mode,args.udp,))
        p.start()
        # if args.mode=='STEALTH':
        #     p = multiprocessing.Process(target=nmapScan.nmapScan, args=(ip,args.mode,args.udp,))
        #     p.start()
        #     break
        # if args.mode=='PASSIVE':
        #     nmapScan(ip,args.mode,args.udp)
        #     break
        # if args.mode=='ACTIVE':
        #     nmapScan(ip,args.mode,args.udp)
        #     break
        # if args.mode=='ALL':
        #     #nmapScan(ip,args.mode,args.udp)
        #     p = multiprocessing.Process(target=nmapScan.nmapScan, args=(ip,args.mode,args.udp,))
        #     p.start()
        #     break
    #     # next use nmap
    #     p = multiprocessing.Process(target=nmapScan, args=(scanip,))
    #     p.start()

