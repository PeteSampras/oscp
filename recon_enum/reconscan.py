#!/usr/bin/env python
from modules.imports import *

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

