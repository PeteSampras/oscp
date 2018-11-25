#!/usr/bin/env python
from modules.imports import *

start = time.time()

if __name__=='__main__':
    if len(sys.argv) < 2:
        function = str(sys.argv[0])
        subprocess.call('python', '{}', '-h'.format(function))
        sys.exit()

    parser = argparse.ArgumentParser(prog='Recon scan',
                                    description='A multi-process service scanner')
    # configuration
    configure_scan(parser)
 
    
    #     # do a dig first
    #     p = multiprocessing.Process(target=dig, args=(scanip,))
    #     p.start()

    #     # next use nmap
    #     p = multiprocessing.Process(target=nmapScan, args=(scanip,))
    #     p.start()

