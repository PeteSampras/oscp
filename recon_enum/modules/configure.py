import argparse
import os
import subprocess
from modules.utility_functions import multProc as mp,write_to_file as w2f,bcolors, replace_file as rf
import fileinput
import atexit

# call functions
def dig_func(ip_addr):
    dig(ip_addr)

def configure_scan(parser):
    #parser = argparse.ArgumentParser(my_args)
    print(bcolors.HEADER)
    print("------------------------------------------------------------")
    print(parser.prog + " - " + parser.description)
    print("------------------------------------------------------------")
    print(bcolors.ENDC)
    #add global parses
    parser.add_argument('--mode','-m',
                        nargs=1,
                        help='Specific mode you want to use: QUIET, ALL',
                        choices=['ALL','PASSIVE','STEALTH','ACTIVE'],
                        default="ALL")
    parser.add_argument('--ip','-i',
                        nargs='*',
                        help='List of IP address you want to target')
    parser.add_argument('--port','-p',
                        nargs='?',
                        help='List of ports you want to target')
    parser.add_argument('--udp','-u', action='store_true',
                        help='Scan UDP?')

    # add subparses
    subparsers=parser.add_subparsers(help='Module specific utilities')
    parser_dig = subparsers.add_parser('dig',
                        parents=[parser],
                        help='Finds DNS information about a target')
    parser_dig.set_defaults(func=dig_func)


    # create folders for parses
    args= parser.parse_args()
    for each in args.ip:
        create_folder(args.ip)
    return

def create_folder(targets):
    # see what needs created.
    dirs = os.listdir("../reports/")
    for scanip in targets:
        scanip = scanip.rstrip()
        if not scanip in dirs:
            print(bcolors.HEADER + "INFO: No folder was found for " + scanip + ". Setting up folder." + bcolors.ENDC)
            subprocess.check_output("mkdir ../reports/" + scanip, shell=True)
            subprocess.check_output("mkdir ../reports/" + scanip + "/exploits", shell=True)
            subprocess.check_output("mkdir ../reports/" + scanip + "/privesc", shell=True)
            print(bcolors.OKGREEN + "INFO: Folder created here: " + "../reports/" + scanip + bcolors.ENDC)
            subprocess.check_output("cp ../templates/windows-template.md ../reports/" + scanip + "/mapping-windows.md", shell=True)
            subprocess.check_output("cp ../templates/linux-template.md ../reports/" + scanip + "/mapping-linux.md", shell=True)
            print(bcolors.OKGREEN + "INFO: Added pentesting templates: " + "../reports/" + scanip + bcolors.ENDC)
            subprocess.check_output("sed -i -e 's/INSERTIPADDRESS/" + scanip + "/g' ../reports/" + scanip + "/mapping-windows.md", shell=True)
            subprocess.check_output("sed -i -e 's/INSERTIPADDRESS/" + scanip + "/g' ../reports/" + scanip + "/mapping-linux.md", shell=True)
    return