from modules.imports import *

def dig(ip_address):
    print(bcolors.HEADER + "INFO: Starting dig scan for " + ip_address + bcolors.ENDC)
    DIGSCAN = "dig " + ip_address
    print(bcolors.HEADER + DIGSCAN + bcolors.ENDC)
    results_dig = subprocess.check_output(DIGSCAN, shell=True)
    print(bcolors.OKGREEN + "INFO: RESULT BELOW - Finished with dig scan for " + ip_address + bcolors.ENDC)
    this=results_dig.decode().replace("<<-","")
    print(this)
    write_to_file(ip_address, "dig", this)
    return