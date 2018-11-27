import subprocess
from modules.utility_functions import *

def mssqlEnum(ip_address, port):
    print(bcolors.HEADER + "INFO: Detected MS-SQL on " + ip_address + ":" + port + bcolors.ENDC)
    print(bcolors.HEADER + "INFO: Performing nmap mssql script scan for " + ip_address + ":" + port + bcolors.ENDC)
    MSSQLSCAN = "nmap -sV -Pn -p "+str(port)+" --script=ms-sql-info,ms-sql-config,ms-sql-dump-hashes,mysql-empty-password,mysql-brute,mysql-users,mysql-variables,mysql-vuln-cve2012-2122 --script-args=mssql.instance-port=1433,mssql.username=sa,mssql.password=sa -oN ../reports/"+str(ip_address)+"/mssql_%s.nmap "+str(ip_address)
    print(bcolors.HEADER + MSSQLSCAN + bcolors.ENDC)
    mssql_results = subprocess.check_output(MSSQLSCAN, shell=True)
    print(bcolors.OKGREEN + "INFO: RESULT BELOW - Finished with MSSQL-scan for " + ip_address + bcolors.ENDC)
    print(mssql_results.decode())
    return