import socket
import multiprocessing
from multiprocessing import Process, Queue
import fileinput
import atexit

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

def connect_to_port(ip_address, port, service):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((ip_address, int(port)))
    banner = s.recv(1024)

    if service == "ftp":
        m="USER anonymous\r\n"
        byt=m.encode()
        s.send(byt)
        user = s.recv(1024)
        m="PASS anonymous\r\n"
        byt=m.encode()
        s.send(byt)
        password = s.recv(1024)
        m="STAT\r\n"
        byt=m.encode()
        s.send(byt)
        stat = s.recv(1024)
        m="SYST\r\n"
        byt=m.encode()
        s.send(byt)
        syst = s.recv(1024)
        total_communication = str(banner) + "\r\n" + str(user.decode()) + "\r\n" + str(password.decode())+ "\r\n" + str(stat.decode())+ "\r\n" + str(syst.decode())
        write_to_file(ip_address, "ftp-banner", total_communication)
    elif service == "smtp":
        total_communication = banner + "\r\n"
        write_to_file(ip_address, "smtp-banner", total_communication)
    elif service == "ssh":
        total_communication = banner
        write_to_file(ip_address, "ssh-banner", total_communication)
    elif service == "pop3":
        s.send("USER root\r\n")
        user = s.recv(1024)
        s.send("PASS root\r\n")
        password = s.recv(1024)
        total_communication = banner +  user +  password
        write_to_file(ip_address, "pop3-banner", total_communication)
    s.close()

# Creates a function for multiprocessing. Several things at once.
def multProc(targetin, scanip, port):
    jobs = []
    p = multiprocessing.Process(target=targetin, args=(scanip,port))
    jobs.append(p)
    p.start()
    return

def replace_file(path,this,that):
    for line in fileinput.input(path,inplace=True):
        if isinstance(this,str):
            if isinstance(that,str):
                that = that.strip()
            else:
                that = that.decode('UTF-8').strip()
            print(line.replace(this,str(that)),end="")        
        else:
            print(line.replace(this,str(that).decode('UTF-8').strip()),end="")


def write_to_file(ip_address,enum_type,data):
    ip_address = ip_address.strip()
    file_path_linux = '../reports/%s/mapping-linux.md' % (ip_address)
    file_path_windows = '../reports/%s/mapping-windows.md' % (ip_address)
    paths = [file_path_linux, file_path_windows]
    print(bcolors.OKGREEN + "INFO: Writing " + enum_type + " to template files:\n " + file_path_linux + "   \n" + file_path_windows + bcolors.ENDC)
    for path in paths:
        if enum_type == "portscan":
            replace_file(path,"INSERTTCPSCAN",data)
            #new = data.decode('UTF-8').strip()
            #subprocess.check_output("replace INSERTTCPSCAN \"" + str(data) + "\"  -- " + path, shell=True)
        if enum_type == "udpscan":
            replace_file(path,"INSERTUDPSCAN",data)
            # subprocess.check_output("replace INSERTTCPSCAN \"" + data + "\"  -- " + path, shell=True)
        if enum_type == "dirb":
            replace_file(path,"INSERTDIRBSCAN",data)
            #subprocess.check_output("replace INSERTDIRBSCAN \"" + data + "\"  -- " + path, shell=True)
        if enum_type=="dig":
            replace_file(path,"INSERTDIGSCAN",data)
        if enum_type == "nikto":
            replace_file(path,"INSERTNIKTOSCAN",data)
            #subprocess.check_output("replace INSERTNIKTOSCAN \"" + data + "\"  -- " + path, shell=True)
        if enum_type == "ftp-banner":
            replace_file(path,"INSERTFTPTEST",data)
            #subprocess.check_output("replace INSERTFTPTEST \"" + data + "\"  -- " + path, shell=True)
        if enum_type == "ftp-scan":
            replace_file(path,"INSERTFTPSCAN",data)    
        if enum_type == "smtp-banner":
            replace_file(path,"INSERTSMTPCONNECT",data)
            #subprocess.check_output("replace INSERTSMTPCONNECT \"" + data + "\"  -- " + path, shell=True)
        if enum_type == "ssh-banner":
            replace_file(path,"INSERTSSHBANNER",data)
        if enum_type == "ssh-connect":
            replace_file(path,"INSERTSSHCONNECT",data)
            #subprocess.check_output("replace INSERTSSHCONNECT \"" + data + "\"  -- " + path, shell=True)
        if enum_type == "pop3-banner":
            replace_file(path,"INSERTPOP3CONNECT",data)
            #subprocess.check_output("replace INSERTPOP3CONNECT \"" + data + "\"  -- " + path, shell=True)
        if enum_type == "curl":
            replace_file(path,"INSERTCURLHEADER",data)
            #subprocess.check_output("replace INSERTCURLHEADER \"" + data + "\"  -- " + path, shell=True)
    return