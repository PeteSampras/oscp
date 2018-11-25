import subprocess
import multiprocessing
from multiprocessing import Process, Queue
import os
import time
import fileinput
import atexit
import sys
import socket
import re
import argparse
from modules.utility_functions import multProc,write_to_file,bcolors, replace_file,connect_to_port
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