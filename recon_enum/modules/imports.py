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
from modules.utility_functions import multProc as mp,write_to_file as w2f,bcolors, replace_file as rf
from modules.configure import configure_scan
import modules.dig
import modules.dirb
import modules.ftpEnum
import modules.httpEnum
import modules.httpsEnum
import modules.mssqlEnum
import modules.nikto
import modules.nmapScan
import modules.pop3scan
import modules.smbEnum
import modules.smbNmap
import modules.smtpEnum
import modules.sshScan
import modules.udpScan