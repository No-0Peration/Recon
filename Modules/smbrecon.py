#!/usr/bin/python
import subprocess
import sys
import os

from Modules import recon

if len(sys.argv) != 2:
    print "Usage: smbrecon.py <ip address>"
    sys.exit(0)

ip = sys.argv[1]
recon.checkpath("./results/" + ip)
try:
    print "\033[1;37m[-]  ----------------------------------------------------------------------------- \033[1;m"
    print('\033[1;37m[-]  |     Starting SMB script scan for {0}\033[1;m'.format(ip))
    print "\033[1;37m[-]  ----------------------------------------------------------------------------- \033[1;m"
    VULNSCAN = "nmap -sV -Pn -vv -p445,139 --script=smb-vuln* --script-args=unsafe=1 -oN './results/{0}/{0}_smb.nmap' {0}".format(ip)
    scanresults = subprocess.check_output(VULNSCAN, shell=True)
    recon.logparsertxt(scanresults)
    if ("445/tcp closed" not in scanresults):
        lines = scanresults.split("\n")
        for line in lines:
            if ("|" in line) or (" . " in line):
                print '\033[1;32m[+]  ' + line + '\033[1;m'
    NBTSCAN = "./samrdump.py %s" % (ip)
    nbtresults = subprocess.check_output(NBTSCAN, shell=True)
    if ("Connection refused" not in nbtresults) and ("Connect error" not in nbtresults) and ("Connection reset" not in nbtresults):
        print('\033[1;32m[+]  SAMRDUMP has connected to {0} if there are results displaying them below\033[1;m'.format(ip))
        lines = nbtresults.split("\n")
        for line in lines:
            if ("Found" in line) or (" . " in line):
                print '\033[1;32m[+]  ' + line + '\033[1;m'
    E4L = "enum4linux {0}".format(ip)
    e4lresults = subprocess.check_output(E4L, shell=True)
    recon.logparserall(e4lresults)
except:
    print('\033[1;31m[-]  SMB script scan for {0} had some errors.\033[1;m'.format(ip))
os.system('stty echo')