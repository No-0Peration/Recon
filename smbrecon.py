#!/usr/bin/python
import sys
import subprocess

if len(sys.argv) != 2:
    print "Usage: smbrecon.py <ip address>"
    sys.exit(0)

ip_address = sys.argv[1]
print "[*] Starting SMB vulnerability checks on {0}".format(ip_address)
VULNSCAN = "nmap -sV -Pn -vv -p445 --script=smb-check-vulns.nse,smb-vuln-* --script-args=unsafe=1 -oN './results/{0}/{0}_smb.nmap' {0}".format(ip_address)
scanresults = subprocess.check_output(VULNSCAN, shell=True)
if ("445/tcp closed" not in scanresults):
    lines = scanresults.split("\n")
    for line in lines:
        if ("|" in line) or (" . " in line):
            print "   [+] " + line
NBTSCAN = "./samrdump.py {0}".format(ip_address)
nbtresults = subprocess.check_output(NBTSCAN, shell=True)
if ("Connection refused" not in nbtresults) and ("Connect error" not in nbtresults) and ("Connection reset" not in nbtresults):
    print "[*] SAMRDUMP User accounts/domains found on {0}".format(ip_address)
    lines = nbtresults.split("\n")
    for line in lines:
        if ("Found" in line) or (" . " in line):
            print "   [+] " + line
