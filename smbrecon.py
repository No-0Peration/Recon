#!/usr/bin/python
import sys
import subprocess

if len(sys.argv) != 2:
    print "Usage: smbrecon.py <ip address>"
    sys.exit(0)

ip = sys.argv[1]
print "[*] Starting SMB vulnerability checks on %s" % (ip)
VULNSCAN = "nmap -sV -Pn -vv -p445 --script=smb-vuln-conficker.nse,smb-vuln-cve2009-3103.nse,smb-vuln-ms06-025.nse,smb-vuln-ms07-029.nse,smb-vuln-ms08-067.nse,smb-vuln-ms10-054.nse,smb-vuln-ms10-061.nse --script-args=unsafe=1 -oN './results/{0}/{0}_smb.nmap' {0}".format(ip)
scanresults = subprocess.check_output(VULNSCAN, shell=True)
if ("445/tcp closed" not in scanresults):
    lines = scanresults.split("\n")
    for line in lines:
        if ("|" in line) or (" . " in line):
            print "   [+] " + line
NBTSCAN = "./samrdump.py %s" % (ip)
nbtresults = subprocess.check_output(NBTSCAN, shell=True)
if ("Connection refused" not in nbtresults) and ("Connect error" not in nbtresults) and ("Connection reset" not in nbtresults):
    print "[*] SAMRDUMP User accounts/domains found on " + ip
    lines = nbtresults.split("\n")
    for line in lines:
        if ("Found" in line) or (" . " in line):
            print "   [+] " + line
