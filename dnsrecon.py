#!/usr/bin/env python
import subprocess
import sys

if len(sys.argv) != 2:
    print "Usage: dnsrecon.py <ip address>"
    sys.exit(0)

ip_address = sys.argv[1]
HOSTNAME = "host %s | cut -d ' ' -f5 | cut -d '.' -f1,2,3" % (ip_address)
DOMAINNAME = "host %s | cut -d ' ' -f5 | cut -d '.' -f2,3" % (ip_address)
port = 25

print('\033[1;34m[*]  Performing nmap DNS script scan for {0}:{1}\033[1;m'.format(ip_address, port))
DNSSCAN = "nmap -sV -Pn -vv -p T:53 U:53 --script=dns-* -oN './results/{0}/{0}_dns.nmap' {0}".format(ip_address)
results = subprocess.check_output(DNSSCAN, shell=True)
outfile = "results/{0}/{0}_dnsrecon.txt".format(ip_address)
f = open(outfile, "w")
f.write(results)
f.close

# grab the hostname
host = subprocess.check_output(HOSTNAME, shell=True).strip()
domain = subprocess.check_output(DOMAINNAME, shell=True).strip()
print('\033[1;34m[*]  Attempting Domain Transfer on {0}\033[1;m'.format(host))
ZT = "dig @{0} {1} axfr".format(host, domain)
ztresults = subprocess.check_output(ZT, shell=True)
if "failed" in ztresults:
    print('\033[1;34m[*]  Zone Transfer failed for {0}\033[1;m'.format(host))
else:
    print('\033[1;32m[*]  Zone Transfer successful for on {0} see output file!!\033[1;m'.format(host))
    outfile = "results/{0}/{0}_zonetransfer.txt".format(ip_address)
    dnsf = open(outfile, "w")
    dnsf.write(ztresults)
    dnsf.close()
