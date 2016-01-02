#!/usr/bin/env python
import subprocess
import sys

if len(sys.argv) != 2:
    print "Usage: dnsrecon.py <ip address>"
    sys.exit(0)

ip_address = sys.argv[1]
HOSTNAME = "host %s | cut -d ' ' -f5 | cut -d '.' -f1,2,3" % (ip_address)
DOMAINNAME = "host %s | cut -d ' ' -f5 | cut -d '.' -f2,3" % (ip_address)

print "INFO: Performing nmap DNS script scan for " + ip_address + ":" + port
DNSSCAN = "nmap -sV -Pn -vv -p T:53 U:53 --script=dns-* -oN './results/%s_dns.nmap' %s" % (ip_address, ip_address)
results = subprocess.check_output(DNSSCAN, shell=True)
outfile = "results/" + ip_address + "_dnsrecon.txt"
f = open(outfile, "w")
f.write(results)
f.close

# grab the hostname
host = subprocess.check_output(HOSTNAME, shell=True).strip()
domain = subprocess.check_output(DOMAINNAME, shell=True).strip()
print "INFO: Attempting Domain Transfer on " + host
ZT = "dig @%s %s axfr" % (host, domain)
ztresults = subprocess.check_output(ZT, shell=True)
if "failed" in ztresults:
    print "INFO: Zone Transfer failed for " + host
else:
    print "[*] Zone Transfer successful for " + host + "(" + ip_address + ")!!! [see output file]"
    outfile = "./results/" + ip_address+ "_zonetransfer.txt"
    dnsf = open(outfile, "w")
    dnsf.write(ztresults)
    dnsf.close()
