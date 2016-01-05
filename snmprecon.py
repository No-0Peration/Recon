#!/usr/bin/env python
import subprocess
import sys

if len(sys.argv) != 2:
    print "Usage: snmprecon.py <ip address>"
    sys.exit(0)

snmpdetect = 0
ip_address = sys.argv[1]

ONESIXONESCAN = "onesixtyone %s" % (ip_address)
results = subprocess.check_output(ONESIXONESCAN, shell=True).strip()

if results != "":
    if "Windows" in results:
        results = results.split("Software: ")[1]
        snmpdetect = 1
    elif "Linux" in results:
        results = results.split("[public] ")[1]
        snmpdetect = 1
    if snmpdetect == 1:
        print "[*] SNMP running on {0}; OS Detect: {1}".format(ip_address, results)
        SNMPWALK = "snmpwalk -c public -v1 {0} 1 > results/{0}/{0}_snmpwalk.txt".format(ip_address)
        results = subprocess.check_output(SNMPWALK, shell=True)

NMAPSCAN = "nmap -vv -sV -sU -Pn -p 161,162 --script=snmp-netstat,snmp-processes snmp-info.nse,snmp-interfaces.nse,snmp-ios-config.nse,snmp-sysdescr.nse,snmp-win32-services.nse,snmp-win32-shares.nse,snmp-win32-software.nse,snmp-win32-users.nse {0}".format(ip_address)
results = subprocess.check_output(NMAPSCAN, shell=True)
outfile = "results/{0}/{0}_snmprecon.txt".format(ip_address)
f = open(outfile, "w")
f.write(results)
f.close

