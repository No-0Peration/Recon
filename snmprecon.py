#!/usr/bin/env python
import subprocess
import sys
import os

if len(sys.argv) != 2:
    print "Usage: snmprecon.py <ip address>"
    sys.exit(0)

snmpdetect = 0
ip_address = sys.argv[1]

fastscan = "nmap -sn {0} | grep \"Nmap scan report for\" | cut -d \" \" -f5".format(str(ip_address))
scanresults = subprocess.check_output(fastscan, shell=True)

targets=[]

for ip_address in (str(scanresults)).split():
    ONESIXONESCAN = "onesixtyone {0} > ./results/{0}/{0}_onesixtyone".format(ip_address)
    results = subprocess.check_output(ONESIXONESCAN, shell=True).strip()

    with open("./results/{0}/{0}_onesixtyone".format(ip_address)) as f:
        lines = f.readlines()
        last = lines[-1]
        for line in lines:
            if line is last:
                if 'Scanning 1 hosts, 2 communities' in line:
                    os.remove("./results/{0}/{0}_onesixtyone".format(ip_address))
                else:
                    targets.append(ip_address)

for ip_address in targets:
    # print "[*] SNMPCHECK running on {0}".format(ip_address)
    # SNMPCHECK = "snmpcheck -t {0} > ./results/{0}/{0}_snmpcheck".format(ip_address)
    # with open(os.devnull, "w") as f:
    #     subprocess.call(SNMPCHECK, shell=True, stdout=f)
    print "[*] SNMPWALK running on {0}".format(ip_address)
    SNMPWALK = "snmpwalk -c public -v1 {0} 1 > ./results/{0}/{0}_snmpwalk".format(ip_address)
    results = subprocess.call(SNMPWALK, shell=True)

    print "[*] NMAP scan running on {0}".format(ip_address)
    NMAPSCAN = "nmap -vv -sV -sU -Pn -p 161,162 --script=snmp-netstat,snmp-processes,snmp-interfaces.nse,snmp-ios-config.nse,snmp-sysdescr.nse,snmp-win32-services.nse,snmp-win32-shares.nse,snmp-win32-software.nse,snmp-win32-users.nse -oN ./results/{0}/{0}_snmp_nmap {0}".format(ip_address)
    with open(os.devnull, "w") as f:
            subprocess.call(NMAPSCAN, shell=True, stdout=f)
