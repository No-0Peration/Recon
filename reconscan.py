#!/usr/bin/env python
'''
 Author: Gerben Visser (0x90) -- @N0_Operation & Bas -- B0x41S & Sander -- DTCTD.
 This tool is an automation script for the reconphase during a pentest, it was inspired by a few github repos.
'''

import os
import sys
import subprocess
import gzip
import re
import recon  # All functions called by the main scanner function


def scanner(ip_address):
    # Start function which takes ip_address to scan as argument
    ip_address = str(ip_address)
    recon.checkpath("./results/{0}".format(ip_address))

    if not recon.checknmaprun(ip_address, "_nmap_scan_import.xml"):
        print('\033[1;34m[*]  Starting new TCP nmap scan for {0}\033[1;m'.format(ip_address))
        tcpscan = "nmap -vv -Pn -A -O -sS -sV --open -oN './results/{0}/{0}.nmap' -oX './results/{0}/{0}_nmap_scan_import.xml' {0}".format(ip_address)
        with open(os.devnull, "w") as f:
            subprocess.call(tcpscan, shell=True, stdout=f)
        tcpresults = file("./results/{0}/{0}_nmap_scan_import.xml".format(ip_address), "r")
        lines = tcpresults
    else:
        print('\033[1;34m[*]  {0} already scanned for TCP ports...\033[1;m'.format(ip_address))
        tcpresults = file("./results/{0}/{0}_nmap_scan_import.xml".format(ip_address), "r")
        lines = tcpresults

    # The forloop below parses the TCP nmap results and looks for open service on which it knows to act.
    serv_dict = {}
    for line in lines:
        ports = []
        if ("tcp" in line) and ("open" in line) and ("service name=" in line) and not ("Discovered" in line):
            port = (re.search("portid=\"(.*?)\"", line))
            service = (re.search("service name=\"(.*?)\"", line))
            port = (port.group().split("\""))[1]
            service = (service.group().split("\""))[1]

            if service in serv_dict:
                ports = serv_dict[service]  # if the service is already in the dict, grab the port list

            ports.append(port)
            serv_dict[service] = ports  # add service to the dictionary along with the associated port(2)

        for port in ports:
            print('\033[1;32m[*]  Open TCP port {0} found on {1}\033[1;m'.format(port, ip_address))

    # Go through the service dictionary to call additional targeted enumeration functions
    for serv in serv_dict:
        ports = serv_dict[serv]
        if serv == "http" in serv:
            for port in ports:
                port = port.split("/")[0]
                recon.multProc(recon.httpEnum, ip_address, port)
        elif serv == "ssl/http" or "https" in serv:
            for port in ports:
                port = port.split("/")[0]
                recon.multProc(recon.httpEnum, ip_address, port)
        elif "ssh" in serv:
            for port in ports:
                port = port.split("/")[0]
                recon.multProc(recon.sshEnum, ip_address, port)
        elif "smtp" in serv:
            for port in ports:
                port = port.split("/")[0]
                recon.multProc(recon.smtpEnum, ip_address, port)
        elif "snmp" in serv:
            for port in ports:
                port = port.split("/")[0]
                recon.multProc(recon.snmpEnum, ip_address, port)
        elif "domain" in serv:
            for port in ports:
                port = port.split("/")[0]
                recon.multProc(recon.dnsEnum, ip_address, port)
        elif "ftp" in serv:
            for port in ports:
                port = port.split("/")[0]
                recon.multProc(recon.ftpEnum, ip_address, port)
        elif "microsoft-ds" in serv:
            for port in ports:
                port = port.split("/")[0]
                recon.multProc(recon.smbEnum, ip_address, port)
        elif "ms-sql" in serv:
            for port in ports:
                port = port.split("/")[0]
                recon.multProc(recon.mssqlEnum, ip_address, port)
        elif "telnet" in serv:
            for port in ports:
                port = port.split("/")[0]
                recon.multProc(recon.telnetEnum, ip_address, port)


    if not recon.checknmaprun(ip_address, "U_nmap_scan_import.xml"):
        print('\033[1;34m[*]  Starting new UDP nmap scan for {0}\033[1;m'.format(ip_address))
        udpscan = "nmap -vv -Pn -sU -sV -A -O -p 53,67,68,88,161,162,137,138,139,389,520,2049 -oN './results/{0}/{0}U.nmap' -oX './results/{0}/{0}U_nmap_scan_import.xml' {0}".format(ip_address)
        with open(os.devnull, "w") as f:
            subprocess.call(udpscan, shell=True, stdout=f)
        udpresults = file("./results/{0}/{0}U_nmap_scan_import.xml".format(ip_address), "r")
        lines = udpresults
    else:
        print('\033[1;34m[*]  {0} already scanned for UDP ports...\033[1;m'.format(ip_address))
        udpresults = file("./results/{0}/{0}U_nmap_scan_import.xml".format(ip_address), "r")
        lines = udpresults

     # The forloop below parses the UDP nmap results and looks for open service on which it knows to act.
    serv_dict = {}
    for line in lines:
        ports = []
        if ("udp" in line) and ("open" in line) and ("service name=" in line) and not ("Discovered" in line):
            port = (re.search("portid=\"(.*?)\"", line))
            service = (re.search("service name=\"(.*?)\"", line))
            port = (port.group().split("\""))[1]
            service = (service.group().split("\""))[1]

            if service in serv_dict:
                ports = serv_dict[service]  # if the service is already in the dict, grab the port list

            ports.append(port)
            serv_dict[service] = ports  # add service to the dictionary along with the associated port(2)

        for port in ports:
            print('\033[1;32m[*]  Open UDP port {0} found on {1}\033[1;m'.format(port, ip_address))

    # Go through the service dictionary to call additional targeted enumeration functions
    for serv in serv_dict:
        ports = serv_dict[serv]
        if serv == "http" in serv:
            for port in ports:
                port = port.split("/")[0]
                recon.multProc(recon.httpEnum, ip_address, port)
        elif serv == "ssl/http" or "https" in serv:
            for port in ports:
                port = port.split("/")[0]
                recon.multProc(recon.httpEnum, ip_address, port)
        elif "ssh" in serv:
            for port in ports:
                port = port.split("/")[0]
                recon.multProc(recon.sshEnum, ip_address, port)
        elif "smtp" in serv:
            for port in ports:
                port = port.split("/")[0]
                recon.multProc(recon.smtpEnum, ip_address, port)
        elif "snmp" in serv:
            for port in ports:
                port = port.split("/")[0]
                recon.multProc(recon.snmpEnum, ip_address, port)
        elif "domain" in serv:
            for port in ports:
                port = port.split("/")[0]
                recon.multProc(recon.dnsEnum, ip_address, port)
        elif "ftp" in serv:
            for port in ports:
                port = port.split("/")[0]
                recon.multProc(recon.ftpEnum, ip_address, port)
        elif "microsoft-ds" in serv:
            for port in ports:
                port = port.split("/")[0]
                recon.multProc(recon.smbEnum, ip_address, port)
        elif "ms-sql" in serv:
            for port in ports:
                port = port.split("/")[0]
                recon.multProc(recon.mssqlEnum, ip_address, port)
        elif "telnet" in serv:
            for port in ports:
                port = port.split("/")[0]
                recon.multProc(recon.telnetEnum, ip_address, port)


    print('\033[1;34m[*]  TCP/UDP Nmap scans completed for {0}\033[1;m'.format(ip_address))
    return

# grab the discover scan results and start scanning up hosts
print '\033[1;32m .d8888b.          .d8888b.  .d8888b. d8b                   8888888b.\033[1;m'
print '\033[1;32md88P  Y88b        d88P  Y88bd88P  Y88b88P                   888   Y88b\033[1;m'
print '\033[1;32m888    888        888    888888    8888P                    888    888\033[1;m'
print '\033[1;32m888    888888  888Y88b. d888888    888  .d8888b             888   d88P .d88b.  .d8888b .d88b. 88888b.\033[1;m'
print '\033[1;32m888    888`Y8bd8P   Y888P888888    888  88K                 8888888P  d8P  Y8bd88P    d88  88b888  88b\033[1;m'
print '\033[1;32m888    888  X88K         888888    888  "Y8888b.   888888   888 T88b  88888888888     888  888888  888\033[1;m'
print '\033[1;32mY88b  d88P.d8  8b.Y88b  d88PY88b  d88P       X88            888  T88b Y8b.    Y88b.   Y88..88P888  888\033[1;m'
print '\033[1;32m "Y8888P" 888  888 "Y8888P"  "Y8888P"    88888P             888   T88b "Y8888  "Y8888P "Y88P" 888  888\033[1;m'
print ''
print '\033[1;32m//////////////////////////////////////////////////////////////////////////////////////////////////////\033[1;m'
print '\033[1;32m///                      with help from the awesome B0x41S & DTCTD                                 ///\033[1;m'
print '\033[1;32m//////////////////////////////////////////////////////////////////////////////////////////////////////\033[1;m'
print ''


if __name__ == '__main__':
    try:
        recon.checkpath("./results/")
    except:
        pass

    # Check if root
if os.getuid() == 0:
    print('\033[1;32m[*]  Checking permissions\033[1;m')
else:
    sys.exit("I cannot run as a mortal. Sorry.")

if os.path.isfile("/usr/share/wordlists/rockyou.txt"):
    print('\033[1;32m[*]  Rockyou wordlist present\033[1;m')
else:
    print('\033[1;31m[*]  Rockyou wordlist is missing trying to decompress...\033[1;m')
    try:
        inFile = gzip.GzipFile("/usr/share/wordlists/rockyou.txt.gz", "rb")
        s = inFile.read()
        inFile.close()

        outFile = file("/usr/share/wordlists/rockyou.txt", "wb")
        outFile.write(s)
        outFile.close()
    except:
        pass
    if os.path.isfile("/usr/share/wordlists/rockyou.txt"):
        print('\033[1;32m[*]  Rockyou wordlist is decompressed!\033[1;m')
    else:
        print('\033[1;31m[*]  Decompression of rockyou.txt failed!\033[1;m')

ips = recon.getIp()

scanner(str(ips))

# Do a quick scan to get active hosts to scan thoroughly
# if  in ips:
#     print '\033[1;34m[*]  Performing sweep to create a target list\033[1;m'
#     fastscan = 'nmap -Pn -sn %s | grep "Nmap scan report for" | cut -d " " -f6 | cut -d "(" -f2 | cut -d ")" -f1' % (str(ips))
#     scanresults = subprocess.check_output(fastscan, shell=True)
#
#     for ip in (str(scanresults)).split():
#         scanner(ip)
# else:
#     scanner(str(ips))