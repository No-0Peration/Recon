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

# print '\033[1;30mGray like Ghost\033[1;m'
# print '\033[1;31mRed like Radish\033[1;m'
# print '\033[1;32mGreen like Grass\033[1;m'
# print '\033[1;33mYellow like Yolk\033[1;m'
# print '\033[1;34mBlue like Blood\033[1;m'
# print '\033[1;35mMagenta like Mimosa\033[1;m'
# print '\033[1;36mCyan like Caribbean\033[1;m'
# print '\033[1;37mWhite like Whipped Cream\033[1;m'
# print '\033[1;38mCrimson like Chianti\033[1;m'
# print '\033[1;41mHighlighted Red like Radish\033[1;m'
# print '\033[1;42mHighlighted Green like Grass\033[1;m'
# print '\033[1;43mHighlighted Brown like Bear\033[1;m'
# print '\033[1;44mHighlighted Blue like Blood\033[1;m'
# print '\033[1;45mHighlighted Magenta like Mimosa\033[1;m'
# print '\033[1;46mHighlighted Cyan like Caribbean\033[1;m'
# print '\033[1;47mHighlighted Gray like Ghost\033[1;m'
# print '\033[1;48mHighlighted Crimson like Chianti\033[1;m'


def scanner(ip_address):
    # Start function which takes ip_address to scan as argument
    ip_address = str(ip_address)
    serv_dict = {}
    recon.checkpath("./results/{0}".format(ip_address))

    if not recon.checknmaprun(ip_address, "_nmap_scan_import.xml"):
        print('\033[1;34m[*]  Starting new TCP nmap scan for {0}\033[1;m'.format(ip_address))
        tcpscan = "nmap -vv -Pn -A -O -sS -sV -p- --open -oN './results/{0}/{0}.nmap' -oX './results/{0}/{0}_nmap_scan_import.xml' {0}".format(ip_address)
        with open(os.devnull, "w") as f:
            subprocess.call(tcpscan, shell=True, stdout=f)
        tcpresults = file("./results/{0}/{0}_nmap_scan_import.xml".format(ip_address), "r")
        lines = tcpresults
    else:
        print('\033[1;34m[*]  {0} already scanned for TCP ports...\033[1;m'.format(ip_address))
        tcpresults = file("./results/{0}/{0}_nmap_scan_import.xml".format(ip_address), "r")
        lines = tcpresults

    # The forloop below parses the nmap results and looks for open service on which it knows to act.
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
        for port in ports:
            print('\033[1;32m[*]  Open port {0} found on {1}\033[1;m'.format(port, ip_address))

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

    print('\033[1;34m[*]  TCP/UDP Nmap scans completed for {0}\033[1;m'.format(ip_address))
    return

# grab the discover scan results and start scanning up hosts
print '\033[1;32m////////////////////////////////////////////////////////////\033[1;m'
print '\033[1;32m///                   Enumeration script                 ///\033[1;m'
print '\033[1;32m///                          --                          ///\033[1;m'
print '\033[1;32m///                          by                          ///\033[1;m'
print '\033[1;32m///          0x90:N0_Operation & B0x41S & DTCTD          ///\033[1;m'
print '\033[1;32m////////////////////////////////////////////////////////////\033[1;m'

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

# Do a quick scan to get active hosts to scan thoroughly

print '\033[1;34m[*]  Performing sweep to create a target list\033[1;m'
fastscan = "nmap -sn %s | grep \"Nmap scan report for\" | cut -d \" \" -f5" % (str(ips))
scanresults = subprocess.check_output(fastscan, shell=True)

for ip in (str(scanresults)).split():
    scanner(ip)
