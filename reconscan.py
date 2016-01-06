#!/usr/bin/env python
'''
 Author: Gerben (0x90) -- @N0_Operation & Bas -- B0x41S & Sander -- DTCTD.
 This tool is an automation script for the reconphase during a pentest, it was inspired by a few github repos.
'''

import os
import sys
import multiprocessing
import multiprocessing.pool
import subprocess
import gzip
import re
import recon  # All functions called by the main scanner function


class NoDaemonProcess(multiprocessing.Process):
    # make 'daemon' attribute always return False
    def _get_daemon(self):
        return False

    def _set_daemon(self, value):
        pass
    daemon = property(_get_daemon, _set_daemon)


class MyPool(multiprocessing.pool.Pool):
    Process = NoDaemonProcess

print "////////////////////////////////////////////////////////////"
print "///             Recon Enumeration script                 ///"
print "///                       --                             ///"
print "///                       by                             ///"
print "///           N0_Operation & B0x41S & DTCTD              ///"
print "////////////////////////////////////////////////////////////"

# Check if root
if os.getuid() == 0:
    print("INFO: Rootcheck DONE..")
else:
    sys.exit("I cannot run as a mortal. Sorry.")

if os.path.isfile("/usr/share/wordlists/rockyou.txt"):
    print("INFO: Rockyou wordlist present")
else:
    print("Rockyou wordlist is missing trying to decompress...")
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
        print("Rockyou wordlist is decompressed!")
    else:
        print("Decompression of rockyou.txt failed!")


def scanner(ip_address):
    # Start function which takes ip_address to scan as argument
    ip_address = str(ip_address)
    serv_dict = {}
    modules = {'dns': recon.dnsEnum, 'ftp': recon.ftpEnum, 'http': recon.httpEnum, 'smb': recon.smbEnum, 'smtp': recon.smtpEnum, 'snmp': recon.snmpEnum, 'ssh': recon.sshEnum, 'telnet': recon.telnetEnum}
    recon.checkpath("./results/{0}".format(ip_address))

    if not recon.checknmaprun(ip_address, "_nmap_scan_import.xml"):
        print("INFO: {0} not scanned or interrupted, starting TCP nmap scan".format(ip_address))
        tcpscan = "nmap -vv -Pn -A -O -sS -sV -T4 --top-ports 100 --open -oN './results/{0}/{0}.nmap' -oX './results/{0}/{0}_nmap_scan_import.xml' {0}".format(ip_address)
        with open(os.devnull, "w") as f:
            subprocess.call(tcpscan, shell=True, stdout=f)
        tcpresults = file("./results/{0}/{0}_nmap_scan_import.xml".format(ip_address), "r")
        tcplines = tcpresults
    else:
        print("INFO: {0} already scanned for TCP ports...".format(ip_address))
        tcpresults = file("./results/{0}/{0}_nmap_scan_import.xml".format(ip_address), "r")
        tcplines = tcpresults

    if not recon.checknmaprun(ip_address, "U_nmap_scan_import.xml"):
        print("INFO: {0} not scanned or interrupted, starting UDP nmap scan".format(ip_address))
        udpscan = "nmap -vv -Pn -sU -sV -A -O -T4 -p 53,67,68,88,161,162,137,138,139,389,520,2049 -oN './results/{0}/{0}U.nmap' -oX './results/{0}/{0}U_nmap_scan_import.xml' {0}".format(ip_address)
        with open(os.devnull, "w") as f:
            subprocess.call(udpscan, shell=True, stdout=f)
        udpresults = file("./results/{0}/{0}U_nmap_scan_import.xml".format(ip_address), "r")
        udplines = udpresults
    else:
        print("INFO: {0} already scanned for UDP ports...".format(ip_address))
        udpresults = file("./results/{0}/{0}U_nmap_scan_import.xml".format(ip_address), "r")
        udplines = udpresults

    # The forloop below parses the nmap results and looks for open service on which it knows to act.
    for line in tcplines:
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
            knownservices = set(modules).intersection(serv_dict)  # find services for which we have a recon module

            for serv in knownservices:
                if serv_dict in serv:
                    port = serv_dict[service]
                    recon.multProc(modules[serv], ip_address, port)

    # Go through the service dictionary to call additional targeted enumeration functions
    # for serv in serv_dict:
    #     ports = serv_dict[serv]
    #     if serv == "http" in serv:
    #         for port in ports:
    #             port = port.split("/")[0]
    #             recon.multProc(recon.httpEnum, ip_address, port)
    #     elif serv == "ssl/http" or "https" in serv:
    #         for port in ports:
    #             port = port.split("/")[0]
    #             recon.multProc(recon.httpEnum, ip_address, port)
    #     elif "ssh" in serv:
    #         for port in ports:
    #             port = port.split("/")[0]
    #             recon.multProc(recon.sshEnum, ip_address, port)
    #     elif "smtp" in serv:
    #         for port in ports:
    #             port = port.split("/")[0]
    #             recon.multProc(recon.smtpEnum, ip_address, port)
    #     elif "snmp" in serv:
    #         for port in ports:
    #             port = port.split("/")[0]
    #             recon.multProc(recon.snmpEnum, ip_address, port)
    #     elif "domain" in serv:
    #         for port in ports:
    #             port = port.split("/")[0]
    #             recon.multProc(recon.dnsEnum, ip_address, port)
    #     elif "ftp" in serv:
    #         for port in ports:
    #             port = port.split("/")[0]
    #             recon.multProc(recon.ftpEnum, ip_address, port)
    #     elif "microsoft-ds" in serv:
    #         for port in ports:
    #             port = port.split("/")[0]
    #             recon.multProc(recon.smbEnum, ip_address, port)
    #     elif "ms-sql" in serv:
    #         for port in ports:
    #             port = port.split("/")[0]
    #             recon.multProc(recon.mssqlEnum, ip_address, port)
    #     elif "telnet" in serv:
    #         for port in ports:
    #             port = port.split("/")[0]
    #             recon.multProc(recon.telnetEnum, ip_address, port)

    print "INFO: TCP/UDP Nmap scans completed for {0}".format(ip_address)
    return

# grab the discover scan results and start scanning up hosts

if __name__ == '__main__':
    try:
        recon.checkpath("./results/")
    except:
        pass

    # ips = recon.getIp()
    ips = "192.168.13.210"
    # Do a quick scan to get active hosts to scan thoroughly
    print "INFO: Performing sweep to create a target list"
    fastscan = "nmap -sP %s | grep \"Nmap scan report for\" | cut -d \" \" -f5" % (str(ips))
    scanresults = subprocess.check_output(fastscan, shell=True)

    num_threads = 4 * multiprocessing.cpu_count()
    pool = MyPool(num_threads)
    pool.map(scanner, [ip for ip in (str(scanresults)).split()])

    print "INFO: All scipts finished"