#!/usr/bin/env python
'''
 Author: Gerben Visser (0x90) -- @N0_Operation & Bas -- B0x41S & Sander -- DTCTD.
 This tool is an automation script for the reconphase during a pentest, it was inspired by a few github repos.
'''

import os, sys
import multiprocessing
import multiprocessing.pool
import subprocess
import recon # All functions called by the main scanner function

class NoDaemonProcess(multiprocessing.Process):
    # make 'daemon' attribute always return False
    def _get_daemon(self):
        return False
    def _set_daemon(self, value):
        pass
    daemon = property(_get_daemon, _set_daemon)

class MyPool(multiprocessing.pool.Pool):
    Process = NoDaemonProcess

# Check if root
if os.getuid() == 0:
    print("r00tness!")
else:
    sys.exit("I cannot run as a mortal. Sorry.")

def scanner(ip_address):
    """ Start function which takes ip_address to scan as argument """
    ip_address = str(ip_address)
    print "INFO: Running general TCP/UDP nmap scans for " + ip_address
    serv_dict = {}
    recon.checkpath("./results/nmap")

    udpscan = "nmap -vv -Pn -sU -sV -A -O -T4 -p 53,67,68,88,161,162,137,138,139,389,520,2049 -oN './results/nmap/%sU.nmap' -oX './results/nmap/%sU_nmap_scan_import.xml' %s" % (ip_address, ip_address, ip_address)
    tcpscan = "nmap -vv -Pn -A -O -sS -sV -T4 --top-ports 100 --open -oN './results/nmap/%s.nmap' -oX './results/nmap/%s_nmap_scan_import.xml' %s" % (ip_address, ip_address, ip_address)

    tcpresults = subprocess.check_output(tcpscan, shell=True)
    udpresults = subprocess.check_output(udpscan, shell=True)
    results = tcpresults

    lines = results.split("\n")

    # The forloop below parses the nmap results and looks for open service on which it knows to act.
    for line in lines:
        ports = []
        line = line.strip()
        if ("tcp" in line) and ("open" in line) and not ("Discovered" in line):
            while "  " in line:
                line = line.replace("  ", " ")
            linesplit = line.split(" ")
            service = linesplit[2]  # grab the service name
            port = line.split(" ")[0]  # grab the port/proto
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

    print "INFO: TCP/UDP Nmap scans completed for " + ip_address
    return

# grab the discover scan results and start scanning up hosts
print "////////////////////////////////////////////////////////////"
print "///                   Enumeration script                 ///"
print "///                          --                          ///"
print "///                          by                          ///"
print "///          0x90:N0_Operation & B0x41S & DTCTD          ///"
print "////////////////////////////////////////////////////////////"

if __name__ == '__main__':
    try:
        recon.checkpath("./results/")
    except:
        pass

    ips = recon.getIp()
    num_threads = 4 * multiprocessing.cpu_count()
    pool = MyPool(num_threads)
    pool.map(scanner, [ip for ip in ips])