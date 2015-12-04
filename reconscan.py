#!/usr/bin/env python
'''
 Author: Gerben Visser (0x90) -- @N0_Operation & Bas -- B0x41S.
 This tool is an automation script for the reconphase during a pentest, it was inspired by a few github repos
'''

import os
import multiprocessing
import subprocess
import recon # All functions called by the main scanner function

# Check if root
if os.getuid() == 0:
    print("r00tness!")
else:
    print("I cannot run as a mortal. Sorry.")
    raise "Helaas"

def scanner(ip_address):
    """ Start function which takes ip_address to scan as argument """
    ip_address = str(ip_address)
    print "INFO: Running general TCP/UDP nmap scans for " + ip_address
    serv_dict = {}
    recon.checkpath("./results/nmap")

    tcpscan = "nmap -vv -Pn -A -sC -sS --top-ports 1000 --min-rtt-timeout 50ms --max-rtt-timeout 60ms --initial-rtt-timeout 100ms --scan-delay 0 --min-rate 450 --max-rate 15000 --max-retries 3 -PE -PS21-23,25,53,80,110-111,135,139,143,443,445,993,995,1723,3306,3389,5900,8080 -PU53,67-69,123,135,137-139,161-162,445,500,514,520,631,1434,1900,4500,49152 --defeat-rst-ratelimit --open --privileged --stats-every 10s -oN './results/nmap/%s.nmap' -oX './results/nmap/%s_nmap_scan_import.xml' %s" % (ip_address, ip_address, ip_address)
    udpscan = "nmap -vv -Pn -sC -sU -T 4 --top-ports 200 -oN './results/nmap/%sU.nmap' -oX './results/nmap/%sU_nmap_scan_import.xml' %s" % (ip_address, ip_address, ip_address)


    tcpresults = subprocess.check_output(tcpscan, shell=True)
    udpresults = subprocess.check_output(udpscan, shell=True)
    results = tcpresults

    lines = results.split("\n")

    #the forloop below parses the nmap results and looks for open service on which it knows to act.
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
    # go through the service dictionary to call additional targeted enumeration functions
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
                recon.multProc(recon.httpEnum, ip_address, port)

    print "INFO: TCP/UDP Nmap scans completed for " + ip_address
    return

# grab the discover scan results and start scanning up hosts
print "////////////////////////////////////////////////////////////"
print "///                 Enumeration script                   ///"
print "///                         --                           ///"
print "///                          by                          ///"
print "///          0x90:N0_Operation &  B0x41S                 ///"
print "////////////////////////////////////////////////////////////"

if __name__ == '__main__':
    try:
        recon.checkpath("./results/")
    except:
        pass
    ips = recon.getIp()
    for ip in ips:
        jobs = []
        p = multiprocessing.Process(target=scanner, args=(ip))
        jobs.append(p)
        p.start()
