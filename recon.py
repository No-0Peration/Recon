#!/usr/bin/env python


'''
 Author: Gerben Visser (0x90) -- @N0_Operation
 A forked project of reconscan.py -- a recon/enumeration script by Mike Czumak (T_v3rn1x) -- @SecuritySift
'''


import subprocess
import multiprocessing
import os
import errno

def checkpath(path):
    try:
        os.makedirs(path)
    except OSError as exception:
        if exception.errno != errno.EEXIST:
            raise


def multProc(targetin, scanip, port):
    jobs = []
    p = multiprocessing.Process(target=targetin, args=(scanip, port))
    jobs.append(p)
    p.start()
    return


def dnsEnum(ip_address, port):
    print "INFO: Detected DNS on " + ip_address + ":" + port
    if port.strip() == "53":
        SCRIPT = "./dnsrecon.py %s" % (ip_address)  # execute the python script
        subprocess.call(SCRIPT, shell=True)
    return


def httpEnum(ip_address, port):
    print "INFO: Detected http on " + ip_address + ":" + port
    print "INFO: Performing nmap web script scan for " + ip_address + ":" + port
    checkpath("./results/nmap")
    HTTPSCAN = "nmap -sV -Pn -vv -p %s --script=http-vhosts,http-userdir-enum,http-apache-negotiation,http-backup-finder,http-config-backup,http-default-accounts,http-email-harvest,http-methods,http-method-tamper,http-passwd,http-robots.txt -oN ./results/%s_http.nmap %s" % (
    port, ip_address, ip_address)
    results = subprocess.check_output(HTTPSCAN, shell=True)
    DIRBUST = "./dirbust.py http://%s:%s %s" % (ip_address, port, ip_address)  # execute the python script
    subprocess.call(DIRBUST, shell=True)
    NIKTOSCAN = "nikto -host %s -p %s > %s._nikto" % (ip_address, port, ip_address)
    subprocess.call(NIKTOSCAN, shell=True)
    return


def httpsEnum(ip_address, port):
    print "INFO: Detected https on " + ip_address + ":" + port
    print "INFO: Performing nmap web script scan for " + ip_address + ":" + port
    checkpath("./results/nmap/")
    HTTPSCANS = "nmap -sV -Pn -vv -p %s --script=http-vhosts,http-userdir-enum,http-apache-negotiation,http-backup-finder,http-config-backup,http-default-accounts,http-email-harvest,http-methods,http-method-tamper,http-passwd,http-robots.txt -oX ./results/nmap/%s_https.nmap %s" % (
    port, ip_address, ip_address)
    results = subprocess.check_output(HTTPSCANS, shell=True)
    DIRBUST = "./dirbust.py https://%s:%s %s" % (ip_address, port, ip_address)  # execute the python script
    subprocess.call(DIRBUST, shell=True)
    NIKTOSCAN = "nikto -host %s -p %s > %s._nikto" % (ip_address, port, ip_address)
    subprocess.call(NIKTOSCAN, shell=True)
    return


def mssqlEnum(ip_address, port):
    print "INFO: Detected MS-SQL on " + ip_address + ":" + port
    print "INFO: Performing nmap mssql script scan for " + ip_address + ":" + port
    checkpath("./results/nmap")
    MSSQLSCAN = "nmap -vv -sV -Pn -p %s --script=ms-sql-info,ms-sql-config,ms-sql-dump-hashes --script-args=mssql.instance-port=1433,smsql.username-sa,mssql.password-sa -oX ./results/nmap/%s_mssql.xml %s" % (
    port, ip_address, ip_address)
    results = subprocess.check_output(MSSQLSCAN, shell=True)


def sshEnum(ip_address, port):
    print "INFO: Detected SSH on " + ip_address + ":" + port
    SCRIPT = "./sshrecon.py %s %s" % (ip_address, port)
    subprocess.call(SCRIPT, shell=True)
    return


def snmpEnum(ip_address, port):
    print "INFO: Detected snmp on " + ip_address + ":" + port
    SCRIPT = "./snmprecon.py %s" % (ip_address)
    subprocess.call(SCRIPT, shell=True)
    return


def smtpEnum(ip_address, port):
    print "INFO: Detected smtp on " + ip_address + ":" + port
    if port.strip() == "25":
        SCRIPT = "./smtprecon.py %s" % (ip_address)
        subprocess.call(SCRIPT, shell=True)
    else:
        print "WARNING: SMTP detected on non-standard port, smtprecon skipped (must run manually)"
    return


def smbEnum(ip_address, port):
    print "INFO: Detected SMB on " + ip_address + ":" + port
    if port.strip() == "445":
        SCRIPT = "./smbrecon.py %s 2>/dev/null" % (ip_address)
        subprocess.call(SCRIPT, shell=True)
    return


def ftpEnum(ip_address, port):
    print "INFO: Detected ftp on " + ip_address + ":" + port
    SCRIPT = "./ftprecon.py %s %s" % (ip_address, port)
    subprocess.call(SCRIPT, shell=True)
    return


def nmapScan(ip_address):
    ip_address = ip_address.strip()
    print "INFO: Running general TCP/UDP nmap scans for " + ip_address
    serv_dict = {}
    checkpath("./results/nmap")

    TCPSCAN = "nmap -vv -Pn -A -sC -sS -T 4 -p- -oN './results/nmap/%s.nmap' -oX './results/nmap/%s_nmap_scan_import.xml' %s" % (
    ip_address, ip_address, ip_address)
    UDPSCAN = "nmap -vv -Pn -A -sC -sU -T 4 --top-ports 200 -oN './results/nmap/%sU.nmap' -oX './results/nmap/%sU_nmap_scan_import.xml' %s" % (ip_address, ip_address, ip_address)
    results = subprocess.check_output(TCPSCAN, shell=True)
    udpresults = subprocess.check_output(UDPSCAN, shell=True)
    lines = results.split("\n")
    for line in lines:
        ports = []
        line = line.strip()
        print line
        if ("tcp" in line) and ("open" in line) and not ("Discovered" in line):
            while "  " in line:
                line = line.replace("  ", " ")
            linesplit = line.split(" ")
            service = linesplit[2]  # grab the service name
            port = line.split(" ")[0]  # grab the port/proto
            print service, port
            if service in serv_dict:
                ports = serv_dict[service]  # if the service is already in the dict, grab the port list
            ports.append(port)
            serv_dict[service] = ports  # add service to the dictionary along with the associated port(2)
    # go through the service dictionary to call additional targeted enumeration functions
    for serv in serv_dict:
        ports = serv_dict[serv]
        if serv == "http":
            for port in ports:
                port = port.split("/")[0]
                multProc(httpEnum, ip_address, port)
        elif serv == "ssl/http" or "https" in serv:
            for port in ports:
                port = port.split("/")[0]
                multProc(httpsEnum, ip_address, port)
        elif "ssh" in serv:
            for port in ports:
                port = port.split("/")[0]
                multProc(sshEnum, ip_address, port)
        elif "smtp" in serv:
            for port in ports:
                port = port.split("/")[0]
                multProc(smtpEnum, ip_address, port)
        elif "snmp" in serv:
            for port in ports:
                port = port.split("/")[0]
                multProc(snmpEnum, ip_address, port)
        elif "domain" in serv:
            for port in ports:
                port = port.split("/")[0]
                multProc(dnsEnum, ip_address, port)
        elif "ftp" in serv:
            for port in ports:
                port = port.split("/")[0]
                multProc(ftpEnum, ip_address, port)
        elif "microsoft-ds" in serv:
            for port in ports:
                port = port.split("/")[0]
                multProc(smbEnum, ip_address, port)
        elif "ms-sql" in serv:
            for port in ports:
                port = port.split("/")[0]
                multProc(httpEnum, ip_address, port)

    print "INFO: TCP/UDP Nmap scans completed for " + ip_address
    return


# grab the discover scan results and start scanning up hosts
print "////////////////////////////////////////////////////////////"
print "///                 Enumeration script                   ///"
print "///                         --                           ///"
print "///                                                      ///"
print "///                 0x90:N0_Operation                    ///"
print "////////////////////////////////////////////////////////////"

if __name__ == '__main__':
    try:
        f = open('./ips', 'r')  # CHANGE THIS!! grab the alive hosts from the discovery scan for enum
        for scanip in f:
            jobs = []
            p = multiprocessing.Process(target=nmapScan, args=(scanip,))
            jobs.append(p)
            p.start()
        f.close()
    except:
        print "Is there a file 'ips' containing the ipadresses you wanna scan?"
