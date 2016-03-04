import subprocess
import multiprocessing
import multiprocessing.pool
import os
import errno
from IPy import IP
import re


def checkpath(path):
    try:
        os.makedirs(path)
    except OSError as exception:
        if exception.errno != errno.EEXIST:
            raise


def checknmaprun(ip_address, name):
    if os.path.isfile("./results/{0}/{0}{1}".format(ip_address, name)):
        with open("./results/{0}/{0}{1}".format(ip_address, name)) as f:
            for line in f:
                if 'exit="success"' in line:
                    return True
                if not line:
                    return False
    else:
        return False

def multProc(targetin, scanip, port):
    jobs = []
    p = multiprocessing.Process(target=targetin, args=(scanip, port))
    jobs.append(p)
    p.start()
    return

def getIp():
    """ Defines the ip range to be scanned """
    try:
        ip_start = raw_input("\033[1;37m[*]  Please enter the ip's to scan (example 192.168.0.1/24)  : \033[1;m")
        ip = IP(ip_start)
        return ip
    except Exception as e:
        raise Exception(e)

def dnsEnum(ip_address, port):
    print('\033[1;34m[*]  Detected DNS on {0} : {1}\033[1;m'.format(ip_address, port))
    if port.strip() == "53":
        SCRIPT = "./dnsrecon.py %s" % (ip_address)  # execute the python script
        subprocess.call(SCRIPT, shell=True)
    return


def httpEnum(ip_address, port):
    print('\033[1;34m[*]  Detected HTTP on {0} : {1}\033[1;m'.format(ip_address, port))
    checkpath("./results/")
    SCRIPT = "./httprecon.py %s %s" % (ip_address, port)  # execute the python script
    subprocess.call(SCRIPT, shell=True)
    return


def mssqlEnum(ip_address, port):
    print('\033[1;34m[*]  Detected SQL on {0} : {1}\033[1;m'.format(ip_address, port))
    print('\033[1;34m[*]  Performing nmap MSSQL script scan for {0} : {1}\033[1;m'.format(ip_address, port))
    MSSQLSCAN = "nmap -vv -sV -Pn -p {0} --script-args=unsafe=1 --script=mysql-vuln-cve2012-2122.nse,ms-sql-info,ms-sql-config,ms-sql-dump-hashes --script-args=mssql.instance-port=1433,smsql.username=sa,mssql.password=sa -oX ./results/{1}/{1}_mssql.xml {1}".format(port, ip_address)
    results = subprocess.check_output(MSSQLSCAN, shell=True)
    outfile = "results/{0}/{0}_mssqlrecon.txt".format(ip_address)
    f = open(outfile, "w")
    f.write(results)
    f.close()
    return

def sshEnum(ip_address, port):
    print('\033[1;34m[*]  Detected SSH on {0} : {1}\033[1;m'.format(ip_address, port))
    SCRIPT = "./sshrecon.py %s %s" % (ip_address, port)
    subprocess.call(SCRIPT, shell=True)
    return

def telnetEnum(ip_address, port):
    print('\033[1;34m[*]  Detected TELNET on {0} : {1}\033[1;m'.format(ip_address, port))
    SCRIPT = "./telnetrecon.py %s %s" % (ip_address, port)
    subprocess.call(SCRIPT, shell=True)
    return

def snmpEnum(ip_address, port):
    print('\033[1;34m[*]  Detected SNMP on {0} : {1}\033[1;m'.format(ip_address, port))
    SCRIPT = "./snmprecon.py %s" % (ip_address)
    subprocess.call(SCRIPT, shell=True)
    return


def smtpEnum(ip_address, port):
    print('\033[1;34m[*]  Detected SMTP on {0} : {1}\033[1;m'.format(ip_address, port))
    if port.strip() == "25":
        SCRIPT = "./smtprecon.py %s" % (ip_address)
        subprocess.call(SCRIPT, shell=True)
    else:
        print '\033[1;33mWARNING: SMTP detected on non-standard port, smtprecon skipped (must run manually)\033[1;m'
    return


def smbEnum(ip_address, port):
    print('\033[1;34m[*]  Detected SMB on {0} : {1}\033[1;m'.format(ip_address, port))
    if port.strip() == "445":
        SCRIPT = "./smbrecon.py %s 2>/dev/null" % (ip_address)
        subprocess.call(SCRIPT, shell=True)
    return


def ftpEnum(ip_address, port):
    print('\033[1;34m[*]  Detected FTP on {0} : {1}\033[1;m'.format(ip_address, port))
    SCRIPT = "./ftprecon.py %s %s" % (ip_address, port)
    subprocess.call(SCRIPT, shell=True)
    return


def scanner(ip_address, protocol):
    ip_address = str(ip_address)
    checkpath("./results/{0}".format(ip_address))
    if not checknmaprun(ip_address, "{0}_nmap_scan_import.xml".format(protocol)):
        print('\033[1;34m[*]  Starting new {0} nmap scan for {1}\033[1;m'.format(protocol, ip_address))
        if protocol == "UDP":
            udpscan = "nmap -vv -Pn -sU -sV -A -O -p 53,67,68,88,161,162,137,138,139,389,520,2049 -oN './results/{0}/{0}U.nmap' -oX './results/{0}/{0}{1}_nmap_scan_import.xml' {0}".format(ip_address, protocol)
            with open(os.devnull, "w") as f:
                subprocess.call(udpscan, shell=True, stdout=f)
            udpresults = file("./results/{0}/{0}{1}_nmap_scan_import.xml".format(ip_address, protocol), "r")
            lines = udpresults
        else:
            tcpscan = "nmap -vv -Pn -A -O -sS -sV --open -oN './results/{0}/{0}.nmap' -oX './results/{0}/{0}{1}_nmap_scan_import.xml' {0}".format(ip_address, protocol)
            with open(os.devnull, "w") as f:
                subprocess.call(tcpscan, shell=True, stdout=f)
            tcpresults = file("./results/{0}/{0}{1}_nmap_scan_import.xml".format(ip_address, protocol), "r")
            lines = tcpresults
    else:
        print('\033[1;34m[*]  {0} already scanned for {1} ports...\033[1;m'.format(ip_address, protocol))
        if protocol == "UDP":
            udpresults = file("./results/{0}/{0}{1}_nmap_scan_import.xml".format(ip_address, protocol), "r")
            lines = udpresults
        else:
            tcpresults = file("./results/{0}/{0}{1}_nmap_scan_import.xml".format(ip_address, protocol), "r")
            lines = tcpresults

    print('\033[1;34m[*]  {0} Nmap scan completed for {1}\033[1;m'.format(protocol, ip_address))

    serv_dict = {}
    for line in lines:
        ports = []
        if (str(protocol).lower() in line) and ("open" in line) and ("service name=" in line) and not ("Discovered" in line):
            port = (re.search("portid=\"(.*?)\"", line))
            service = (re.search("service name=\"(.*?)\"", line))
            port = (port.group().split("\""))[1]
            service = (service.group().split("\""))[1]

            if service in serv_dict:
                ports = serv_dict[service]  # if the service is already in the dict, grab the port list

            if port not in ports:
                ports.append(port)
            serv_dict[service] = ports  # add service to the dictionary along with the associated port(2)
            print('\033[1;32m[*]  Open {0} port {1} found on {2}\033[1;m'.format(protocol, port, ip_address))

    # Go through the service dictionary to call additional targeted enumeration functions
    for serv in serv_dict:
        ports = serv_dict[serv]
        if serv == "http" in serv:
            for port in ports:
                port = port.split("/")[0]
                multProc(httpEnum, ip_address, port)
        elif serv == "ssl/http" or "https" in serv:
            for port in ports:
                port = port.split("/")[0]
                multProc(httpEnum, ip_address, port)
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
                multProc(mssqlEnum, ip_address, port)
        elif "telnet" in serv:
            for port in ports:
                port = port.split("/")[0]
                multProc(telnetEnum, ip_address, port)

    return