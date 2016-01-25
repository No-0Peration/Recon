import subprocess
import multiprocessing
import multiprocessing.pool
import os
import errno
from IPy import IP


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
    f.close
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