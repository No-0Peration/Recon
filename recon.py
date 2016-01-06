import errno
import multiprocessing
import multiprocessing.pool
import os
import subprocess

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
        ip_start = raw_input("Please enter the ip's to scan (example 192.168.0.1/24)  : ")
        ip = IP(ip_start)
        return ip
    except Exception as e:
        raise Exception(e)


def dnsEnum(ip_address, port):
    print "INFO: Detected DNS on {0}:{1}".format(ip_address, port)
    if port.strip() == "53":
        SCRIPT = "./dnsrecon.py {0}".format(ip_address)  # execute the python script
        subprocess.call(SCRIPT, shell=True)
    return


def httpEnum(ip_address, port):
    print "INFO: Detected http on {0}:{1}".format(ip_address, port)
    SCRIPT = "./httprecon.py {0} {1}".format(ip_address, port)  # execute the python script
    subprocess.call(SCRIPT, shell=True)
    return


def mssqlEnum(ip_address, port):
    print "INFO: Detected MS-SQL on {0}:{1}".format(ip_address, port)
    print "INFO: Performing nmap mssql script scan for {0}:{1}".format(ip_address, port)
    MSSQLSCAN = "nmap -vv -sV -Pn -p {0} --script-args=unsafe=1 --script=mysql-vuln-cve2012-2122.nse,ms-sql-info,ms-sql-config,ms-sql-dump-hashes --script-args=mssql.instance-port=1433,smsql.username=sa,mssql.password=sa -oX ./results/{1}/{1}_mssql.xml {1}".format(port, ip_address)
    results = subprocess.check_output(MSSQLSCAN, shell=True)
    outfile = "results/{0}/{0}_mssqlrecon.txt".format(ip_address)
    f = open(outfile, "w")
    f.write(results)
    f.close
    return


def sshEnum(ip_address, port):
    print "INFO: Detected SSH on {0}:{1}".format(ip_address, port)
    SCRIPT = "./sshrecon.py {0} {1}".format(ip_address, port)
    subprocess.call(SCRIPT, shell=True)
    return


def telnetEnum(ip_address, port):
    print "INFO: Detected Telnet on {0}:{1}".format(ip_address, port)
    SCRIPT = "./telnetrecon.py {0} {1}".format(ip_address, port)
    subprocess.call(SCRIPT, shell=True)
    return


def snmpEnum(ip_address, port):
    print "INFO: Detected snmp on {0}:{1}".format(ip_address, port)
    SCRIPT = "./snmprecon.py {0}".format(ip_address)
    subprocess.call(SCRIPT, shell=True)
    return


def smtpEnum(ip_address, port):
    print "INFO: Detected smtp on {0}:{1}".format(ip_address, port)
    if port.strip() == "25":
        SCRIPT = "./smtprecon.py {0}".format(ip_address)
        subprocess.call(SCRIPT, shell=True)
    else:
        print "WARNING: SMTP detected on non-standard port, smtprecon skipped (must run manually)"
    return


def smbEnum(ip_address, port):
    print "INFO: Detected SMB on {0}:{1}".format(ip_address, port)
    if port.strip() == "445":
        SCRIPT = "./smbrecon.py {0} 2>/dev/null".format(ip_address)
        subprocess.call(SCRIPT, shell=True)
    return


def ftpEnum(ip_address, port):
    print "INFO: Detected ftp on {0}:{1}".format(ip_address, port)
    SCRIPT = "./ftprecon.py {0} {1}".format(ip_address, port)
    subprocess.call(SCRIPT, shell=True)
    return