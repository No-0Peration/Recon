import subprocess
import multiprocessing
import multiprocessing.pool
import os
import errno
from IPy import IP

class NoDaemonProcess(multiprocessing.Process):
    # make 'daemon' attribute always return False
    def _get_daemon(self):
        return False
    def _set_daemon(self, value):
        pass
    daemon = property(_get_daemon, _set_daemon)

class MyPool(multiprocessing.pool.Pool):
    Process = NoDaemonProcess

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

def PoolProc(targetin, scanip, port):
    num_threads = 4 * multiprocessing.cpu_count()
    pool = MyPool(num_threads)
    pool.map(targetin(scanip, port))
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
    print "INFO: Detected DNS on " + ip_address + ":" + port
    if port.strip() == "53":
        SCRIPT = "./dnsrecon.py %s" % (ip_address)  # execute the python script
        subprocess.call(SCRIPT, shell=True)
    return


def httpEnum(ip_address, port):
    print "INFO: Detected http on " + ip_address + ":" + port
    checkpath("./results/nmap")
    SCRIPT = "./httprecon.py %s" % (ip_address, port)  # execute the python script
    subprocess.call(SCRIPT, shell=True)
    return


def mssqlEnum(ip_address, port):
    print "INFO: Detected MS-SQL on " + ip_address + ":" + port
    print "INFO: Performing nmap mssql script scan for " + ip_address + ":" + port
    MSSQLSCAN = "nmap -vv -sV -Pn -p {0} --script-args=unsafe=1 --script=mysql-vuln-cve2012-2122.nse,ms-sql-info,ms-sql-config,ms-sql-dump-hashes --script-args=mssql.instance-port=1433,smsql.username=sa,mssql.password=sa -oX ./results/{1}/{1}_mssql.xml {1}".format(port, ip_address)
    results = subprocess.check_output(MSSQLSCAN, shell=True)
    outfile = "results/{0}/{0}_mssqlrecon.txt".format(ip_address)
    f = open(outfile, "w")
    f.write(results)
    f.close
    return

def sshEnum(ip_address, port):
    print "INFO: Detected SSH on " + ip_address + ":" + port
    SCRIPT = "./sshrecon.py %s %s" % (ip_address, port)
    subprocess.call(SCRIPT, shell=True)
    return

def telnetEnum(ip_address, port):
    print "INFO: Detected Telnet on " + ip_address + ":" + port
    SCRIPT = "./telnetrecon.py %s %s" % (ip_address, port)
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