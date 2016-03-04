#!/usr/bin/env python
import subprocess
import sys

if len(sys.argv) != 3:
    print "Usage: httprecon.py <ip address> <port>"
    sys.exit(0)

ip_address = sys.argv[1].strip()
port = sys.argv[2].strip()
if str(port) == "443":
    header = "https://"
else:
    header = "http://"

print('\033[1;34m[*]  Performing nmap HTTP script scan for {0}:{1}\033[1;m'.format(ip_address, port))
HTTPSCAN = "nmap -sV -Pn -vv -p {0} --script-args=unsafe=1 --script=http-enum,http-feed,http-open-proxy,http-headers,http-cors,http-server-header,http-php-version,http-form-brute,http-iis-short-name-brute,http-waf-fingerprint,http-auth,http-trace,http-iis-webdav-vuln,http-useragent-tester,http-vuln-cve2011-3368,http-userdir-enum,http-passwd,http-csrf,http-wordpress-enum,http-frontpage-login,http-dombased-xss,http-phpself-xss,http-sql-injection,http-drupal-enum-users,http-referer-checker,http-vuln-cve2009-3960,http-methods,http-open-redirect,http-vuln*,http-stored-xss,http-put,http-proxy-brute,http-rfi-spider,http-method-tamper,http-phpmyadmin-dir-traversal -oN ./results/{1}/{1}_http.nmap.{0} {1}".format(port, ip_address)
results = subprocess.check_output(HTTPSCAN, shell=True)
outfile = "results/{0}/{0}_HTTPrecon.txt".format(ip_address)
NIKTOSCAN = "nikto -host {0} -p {1} > ./results/{0}/{0}.{1}_nikto".format(ip_address, port)
print('\033[1;34m[*]  Performing NIKTO scan for {0}:{1}\033[1;m'.format(ip_address, port))
subprocess.call(NIKTOSCAN, shell=True)
ARACHNI = "arachni {0}{1}:{2} --output-only-positives --scope-include-subdomains".format(header, ip_address, port)
print('\033[1;34m[*]  Performing ARACHNI scan for {0}:{1}\033[1;m'.format(ip_address, port))
results2 = subprocess.check_output(ARACHNI, shell=True)
outfile2 = "results/{0}/{0}_Arachnirecon.txt".format(ip_address)
DIRBUST = "./Modules/dirbust.py {2}{0}:{1} {0} {1}".format(ip_address, port, header)  # execute the python script
subprocess.call(DIRBUST, shell=True)
f = open(outfile, "w")
f.write(results)
f.close()
f = open(outfile2, "w")
f.write(results2)
f.close()

