#!/usr/bin/env python
import subprocess
import sys

if len(sys.argv) != 3:
    print "Usage: httprecon.py <ip address> <port>"
    sys.exit(0)

ip_address = sys.argv[1].strip()
port = sys.argv[2].strip()
print "INFO: Performing nmap HTTP script scan for " + ip_address + ":" + port
HTTPSCAN = "nmap -sV -Pn -vv -p %s --script-args=unsafe=1 --script=http-enum,http-feed,http-open-proxy,http-headers,http-cors,http-server-header,http-php-version,http-form-brute,http-iis-short-name-brute,http-waf-fingerprint,http-auth,http-trace,http-iis-webdav-vuln,http-useragent-tester,http-vuln-cve2011-3368,http-userdir-enum,http-passwd,http-csrf,http-wordpress-enum,http-frontpage-login,http-dombased-xss,http-phpself-xss,http-sql-injection,http-drupal-enum-users,http-referer-checker,http-vuln-cve2009-3960,http-methods,http-open-redirect,http-vuln-cve2011-3192,http-stored-xss,http-vuln-cve2013-0156,http-put,http-proxy-brute,http-rfi-spider,http-method-tamper,http-phpmyadmin-dir-traversal -oN ./results/%s_http.nmap.%s %s" % (port, ip_address, port, ip_address)
results = subprocess.check_output(HTTPSCAN, shell=True)
outfile = "results/" + ip_address + "_HTTPrecon.txt"
DIRBUST = "./dirbust.py http://%s:%s %s" % (ip_address, port, ip_address)  # execute the python script
subprocess.call(DIRBUST, shell=True)
NIKTOSCAN = "nikto -host %s -p %s > ./results/%s.%s_nikto" % (ip_address, port, ip_address, port)
subprocess.call(NIKTOSCAN, shell=True)
f = open(outfile, "w")
f.write(results)
f.close

#incorporate Wafw00f // whatweb // xsstracer // wpscan // sqlmap // arachni
#wafw00f http://$TARGET
#whatweb http://$TARGET
#xsstracer $TARGET 80
#wpscan --url http://$TARGET --batch
#sqlmap -u "http://$TARGET" --batch --crawl=5 -f
#arachni http://$TARGET --output-only-positives --scope-include-subdomains