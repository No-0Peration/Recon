#!/usr/bin/python

import sys
import os
import subprocess

if len(sys.argv) != 3:
    print "Usage: dirbust.py <target url> <scan name>"
    sys.exit(0)

url = str(sys.argv[1])
name = str(sys.argv[2])
folders = ["/usr/share/dirbuster/wordlists/"]

found = []
print "INFO: Starting dirb scan for {0}".format(url)
for folder in folders:
    for filename in os.listdir(folder):
        outfile = "results/{0}/{0}_dirbuster.txt".format(url)
        DIRBSCAN = "dirb {0} {1}/{2} {3} -S -r".format(url, folder, filename, outfile)
        try:
            results = subprocess.check_output(DIRBSCAN, shell=True)
            resultarr = results.split("\n")
            for line in resultarr:
                if "+" in line:
                    if line not in found:
                        found.append(line)
        except:
            pass

try:
    if found[0] != "":
        print "[*] Dirb found the following items..."
        for item in found:
            if ("CODE:200" in item):
                print "   " + item
except:
    print "INFO: No items found during dirb scan of " + url



