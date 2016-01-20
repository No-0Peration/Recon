#!/usr/bin/python

import sys
import os
import subprocess

if len(sys.argv) != 3:
    print "Usage: dirbust.py <target url> <scan name>"
    sys.exit(0)

ip = str(sys.argv[1])
name = str(sys.argv[2])
folder = "./wordlists"

found = []
print "INFO: Starting DIRBUSTER scan for " + ip
for filename in os.listdir(folder):
    outfile = " -o " + "./results/" + name + "/" + name + "_dirb_" + filename
    DIRBSCAN = "dirb http://%s %s/%s %s -S -r" % (ip, folder, filename, outfile)
    try:
        results = subprocess.check_output(DIRBSCAN, shell=True)
        resultarr = results.split("\n")
        for line in resultarr:
            if "+" in line or "==>" in line:
                 if line not in found:
                    found.append(line)
    except:
        pass

try:
    if found[0] != "":
        print "[*] Dirb found the following items..."
        for item in found:
            if ("CODE:200" in item or "DIRECTORY" in item):
                print "   " + item
except:
    print "INFO: No items found during dirb scan of " + ip





