#!/usr/bin/env python
'''
 Author: Gerben (0x90) -- @N0_Operation & Bas -- B0x41S & Sander -- DTCTD.
 This tool is an automation script for the reconphase during a pentest, it was inspired by a few github repos.
'''

import os
import sys
import gzip
import recon  # All functions called by the main scanner function
import psutil


# grab the discover scan results and start scanning up hostsprint

print '\033[1;30m ########:: ########:: ######::: #######:: ##::: ##:::::\033[1;m'
print '\033[1;30m ##.... ##: ##.....:: ##... ##: ##.... ##: ###:: ##:::::\033[1;m'
print '\033[1;30m ##:::: ##: ##::::::: ##:::..:: ##:::: ##: ####: ##:::::\033[1;m'
print '\033[1;30m ########:: ######::: ##::::::: ##:::: ##: ## ## ##:::::\033[1;m'
print '\033[1;30m ##.. ##::: ##...:::: ##::::::: ##:::: ##: ##. ####:::::\033[1;m'
print '\033[1;30m ##::. ##:: ##::::::: ##::: ##: ##:::: ##: ##:. ###:::::\033[1;m'
print '\033[1;30m ##:::. ##: ########:. ######::. #######:: ##::. ##:::::\033[1;m'
print '\033[1;30m..:::::..::........:::......::::.......:::..::::..::0x90\033[1;m'

try:
    if __name__ == '__main__':
        try:
            recon.checkpath("./results/")
        except:
            pass

        # Check if root
        if os.getuid() == 0:
            print('\033[1;32m[*]  Checking permissions\033[1;m')
        else:
            sys.exit("I cannot run as a mortal. Sorry.")

        if os.path.isfile("/usr/share/wordlists/rockyou.txt"):
            print('\033[1;32m[*]  Rockyou wordlist present\033[1;m')
        else:
            print('\033[1;31m[*]  Rockyou wordlist is missing trying to decompress...\033[1;m')
            try:
                inFile = gzip.GzipFile("/usr/share/wordlists/rockyou.txt.gz", "rb")
                s = inFile.read()
                inFile.close()
                outFile = file("/usr/share/wordlists/rockyou.txt", "wb")
                outFile.write(s)
                outFile.close()
            except:
                pass
            if os.path.isfile("/usr/share/wordlists/rockyou.txt"):
                print('\033[1;32m[*]  Rockyou wordlist is decompressed!\033[1;m')
            else:
                print('\033[1;31m[*]  Decompression of rockyou.txt failed!\033[1;m')
        try:
            # See if there is a target list in the file ips
            with open("./ips") as f:
                print('\033[1;32m[*]  Found IP list, using as input\033[1;m')
                ips = f.readlines()
                for ip in ips:
                    recon.scanner(ip.strip('\n\r'), 'TCP')
                    recon.scanner(ip.strip('\n\r'), 'UDP')
        except:
            ips = recon.getIp()

            for ip in (str(ips)).split():
                recon.scanner(ip, 'TCP')
                recon.scanner(ip, 'UDP')
except:
    print '\033[1;31m[*]  Recon is ending: Killing all Processes!\033[1;m'
    PROCNAME = ("python", "nmap", "dirb", "hydra")
    for proc in psutil.process_iter():
        if proc.name() in PROCNAME:
            proc.kill()
    exit()


