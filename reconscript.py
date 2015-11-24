#!/usr/bin/env python
'''
 Author: Gerben Visser (0x90) -- @N0_Operation
 A forked project of reconscan.py -- a recon/enumeration script by Mike Czumak (T_v3rn1x) -- @SecuritySift
'''

import multiprocessing
import recon

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
            p = multiprocessing.Process(target=recon.nmapScan(), args=(scanip,))
            jobs.append(p)
            p.start()
        f.close()
    except:
        print "Is there a file 'ips' containing the ipadresses you wanna scan?"
