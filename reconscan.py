#!/usr/bin/env python
'''
 Author: Gerben (0x90) -- @N0_Operation
 This tool is an automation script for the reconphase during a pentest, it was inspired by a few github repos.
'''

from Modules import recon

recon.bootstrap()

try:
    if __name__ == '__main__':
        try:
            recon.checkpath("./results/")
            recon.checkpreq()
        except:
            pass

        try:
            recon.startrecon()
        except:
            ips = recon.getIp()

            for ip in (str(ips)).split():
                recon.scanner(ip, 'TCP')
                recon.scanner(ip, 'UDP')

except:
    recon.killrecon()
finally:
    recon.finnished()


