#!/usr/bin/env python
'''
 Author: Gerben (0x90) -- @N0_Operation
 This tool is an automation script for the reconphase during a pentest, it was inspired by a few github repos.
'''

import os
from Modules import recon

os.system('cls' if os.name == 'nt' else 'clear')
print "\033[1;37m[-]  ----------------------------------------------------------------------------- \033[1;m"
print '\033[1;37m[-]  ::::::::::::: ########:: ########:: ######::: #######:: ##::: ##::::::::::::: \033[1;m'
print '\033[1;37m[-]  ::::::::::::: ##.... ##: ##.....:: ##... ##: ##.... ##: ###:: ##::::::::::::: \033[1;m'
print '\033[1;37m[-]  ::::::::::::: ##:::: ##: ##::::::: ##:::..:: ##:::: ##: ####: ##::::::::::::: \033[1;m'
print '\033[1;37m[-]  ::::::::::::: ########:: ######::: ##::::::: ##:::: ##: ## ## ##::::::::::::: \033[1;m'
print '\033[1;37m[-]  ::::::::::::: ##.. ##::: ##...:::: ##::::::: ##:::: ##: ##. ####::::::::::::: \033[1;m'
print '\033[1;37m[-]  ::::::::::::: ##::. ##:: ##::::::: ##::: ##: ##:::: ##: ##:. ###::::::::::::: \033[1;m'
print '\033[1;37m[-]  ::::::::::::: ##:::. ##: ########:. ######::. #######:: ##::. ##::::::::::::: \033[1;m'
print '\033[1;37m[-]  :::::::::::::..:::::..::........:::......::::.......:::..::::..::::::::: 0x90 \033[1;m'
print "\033[1;37m[-]  ----------------------------------------------------------------------------- \033[1;m"

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
    print '\033[1;31m[-]  Recon is ending: Killing all Processes!\033[1;m'
    recon.killrecon()
finally:
    recon.finnished()


