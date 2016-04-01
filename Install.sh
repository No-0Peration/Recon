#!/usr/bin/env bash

echo -e "[+]  Installing package dependencies..."
apt-get install arachni dirb nmap hydra sqlmap enum4linux nikto python
pip install python-libnmap
