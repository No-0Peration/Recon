#!/bin/bash

kill $(pidof python)
kill $(pidof nmap)
kill $(pidof dirb)
kill $(pidof hydra)
