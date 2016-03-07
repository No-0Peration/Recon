#!/usr/bin/python
from xml.etree import ElementTree
from libnmap.parser import NmapParser
import sys

if len(sys.argv) != 3:
    print "Usage: logparser.py <ip address> <protocol>"
    sys.exit(0)

ip = sys.argv[1]
protocol = sys.argv[2]

def logparser(ip, protocol):
    from xml.etree import ElementTree
    from libnmap.parser import NmapParser

    with open ('../results/{0}/{0}{1}_nmap_scan_import.xml'.format(ip, protocol), 'rt') as file: #ElementTree module is opening the XML file
        tree = ElementTree.parse(file)


    #Additional information which can be printed if this section is activated
    for node_1 in tree.iter('hostname'):
        host_name =   node_1.attrib.get('name')
        dns_type = node_1.attrib.get('type')
        print "Hostname: ",host_name, "Type:", dns_type

    for node_2 in tree.iter('address'):
        ip_add =   node_2.attrib.get('addr')
        mac_type = node_2.attrib.get('vendor')
        print "IP Info: ",ip_add, mac_type


    rep = NmapParser.parse_fromfile('../results/{0}/{0}{1}_nmap_scan_import.xml'.format(ip, protocol)) #NmapParse module is opening the XML file
    #For loop used by NmapParser to print the hostname and the IP
    for _host in rep.hosts:
        host = ', '.join(_host.hostnames)
        ip = (_host.address)
        print "----------------------------------------------------------------------------- "
        print "HostName: "'{0: >35}'.format(host,"--", ip)


    #Lists in order to store Additional information, Product and version next to the port information.
    list_product=[]
    list_version=[]
    list_extrainf=[]
    for node_4 in tree.iter('service'): #ElementTree manipulation. Service Element which included the sub-elements product, version, extrainfo
        product = node_4.attrib.get('product')
        version = node_4.attrib.get('version')
        extrainf = node_4.attrib.get('extrainfo')
        list_product.append(product)
        list_version.append(version)
        list_extrainf.append(extrainf)

    for osmatch in _host.os.osmatches: #NmapParser manipulation to detect OS and accuracy of detection.
        os = osmatch.name
        accuracy = osmatch.accuracy
        print "Operating System Guess: ", os, "- Accuracy Detection", accuracy
        break
    print "----------------------------------------------------------------------------- "

    if protocol == 'UDP':
        os = 'UDP'
    if 'Microsoft' in os:
        counter = 0
        for services in _host.services: #NmapParser manipulation to list services, their ports and their state. The list elements defined above are printed next to each line.
            #print "Port: "'{0: <5}'.format(services.port), "Product: "'{0: <15}'.format(list_product[counter],list_version[counter],list_extrainf[counter]), "State: "'{0: <5}'.format(services.state), "Protocol: "'{0: <5}'.format(services.protocol)
            print "Port: "'{0: <5}'.format(services.port), "State: "'{0: <5}'.format(services.state), "Protocol: "'{0: <2}'.format(services.protocol),"Product: "'{0: <35}'.format(list_product[counter]),"Version: "'{0: <20}'.format(list_version[counter]),"ExtrInfo: "'{0: <10}'.format(list_extrainf[counter])
            #,,,
            counter = counter + 1

    if 'Linux' in os:
        counter = 0
        for services in _host.services: #NmapParser manipulation to list services, their ports and their state. The list elements defined above are printed next to each line.
            #print "Port: "'{0: <5}'.format(services.port), "Product: "'{0: <15}'.format(list_product[counter],list_version[counter],list_extrainf[counter]), "State: "'{0: <5}'.format(services.state), "Protocol: "'{0: <5}'.format(services.protocol)
            print "Port: "'{0: <5}'.format(services.port), "State: "'{0: <5}'.format(services.state), "Protocol: "'{0: <2}'.format(services.protocol),"Product: "'{0: <15}'.format(list_product[counter]),"Version: "'{0: <10}'.format(list_version[counter]),"ExtrInfo: "'{0: <10}'.format(list_extrainf[counter])
            #,,,
            counter = counter + 1

    if 'UDP' in os:
        counter = 0
        for services in _host.services: #NmapParser manipulation to list services, their ports and their state. The list elements defined above are printed next to each line.
            #print "Port: "'{0: <5}'.format(services.port), "Product: "'{0: <15}'.format(list_product[counter],list_version[counter],list_extrainf[counter]), "State: "'{0: <5}'.format(services.state), "Protocol: "'{0: <5}'.format(services.protocol)
            print "Port: "'{0: <5}'.format(services.port), "State: "'{0: <15}'.format(services.state), "Protocol: "'{0: <2}'.format(services.protocol),"Product: "'{0: <15}'.format(list_product[counter]),"Version: "'{0: <10}'.format(list_version[counter]),"ExtrInfo: "'{0: <10}'.format(list_extrainf[counter])
            #,,,
            counter = counter + 1
    return
logparser(ip, protocol)