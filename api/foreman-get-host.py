#!/usr/bin/env python
# foreman-get-host.py
# Get details of a given host from kattelo/foreman
# using foreman
# abdul.karim
# v1.0
import urllib2,urllib
import sys, os
import re
import base64
from urlparse import urlparse
from optparse import OptionParser
import getpass,socket
import json, commands
from netaddr import IPNetwork,IPAddress
from foreman_common import getPasswd, getUsername, getBaseURL,getPage,findSubnet,delInterface,showInterfaces

#some version of python fail on self sign ssl certs
if sys.version_info[0] == 2 and sys.version_info[1] > 6:
	#version 2.7 of python fail on self sign ssl certs
	import ssl
	ssl._create_default_https_context = ssl._create_unverified_context

DEBUG=False
parser = OptionParser()
parser.add_option("-n", "--node", dest="hostname",
                  help="hostname to find")
parser.add_option("-x","--show-vm-hosted-by", dest="hypervisor",
                  action="store_true", default=False,
                  help="show hypervisor")
parser.add_option("-i","--interface", dest="interfaces",
                  action="store_true", default=False,
                  help="show interfaces")
parser.add_option("-a","--all-host", dest="allhost",
                  action="store_true", default=False,
                  help="all hosts")
parser.add_option("--delete-interface", dest="deleteinterface",
                  action="store_true", default=False,
                  help="delete macvtap interface")
parser.add_option("-j", "--sjon",
                  action="store_true", dest="json", default=False,
                  help="json output")
parser.add_option("-D", "--debug",
                  action="store_true", dest="debug", default=False,
                  help="print debug informaiton")
parser.add_option("-v", "--verbose",
                  action="store_true", dest="verbose", default=False,
                  help="print status messages to stdout")

(options, args) = parser.parse_args()


apiBaseURL=getBaseURL()
theurl=apiBaseURL+"/hosts"
if options.debug:
	DEBUG=True
if not options.hostname and not options.allhost:
	parser.print_help()
	sys.exit(0)

def showHostDetails(hostdetails=[]):
	name = hostdetails["name"]
	mac = hostdetails["mac"]
	model =  hostdetails["model_id"]
	ip=hostdetails["ip"]
	gateway=''
	network=''
	mask=''
	dns=''
	#if not ip == None:
		#subnet = findSubnet(ip,username,password)
		#gateway = subnet['gateway']
		#network = subnet['network']
		#mask = subnet['mask']
		#dns = subnet['dns_primary']
	fqdn=name
	host= fqdn.split('.',1)[0]
	hostgroup_id=hostdetails['hostgroup_id']
	hostgroup_name=hostdetails['hostgroup_name']
	model_name=hostdetails['model_name']
	host_param = hostdetails['all_parameters']
	interfaces = hostdetails['interfaces']

	if DEBUG:
		print host 
	
	if options.json:
		print json.dumps(hostdetails,indent=4)
	if options.hypervisor:
		if model_name in "KVM zone":
		  for param in host_param:
			if param['name'] == 'vm_hosted_by':
				print ip,fqdn," => "+param['value']
	else:
	  print fqdn+","+ip+","+hostgroup_name
	if options.interfaces:
          if options.deleteinterface:
	    showInterfaces(fqdn,interfaces,True)
	  else:
	    showInterfaces(fqdn,interfaces)

def showSimpleHostDetails(hostdetails=[]):
	name = hostdetails["name"]
	mac = hostdetails["mac"]
	model =  hostdetails["model_id"]
	ip=hostdetails["ip"]
	if ip == None:
	   ip = "None"
	fqdn=name
	host= fqdn.split('.',1)[0]
	hostgroup_name=hostdetails['hostgroup_name']
	if hostgroup_name == None:
		 hostgroup_name = "None"
	model_name=hostdetails['model_name']
	if DEBUG:
		print host 
	
	if options.json:
		print json.dumps(hostdetails,indent=4)
	print fqdn+",",ip,","+hostgroup_name

if __name__ == '__main__':
  hostname=options.hostname
  username=getUsername()
  password=getPasswd(username)
  if options.allhost:
    hostCount=getPage(theurl+"?per_page=1",username,password)['total']
    allHosts=getPage(theurl+"?per_page="+str(hostCount),username,password)
    for host in allHosts['results']:
	showSimpleHostDetails(host)
  else:
	thepage=getPage(theurl+"/"+hostname,username,password)
	showHostDetails(thepage)
