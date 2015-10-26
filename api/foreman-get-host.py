#!/usr/bin/env python
# foreman-get-host.py
# Get details of a given host from kattelo/foreman
# using foreman api
# set forman_apibaseurl as environment variable
# export forman_apibaseurl = https://<your_foreman_api_url>/api
#
# abdul.karim
# v1.0
# tested on foreman version 1.9.2
# License:
# This script is mainly for my own benefit but anyone is open to use it freely.
#

import urllib2,urllib
import sys, os
import base64
from urlparse import urlparse
from optparse import OptionParser
import getpass,socket
import json
from netaddr import IPNetwork,IPAddress

#some version of python fail on self sign ssl certs, if so uncomment following two lines
import ssl
ssl._create_default_https_context = ssl._create_unverified_context

# set api uri
# i.e https://<foreman.yourdomain>/api
# or set environment vairable foreman_apibaseurl
apiBaseURL=""

DEBUG=False
VERBOSE=False
parser = OptionParser()
parser.add_option("-n", "--node", dest="hostname",
                  help="hostname to find")
parser.add_option("-x","--show-vm-hosted-by", dest="hypervisor",
                  action="store_true", default=False,
                  help="show hypervisor, onlu if vm_hosted_by param is set")
parser.add_option("-j", "--json",
                  action="store_true", dest="json", default=False,
                  help="out json format")
parser.add_option("-D", "--debug",
                  action="store_true", dest="debug", default=False,
                  help="print debug informaiton")
parser.add_option("-v", "--verbose",
                  action="store_true", dest="verbose", default=False,
                  help="don't print status messages to stdout")

(options, args) = parser.parse_args()


if options.debug:
	DEBUG=True
if options.verbose:
	VERBOSE=True
if not options.hostname:
	parser.print_help()
	sys.exit(0)

def getBaseURL():
	apiBaseURL=os.getenv("foreman_apibaseurl")
	if apiBaseURL == None:
		print "couldn't determine base api url. sent env foreman_apibaseurl"
		sys.exit(0)	
	return apiBaseURL

def getUsername():
	# get username and passsword
	username=os.getenv("foreman_user")
	if (username == None):
		username = raw_input("Enter username :")
	return username
def getPasswd():
	# get username and passsword
	password=os.getenv("foreman_password")
	if (password == None):
		password = getpass.getpass("Enter your password for user ["+username+"] :")
	return password

def getPage(theurl):
	global username,password
	if (username == None):
		username = raw_input("Enter username :")
	if (password == None):
		password = getpass.getpass("Enter your password for user ["+username+"] :")
	
	req = urllib2.Request(theurl)
	try:
		handle = urllib2.urlopen(req)
	except IOError, e:
	    # here we *want* to fail
	    pass
	else:
	    # If we don't fail then the page isn't protected
	    print "This page isn't protected by authentication."
	    sys.exit(1)

	if not hasattr(e, 'code') or e.code != 401:
	    # we got an error - but not a 401 error
	    print "This page isn't protected by authentication."
	    print 'But we failed for another reason.'
	    print e
	    sys.exit(1)

	base64string = base64.encodestring(
                '%s:%s' % (username, password))[:-1]
	authheader =  "Basic %s" % base64string
	req.add_header("Authorization", authheader)
	try:
		handle = urllib2.urlopen(req)
	except urllib2.HTTPError, err:
	    # here we shouldn't fail if the username/password is right
	    if ( str(err.code) == "404" ):
	    	print "Url not found : " + str(err.code)
	    else:
	    	print "It looks like the username or password is wrong. "  +str (err.code)
	    sys.exit(1)
	except IOError, e:
		print "Something else went wrong"
	thepage = handle.read()
	return json.loads(thepage)

def getSubnets(theurl):
	global username,password
	# returns page from given url
	# get username and passsword
	if (username == None):
		username = raw_input("Enter username :")
	if (password == None):
		password = getpass.getpass("Enter your password for user ["+username+"] :")
	
	req = urllib2.Request(theurl)
	try:
		handle = urllib2.urlopen(req)
	except IOError, e:
	    # here we *want* to fail
	    pass
	else:
	    # If we don't fail then the page isn't protected
	    print "This page isn't protected by authentication."
	    sys.exit(1)

	if not hasattr(e, 'code') or e.code != 401:
	    # we got an error - but not a 401 error
	    print "This page isn't protected by authentication."
	    print 'But we failed for another reason.'
	    sys.exit(1)

	base64string = base64.encodestring(
                '%s:%s' % (username, password))[:-1]
	authheader =  "Basic %s" % base64string
	req.add_header("Authorization", authheader)
	try:
		handle = urllib2.urlopen(req)
	except urllib2.HTTPError, err:
	    # here we shouldn't fail if the username/password is right
	    if ( str(err.code) == "404" ):
	    	print "Url not found : " + str(err.code)
	    else:
	    	print "It looks like the username or password is wrong. "  +str (err.code)
	    sys.exit(1)
	except IOError, e:
		print "Something else went wrong"
	thepage = handle.read()
	return json.loads(thepage)


def findSubnet(ip):
	subnets = getSubnets(apiBaseURL+"/subnets")
	subnet_name=""
	for s in subnets['results']:
		network = s['network']
		mask = s['mask']
		name = s['name']
		if IPAddress(ip) in IPNetwork(network+'/'+mask):
			subnet_name=name
			break

	return getSubnets(apiBaseURL+"/subnets/"+subnet_name)
		
	if DEBUG:
		print subnets

if __name__ == '__main__':
	if apiBaseURL == "":
		apiBaseURL = getBaseURL()

	hosturl=apiBaseURL+"/hosts"
	hostname=options.hostname
	if VERBOSE:
		print "Using api url " + apiBaseURL
		print "Using hosts url " + hosturl
	username=getUsername()
	password=getPasswd()
	thepage=getPage(hosturl+"/"+hostname)

	name = thepage["name"]
	mac = thepage["mac"]
	model =  thepage["model_id"]
	ip=thepage["ip"]
	subnet = findSubnet(ip)
	gateway = subnet['gateway']
	network = subnet['network']
	mask = subnet['mask']
	dns = subnet['dns_primary']
	fqdn=options.hostname
	host= fqdn.split('.',1)[0]
	model_name=str(thepage['model_name'])
	hostgroup=thepage['hostgroup_name']
	if DEBUG:
		print thepage 

	if options.json:
		print json.dumps(thepage,indent=4)
		sys.exit(0)
	print ip,fqdn,hostgroup
