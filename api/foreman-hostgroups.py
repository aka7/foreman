#!/usr/bin/env python
# hostgroup search 
# 
# abdul.karim
# v1.0
# 25/08/2015
###################################

import urllib2,urllib
import sys, os
import base64
from urlparse import urlparse
from optparse import OptionParser
import getpass,socket
import json,re
from lxml import html
from foreman_common import getPasswd, getUsername,getBaseURL

if sys.version_info[0] == 2 and sys.version_info[1] > 6:
	#version 2.7 of python fail on self sign ssl certs
	import ssl
	ssl._create_default_https_context = ssl._create_unverified_context

DEBUG=False
parser = OptionParser()
parser.add_option("-g", "--hostgroup", dest="hostgroup",
                  help="show all hosts with hostgroup")
parser.add_option("-e", "--evironment", dest="environment",
                  help="show all hosts with this environment name")
parser.add_option("-D", "--debug",
                  action="store_true", dest="debug", default=False,
                  help="print debug informaiton")
parser.add_option("-v", "--verbose",
                  action="store_true", dest="verbose", default=False,
                  help="print status messages to stdout")

(options, args) = parser.parse_args()



apiBaseURL=getBaseURL()
emmet_url=apiBaseURL+"/hosts"
if options.debug:
	DEBUG=True
if not options.hostgroup:
	parser.print_help()
	sys.exit(0)

def getHost(theurl,host):
	"""
	This method returns html page from given admingw url
	It uses the hostname to run CQL query
	"""
	global username,password
	if (username == None):
		username = raw_input("Enter username : ")
	if (password == None):
		password = getpass.getpass("Enter your password for user ["+username+"] :")

	
	raw_params = {'cata_query' : 'list host with host_fqdn ="'+host+'%" tag h  join via has_netif to netif,netvif, tag n  result order n.if_ipv4addr print h.host_fqdn,n.if_name,n.if_ipv4addr','sidenav' : 'query','tabnav' : 'main', 'RUN' : 'run'}
	params = urllib.urlencode(raw_params)
	req = urllib2.Request(theurl,params)

	if options.verbose:
		print "Using url : " +theurl
		print 'Using query params : ' + raw_params['cata_query']
		print "#################################################"
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

	authline = e.headers['www-authenticate']
	# this gets the www-authenticate line from the headers
	# which has the authentication scheme and realm in it
	

	authobj = re.compile(
	    r'''(?:\s*www-authenticate\s*:)?\s*(\w*)\s+realm=['"]([^'"]+)['"]''',
	    re.IGNORECASE)
	# this regular expression is used to extract scheme and realm
	matchobj = authobj.match(authline)

	if not matchobj:
	    # if the authline isn't matched by the regular expression
	    # then something is wrong
	    print 'The authentication header is badly formed.'
	    print authline
    	    sys.exit(1)

	scheme = matchobj.group(1)
	realm = matchobj.group(2)
	# here we've extracted the scheme
	# and the realm from the header
	if scheme.lower() != 'basic':
	    print 'This example only works with BASIC authentication.'
    	    sys.exit(1)

	base64string = base64.encodestring(
                '%s:%s' % (username, password))[:-1]
	authheader =  "Basic %s" % base64string
	req.add_header("Authorization", authheader)
	try:
	    handle = urllib2.urlopen(req)
	except IOError, e:
	    # here we shouldn't fail if the username/password is right
	    print "It looks like the username or password is wrong."
	    sys.exit(1)
	thepage = handle.read()
	tree = html.fromstring(thepage)
	tr_nodes = tree.xpath('//table[@class="olist"]/tr')
	td_content = [[td.text for td in tr.xpath('td')] for tr in tr_nodes[0:]]
	
	if DEBUG:
		print td_content

	for content in sorted(td_content,key=lambda ip:ip[2]):
		_host_fqdn = content[0]
		_host = _host_fqdn.split('.',1)[0]
		_domain = _host_fqdn.split('.',1)[1]
		_eth = content[1]
		_ip = content[2]
		return _host_fqdn 

#function to return output from a given url. response must be in json format.
def getPage(theurl):
	if DEBUG:
		print theurl
	global username,password
	if (username == None):
		username = raw_input("Enter username :")
	if (password == None):
		password = getpass.getpass("Enter your password for user ["+username+"] :")
	
	req = urllib2.Request(theurl)
	base64string = base64.encodestring(
                '%s:%s' % (username, password))[:-1]
	authheader =  "Basic %s" % base64string
	req.add_header("Authorization", authheader)
	try:
		handle = urllib2.urlopen(req)
	except urllib2.HTTPError, err:
	    # here we shouldn't fail if the username/password is right
	    if ( str(err.code) == "404" ):
	    	print "Url [ "+theurl+"] not found : " + str(err.code)
	    	sys.exit(1)
	    else:
	    	print "It looks like the username or password is wrong. "  +str (err.code)
		print err
	    	sys.exit(1)
	except IOError, e:
		print "Something else went wrong"
		print e
	response = handle.read()
	return json.loads(response)

def get_vm_hosted_by(parameters):
	for param in parameters:
		if param['name'] == 'vm_hosted_by':
			return param['value']
	return None

if __name__ == '__main__':

	hostgroup=options.hostgroup
	username=getUsername()
	password=getPasswd(username)
	
	hostCount=getPage(emmet_url+"?per_page=1")['total']
	allHosts=getPage(emmet_url+"?per_page="+str(hostCount))
	for host in allHosts['results']:
		hostname=host['name']
		ip=host['ip']
		hgroup_name=host['hostgroup_name']
		env_name=host['environment_name']
		if  hgroup_name == None:
		  hgroup_name="None"
		if  ip == None:
		   ip="None"
		if options.environment:
		  envname=options.environment
		  try:
                    if envname.lower() in env_name.lower():
		      print hostname +","+ip+","+hgroup_name,env_name
		  except:
			pass
		else:
		  if hostgroup.lower() in hgroup_name.lower():
		    print hostname +","+ip+","+hgroup_name,env_name
