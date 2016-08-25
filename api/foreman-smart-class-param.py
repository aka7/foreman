#!/usr/bin/env python
# Get details of smartclass parameters
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
from foreman_common import getUsername, getPasswd, getBaseURL

if sys.version_info[0] == 2 and sys.version_info[1] > 6:
	#version 2.7 of python fail on self sign ssl certs
	import ssl
	ssl._create_default_https_context = ssl._create_unverified_context

DEBUG=False
parser = OptionParser()
parser.add_option("-i", "--id", dest="paramid",
                  help="smart class paramter id")
parser.add_option("-m", "--match", dest="match",
                  help="match value")
parser.add_option("-D", "--debug",
                  action="store_true", dest="debug", default=False,
                  help="print debug informaiton")
parser.add_option("-j", "--json",
                  action="store_true", dest="json", default=False,
                  help="print json format")
parser.add_option("-v", "--verbose",
                  action="store_true", dest="verbose", default=False,
                  help="print status messages to stdout")

(options, args) = parser.parse_args()



apiBaseURL=getBaseURL()
if options.debug:
	DEBUG=True
if not options.paramid:
	parser.print_help()
	sys.exit(0)

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

	username=getUsername()
	password=getPasswd(username)
	paramid=options.paramid
	
	smart_class_param_url=apiBaseURL+"/smart_class_parameters/"+paramid+"/override_values"
	
	paramCount=getPage(smart_class_param_url+"?per_page=1")['total']
	allOverrides=getPage(smart_class_param_url+"?per_page="+str(paramCount))

	if options.match:
		for override in allOverrides['results']:
			match=override['match']
			value=override['value']
			if options.match.lower() in match.lower():
		                print match
				if options.json:
					print json.dumps(value, indent=4)
				else:
		  		  for i in  value:
					print i+": ALL"
				
			
		sys.exit(0)
	for override in allOverrides['results']:
		match=override['match']
		value=override['value']
		a="["	
		print match
		if options.json:
			print json.dumps(value, indent=4)
		else:
		  for i in  value:
			print i+": ALL"
			a+="\""+i+"\","
		  a+="]"
		  print
		  print a.replace(",]","]")
		print
