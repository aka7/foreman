#!/usr/bin/env python
# 
# Get host report status from foreman
# using foreman api
# export foreman_apibaseurl = https://<your_foreman_api_url>/api
# abdul.karim@sky.uk
# SNS
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
import ssl
from datetime import datetime
import dateutil.parser,pytz

#some version of python fail on self sign ssl certs
ssl._create_default_https_context = ssl._create_unverified_context

DEBUG=False
parser = OptionParser()
parser.add_option("-j", "--json",
                  action="store_true", dest="json", default=False,
                  help="json output")
parser.add_option("-e", "--error-state",
                  action="store_true", dest="searcherror", default=False,
                  help="get all hosts in puppet error state")
parser.add_option("-D", "--debug",
                  action="store_true", dest="debug", default=False,
                  help="print debug informaiton")
parser.add_option("-v", "--verbose",
                  action="store_true", dest="verbose", default=False,
                  help="print status messages to stdout")

(options, args) = parser.parse_args()



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
		username = raw_input("Enter cauth username :")
	return username
def getPasswd():
	# get username and passsword
	password=os.getenv("foreman_pw")
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

if __name__ == '__main__':

  # set api uri
  #i.e https://<foreman.yourdomain>/api
  # or set environment vairable foreman_apibaseurl
  apiBaseURL=getBaseURL()

  search="last_report+<+\"35+minutes+ago\"+and+status.enabled+%3D+true"
  msg="Hosts out of sync:"
  if options.searcherror:
  	search="last_report+>+\"35+minutes+ago\"+and+%28status.failed+>+0+or+status.failed_restarts+>+0%29+and+status.enabled+%3D+true"
  	msg="Hosts in error state:"

  searchurl=apiBaseURL+"/hosts?search="+search
  if options.debug:
  	DEBUG=True
  username=getUsername()
  password=getPasswd()
  thepage=getPage(searchurl)
  if DEBUG:
    print json.dumps(thepage,indent=4)
  print msg
  timenow=datetime.now(pytz.UTC)
  for host in thepage['results']:	
		name = host["name"]
		lastreport = host["last_report"]
		if options.json:
			print json.dumps(host,indent=4)
		reporttime = dateutil.parser.parse(lastreport)
		timediff = timenow - reporttime
		print name, "[ "+str(timediff)+" ]"
