#!/usr/bin/env python
# 
# Get host report status from foreman
# using foreman api
# export foreman_apibaseurl = https://<your_foreman_api_url>/api
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
from datetime import datetime
import dateutil.parser,pytz
from foreman_common import getPasswd,getUsername,getBaseURL,getPage
#some version of python fail on self sign ssl certs
if sys.version_info[0] == 2 and sys.version_info[1] > 6:
	#version 2.7 of python fail on self sign ssl certs
	import ssl
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
  password=getPasswd(username)
  thepage=getPage(searchurl,username,password)
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
