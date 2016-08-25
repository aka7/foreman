#!/usr/bin/env python
# 
# common fucntions
# using foreman api
# export foreman_apibaseurl = https://<your_foreman_api_url>/api
# abdul.karim@aka-it.com
# v1.0
import urllib2,urllib
import sys, os
import re
import csv,operator
import base64
from urlparse import urlparse
from optparse import OptionParser
import getpass,socket
import json, commands
from netaddr import IPNetwork,IPAddress
import ssl
from datetime import datetime
import dateutil.parser,pytz
from configReader import read_properties

default_endpoint="https://<your_foreman_api_url>/api"
VERBOSE=False
DEBUG=False

def getBaseURL():
  apiBaseURL=os.getenv("foreman_apibaseurl")
  if apiBaseURL == None:
    apiBaseURL=default_endpoint
  return apiBaseURL

def readRCFile():
  username=None
  password=None
  homedir=os.path.expanduser("~")
  rcfile=homedir+"/.foremanrc"
  if os.path.isfile(rcfile):
    result=read_properties(rcfile)
    try:
      username=result['user.name']
    except KeyError:
      username=None
    try:
      password=result['user.password']
    except KeyError:
      password=None
  return [username,password]

def getUsername():
	# get username
	creds = readRCFile()
	username=creds[0]
	if (username == None):
	  username=os.getenv("foreman_user")
	  if (username == None):
		username = raw_input("Enter username :")
	return username
def getPasswd(username):
	# get username and password
	creds = readRCFile()
	password=creds[1]
	if (password == None):
	  password=os.getenv("foreman_pw")
	  if (password == None):
		password = getpass.getpass("Enter your password for user ["+username+"] :")
	return password

def getPage(theurl,username,password):
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
	    print theurl
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
	    	print "Url [ "+theurl+"] not found : " + str(err.code)
	    else:
	    	print "It looks like the username or password is wrong. "  +str (err.code)
	    sys.exit(1)
  except IOError, e:
		print "Something else went wrong"
  thepage = handle.read()
  return json.loads(thepage)
def delInterface(theurl,username,password):
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
		req.get_method = lambda: 'DELETE' #creates the delete method
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

def findSubnet(ip,username,password):
  apiBaseURL=getBaseURL()
  subnets = getPage(apiBaseURL+"/subnets",username,password)
  if DEBUG:
		print subnets
  subnet_name=""
  for s in subnets['results']:
		network = s['network']
		mask = s['mask']
		name = s['name']
		if IPAddress(ip) in IPNetwork(network+'/'+mask):
			subnet_name=name
			break

  if DEBUG:
		print subnets
  return getPage(apiBaseURL+"/subnets/"+subnet_name,username,password)

def showInterfaces(fqdn,interfaces=[],delete_interface=False):
  for interface in interfaces:
    id=str(interface['id'])
    name = interface['identifier']	
    mac = interface['mac']
    print "\t",name,mac
    if delete_interface:
	if 'macvtap' in name:
		print "deleting macvtap interface",name,id
		delete_url=default_endpoint+"/hosts/"+fqdn+"/interfaces/"+id
		username=getUsername()
		password=getPasswd(username)
		output=delInterface(delete_url,username,password)
		print output
