#!/usr/bin/python

import os
import sys 
import getopt
import syslog
import hashlib
import requests
from pymemcache.client import base
from requests.exceptions import ConnectionError

"""
	Script: apache-mstr-auth.py
	Version 1.0
	2021/OCT/10
	
	This script is an external authenticator program which integrates the Apache 
	module mod_authnz_external with MicroStrategy defined users. Authentication is 
	cached if memcached is available.
	
"""

# Configurable values
CONFIG_MSTR_MODE = 1
CONFIG_MSTR_URL = 'http://bi-web01.scapr.org/MicroStrategyLibrary/api/';
CONFIG_CACHE_TTL = 86400
CONFIG_CACHE_HOST = '127.0.0.1'



##
def cache_lookup(mykey):
	token = None
	status = False
	
	try:
		client = base.Client(CONFIG_CACHE_HOST)
		token = client.get(mykey)
		if token != None: 
			status = True
	except Exception as e:
		syslog.syslog( "MSTR/Login cache not available for lookup, trying online")
	
	return status, token

##
def cache_store(mykey, myvalue):
	try:
		client = base.Client(CONFIG_CACHE_HOST)
		cacheok = client.set(mykey, myvalue, CONFIG_CACHE_TTL)
		if not cacheok:
			syslog.syslog( "MSTR/Failed storing login on cache")
		
	except Exception as e:
		syslog.syslog( "MSTR/Login cache not available for storing data")

#
def cache_key(mylogin, mypassword):
	object = hashlib.sha256(("%s/%s" % (mylogin, mypassword)))
	v = object.hexdigest()
	return v

##
# Function: login_cache 
# Description: Login using cached data		
#
def login_cache(mylogin, mypassword):
	token = None
	status = False
	
	# Cache lookup logic
	status, token = cache_lookup(cache_key(mylogin, mypassword))

	return status, token

##
# Function: login_online 
# Description: Login online using Microstrategy API site
#
def login_online(mylogin, mypassword):	
	token = None
	status = False
	
	data_json = {'username': mylogin, 'password': mypassword, 'loginMode': CONFIG_MSTR_MODE}
	r = requests.post(CONFIG_MSTR_URL + 'auth/login', data=data_json)
	if r.ok:
		token = r.headers['X-MSTR-AuthToken']
		status = True
	else:
		syslog.syslog("HTTP %i - %s, Message %s" % (r.status_code, r.reason, r.text))

	return status, token

# Login wrapper
def login(mylogin, mypassword):	
	token = None
	status = False
		
	status, token = login_cache(mylogin, mypassword)
	if status:
		syslog.syslog( "MSTR/Successful cached login for user=%s with token=%s" % (mylogin, token))
	else: 		
		status, token = login_online(mylogin, mypassword)
		if status:
			cache_store(cache_key(mylogin, mypassword), token)
			syslog.syslog( "MSTR/Successful online login for user=%s with token=%s" % (mylogin, token))
			
		
	return status, token
	

## Script main function
def main():
	token = None
	status = False
	myuser = sys.stdin.readline().rstrip()
	mypass = sys.stdin.readline().rstrip()
	
	status, token = login(myuser, mypass)
	if not status:
		syslog.syslog( "MSTR/Failed login for user=%s" % (myuser))
		sys.exit(os.EX_NOPERM)
    
	sys.exit(os.EX_OK)	
    

### Main program
if __name__ == "__main__":
   main()
