#!/usr/bin/env python3

'''
Licensed Under Apache 2.0
Copyright (C) MC874
All rights Reserved

Commits preserved free as is;
Permitted for Commercial Use or Private use.
With other Circumstances such as free Distribution and Modification.
All the state bounds with Conditions.

Following states, it's conditions to indicate the changes
As well mention it's License use and Copyright holders.

Heavily forbid Trademark act.
Provides NO WARRANTY; implies 'WITHOUT' to all it's related such as MERCHANTABILITY.
Derived details <https://www.apache.org/licenses/LICENSE-2.0>
'''

import csv
import ssl
import json
import socket
import subprocess
import requests,re
import os, fnmatch
from time import sleep
from itertools import islice
from threading import Thread
from collections import defaultdict
from os.path import abspath, dirname
from pkg_resources import parse_version
from multiprocessing import Process, Manager, Value, Queue, cpu_count

inpute = 'input'
output = 'output'
work_at_time = 20
expected_response = 101
cflare_domain = 'id3.sshws.me'
cfront_domain = 'd20bqb0z6saqqh.cloudfront.net'

txtfiles= []
txtlines= []
maxi = cpu_count()
columns = defaultdict(list)

payloads = {'Host': '', 'SNI': '', 'Proxy': ''}
switch = { 'bloc': 0, 'rot': 0, 'dir': 0, 'numtotal': 0, 'numline': 0, 'nametag': 'result', 'type': '', 'loc': ''}
cipher = (':ECDHE-RSA-AES128-GCM-SHA256:DES-CBC3-SHA:AES256-SHA:AES128-SHA:AES128-SHA256:AES256-GCM-SHA384:AES256-SHA256:ECDHE-RSA-DES-CBC3:EDH-RSA-DES-CBC3:EECDH+AESGCM:EDH-RSA-DES-CBC3-SHA:EDH-AESGCM:AES256+EECDH:ECHDE-RSA-AES256-GCM-SHA384:ECHDE-ECDSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECHDE-ECDSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:AES256+EDH:DHE-DSS-AES128-GCM-SHA256:kEDH+AESGCM:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA:ECDHE-ECDSA-AES256-SHA:DHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA:DHE-DSS-AES128-SHA256:DHE-RSA-A$:DHE-RSA-AES256-SHA256:DHE-DSS-AES256-SHA:DHE-RSA-AES256-SHA:HIGH:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!3DES:!MD5:!PSK')

class colors:
	RED_BG = '\033[41m\033[1m'
	GREEN_BG = '\033[42m'
	ENDC = '\033[m'

''' User-Input Section '''
# Takes Domain Fronting
def doma():
	print('1. Custom SSH Address')
	print('2. Default CloudFront')
	print('3. Default CloudFlare')
	print('')
	ans=input(' Choose SSH : ').lower()
	if ans=='1':
		domain=input(' Domain : ')
		payloads['Host']=f'{domain}'
	elif ans=='2':
		payloads['Host']=f'{cfront_domain}'
	elif ans=='3':
		payloads['Host']=f'{cflare_domain}'
	else:
		uinput()
	print('')
	frontdom = payloads['Host']
	print(' Selected ['+colors.GREEN_BG+f' {frontdom} '+colors.ENDC+'] as Domain Fronting!')
	print(' ['+ colors.RED_BG + ' INVALID ' + colors.ENDC + '] SSH Will Give 0 Result!' )

# Add Output
def outfile(): 
	print('[' + colors.RED_BG + ' Output File Name ' + colors.ENDC + ']')
	nametag = input(' Input File Name : ')
	switch['nametag'] = nametag
	print('')

# Rot Switch control
def option():
	global file_hosts
	print('')
	if switch['bloc'] == 1:
		if switch['rot']==2:
			print('[' + colors.RED_BG + ' Proxy/IP for Host Rotate ' + colors.ENDC + ']')
			prox = input(' Input Proxy : ')
			payloads['Proxy']=prox
		elif switch['rot']==0:
			print('[' + colors.RED_BG + ' Hostname/SNI for Proxy Rotate' + colors.ENDC + ']')
			bugger = input(' Input Hostname : ')
			payloads['SNI']=bugger
	print('')

# Outrange input as finish
def uinput():
	global switcher, payloads
	print('')
	print('['+colors.RED_BG+' Target Block Exceeded ' + colors.ENDC + ']' )
	print('1. Go Back to Menu')
	print('2. Quit Instead')
	print('')
	ans=input(' Choose Option: ')
	if ans=='1':
		print("\033c\033[3J\033[2J\033[0m\033[H")
		payloads = {'Host': '', 'SNI': '', 'Proxy': ''}
		switch = { 'bloc': '', 'rot': '', 'dir': '', 'type': '', 'loc': '', 'nametag': 'result'}
		menu()
	elif ans=='2':
		print("\033c\033[3J\033[2J\033[0m\033[H")
		exit()
	else:
		print('['+colors.RED_BG+' GGRRR! ' + colors.ENDC + '] Invalid INPUT!' )
		print('')
		menu()

''' Reading List Section '''
# Reading from Files
def filet():
	num_file = 1
	print('1. Scan Files in Input Folder')
	print('2. Scan Files in Current Folder')
	print('3. Scan Files in Termux Host')
	print('4. Scan Files in Termux')
	print('5. Scan Custom Path')
	print('')
	ans=input(' Choose Scan Input : ').lower()
	print('')
	if ans=='1':
		files = os.listdir(inpute)
		switch['dir']=0
	elif ans=='2':
		files = [f for f in os.listdir('.') if os.path.isfile(f)]
		switch['dir']=1
	elif ans=='3':
		files = os.listdir('$home/storage/shared/' + inpute)
		switch['dir']=2
	elif ans=='4':
		files = os.listdir('$home/storage/shared/')
		switch['dir']=3
	elif ans=='5':
		path = input(' Input your Folder: ')
		files = os.listdir(path)
		switch['dir']=4
	else:
		uinput()
	print(' [' + colors.RED_BG + ' Files Found ' + colors.ENDC + '] ')
	for f in files:
		if fnmatch.fnmatch(f, '*.txt'):
			switch['type']=0
		elif fnmatch.fnmatch(f, '*.csv'):
			switch['type']=1
		print( str(num_file),str(f))
		num_file=num_file+1
		txtfiles.append(str(f))
	print('')
	print(' M back to Menu ')
	fileselector = input(' Choose Target Files : ')
	if fileselector.isdigit():
		print('')
		print(' Chosen File : ' + colors.RED_BG + ' '+txtfiles[int(fileselector)-1]+' '+colors.ENDC)
		print('')
		direct = switch['dir']
		if direct == 0:
			file_hosts = inpute +'/'+ str(txtfiles[int(fileselector)-1])
		elif direct == 1:
			file_hosts = str(txtfiles[int(fileselector)-1])
		elif direct == 2:
			file_hosts = './storage/shared/' + inpute +'/'+ str(txtfiles[int(fileselector)-1])
		elif direct == 3:
			file_hosts = './storage/shared/' + str(txtfiles[int(fileselector)-1])
		else:
			file_hosts = path
		switch['loc']=file_hosts
	else:
		uinput()

# Reading Lines
def liner():
	switch['type']=2
	num_line=1
	print('[' + colors.RED_BG + ' List of String based on Lines ' + colors.ENDC + ']')
	with open(switch['loc'], 'r') as liner:
		for f in liner:
			print(str(num_line),str(f.strip()))
			num_line=num_line+1
			txtlines.append(str(f.strip()))
	print('')
	print(' M back to Menu ')
	lineselector = input(' Choose Target Lines : ')
	print('')
	print(' Chosen Line : ' + colors.RED_BG + ' '+txtlines[int(lineselector)-1]+' '+colors.ENDC)
	print('')
	if lineselector.isdigit():
		switch['loc']=txtlines[int(lineselector)-1]
	else:
		uinput()

# Reading from Online enumeration
def hacki():
	global domainlist
	subd = input('\nInput Domain: ')
	subd = subd.replace('https://','').replace('http://','')
	r = requests.get('https://api.hackertarget.com/hostsearch/?q=' + subd, allow_redirects=False)
	if r.text == 'error invalid host':
		exit('ERR: error invalid host')
	else:
		switch['type']=3
		domainlist = re.findall('(.*?),',r.text)

''' Main Control Section '''
# Running Process
def executor():
	total = []
	for i in range(maxi):
		appendix.put('ENDED')
		if switch['bloc']==0:
			p = Process(target=grabber, args=(appendix,Resultee,Faily))
		elif switch['bloc']==1:
			p = Process(target=wsee, args=(appendix,Resultee,Faily))
		elif switch['bloc']==2:
			p = Process(target=wsrect, args=(appendix,Resultee,Faily))
		else:
			p = Process(target=h2srect, args=(appendix,Resultee,Faily))
		p.start()
		total.append(p)
	for p in total:
		p.join()
	p.terminate()

# Running Process and Reading text list
''' Type 0: takes txt
	Type 1: takes csv
	Type 2: takes input
	Type 3: takes online enum '''

def serv():
	global appendix, Faily, Resultee
	Faily=Value('i',0)
	appendix = Queue()
	Resultee=Value('d',0)
	if switch['type']==0:
		with open(switch['loc'], 'r') as f:
			for line in f:
				liner = [line] + list(islice(f, work_at_time-1))
				for i in liner:
					appendix.put(str(re.sub('\n', '', i.strip())))
				executor()
	elif switch['type']==1:
		with open(switch['loc'], 'r') as f:
			reader = csv.reader(csv_file)
			for row in reader:
				for (i,v) in enumerate(row):
					columns[i].append(v)
			appendix.put(columns[9]+columns[3])
		executor()
	elif switch['type']==2:
		appendix.put(str(switch['loc']))
		executor()
	else:
		for domain in domainlist:
			appendix.put(domain)
		executor()
	print('')
	print(' Failed Result : '  + colors.RED_BG + ' '+ str(Faily.value) +' '+ colors.ENDC )
	print(' Success Result : ' + colors.GREEN_BG + ' '+ str(Resultee.value) + ' '+colors.ENDC)

''' Main Process '''
# Ping DNS over TCP to check connection
def pinger():
	while True:
		try:
			sock = socket.socket()
			sock.connect(('zendesk4.grabtaxi.com', 80))
			sock.sendall(bytes(f'GET / HTTP/1.1\r\nHost: {cflare_domain}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dXP3jD9Ipw0B2EmWrMDTEw==\r\nSec-Websocket-Version: 13\r\nSec-Websocket-Accept: GLWt4W8Ogwo6lmX9ZGa314RMRr0=\r\nSec-WebSocket-Extensions: superspeed\r\nOrigin: http://{payloads["Host"]}\r\nPragma: no-cache\r\n\r\n', encoding='utf-8'))
			sock.recv(13)
			sock = re.findall("b'HTTP\/[1-9]\.[1-9]\ (.*?)\ ", line)
			if int(sock[0]) == 101:
				break
		except socket.error as e:
			print(e)
			print("["+colors.RED_BG+" Check Your Internet Connection! "+colors.ENDC+"]")
			sleep(3)

# Websocket SSL: Takes CDN/Local
''' Rot 0: Rotate Proxy Mode
	Rot 1: Direct Mode
	Rot 2: Rotate Host Mode
	Rot 3: Normal Mode'''

def wsee(appendix,Resultee,Faily):
	while True:
		onliner = appendix.get()
		if onliner == 'ENDED':
			break
		else:
			try:
				pinger()
				with socket.socket() as sock:
					sock.settimeout(5)
					sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
					cont = ssl.create_default_context()
					cont.set_ciphers(cipher)
					if switch['rot']==0:
						sock = cont.wrap_socket(sock, server_hostname = f'{payloads["SNI"]}')
						sock.connect((onliner, 443))
						sock.sendall(bytes(f'GET wss://{payloads["SNI"]}/ HTTP/1.1\r\nHost: {payloads["Host"]}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dXP3jD9Ipw0B2EmWrMDTEw==\r\nSec-Websocket-Version: 13\r\nSec-Websocket-Accept: GLWt4W8Ogwo6lmX9ZGa314RMRr0=\r\nSec-WebSocket-Extensions: superspeed\r\nOrigin: https://{payloads["SNI"]}\r\nPragma: no-cache\r\n\r\n', encoding='utf-8'))
					elif switch['rot']==1:
						sock.connect((onliner, 80))
						sock.sendall(bytes(f'GET ws://{onliner}/ HTTP/1.1\r\nHost: {payloads["Host"]}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dXP3jD9Ipw0B2EmWrMDTEw==\r\nSec-Websocket-Version: 13\r\nSec-Websocket-Accept: GLWt4W8Ogwo6lmX9ZGa314RMRr0=\r\nSec-WebSocket-Extensions: superspeed\r\nOrigin: https://{onliner}\r\nPragma: no-cache\r\n\r\n', encoding='utf-8'))
					else:
						if switch['rot']==2:
							sock = cont.wrap_socket(sock, server_hostname = onliner)
							sock.connect((f'{payloads["Proxy"]}', 443))
						else:
							sock = cont.wrap_socket(sock, server_hostname = onliner)
							sock.connect((onliner, 443))
						sock.sendall(bytes(f'GET wss://{onliner}/ HTTP/1.1\r\nHost: {payloads["Host"]}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dXP3jD9Ipw0B2EmWrMDTEw==\r\nSec-Websocket-Version: 13\r\nSec-Websocket-Accept: GLWt4W8Ogwo6lmX9ZGa314RMRr0=\r\nSec-WebSocket-Extensions: superspeed\r\nOrigin: https://{onliner}\r\nPragma: no-cache\r\n\r\n', encoding='utf-8'))
					line = str(sock.recv(13))
					resu = re.findall("b'HTTP\/[1-9]\.[1-9]\ (.*?)\ ", line)
					if not resu:
						print(' ['+colors.RED_BG+' FAIL '+colors.ENDC+'] ' + onliner + ' [' + colors.RED_BG +' EMPTY '+colors.ENDC+']')
						with Faily.get_lock():
							Faily.value +=1
					else:
						if int(resu[0]) == expected_response:
							print(' ['+colors.GREEN_BG+' HIT '+colors.ENDC+'] ' + onliner+ ' [' +colors.GREEN_BG+' ' + str(resu[0]) + ' '+colors.ENDC+']')
							print(onliner, file=open(f'{output}/{switch["nametag"]}.txt', 'a'))
							with Resultee.get_lock():
								Resultee.value +=1
						else:
							print(' ['+colors.RED_BG+' FAIL '+colors.ENDC+'] ' + onliner + ' [' +colors.RED_BG+' ' + str(resu[0]) + ' '+colors.ENDC+']')
							with Faily.get_lock():
								Faily.value +=1
			except(ssl.SSLError):
				print(' ['+colors.RED_BG+' FAIL '+colors.ENDC+'] ' + onliner + ' [' + colors.RED_BG +' NOT SSL '+colors.ENDC+']')
				with Faily.get_lock():
					Faily.value +=1
			except(socket.gaierror) or (socket.timeout):
				print(' ['+colors.RED_BG+' FAIL '+colors.ENDC+'] ' + onliner + ' [' + colors.RED_BG +' INVALID '+colors.ENDC+']')
				with Faily.get_lock():
					Faily.value +=1
			except(socket.error):
				print(' ['+colors.RED_BG+' FAIL '+colors.ENDC+'] ' + onliner + ' [' + colors.RED_BG +' TIMEOUT '+colors.ENDC+']')
				with Faily.get_lock():
					Faily.value +=1
			except Exception as e:
				print(e)
				pass

# Websocket Direct: Takes CDN/Local
'''	Rot 1: Local Mode
	Rot 0: Normal Mode '''

def wsrect(appendix,Resultee,Faily):
	while True:
		onliner = appendix.get()
		if onliner == 'ENDED':
			break
		else:
			try:
				pinger()
				with socket.socket() as sock:
					sock.settimeout(5)
					sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
					cont = ssl.create_default_context()
					cont.set_ciphers(cipher)
					if switch['rot'] == 0:
						sock = cont.wrap_socket(sock, server_hostname = f'{onliner}')
						sock.connect((onliner, 443))
						sock.sendall(bytes(f'GET / HTTP/1.1\r\nHost: {payloads["Host"]}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dXP3jD9Ipw0B2EmWrMDTEw==\r\nSec-Websocket-Version: 13\r\nSec-Websocket-Accept: GLWt4W8Ogwo6lmX9ZGa314RMRr0=\r\nSec-WebSocket-Extensions: superspeed\r\nOrigin: http://{payloads["Host"]}\r\nPragma: no-cache\r\n\r\n', encoding='utf-8'))
					else:
						sock.connect((onliner, 80))
						sock.sendall(bytes(f'GET / HTTP/1.1\r\nHost: {onliner}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dXP3jD9Ipw0B2EmWrMDTEw==\r\nSec-Websocket-Version: 13\r\nSec-Websocket-Accept: GLWt4W8Ogwo6lmX9ZGa314RMRr0=\r\nSec-WebSocket-Extensions: superspeed\r\nOrigin: http://{payloads["Host"]}\r\nPragma: no-cache\r\n\r\n', encoding='utf-8'))
					line = str(sock.recv(13))
					resu = re.findall("b'HTTP\/[1-9]\.[1-9]\ (.*?)\ ", line)
					if not resu:
						print(' ['+colors.RED_BG+' FAIL '+colors.ENDC+'] ' + onliner + ' [' + colors.RED_BG +' EMPTY '+colors.ENDC+']')
						with Faily.get_lock():
							Faily.value +=1
					else:
						if int(resu[0]) == expected_response:
							print(' ['+colors.GREEN_BG+' HIT '+colors.ENDC+'] ' + onliner+ ' [' +colors.GREEN_BG+' ' + str(resu[0]) + ' '+colors.ENDC+']')
							print(onliner, file=open(f'{output}/{switch["nametag"]}.txt', 'a'))
							with Resultee.get_lock():
								Resultee.value +=1
						else:
							print(' ['+colors.RED_BG+' FAIL '+colors.ENDC+'] ' + onliner + ' [' +colors.RED_BG+' ' + str(resu[0]) + ' '+colors.ENDC+']')
							with Faily.get_lock():
								Faily.value +=1
			except(ssl.SSLError):
				print(' ['+colors.RED_BG+' FAIL '+colors.ENDC+'] ' + onliner + ' [' + colors.RED_BG +' NOT SSL '+colors.ENDC+']')
				with Faily.get_lock():
					Faily.value +=1
			except(socket.gaierror) or (socket.timeout):
				print(' ['+colors.RED_BG+' FAIL '+colors.ENDC+'] ' + onliner + ' [' + colors.RED_BG +' INVALID '+colors.ENDC+']')
				with Faily.get_lock():
					Faily.value +=1
			except(socket.error):
				print(' ['+colors.RED_BG+' FAIL '+colors.ENDC+'] ' + onliner + ' [' + colors.RED_BG +' TIMEOUT '+colors.ENDC+']')
				with Faily.get_lock():
					Faily.value +=1
			except Exception as e:
				print(e)
				pass

# Websocket SSL: Takes CDN/Local
'''	Rot 1: Local
	Rot 0: Normal Mode '''

def h2srect(appendix,Resultee,Faily):
	while True:
		onliner = appendix.get()
		if onliner == 'ENDED':
			break
		else:
			try:
				pinger()
				with socket.socket() as sock:
					sock.settimeout(5)
					sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
					sock.connect((onliner, 80))
					if switch['rot']==0:
						sock.sendall(bytes(f'GET h2c://{onliner}/ HTTP/1.1\r\nHost: {payloads["Host"]}\r\nUpgrade: h2c\r\nConnection: Upgrade, HTTP2-Settings\r\nHTTP2-Settings: \r\n\r\n', encoding='utf-8'))
					else:
						sock.connect((onliner, 80))
						sock.sendall(bytes(f'GET / HTTP/1.1\r\nHost: {onliner}\r\nUpgrade: h2c\r\nConnection: Upgrade, HTTP2-Settings\r\nHTTP2-Settings: \r\n\r\n', encoding='utf-8'))
					line = str(sock.recv(13))
					resu = re.findall("b'HTTP\/[1-9]\.[1-9]\ (.*?)\ ", line)
					if not resu:
						print(' ['+colors.RED_BG+' FAIL '+colors.ENDC+'] ' + onliner + ' [' + colors.RED_BG +' EMPTY '+colors.ENDC+']')
						with Faily.get_lock():
							Faily.value +=1
					else:
						if int(resu[0]) == expected_response:
							print(' ['+colors.GREEN_BG+' HIT '+colors.ENDC+'] ' + onliner+ ' [' +colors.GREEN_BG+' ' + str(resu[0]) + ' '+colors.ENDC+']')
							print(onliner, file=open(f'{output}/{switch["nametag"]}.txt', 'a'))
							with Resultee.get_lock():
								Resultee.value +=1
						else:
							print(' ['+colors.RED_BG+' FAIL '+colors.ENDC+'] ' + onliner + ' [' +colors.RED_BG+' ' + str(resu[0]) + ' '+colors.ENDC+']')
							with Faily.get_lock():
								Faily.value +=1
			except(ssl.SSLError):
				print(' ['+colors.RED_BG+' FAIL '+colors.ENDC+'] ' + onliner + ' [' + colors.RED_BG +' NOT SSL '+colors.ENDC+']')
				with Faily.get_lock():
					Faily.value +=1
			except(socket.gaierror) or (socket.timeout):
				print(' ['+colors.RED_BG+' FAIL '+colors.ENDC+'] ' + onliner + ' [' + colors.RED_BG +' INVALID '+colors.ENDC+']')
				with Faily.get_lock():
					Faily.value +=1
			except(socket.error):
				print(' ['+colors.RED_BG+' FAIL '+colors.ENDC+'] ' + onliner + ' [' + colors.RED_BG +' TIMEOUT '+colors.ENDC+']')
				with Faily.get_lock():
					Faily.value +=1
			except Exception as e:
				print(e)
				pass

# ZGrab Mode: Only Local; Takes 443/80
def grabber(appendix,Resultee,Faily):
	while True:
		onliner = appendix.get()
		if onliner == 'ENDED':
			break
		else:
			try:
				pinger()
				if switch['rot']==0:
					commando=f"echo {onliner} | zgrab2 http --custom-headers-names='Upgrade,Sec-WebSocket-Key,Sec-WebSocket-Version,Connection' --custom-headers-values='websocket,dXP3jD9Ipw0B2EmWrMDTEw==,13,Upgrade' --remove-accept-header --dynamic-origin --use-https --port 443 --max-redirects 10 --retry-https --cipher-suite= portable -t 10 | jq '.data.http.result.response.status_code,.domain' | grep -A 1 -E --line-buffered '^101'"
				elif switch['rot']==1:
					commando =f"echo {onliner} | zgrab2 http --custom-headers-names='Upgrade,Sec-WebSocket-Key,Sec-WebSocket-Version,Connection' --custom-headers-values='websocket,dXP3jD9Ipw0B2EmWrMDTEw==,13,Upgrade' --remove-accept-header --dynamic-origin --port 80 --max-redirects 10 --cipher-suite= portable -t 10 | jq '.data.http.result.response.status_code,.domain' | grep -A 1 -E --line-buffered '^101'"
				elif switch['rot']==2:
					commando=f"echo {onliner} | zgrab2 http --custom-headers-names='Upgrade,HTTP2-Settings,Connection' --custom-headers-values='h2,AAMAAABkAARAAAAAAAIAAAAA,Upgrade' --remove-accept-header --dynamic-origin --use-https --port 443 --max-redirects 10 --retry-https --cipher-suite= portable -t 10 | jq '.data.http.result.response.status_code,.domain' | grep -A 1 -E --line-buffered '^101'"
				else:
					commando =f"echo {onliner} | zgrab2 http --custom-headers-names='Upgrade,HTTP2-Settings,Connection' --custom-headers-values='h2c,AAMAAABkAARAAAAAAAIAAAAA,Upgrade' --remove-accept-header --dynamic-origin --port 80 --max-redirects 10 --cipher-suite= portable -t 10 | jq '.data.http.result.response.status_code,.domain' | grep -A 1 -E --line-buffered '^101'"
				commando=subprocess.Popen(commando,shell=True,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
				commando = commando.stdout.read().decode('utf-8') + commando.stderr.read().decode('utf-8')
				rege = re.split(r'\n',commando)
				if rege[0]==f'{expected_response}':
					print(' ['+colors.GREEN_BG+' HIT '+colors.ENDC+'] ' + rege[1])
					print(rege[1], file=open(f'{switch["nametag"]}.txt', 'a'))
					with Resultee.get_lock():
						Resultee.value +=1
				else:
					print(' ['+colors.RED_BG+' FAIL '+colors.ENDC+'] ' + onliner)
					with Faily.get_lock():
						Faily.value +=1
			except Exception as e:
				print(e)
				print(' [' + colors.RED_BG+'Check Your ZGrab Installation!'+colors.ENDC+'] ' + onliner)
				menu()

''' Frontier Section '''
# Check for Updates / Bin
def checker():
	with open('.wsee/CONFIG') as f:
		data = json.load(f)
		if data['config']['update-wsee'] == True:
			print('[' + colors.RED_BG + ' Checking for update... ' +  colors.ENDC + ']')
			resp = requests.get('https://raw.githubusercontent.com/MC874/wsee/main/VERSION')
			with open('./.wsee/VERSION') as f:
				verlocal = f.read()
			if parse_version(resp.text) > parse_version(verlocal):
				print('[' + colors.GREEN_BG + ' Update Available ' + colors.ENDC + ']')
				print('1) Ignore Update')
				print('2) Apply Update')
				ans=input(' Choose : ')
				if ans=='2':
					os.remove('wsee.py')
					upd = requests.get('https://raw.githubusercontent.com/MC874/wsee/main/wsee.py')
					with open('wsee.py', 'a') as pd:
						pd.write(upd.text)
						print("\033c\033[3J\033[2J\033[0m\033[H")
					print('[' + colors.GREEN_BG + ' Script Updated! ' + colors.ENDC + ']')
					sleep(3)
					print("\033c\033[3J\033[2J\033[0m\033[H")
					exit()
				else:
					print("\033c\033[3J\033[2J\033[0m\033[H")
			else:
				print('[' + colors.RED_BG + ' No Update Available ' +  colors.ENDC + ']')
				sleep(3)
				print("\033c\033[3J\033[2J\033[0m\033[H")
		else:
			return

# Main Menu; Handles everything.
def menu():
	print('''
__  _  ________ ____   ____  
\ \/ \/ /  ___// __ \_/ __ \ 
 \     /\___ \\  ___/\  ___/ 
  \/\_//____  >\___  >\___  >
            \/     \/     \/  

	''')
	print('    [' + colors.RED_BG + ' Domain : Fronting ' + colors.ENDC + ']')
	print('     ['+colors.RED_BG+' Author ' + colors.ENDC + ':' + colors.GREEN_BG + ' Kiynox ' + colors.ENDC + ']')
	print('')
	print('1. CDN Websocket')
	print('2. Local Websocket')
	print('3. HTTP/2 Socket')
	print('')
	ans=input(' Choose Modes : ').lower()
	print('')
	if ans=='1':
		print('1. [Fronting] Websocket SSL')
		print('2. [Fronting] Websocket Proxy Rotate')
		print('3. [Fronting] Websocket Host Rotate')
		print('4. [Fronting] Websocket Direct')
		print('')
		ans=input(' Choose Modes : ').lower()
		print('')
		if ans=='1':
			switch['bloc']=1
			switch['rot']=3
		elif ans=='2':
			switch['bloc']=1
			switch['rot']=0
		elif ans=='3':
			switch['bloc']=1
			switch['rot']=2
		elif ans=='4':
			switch['bloc']=1
			switch['rot']=1
	elif ans=='2':
		print('1. [Local] Websocket SSL')
		print('2. [Local] Websocket Direct')
		print('3. [Local] Websocket SSL ZGrab')
		print('4. [Local] Websocket Direct ZGrab')
		print('')
		ans=input(' Choose Modes : ').lower()
		print('')
		if ans=='1':
			switch['bloc']=2
			switch['rot']=0
		elif ans=='2':
			switch['bloc']=2
			switch['rot']=1
		elif ans=='3':
			switch['bloc']=0
			switch['rot']=0
		elif ans=='4':
			switch['bloc']=0
			switch['rot']=1
		else:
			uinput()
	elif ans=='3':
		print('1. [Fronting] HTTP/2 Direct')
		print('2. [Local] HTTP/2 Direct')
		print('3. [Local] HTTP/2 Direct ZGrab')
		print('')
		ans=input(' Choose Modes : ').lower()
		print('')
		if ans=='1':
			switch['bloc']=3
			switch['rot']=0
		elif ans=='2':
			switch['bloc']=3
			switch['rot']=1
		elif ans == '3':
			switch['bloc']=0
			switch['rot']=3
		else:
			uinput()
	else:
		uinput()
	print('1. Scan File (.txt)')
	print('2. Scan Online (HackerTarget)')
	print('3. Scan Custom Input')
	print('')
	ans=input(' Choose Scan Input :  ').lower()
	print('')
	if ans=='1':
		print('1. Scan Local Files')
		print('3. Scan Local Lines')
		print()
		ans=input(' Choose Scan Input :  ').lower()
		print()
		if ans == '1':
			filet()
			outfile()
		elif ans == '2':
			filet()
			liner()
			outfile()
		else:
			uinput()
		if switch['bloc']==1:
			doma()
		option()
		serv()
		uinput()
	elif ans=='2':
		if switch['bloc']==1:
			doma()
		hacki()
		outfile()
		option()
		serv()
		uinput()
	elif ans=='3':
		print('1. Scan Custom Hostname/SNI')
		print('2. Scan Custom Proxy/IP')
		print('')
		ans = input(' Choose Scan Input: ')
		print('')
		if ans == '1':
			cus = input(' Input Hostname : ')
		elif ans == '2':
			cus = input(' Input IP : ')
		else:
			uinput()
		print()
		switch['loc']=cus
		switch['type']=2
		outfile()
		doma()
		option()
		serv()
		uinput()
	else:
		uinput()

if __name__ == '__main__':
	os.chdir(dirname(abspath(__file__)))
	checker()
	menu()