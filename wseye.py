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
import base64
import socket
import subprocess
import requests,re
import os, fnmatch
from time import sleep
from threading import Thread
from collections import defaultdict
from os.path import abspath, dirname
from pkg_resources import parse_version
from multiprocessing import Process, Manager, Value, Queue, cpu_count

hostpath = 'host'
output = 'output'
expected_response = 101
cflare_domain = 'id-herza.sshws.net'
cfront_domain = 'dhxqu5ob0t1lp.cloudfront.net'

txtfiles= []
appendix = Queue()
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
columns = defaultdict(list)
cont = ssl.create_default_context()
payloads = {'Host': '', 'SNI': '', 'Proxy': ''}
switch = { 'bloc': '', 'rot': '', 'dir': '', 'type': '', 'loc': '', 'nametag': 'result'}
cipher = (':ECDHE-RSA-AES128-GCM-SHA256:DES-CBC3-SHA:AES256-SHA:AES128-SHA:AES128-SHA256:AES256-GCM-SHA384:AES256-SHA256:ECDHE-RSA-DES-CBC3:EDH-RSA-DES-CBC3:EECDH+AESGCM:EDH-RSA-DES-CBC3-SHA:EDH-AESGCM:AES256+EECDH:ECHDE-RSA-AES256-GCM-SHA384:ECHDE-ECDSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECHDE-ECDSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:AES256+EDH:DHE-DSS-AES128-GCM-SHA256:kEDH+AESGCM:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA:ECDHE-ECDSA-AES256-SHA:DHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA:DHE-DSS-AES128-SHA256:DHE-RSA-A$:DHE-RSA-AES256-SHA256:DHE-DSS-AES256-SHA:DHE-RSA-AES256-SHA:HIGH:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!3DES:!MD5:!PSK')

class colors:
	RED_BG = '\033[41m\033[1m'
	GREEN_BG = '\033[42m'
	ENDC = '\033[m'

def option():
	global file_hosts
	if switch['rot']=='1':
		print('[' + colors.RED_BG + ' Input your Proxy ' + colors.ENDC + ']')
		prox = input(' Proxy : ')
		payloads['Proxy']=prox
	elif switch['rot']=='2':
		print('[' + colors.RED_BG + ' Input your BugHost ' + colors.ENDC + ']')
		bugger = input(' SNI : ')
		payloads['SNI']=bugger
	print('[' + colors.RED_BG + ' Input your Output File Name ' + colors.ENDC + ']')
	nametag = input(' Output as : ')
	print('')
	switch['nametag'] = nametag
	return

def doma():
	print('1. Custom Domain')
	print('2. Default CloudFront')
	print('3. Default CloudFlare')
	print('Q to Quit')
	print('M to Menu')
	print('')
	ans=input(' Choose Option : ').lower()
	print('')
	if ans=='1':
		domain=input(' Domain : ')
		payloads['Host']=f'{domain}'
	elif ans=='2':
		payloads['Host']=f'{cfront_domain}'
	elif ans=='3':
		payloads['Host']=f'{cflare_domain}'
	elif ans=='q':
		exit()
	elif ans=='m':
		menu()
	else:
		print('['+colors.RED_BG+' GGRRR! ' + colors.ENDC + '] Invalid INPUT!' )
		print('')
		menu()
	frontdom = payloads['Host']
	print('['+colors.GREEN_BG + f' {frontdom} '+ colors.ENDC + '] Selected as Domain Fronting!')
	print('['+colors.RED_BG+' Warning! ' + colors.ENDC + '] : [' + colors.RED_BG + ' INVALID ' + colors.ENDC + '] Domain Will Give 0 Result!' )
	print('')
	return

def uinput():
	print('')
	print('Scanning Finished!')
	print('1. Go Back to Menu')
	print('2. Scanning Again')
	print('3. Quit Instead')
	print('')
	ans=input('Choose Option: ')
	if ans=='1':
		print (u"{}[2J{}[;H".format(chr(27), chr(27)), end="")
		menu()
	elif ans=='2':
		print (u"{}[2J{}[;H".format(chr(27), chr(27)), end="")
		return
	elif ans=='3':
		exit()
	else:
		print('['+colors.RED_BG+' GGRRR! ' + colors.ENDC + '] Invalid INPUT!' )
		print('')
		print (u"{}[2J{}[;H".format(chr(27), chr(27)), end="")
		menu()
	
def filet():
	num_file = 1
	print('1. Check Files in Host Folder')
	print('2. Check Files in Current Folder')
	print('3. Check Files in Termux Host')
	print('4. Check Files in Termux')
	print('5. Custom Path')
	print('q to Quit')
	print('m to Menu')
	print('')
	ans=input(' Choose : ').lower()
	if ans=='1':
		files = os.listdir(hostpath)
		switch['dir']='0'
	elif ans=='2':
		files = [f for f in os.listdir('.') if os.path.isfile(f)]
		switch['dir']='1'
	elif ans=='3':
		files = os.listdir('./storage/shared/' + hostpath)
		switch['dir']='2'
	elif ans=='4':
		files = os.listdir('./storage/shared/')
		switch['dir']='3'
	elif ans=='5':
		path = input(' Input your Folder: ')
		files = os.listdir(path)
		switch['dir']='4'
	elif ans=='q':
		exit()
	elif ans=='m':
		menu()
	else:
		print('['+colors.RED_BG+' GGRRR! ' + colors.ENDC + '] Invalid INPUT!' )
		print('')
		menu()
	print(' [' + colors.RED_BG + ' Files Found ' + colors.ENDC + '] ')
	for f in files:
		if fnmatch.fnmatch(f, '*.txt'):
			switch['type']='txt'
		elif fnmatch.fnmatch(f, '*.csv'):
			switch['type']='csv'
		print( str(num_file),str(f))
		num_file=num_file+1
		txtfiles.append(str(f))
	print('')
	print(' M back to Menu ')
	fileselector = input(' Choose Target Files : ')
	if fileselector.isdigit():
		print('')
		print(' Target Chosen : ' + colors.RED_BG + ' '+txtfiles[int(fileselector)-1]+' '+colors.ENDC)
		direct = switch['dir']
		if direct == '0':
			file_hosts = str(hostpath) +'/'+ str(txtfiles[int(fileselector)-1])
		elif direct == '1':
			file_hosts = str(txtfiles[int(fileselector)-1])
		elif direct == '2':
			file_hosts = './storage/shared/' + str(hostpath) +'/'+ str(txtfiles[int(fileselector)-1])
		elif direct == '3':
			file_hosts = './storage/shared/' + str(txtfiles[int(fileselector)-1])
		elif direct == '4':
			file_hosts = path
		switch['loc']=file_hosts
	else:
		menu()
	return

def hacki():
	global domainlist
	subd = input('\nInput Domain: ')
	subd = subd.replace('https://','').replace('http://','')
	r = requests.get('https://api.hackertarget.com/hostsearch/?q=' + subd, allow_redirects=False)
	if r.text == 'error invalid host':
		exit('ERR: error invalid host')
	else:
		switch['type']='enum'
		domainlist = re.findall('(.*?),',r.text)
		return

def executor():
	global Faily, Resultee, Run
	procount = cpu_count()
	Faily=Value('i',0)
	Resultee=Value('d',0)
	Run = Value('f', 1)
	def filement():
		if Run.value:
			if switch['type']=='txt':
				with open(switch['loc'], 'r') as f:
					for liner in f:
						appendix.put(liner.strip())
			elif switch['type']=='csv':
				with open(switch['loc'], 'r') as f:
					reader = csv.reader(csv_file)
					for row in reader:
						for (i,v) in enumerate(row):
							columns[i].append(v)
					appendix.put(columns[9]+columns[3])
			elif switch['type']=='enum':
				apppendix.put(domainlist)
			for i in range(procount):
				appendix.put('ENDED')
	if 0 <= int(switch['dir']) < 4:
		filament = Thread(target=filement)
		filament.start()
	processes = []
	for process_num in range(procount):
		if switch['bloc']=='0':
			p = Process(target=grabber, args=(appendix,Resultee,Faily))
		elif switch['bloc']=='1':
			p = Process(target=wsee, args=(appendix,Resultee,Faily))
		elif switch['bloc']=='2':
			p = Process(target=wsrect, args=(appendix,Resultee,Faily))
		elif switch['bloc']=='3':
			p = Process(target=h2see, args=(appendix,Resultee,Faily))
		elif switch['bloc']=='4':
			p = Process(target=h2srect, args=(appendix,Resultee,Faily))
		elif switch['bloc']=='5':
			p = Process(target=nowsee, args=(appendix,Resultee,Faily))
		p.start()
		processes.append(p)
	for p in processes:
		p.join()
	if 0 <= int(switch['dir']) < 4:
		filament.join()
	print('')
	print(' Failed Result : '  + colors.RED_BG + ' '+ str(Faily.value) +' '+ colors.ENDC )
	print(' Successfull Result : ' + colors.GREEN_BG + ' '+ str(Resultee.value) + ' '+colors.ENDC)
	return

def pinger():
	try:
		sock.settimeout(3)
		sock.connect(('8.8.8.8',53))
		Run.value = 1
	except socket.error:
		print("["+colors.RED_BG+" Check Your Internet Connection! "+colors.ENDC+"]")
		sleep(10)
		Run.value = 0
		pinger()

def wsee(appendix,Resultee,Faily):
	while True:
		onliner = appendix.get()
		if onliner == 'ENDED':
			break
		else:
			try:
				pinger()
				print('Using WS SSL')
				cont.set_ciphers(cipher)
				if switch['rot']=='3':
					print('Rotate Proxy')
					sock = cont.wrap_socket(sock, server_hostname = f'{payloads["SNI"]}')
					sock.connect((onliner, 443))
					sock.sendall(bytes(f'GET wss://{payloads["SNI"]}/ HTTP/1.1\r\nHost: {payloads["Host"]}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dXP3jD9Ipw0B2EmWrMDTEw==\r\nSec-Websocket-Version: 13\r\nSec-Websocket-Accept: GLWt4W8Ogwo6lmX9ZGa314RMRr0=\r\nSec-WebSocket-Extensions: superspeed\r\nOrigin: https://{payloads["SNI"]}\r\nPragma: no-cache\r\n\r\n', encoding='utf-8'))
				elif 0 <= int(switch['rot']) < 2:
					if switch['rot']=='1':
						print('Rotate Host')
						sock = cont.wrap_socket(sock, server_hostname = onliner)
						sock.connect((payloads["Proxy"], 443))
					else:
						print('Rotate 0/2 Normal/Local')
						sock = cont.wrap_socket(sock, server_hostname = onliner)
						sock.connect((onliner, 443))
					if switch['rot']=='2':
						print('Sending Payload WS SSL Local')
						sock.sendall(bytes(f'GET wss://{onliner}/ HTTP/1.1\r\nHost: {onliner}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dXP3jD9Ipw0B2EmWrMDTEw==\r\nSec-Websocket-Version: 13\r\nSec-Websocket-Accept: GLWt4W8Ogwo6lmX9ZGa314RMRr0=\r\nSec-WebSocket-Extensions: superspeed\r\nOrigin: https://{onliner}\r\nPragma: no-cache\r\n\r\n', encoding='utf-8'))
					else:
						print('Sending Payload WS SSL Normal')
						sock.sendall(bytes(f'GET wss://{onliner}/ HTTP/1.1\r\nHost: {payloads["Host"]}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dXP3jD9Ipw0B2EmWrMDTEw==\r\nSec-Websocket-Version: 13\r\nSec-Websocket-Accept: GLWt4W8Ogwo6lmX9ZGa314RMRr0=\r\nSec-WebSocket-Extensions: superspeed\r\nOrigin: https://{onliner}\r\nPragma: no-cache\r\n\r\n', encoding='utf-8'))
				sock.settimeout(5)
				sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
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
					elif int(resu[0]) != expected_response:
						print(' ['+colors.RED_BG+' FAIL '+colors.ENDC+'] ' + onliner + ' [' +colors.RED_BG+' ' + str(resu[0]) + ' '+colors.ENDC+']')
						with Faily.get_lock():
							Faily.value +=1
				sock.close()
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

def wsrect(appendix,Resultee,Faily):
	while True:
		onliner = appendix.get()
		if onliner == 'ENDED':
			break
		else:
			try:
				pinger()
				print('Using WS Direct')
				sock.connect((onliner, 80))
				if switch['rot'] == '0':
					print('Sending Payload WS Direct Normal')
					sock.sendall(bytes(f'GET / HTTP/1.1\r\nHost: {payloads["Host"]}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dXP3jD9Ipw0B2EmWrMDTEw==\r\nSec-Websocket-Version: 13\r\nSec-Websocket-Accept: GLWt4W8Ogwo6lmX9ZGa314RMRr0=\r\nSec-WebSocket-Extensions: superspeed\r\nOrigin: http://{payloads["Host"]}\r\nPragma: no-cache\r\n\r\n', encoding='utf-8'))
				else:
					print('Sending payload WS Direct Local')
					sock.sendall(bytes(f'GET / HTTP/1.1\r\nHost: {onliner}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dXP3jD9Ipw0B2EmWrMDTEw==\r\nSec-Websocket-Version: 13\r\nSec-Websocket-Accept: GLWt4W8Ogwo6lmX9ZGa314RMRr0=\r\nSec-WebSocket-Extensions: superspeed\r\nOrigin: http://{payloads["Host"]}\r\nPragma: no-cache\r\n\r\n', encoding='utf-8'))
				sock.settimeout(5)
				sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
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
					elif int(resu[0]) != expected_response:
						print(' ['+colors.RED_BG+' FAIL '+colors.ENDC+'] ' + onliner + ' [' +colors.RED_BG+' ' + str(resu[0]) + ' '+colors.ENDC+']')
						with Faily.get_lock():
							Faily.value +=1
				sock.close()
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

def h2see(appendix,Resultee,Faily):
	while True:
		onliner = appendix.get()
		if onliner == 'ENDED':
			break
		else:
			try:
				pinger()
				print('Using H2C SSL')
				cont.set_ciphers(cipher)
				if switch['rot']=='3':
					print('Rotate Proxy')
					sock = cont.wrap_socket(sock, server_hostname = f'{payloads["SNI"]}')
					sock.connect((onliner, 443))
					sock.sendall(bytes(f'GET h2c://{payloads["SNI"]}/ HTTP/1.1\r\nHost: {payloads["Host"]}\r\nUpgrade: h2c\r\nConnection: Upgrade, HTTP2-Settings\r\nHTTP2-Settings: {base64.encode(payloads["SNI"])}\r\n\r\n', encoding='utf-8'))
				elif (0 <= int(switch['rot']) < 2):
					if switch['rot']=='1':
						print('Rotate Host')
						sock = cont.wrap_socket(sock, server_hostname = onliner)
						sock.connect((payloads["Proxy"], 443))
					else:
						print('Rotate 0/2 Normal/Local')
						sock = cont.wrap_socket(sock, server_hostname = onliner)
						sock.connect((onliner, 443))
					if switch['rot']=='2':
						print('Sending Payload H2 SSL Local')
						sock.sendall(bytes(f'GET h2c://{onliner}/ HTTP/1.1\r\nHost: {onliner}\r\nUpgrade: h2c\r\nConnection: Upgrade, HTTP2-Settings\r\nHTTP2-Settings: {base64.encode(onliner)}\r\n\r\n', encoding='utf-8'))
					else:
						print('Sending Payload H2 SSL Normal')
						sock.sendall(bytes(f'GET h2c://{onliner}/ HTTP/1.1\r\nHost: {payloads["Host"]}\r\nUpgrade: h2c\r\nConnection: Upgrade, HTTP2-Settings\r\nHTTP2-Settings: {base64.encode(onliner)}\r\n\r\n', encoding='utf-8'))
				sock.settimeout(5)
				sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
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
					elif int(resu[0]) != expected_response:
						print(' ['+colors.RED_BG+' FAIL '+colors.ENDC+'] ' + onliner + ' [' +colors.RED_BG+' ' + str(resu[0]) + ' '+colors.ENDC+']')
						with Faily.get_lock():
							Faily.value +=1
				sock.close()
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

def h2srect(appendix,Resultee,Faily):
	while True:
		onliner = appendix.get()
		if onliner == 'ENDED':
			break
		else:
			try:
				pinger()
				sock.connect((onliner, 80))
				if switch['rot']=='0':
					print('Sending Payload H2 Direct Normal')
					sock.sendall(bytes(f'GET / HTTP/1.1\r\nHost: {payloads["Host"]}\r\nUpgrade: h2c\r\nConnection: Upgrade, HTTP2-Settings\r\nHTTP2-Settings: {base64.encode(payloads["Host"])}\r\n\r\n', encoding='utf-8'))
				else:
					print('Sending Payload H2 Direct Local')
					sock.sendall(bytes(f'GET / HTTP/1.1\r\nHost: {onliner}\r\nUpgrade: h2c\r\nConnection: Upgrade, HTTP2-Settings\r\nHTTP2-Settings: {base64.encode(payloads["Host"])}\r\n\r\n', encoding='utf-8'))
				sock.settimeout(5)
				sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
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
					elif int(resu[0]) != expected_response:
						print(' ['+colors.RED_BG+' FAIL '+colors.ENDC+'] ' + onliner + ' [' +colors.RED_BG+' ' + str(resu[0]) + ' '+colors.ENDC+']')
						with Faily.get_lock():
							Faily.value +=1
				sock.close()
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

def nowsee(appendix,Resultee,Faily):
	while True:
		onliner = appendix.get()
		if onliner == 'ENDED':
			break
		else:
			try:
				pinger()
				if switch['rot']=='0':
					cont.set_ciphers(cipher)
					sock = cont.wrap_socket(sock, server_hostname = onliner)
					sock.connect((onliner, 443))
				else:
					sock.connect((onliner, 80))
				sock.sendall(bytes(f'GET / HTTP/1.1\r\nHost: {onliner}\r\nAccept: */*\r\nAccept-Encoding: *\r\nAccept-Language: *\r\nUpgrade-Insecure-Requests: 1\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.93 Safari/537.36\r\n\r\n', encoding='utf-8'))
				sock.settimeout(5)
				sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
				line = str(sock.recv(13))
				resu = re.findall("b'HTTP\/[1-9]\.[1-9]\ (.*?)\ ", line)
				if not resu:
					print(' ['+colors.RED_BG+' FAIL '+colors.ENDC+'] ' + onliner + ' [' + colors.RED_BG +' EMPTY '+colors.ENDC+']')
					with Faily.get_lock():
						Faily.value +=1
				else:
					if int(resu[0]) == 200:
						print(' ['+colors.GREEN_BG+' HIT '+colors.ENDC+'] ' + onliner+ ' [' +colors.GREEN_BG+' ' + str(resu[0]) + ' '+colors.ENDC+']')
						print(onliner, file=open(f'{output}/{switch["nametag"]}.txt', 'a'))
						with Resultee.get_lock():
							Resultee.value +=1
					elif int(resu[0]) != 200:
						print(' ['+colors.RED_BG+' FAIL '+colors.ENDC+'] ' + onliner + ' [' +colors.RED_BG+' ' + str(resu[0]) + ' '+colors.ENDC+']')
						with Faily.get_lock():
							Faily.value +=1
				sock.close()
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

def grabber(appendix,Resultee,Faily):
	while True:
		onliner = appendix.get()
		if onliner == 'ENDED':
			break
		else:
			try:
				pinger()
				if switch['rot']=='0':
					commando=f"echo {onliner} | zgrab2 http --custom-headers-names='Upgrade,Sec-WebSocket-Key,Sec-WebSocket-Version,Connection' --custom-headers-values='websocket,dXP3jD9Ipw0B2EmWrMDTEw==,13,Upgrade' --remove-accept-header --dynamic-origin --use-https --port 443 --max-redirects 10 --retry-https --cipher-suite= portable -t 10 | jq '.data.http.result.response.status_code,.domain' | grep -A 1 -E --line-buffered '^101'"
				elif switch['rot']=='1':
					commando =f"echo {onliner} | zgrab2 http --custom-headers-names='Upgrade,Sec-WebSocket-Key,Sec-WebSocket-Version,Connection' --custom-headers-values='websocket,dXP3jD9Ipw0B2EmWrMDTEw==,13,Upgrade' --remove-accept-header --dynamic-origin --port 80 --max-redirects 10 --cipher-suite= portable -t 10 | jq '.data.http.result.response.status_code,.domain' | grep -A 1 -E --line-buffered '^101'"
				elif switch['rot']=='2':
					commando=f"echo {onliner} | zgrab2 http --custom-headers-names='Upgrade,HTTP2-Settings,Connection' --custom-headers-values='h2,AAMAAABkAARAAAAAAAIAAAAA,Upgrade' --remove-accept-header --dynamic-origin --use-https --port 443 --max-redirects 10 --retry-https --cipher-suite= portable -t 10 | jq '.data.http.result.response.status_code,.domain' | grep -A 1 -E --line-buffered '^101'"
				elif switch['rot']=='3':
					commando =f"echo {onliner} | zgrab2 http --custom-headers-names='Upgrade,HTTP2-Settings,Connection' --custom-headers-values='h2c,AAMAAABkAARAAAAAAAIAAAAA,Upgrade' --remove-accept-header --dynamic-origin --port 80 --max-redirects 10 --cipher-suite= portable -t 10 | jq '.data.http.result.response.status_code,.domain' | grep -A 1 -E --line-buffered '^101'"
				commando=subprocess.Popen(commando,shell=True,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
				commando = commando.stdout.read().decode('utf-8') + commando.stderr.read().decode('utf-8')
				rege = re.split(r'\n',commando)
				if rege[0]==f'{expected_response}':
					print(' ['+colors.GREEN_BG+' HIT '+colors.ENDC+'] ' + rege[1])
					print(rege[1], file=open(f'{switch["nametag"]}.txt', 'a'))
					with Resultee.get_lock():
						Resultee.value +=1
				elif rege[0]!=f'{expected_response}':
					print(' ['+colors.RED_BG+' FAIL '+colors.ENDC+'] ' + onliner)
					with Faily.get_lock():
						Faily.value +=1
			except Exception as e:
				print(e)
				print(' [' + colors.RED_BG+'Check Your ZGrab Installation!'+colors.ENDC+'] ' + onliner)
				menu()

def checker():
	with open('.wsee/CONFIG') as f:
		data = json.load(f)
		if data['config']['update-wsee'] == True:
			print('[' + colors.RED_BG + ' Checking for update... ' +  colors.ENDC + ']')
			resp = requests.get('https://raw.githubusercontent.com/MC874/wsee/main/VERSION')
			if parse_version(resp.text) > parse_version("1.10.0"):
				print('[' + colors.GREEN_BG + ' Update Available ' + colors.ENDC + ']')
				print('1) Ignore Update')
				print('2) Apply Update')
				ans=input(' Choose : ')
				if ans=='2':
					os.remove('wsee.py')
					upd = requests.get('https://raw.githubusercontent.com/MC874/wsee/main/wsee.py')
					with open('wsee.py', 'a') as pd:
						pd.write(upd.text)
						print (u"{}[2J{}[;H".format(chr(27), chr(27)), end="")
						pd.close()
						f.close()
					print('[' + colors.GREEN_BG + ' Updated! ' + colors.ENDC + ']')
					exit()
				else:
					print (u"{}[2J{}[;H".format(chr(27), chr(27)), end="")
					f.close()
					return
			else:
				print('[' + colors.RED_BG + ' No Update Available ' +  colors.ENDC + ']')
				sleep(3)
				print (u"{}[2J{}[;H".format(chr(27), chr(27)), end="")
				f.close()
				return
		else:
			f.close()
			return

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
	print('3. CDN H2C')
	print('4. Local H2C')
	print('5. TLS/SSL')
	print('6. Direct/Proxy')
	print('q to Quit')
	print('')
	ans=input(' Choose Option : ').lower()
	print('')
	global headers, switch
	if ans=='1':
		print('1. CDN SSL')
		print('2. CDN SSL Proxy Rotate')
		print('3. CDN SSL Host Rotate')
		print('4. CDN Direct')
		print('q to Quit')
		print('m to Menu')
		print('')
		ans=input(' Choose Option : ').lower()
		print('')
		if ans=='1':
			switch['bloc']='1'
			switch['rot']='0'
		elif ans=='2':
			switch['bloc']='1'
			switch['rot']='3'
		elif ans=='3':
			switch['bloc']='1'
			switch['rot']='1'
		elif ans=='4':
			switch['bloc']='2'
			switch['rot']='0'
		elif ans=='q':
			exit()
		elif ans=='m':
			menu()
		else:
			print('['+colors.RED_BG+' GGRRR! ' + colors.ENDC + '] Invalid INPUT!' )
			print('')
			menu()
	elif ans=='2':
		print('1. Local SSL')
		print('2. Local Direct')
		print('3. Local SSL ZGrab')
		print('4. Local Direct ZGrab')
		print('q to Quit')
		print('')
		ans=input(' Choose Option : ').lower()
		print('')
		if ans=='1':
			switch['bloc']='1'
			switch['rot']='2'
		elif ans=='2':
			switch['bloc']='2'
			switch['rot']='1'
		elif ans=='3':
			switch['bloc']='0'
			switch['rot']='0'
		elif ans=='4':
			switch['bloc']='0'
			switch['rot']='1'
		elif ans=='q':
			exit()
		elif ans=='m':
			menu()
		else:
			print('['+colors.RED_BG+' GGRRR! ' + colors.ENDC + '] Invalid INPUT!' )
			print('')
			menu()
	elif ans=='3':
		print('1. H2 SSL')
		print('2. H2 SSL Proxy Rotate')
		print('3. H2 SSL Host Rotate')
		print('4. H2C Direct')
		print('q to Quit')
		print('m to Menu')
		print('')
		ans=input(' Choose Option : ').lower()
		print('')
		if ans=='1':
			switch['bloc']='3'
			switch['rot']='0'
		elif ans=='2':
			switch['bloc']='3'
			switch['rot']='3'
		elif ans=='3':
			switch['bloc']='3'
			switch['rot']='1'
		elif ans=='4':
			switch['bloc']='4'
			switch['rot']='0'
		elif ans=='q':
			exit()
		elif ans=='m':
			menu()
		else:
			print('['+colors.RED_BG+' GGRRR! ' + colors.ENDC + '] Invalid INPUT!' )
			print('')
			menu()
	elif ans=='4':
		print('1. Local H2C SSL')
		print('2. Local H2C Direct')
		print('3. Local H2C SSL ZGrab')
		print('4. Local H2C Direct ZGrab')
		print('m to Menu')
		print('q to Quit')
		print('')
		ans=input(' Choose Option : ')
		print('')
		if ans=='1':
			switch['bloc']='3'
			switch['rot']='2'
		elif ans=='2':
			switch['bloc']='4'
			switch['rot']='1'
		elif ans=='3':
			switch['bloc']='0'
			switch['rot']='2'
		elif ans=='4':
			switch['bloc']='0'
			switch['rot']='3'
		elif ans=='q':
			exit()
		elif ans=='m':
			menu()
		else:
			print('['+colors.RED_BG+' GGRRR! ' + colors.ENDC + '] Invalid INPUT!' )
			print('')
			menu()
	elif ans=='5':
		switch['bloc']='5'
		switch['rot']='0'
	elif ans=='6':
		switch['bloc']='5'
		switch['rot']='`1'
	elif ans=='q':
		exit()
	print()
	print(switch)
	print()
	print('1. Scan File (.txt)')
	print('2. Scan Online (HackerTarget)')
	print('Q to Quit')
	print('M to Menu')
	print('')
	ans=input(' Choose Option :  ').lower()
	print('')
	if ans=='1':
		def text():
			if (switch['bloc']=='1') or (switch['bloc']=='3'):
				doma()
			filet()
			option()
			executor()
			uinput()
			text()
		text()
	elif ans=='2':
		def enum():
			if (switch['bloc']=='1') or (switch['bloc']=='3'):
				doma()
			hacki()
			option()
			executor()
			uinput()
			enum()
		enum()
	elif ans=='m':
		menu()
	elif ans=='q':
		exit()
	else:
		print('['+colors.RED_BG+' GGRRR! ' + colors.ENDC + '] Invalid INPUT!' )
		print('')
		menu()

if __name__ == '__main__':
	os.chdir(dirname(abspath(__file__)))
	if not os.path.exists(output):
		os.makedirs(output)
	checker()
	menu()