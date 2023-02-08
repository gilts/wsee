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
import ctypes
import socket
import subprocess
import os, fnmatch
import requests, re
from time import sleep
from jsonmerge import merge
from threading import Thread
from collections import defaultdict
from os.path import abspath, dirname
from pkg_resources import parse_version
from itertools import islice, chain, repeat
from multiprocessing import Process, Manager, Value, Queue, cpu_count

inpute = 'input'
output = 'output'

work_at_time = 20
expected_response = 101
maxi = cpu_count()

cflare_domain = 'id3.sshws.me'
cfront_domain = 'd20bqb0z6saqqh.cloudfront.net'
customPayloads = { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.93 Safari/537.36', 'Upgrade-Insecure-Requests': '1', 'Accept': '*/*' }

props = { 'Host': '', 'SNI': '', 'Proxy': '', 'nametag': 'result'}
switch = { 'bloc': 0, 'rot': 0, 'dir': 0, 'numtotal': 0, 'numline': 0, 'type': 0 }
cipher = (':ECDHE-RSA-AES128-GCM-SHA256:DES-CBC3-SHA:AES256-SHA:AES128-SHA:AES128-SHA256:AES256-GCM-SHA384:AES256-SHA256:ECDHE-RSA-DES-CBC3:EDH-RSA-DES-CBC3:EECDH+AESGCM:EDH-RSA-DES-CBC3-SHA:EDH-AESGCM:AES256+EECDH:ECHDE-RSA-AES256-GCM-SHA384:ECHDE-ECDSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECHDE-ECDSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:AES256+EDH:DHE-DSS-AES128-GCM-SHA256:kEDH+AESGCM:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA:ECDHE-ECDSA-AES256-SHA:DHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA:DHE-DSS-AES128-SHA256:DHE-RSA-A$:DHE-RSA-AES256-SHA256:DHE-DSS-AES256-SHA:DHE-RSA-AES256-SHA:HIGH:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!3DES:!MD5:!PSK')

class colors:
	RED_BG = '\033[41m\033[1m'
	GREEN_BG = '\033[42m'
	ENDC = '\033[m'

''' User-Input Section '''
# Takes Domain Fronting
def doma():
	inputs = { '1': 'Custom SSH Address', '2': 'Default CloudFront', '3': 'Default CloudFlare' }
	inputs = user_input(inputs)
	if inputs == '1':
		inputs = input(' inputs : ')
		print('')
		props['Host'] = inputs
	elif inputs == '2':
		props['Host'] = cfront_domain
	elif inputs == '3':
		props['Host'] = cflare_domain
	print(' Selected ['+colors.GREEN_BG+f' {props["Host"]} '+colors.ENDC+'] as Domain Fronting!')
	print(' ['+ colors.RED_BG + ' INVALID ' + colors.ENDC + '] SSH Will Give 0 Result!' )
	print('')

# Child Controller
def option():
	print('[' + colors.RED_BG + ' Output File Name ' + colors.ENDC + ']')
	inputs = input(' Input File Name : ')
	props['nametag'] = inputs
	print('')
	if switch['bloc'] == 1:
		if switch['rot'] == 2:
			print('[' + colors.RED_BG + ' Proxy/IP for Host Rotate ' + colors.ENDC + ']')
			inputs = input(' Input Proxy : ')
			props['Proxy'] = inputs
		elif switch['rot'] == 0:
			print('[' + colors.RED_BG + ' Hostname/SNI for Proxy Rotate' + colors.ENDC + ']')
			inputs = input(' Input Hostname : ')
			props['SNI'] = bugger
	print('')

# Outrange input as finish
def uinput():
	global switch, props
	print('')
	print('['+colors.RED_BG+' Target Block Exceeded ' + colors.ENDC + ']' )
	inputs = { '1': 'Go Back to Menu', '2': 'Quit Instead' }
	inputs = user_input(inputs)
	if inputs == '1':
		props = { 'Host': '', 'SNI': '', 'Proxy': '', 'nametag': 'result'}
		switch = { 'bloc': 0, 'rot': 0, 'dir': 0, 'numtotal': 0, 'numline': 0, 'type': 0 }
		print("\033c\033[3J\033[2J\033[0m\033[H")
		menu()
	elif inputs == '2':
		exit()

# Display Input
def user_input(inputs):
	for i,j in inputs.items():
		print(f'{i}). {j}')
	prompts = chain(["Choose: "], repeat("Invalid Input, Try Again: ", 2))
	prompts = map(input, prompts)
	prompts = next(filter(inputs.__contains__, prompts), None)
	print('')
	if prompts is None:
		uinput()
	else:
		return prompts

''' Reading List Section '''
# Reading from Files
def filet():
	txtfiles = []
	num_file = 1
	inputs = { '1': 'Scan Files in Input Folder', '2': 'Scan Files in Current Folder', '3': 'Scan Files in Termux Host', '4': 'Scan Files in Termux', '5': 'Scan Custom Path' }
	inputs = user_input(inputs)
	if inputs == '1':
		files = os.listdir(inpute)
		switch['dir'] = 0
	elif inputs == '2':
		files = [f for f in os.listdir('.') if os.path.isfile(f)]
		switch['dir'] = 1
	elif inputs == '3':
		files = os.listdir('$home/storage/shared/' + inpute)
		switch['dir'] = 2
	elif inputs == '4':
		files = os.listdir('$home/storage/shared/')
		switch['dir'] = 3
	elif inputs == '5':
		path = input(' Input your Folder: ')
		files = os.listdir(path)
		switch['dir'] = 4
	print(' [' + colors.RED_BG + ' Files Found ' + colors.ENDC + '] ')
	for f in files:
		if fnmatch.fnmatch(f, '*.txt'):
			switch['type'] = 0
		elif fnmatch.fnmatch(f, '*.csv'):
			switch['type'] = 1
		print(str(num_file), str(f))
		num_file = num_file + 1
		txtfiles.append(str(f))
	print('')
	print(' M back to Menu ')
	inputs = input(' Choose Target Files : ')
	print('')
	print(' Chosen File : ' + colors.RED_BG + ' '+txtfiles[int(inputs)-1]+' '+colors.ENDC)
	print('')
	direct = switch['dir']
	if direct == 0:
		processor = inpute +'/'+ str(txtfiles[int(inputs)-1])
	elif direct == 1:
		processor = str(txtfiles[int(inputs)-1])
	elif direct == 2:
		processor = './storage/shared/' + inpute +'/'+ str(txtfiles[int(inputs)-1])
	elif direct == 3:
		processor = './storage/shared/' + str(txtfiles[int(inputs)-1])
	else:
		processor = path
	return processor

# Reading Lines
def liner(processor):
	switch['type'] = 2
	num_line = 1
	txtlines = []
	print('[' + colors.RED_BG + ' List of String based on Lines ' + colors.ENDC + ']')
	with open(processor, 'r') as liner:
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
		processor = txtlines[int(lineselector)-1]
	return processor

# Reading from Online enumeration
def hacki():
	inputs = input('\nInput Domain: ')
	print('')
	inputs = inputs.replace('https://','').replace('http://','')
	response = requests.get('https://api.hackertarget.com/hostsearch/?q=' + inputs)
	if response.text == 'error invalid host':
		exit('ERR: error invalid host')
	else:
		switch['type'] = 3
		processor = re.findall('(.*?),', response.text)
	return processor

''' Main Control Section '''
def reserver(processor):
	Faily = Value('i', 0)
	appendix = Queue()
	Resulty = Value('d', 0)
	columns = defaultdict(list)
	if switch['type'] == 0:
		with open(processor, 'r') as f:
			for line in f:
				appendix.put(line.strip())
		processor(appendix, Faily, Resulty)
	elif switch['type']==1:
		csv_file = open(processor, 'r').read()
		reader = csv.reader(csv_file)
		for row in reader:
			for (i,v) in enumerate(row):
				columns[i].append(v)
		appendix.put(columns[9]+columns[3])
		csv_file.close()
		processor(appendix, Faily, Resulty)
	elif switch['type']==2:
		appendix.put(processor)
		processor(appendix, Faily, Resulty)
	else:
		for process in processor:
			appendix.put(process)
		processor(appendix, Faily, Resulty)
	print(' Failed Result : ' + colors.RED_BG + ' ' + str(Faily.value) + ' ' + colors.ENDC )
	print(' Success Result : ' + colors.GREEN_BG + ' ' + str(Resulty.value) + ' ' + colors.ENDC)
	print('')

# Running Process and Reading text list
''' Type 0: takes txt
	Type 1: takes csv
	Type 2: takes input
	Type 3: takes online enum '''
def server(processor):
	global customPayloads
	if switch['bloc'] == 3:
		with open('./bin/payloads/http2', 'r') as f:
			payloads = json.load(f)
	else:
		with open('./bin/payloads/websocket', 'r') as f:
			payloads = json.load(f)
	mergedPayloads = merge(payloads, customPayloads)
	payloads = ''
	for i, j in mergedPayloads.items():
		payloads += f"'{i}': '{j}'\r\n"
	Resulty = Manager().dict()
	Resulty['Success'] = 0
	Resulty['Fail'] = 0
	payloads = Value(ctypes.c_wchar_p, payloads)
	appendix = Queue(200)
	columns = defaultdict(list)
	if switch['type'] == 0:
		f = open(processor, 'r')
		for line in f:
			liner = [line] + list(islice(f, 4))
			for i in liner:
				appendix.put(i.strip())
		f.close()
		executor(appendix, Resulty, payloads)
	elif switch['type']==1:
		csv_file = open(processor, 'r').read()
		reader = csv.reader(csv_file)
		for row in reader:
			for (i,v) in enumerate(row):
				columns[i].append(v)
		appendix.put(columns[9]+columns[3])
		csv_file.close()
		executor(appendix, Resulty, payloads)
	elif switch['type']==2:
		appendix.put(processor)
		executor(appendix, Resulty, payloads)
	else:
		for process in processor:
			appendix.put(process)
		executor(appendix, Resulty, payloads)
	print(' Failed Result : ' + colors.RED_BG + ' ' + str(Resulty['Fail']) + ' ' + colors.ENDC )
	print(' Success Result : ' + colors.GREEN_BG + ' ' + str(Resulty['Success']) + ' ' + colors.ENDC)
	print('')
	uinput()

# Running Process
def executor(appendix, Resulty, payloads):
	total = []
	for i in range(maxi):
		appendix.put('ENDED')
		p = Process(target = processor, args = (appendix, Resulty, payloads))
		p.start()
		total.append(p)
	for p in total:
		p.join()
	p.terminate()

# Processing Main Process
def processor(appendix, Resulty, payloads):
	while True:
		onliner = appendix.get()
		if onliner == 'ENDED':
			break
		try:
			pinger(payloads)
			if switch['bloc'] == 0:
				grabber(onliner, Resulty)
			elif switch['bloc'] == 1:
				wsee(onliner, Resulty, payloads)
			elif switch['bloc'] == 2:
				wsrect(onliner, Resulty, payloads)
			else:
				h2srect(onliner, Resulty, payloads)
		except(ssl.SSLError):
			print(' [' + colors.RED_BG + ' FAIL ' + colors.ENDC + '] ' + onliner + ' [' + colors.RED_BG + ' NOT SSL ' + colors.ENDC + ']')
			Resulty['Fail'] += 1
		except(socket.gaierror) or (socket.timeout):
			print(' [' + colors.RED_BG + ' FAIL ' + colors.ENDC + '] ' + onliner + ' [' + colors.RED_BG + ' INVALID ' + colors.ENDC + ']')
			Resulty['Fail'] += 1
		except(socket.error):
			print(' [' + colors.RED_BG + ' FAIL ' + colors.ENDC + '] ' + onliner + ' [' + colors.RED_BG + ' TIMEOUT ' + colors.ENDC + ']')
			Resulty['Fail'] += 1
		except Exception as e:
			print(e)
			pass

''' Main Process '''
# Ping DNS over TCP to check connection
def pinger(payloads):
	while True:
		try:
			sock = socket.socket()
			sock.settimeout(5)
			sock.connect(('nghttp2.org', 80))
			sock.sendall(f'GET / HTTP/1.1\r\nHost: nghttp2.org\r\nConnection: Upgrade, HTTP2-Settings\r\nUpgrade: h2c\r\nHTTP2-Settings: \r\n'.encode())
			line = str(sock.recv(13))
			sock.close()
			sock = re.findall("b'HTTP\/[1-9]\.[1-9]\ (.*?)\ ", line)
			if int(sock[0]) == 101:
				break
		except socket.error as e:
			print(e)
			print("[" + colors.RED_BG + " Check Your Internet Connection! " + colors.ENDC + "]")
			sleep(3)

# Websocket SSL: Takes CDN/Local
''' Rot 0: Rotate Proxy Mode
	Rot 1: Direct Mode
	Rot 2: Rotate Host Mode
	Rot 3: Normal Mode'''
def wsee(onliner, Resulty, payloads):
	sock = socket.socket()
	sock.settimeout(5)
	sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
	cont = ssl.create_default_context()
	cont.set_ciphers(cipher)
	if switch['rot'] == 0:
		sock = cont.wrap_socket(sock, server_hostname = f'{props["SNI"]}')
		sock.connect((onliner, 443))
		sock.sendall(f'GET wss://{props["SNI"]}/ HTTP/1.1\r\nHost: {props["Host"]}\r\n{payloads}\r\n'.encode())
	elif switch['rot'] == 1:
		sock.connect((onliner, 80))
		sock.sendall(f'GET / HTTP/1.1\r\nHost: {props["Host"]}\r\n{payloads}\r\n'.encode())
	else:
		if switch['rot'] == 2:
			sock = cont.wrap_socket(sock, server_hostname = onliner)
			sock.connect((f'{props["Proxy"]}', 443))
		else:
			sock = cont.wrap_socket(sock, server_hostname = onliner)
			sock.connect((onliner, 443))
		sock.sendall(f'GET wss://{onliner}/ HTTP/1.1\r\nHost: {props["Host"]}\r\n{payloads}\r\n'.encode())
	line = str(sock.recv(13))
	resu = re.findall("b'HTTP\/[1-9]\.[1-9]\ (.*?)\ ", line)
	if int(resu[0]) == expected_response:
		print(' [' + colors.GREEN_BG + ' HIT ' + colors.ENDC + '] ' + onliner + ' [' + colors.GREEN_BG + ' ' + str(resu[0]) + ' ' + colors.ENDC + ']')
		print(onliner, file = open(f'{output}/{props["nametag"]}.txt', 'a'))
		Resulty['Success'] += 1
	else:
		print(' [' + colors.RED_BG + ' FAIL ' + colors.ENDC + '] ' + onliner + ' [' + colors.RED_BG + ' ' + str(resu[0]) + ' ' + colors.ENDC + ']')
		Resulty['Fail'] += 1
	sock.close()

# Websocket Direct: Takes CDN/Local
'''	Rot 1: Local Mode
	Rot 0: Normal Mode '''

def wsrect(onliner, Resulty, payloads):
	sock = socket.socket()
	sock.settimeout(5)
	sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
	cont = ssl.create_default_context()
	cont.set_ciphers(cipher)
	if switch['rot'] == 0:
		sock = cont.wrap_socket(sock, server_hostname = f'{onliner}')
		sock.connect((onliner, 443))
		sock.sendall(f'GET wss://{onliner} HTTP/1.1\r\nHost: {props["Host"]}\r\n{payloads}\r\n'.encode())
	else:
		sock.connect((onliner, 80))
		sock.sendall(f'GET / HTTP/1.1\r\nHost: {onliner}\r\n{payloads}\r\n'.encode())
	line = str(sock.recv(13))
	resu = re.findall("b'HTTP\/[1-9]\.[1-9]\ (.*?)\ ", line)
	if int(resu[0]) == expected_response:
		print(' [' + colors.GREEN_BG + ' HIT ' + colors.ENDC + '] ' + onliner + ' [' + colors.GREEN_BG + ' ' + str(resu[0]) + ' ' + colors.ENDC + ']')
		print(onliner, file = open(f'{output}/{props["nametag"]}.txt', 'a'))
		Resulty['Success'] += 1
	else:
		print(' [' + colors.RED_BG + ' FAIL ' + colors.ENDC + '] ' + onliner + ' [' + colors.RED_BG + ' ' + str(resu[0]) + ' ' + colors.ENDC + ']')
		Resulty['Fail'] += 1
	sock.close()

# Websocket SSL: Takes CDN/Local
'''	Rot 1: Local
	Rot 0: Normal Mode '''

def h2srect(onliner, Resulty, payloads):
	sock = socket.socket()
	sock.settimeout(5)
	sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
	sock.connect((onliner, 80))
	if switch['rot']==0:
		sock.sendall(f'GET / HTTP/1.1\r\nHost: {props["Host"]}\r\n{payloads}\r\n'.encode())
	else:
		sock.connect((onliner, 80))
		sock.sendall(f'GET / HTTP/1.1\r\nHost: {onliner}\r\n{payloads}\r\n'.encode())
	line = str(sock.recv(13))
	resu = re.findall("b'HTTP\/[1-9]\.[1-9]\ (.*?)\ ", line)
	if int(resu[0]) == expected_response:
		print(' [' + colors.GREEN_BG + ' HIT ' + colors.ENDC + '] ' + onliner + ' [' + colors.GREEN_BG + ' ' + str(resu[0]) + ' ' + colors.ENDC + ']')
		print(onliner, file = open(f'{output}/{props["nametag"]}.txt', 'a'))
		Resulty['Success'] += 1
	else:
		print(' [' + colors.RED_BG + ' FAIL ' + colors.ENDC + '] ' + onliner + ' [' + colors.RED_BG + ' ' + str(resu[0]) + ' ' + colors.ENDC + ']')
		Resulty['Fail'] += 1
	sock.close()

# ZGrab Mode: Only Local; Takes 443/80
def grabber(onliner, Resulty):
	if switch['rot'] == 0:
		commando = f"echo {onliner} | zgrab2 http --custom-headers-names='Upgrade,Sec-WebSocket-Key,Sec-WebSocket-Version,Connection' --custom-headers-values='websocket,dXP3jD9Ipw0B2EmWrMDTEw==,13,Upgrade' --remove-accept-header --dynamic-origin --use-https --port 443 --max-redirects 10 --retry-https --cipher-suite= portable -t 10 | jq '.data.http.result.response.status_code,.domain' | grep -A 1 -E --line-buffered '^101'"
	elif switch['rot'] == 1:
		commando = f"echo {onliner} | zgrab2 http --custom-headers-names='Upgrade,Sec-WebSocket-Key,Sec-WebSocket-Version,Connection' --custom-headers-values='websocket,dXP3jD9Ipw0B2EmWrMDTEw==,13,Upgrade' --remove-accept-header --dynamic-origin --port 80 --max-redirects 10 --cipher-suite= portable -t 10 | jq '.data.http.result.response.status_code,.domain' | grep -A 1 -E --line-buffered '^101'"
	elif switch['rot']== 2:
		commando = f"echo {onliner} | zgrab2 http --custom-headers-values='h2c,AAMAAABkAARAAAAAAAIAAAAA,Upgrade' --remove-accept-header --dynamic-origin --use-https --port 443 --max-redirects 10 --retry-https --cipher-suite= portable -t 10 | jq '.data.http.result.response.status_code,.domain' | grep -A 1 -E --line-buffered '^101'"
	else:
		commando = f"echo {onliner} | zgrab2 http --custom-headers-names='Upgrade,HTTP2-Settings,Connection' --custom-headers-values='h2c,AAMAAABkAARAAAAAAAIAAAAA,Upgrade' --remove-accept-header --dynamic-origin --port 80 --max-redirects 10 --cipher-suite= portable -t 10 | jq '.data.http.result.response.status_code,.domain' | grep -A 1 -E --line-buffered '^101'"
	commando = subprocess.Popen(commando, shell = True, stdin = subprocess.PIPE, stdout = subprocess.PIPE, stderr = subprocess.PIPE)
	commando = commando.stdout.read().decode('utf-8') + commando.stderr.read().decode('utf-8')
	rege = re.split(r'\n',commando)
	if rege[0] == f'{expected_response}':
		print(' [' + colors.GREEN_BG + ' HIT ' + colors.ENDC + '] ' + rege[1])
		print(rege[1], file = open(f'{props["nametag"]}.txt', 'a'))
		Resulty['Success'] += 1
	else:
		print(' [' + colors.RED_BG + ' FAIL ' + colors.ENDC + '] ' + onliner)
		Resulty['Fail'] += 1

''' Frontier Section '''
# Apply Updates
def updater():
	print('[' + colors.GREEN_BG + ' Update Available ' + colors.ENDC + ']')
	inputs = { '1': 'Ignore Update', '2': 'Apply Update' }
	inputs = user_input(inputs)
	if inputs == '2':
		os.remove('wsee.py')
		response = requests.get('https://raw.githubusercontent.com/MC874/wsee/main/wsee.py')
		with open('wsee.py', 'a') as f:
			f.write(response.text)
		print('[' + colors.GREEN_BG + ' Script Updated! ' + colors.ENDC + ']')
		sleep(3)
		exit()
	else:
		pass

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
			updater()
		else:
			print('[' + colors.RED_BG + ' No Update Available ' +  colors.ENDC + ']')
			sleep(3)
	print("\033c\033[3J\033[2J\033[0m\033[H")

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
	inputs = { '1': 'CDN Websocket', '2': 'Local Websocket', '3': 'HTTP/2 Socket' }
	inputs = user_input(inputs)
	if inputs == '1':
		inputs = { '1': '[Fronting] Websocket SSL', '2': '[Fronting] Websocket Proxy Rotate', '3': '[Fronting] Websocket Host Rotate', '4': '[Fronting] Websocket Direct' }
		inputs = user_input(inputs)
		if inputs == '1':
			switch['bloc'] = 1
			switch['rot'] = 3
		elif inputs == '2':
			switch['bloc'] = 1
			switch['rot'] = 0
		elif inputs == '3':
			switch['bloc'] = 1
			switch['rot'] = 2
		elif inputs == '4':
			switch['bloc'] = 1
			switch['rot'] = 1
	elif inputs == '2':
		inputs = { '1': '[Local] Websocket SSL', '2': '[Local] Websocket Direct', '3': '[Local] Websocket SSL ZGrab', '4': '[Local] Websocket Direct ZGrab' }
		inputs = user_input(inputs)
		if inputs == '1':
			switch['bloc'] = 2
			switch['rot'] = 0
		elif inputs == '2':
			switch['bloc'] = 2
			switch['rot'] = 1
		elif inputs == '3':
			switch['bloc'] = 0
			switch['rot'] = 0
		elif inputs == '4':
			switch['bloc'] = 0
			switch['rot'] = 1
	elif inputs == '3':
		inputs = { '1': '[Fronting] HTTP/2 Direct', '2': '[Local] HTTP/2 Direct', '3': '[Local] HTTP/2 Direct ZGrab' }
		inputs = user_input(inputs)
		if inputs == '1':
			switch['bloc'] = 3
			switch['rot'] = 0
		elif inputs == '2':
			switch['bloc'] = 3
			switch['rot'] = 1
		elif inputs == '3':
			switch['bloc'] = 0
			switch['rot'] = 3
	inputs = { '1': 'Scan File (.txt)', '2': 'Scan Online (HackerTarget)', '3': 'Scan Custom Input' }
	inputs = user_input(inputs)
	if inputs == '1':
		inputs = { '1': 'Scan Local Files', '2': 'Scan Local Lines' }
		inputs = user_input(inputs)
		if inputs == '1':
			processor = filet()
		elif inputs == '2':
			processor = filet()
			processor = liner(processor)
	elif inputs == '2':
		processor = hacki()
	elif inputs == '3':
		inputs = { '1': 'Scan Custom Hostname/SNI', '2': 'Scan Custom Proxy/IP' }
		inputs = user_input(inputs)
		if inputs == '1':
			processor = input(' Input Hostname : ')
		elif inputs == '2':
			processor = input(' Input IP : ')
		print()
		switch['type']=2
	if switch['bloc']==1:
		doma()
	option()
	server(processor)

if __name__ == '__main__':
	os.chdir(dirname(abspath(__file__)))
	checker()
	menu()
	exit()