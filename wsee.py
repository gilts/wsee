#!/usr/bin/env python3

'''
Licensed Under Apache 2.0
Copyright (C) MC874/MC189/MC & Kiynox
All Rights Reserved

Commits preserved free as is;
Permitted for Commercial Use or Private use.
With other Circumstances such as Free Distribution and Modification.
All the State bounds with Conditions.

Following states, it's conditions to indicate the changes
As well mention it's License Use and Copyright Holders.

Heavily forbid Trademark act.
Provides NO WARRANTY; implies 'WITHOUT' to all it's related such as MERCHANTABILITY.
Derived details <https://www.apache.org/licenses/LICENSE-2.0>
'''

import csv
import ssl
import json
import ctypes
import socket
import fsspec
import subprocess
import os, fnmatch
import requests, re
from time import sleep
from pathlib import Path
from jsonmerge import merge
from threading import Thread
from collections import defaultdict
from os.path import abspath, dirname
from pkg_resources import parse_version
from itertools import chain, repeat
from multiprocessing import Process, Manager, Value, Queue, cpu_count

input_folder = 'input'
output_folder = 'output'

cflare_domain = 'id3.sshws.me'
cfront_domain = 'd20bqb0z6saqqh.cloudfront.net'

customPayloads = { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.93 Safari/537.36', 'Upgrade-Insecure-Requests': '1', 'Accept': '*/*' }
cipher = (':ECDHE-RSA-AES128-GCM-SHA256:DES-CBC3-SHA:AES256-SHA:AES128-SHA:AES128-SHA256:AES256-GCM-SHA384:AES256-SHA256:ECDHE-RSA-DES-CBC3:EDH-RSA-DES-CBC3:EECDH+AESGCM:EDH-RSA-DES-CBC3-SHA:EDH-AESGCM:AES256+EECDH:ECHDE-RSA-AES256-GCM-SHA384:ECHDE-ECDSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECHDE-ECDSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:AES256+EDH:DHE-DSS-AES128-GCM-SHA256:kEDH+AESGCM:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA:ECDHE-ECDSA-AES256-SHA:DHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA:DHE-DSS-AES128-SHA256:DHE-RSA-A$:DHE-RSA-AES256-SHA256:DHE-DSS-AES256-SHA:DHE-RSA-AES256-SHA:HIGH:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!3DES:!MD5:!PSK')

class colors:
	RED_BG = '\033[41m\033[1m'
	GREEN_BG = '\033[42m'
	ENDC = '\033[m'

''' User-Input Section '''
# Child Controller
def option(processor):
	global customPayloads, output_folder
	while True:
		inputs = { '1': 'Done', '2': 'Output File', '3': 'Process Count', '4': 'Timeout', '5': 'Pinger', '6': 'Retry', '7': 'Deep Level' }
		if not switch['function'].value == 0:
			general = { '8': 'Scope Level', '9': 'Custom Headers' }
			inputs = merge(inputs, general)
		if (switch['function'].value == 1) or (switch['function'].value == 3 and switch['rotate'].value == 0):
			fronting_domain = { '10': 'Fronting Domain' }
			inputs = merge(inputs, fronting_domain)
		if (switch['function'].value == 1) and (switch['rotate'].value in [0, 2]):
			rotates = { '11': 'Use Rotate' }
			inputs = merge(inputs, rotates)
		inputs = user_input(inputs)
		if inputs == '2':
			inputs = { '1': 'Save to Output Folder', '2': 'Custom Folder' }
			if switch['file_type'].value in [0, 1, 2]:
				current = { '3': 'Save to the Same Folder as Input' }
				inputs = merge(inputs, current)
			inputs = user_input(inputs)
			outname = input('Output File Name: ')
			print('')
			if inputs == 2:
				print('[' + colors.RED_BG + ' Add Full Path! (./tst.txt) ' +  colors.ENDC + ']')
				output_folder = input('Output Folder Location: ')
				print('')
			elif inputs == 3:
				output_folder = re.search('(.*)\/.*$', str(processor)).group(1)
			print(output_folder)
			props['output'].value = f'{output_folder}/{outname}'
		elif inputs == '3':
			inputs = input('How Many Process?: ')
			print()
			switch['count'].value = int(inputs)
		elif inputs == '4':
			inputs = input('Timeout in Seconds: ')
			print()
			switch['timeout'].value = int(inputs)
		elif inputs == '5':
			inputs = { '1': 'Enable Ping', '2': 'Disable Ping' }
			inputs = user_input(inputs)
			if inputs == '1':
				switch['pinger'].value = 1
			else:
				switch['pinger'].value = 2
		elif inputs == '6':
			retry_count = input('Input Number of Retry: ')
			print('')
			switch['retry'].value = retry_count
		elif inputs == '7':
			inputs = { '1': 'Retry on Timeout', '2': 'Retry on Fail', '3': 'Disable Retry' }
			inputs = user_input(inputs)
			if inputs == '1':
				switch['deep'].value = 1
			elif inputs == '2':
				switch['deep'].value = 2
			else:
				switch['deep'].value = 0
		elif inputs == '8':
			inputs = { '0': 'Only Proper Status', '1': 'Include Domain Fronted', '2': 'Include Anything Connect' }
			inputs = user_input(inputs)
			if inputs == '0':
				switch['scope'].value = 0
			elif inputs == '1':
				switch['scope'].value = 1
			else:
				switch['scope'].value = 2
		elif inputs == '9':
			custom_headers = input('Input Headers: ')
			print('')
			custom_headers = json.loads(custom_headers)
			customPayloads = merge(customPayloads, custom_headers)
		elif inputs == '10':
			inputs = { '1': 'Custom SSH Address', '2': 'Default CloudFront', '3': 'Default CloudFlare' }
			inputs = user_input(inputs)
			if inputs == '1':
				inputs = input(' inputs : ')
				print('')
				props['fronting'].value = inputs
			elif inputs == '2':
				props['fronting'].value = cfront_domain
			elif inputs == '3':
				props['fronting'].value = cflare_domain
			print(' Selected [' + colors.GREEN_BG + f' {props["fronting"].value} ' + colors.ENDC + '] as Domain Fronting!')
			print(' ['+ colors.RED_BG + ' INVALID ' + colors.ENDC + '] SSH Will Give 0 Result!' )
			print('')
		elif inputs == '11':
			if switch['rotate'].value == 2:
				print('[' + colors.RED_BG + ' Proxy/IP for Host Rotate ' + colors.ENDC + ']')
				inputs = input(' Input Proxy : ')
			elif switch['rotate'].value == 0:
				print('[' + colors.RED_BG + ' Hostname/SNI for Proxy Rotate' + colors.ENDC + ']')
				inputs = input(' Input Hostname : ')
			props['rotate'].value = inputs
		else:
			break
	print('')

# Iterate Global Var
def global_var():
	global props, switch
	print(output_folder)
	props = { 'fronting': Value(ctypes.c_wchar_p, cflare_domain, lock = False), 'rotate': Value(ctypes.c_wchar_p, '', lock = False), 'proxy': Value(ctypes.c_wchar_p, '', lock = False), 'payload': Value(ctypes.c_wchar_p, '', lock = False), 'output': Value(ctypes.c_wchar_p, f'{output_folder}/result', lock = False)}
	switch = { 'function': Value('i', 0, lock = False), 'rotate': Value('i', 0, lock = False), 'file_type': Value('i', 0, lock = False), 'scope': Value('i', 0, lock = False), 'count': Value('i', cpu_count(), lock = False), 'timeout': Value('i', 5, lock = False), 'pinger': Value('i', 2, lock = False), 'retry': Value('i', 2, lock = False), 'deep': Value('i', 0, lock = False), 'Fail': Value('i', 0, lock = False), 'Success': Value('i', 0, lock = False)}

# Outrange input as finish
def uinput():
	global switch, props
	print('')
	print('[' + colors.RED_BG+' Target Block Exceeded ' + colors.ENDC + ']' )
	inputs = { '1': 'Go Back to Menu', '2': 'Quit Instead' }
	inputs = user_input(inputs)
	if inputs == '1':
		global_var()
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
'''	Dir 0 = takes from Input Folder
	Dir 1 = takes from Current Script Folder
	Dir 2 =	takes from Internal Storage Input Folder
	Dir 3 =	takes from Internal Storage
	Dir 4 =	takes from Custom Folder	'''
def filet():
	txtfiles = []
	num_file = 1
	inputs = { '1': 'Scan Files in Input Folder', '2': 'Scan Files in Current Folder', '3': 'Scan Files in Termux Host', '4': 'Scan Files in Termux', '5': 'Scan Custom Path' }
	inputs = user_input(inputs)
	if inputs == '1':
		files = os.listdir(input_folder)
		locator = 0
	elif inputs == '2':
		files = [f for f in os.listdir('.') if os.path.isfile(f)]
		locator = 1
	elif inputs == '3':
		files = os.listdir('$home/storage/shared/' + input_folder)
		locator = 2
	elif inputs == '4':
		files = os.listdir('$home/storage/shared/')
		locator = 3
	elif inputs == '5':
		path = input(' Input your Folder: ')
		files = os.listdir(path)
		locator = 4
	print(' [' + colors.RED_BG + ' Files Found ' + colors.ENDC + '] ')
	for f in files:
		if fnmatch.fnmatch(f, '*.txt'):
			switch['file_type'].value = 0
		elif fnmatch.fnmatch(f, '*.csv'):
			switch['file_type'].value = 1
		print(str(num_file), str(f))
		num_file = num_file + 1
		txtfiles.append(str(f))
	print('')
	print(' M back to Menu ')
	inputs = input(' Choose Target Files : ')
	print('')
	print(' Chosen File : ' + colors.RED_BG + ' ' + txtfiles[int(inputs)-1] + ' ' + colors.ENDC)
	print('')
	if locator == 0:
		processor = './' + input_folder + '/' + str(txtfiles[int(inputs)-1])
	elif locator == 1:
		processor = './' + str(txtfiles[int(inputs)-1])
	elif locator == 2:
		processor = './storage/shared/' + input_folder + '/' + str(txtfiles[int(inputs)-1])
	elif locator == 3:
		processor = './storage/shared/' + str(txtfiles[int(inputs)-1])
	else:
		processor = path
	return processor

# Reading Lines
def liner(processor):
	switch['file_type'].value = 2
	num_line = 1
	txtlines = []
	print('[' + colors.RED_BG + ' List of String based on Lines ' + colors.ENDC + ']')
	with open(processor, 'r') as liner:
		for f in liner:
			print(str(num_line), str(f.strip()))
			num_line = num_line+1
			txtlines.append(str(f.strip()))
	print('')
	print(' M back to Menu ')
	lineselector = input(' Choose Target Lines : ')
	print('')
	print(' Chosen Line : ' + colors.RED_BG + ' ' + txtlines[int(lineselector)-1] + ' ' + colors.ENDC)
	print('')
	if lineselector.isdigit():
		processor = txtlines[int(lineselector)-1]
	return processor

# Reading from Online enumeration
def hacki():
	inputs = input('\nInput Domain: ')
	print('')
	inputs = inputs.replace('https://', '').replace('http://', '')
	response = requests.get('https://api.hackertarget.com/hostsearch/?q=' + inputs)
	if response.text == 'error invalid host':
		exit('ERR: error invalid host')
	else:
		switch['file_type'].value = 3
		processor = re.findall('(.*?),', response.text)
	return processor

''' Main Control Section '''
# Running Process and Reading text list
''' Type 0: takes txt
	Type 1: takes csv
	Type 2: takes input
	Type 3: takes online enum '''

def server(tasker, processor):
	columns = defaultdict(list)
	if switch['file_type'].value == 0:
		f = open(processor, 'r')
		for line in f:
			tasker.put(line.strip())
		f.close()
	elif switch['file_type'].value == 1:
		csv_file = open(processor, 'r').read()
		reader = csv.reader(csv_file)
		for row in reader:
			for (i,v) in enumerate(row):
				columns[i].append(v)
			tasker.put(columns[9] + columns[3])
		csv_file.close()
	elif switch['file_type'].value == 2:
		tasker.put(processor)
	else:
		for process in processor:
			tasker.put(process.strip())
	for i in range(switch['count'].value):
		tasker.put(None)

# Running Process
def executor(process):
	global customPayloads
	if switch['function'].value == 3:
		with open('./bin/payloads/http2', 'r') as f:
			payloads = json.load(f)
	else:
		with open('./bin/payloads/websocket', 'r') as f:
			payloads = json.load(f)
	mergedPayloads = merge(payloads, customPayloads)
	payloads = ''
	for i, j in mergedPayloads.items():
		payloads += f"'{i}': '{j}'\r\n"
	props['payload'].value = payloads
	tasker = Queue(switch['count'].value*10)

	total = []
	task_producer = Thread(target = server, args = (tasker, process, ))
	task_producer.start()
	for i in range(switch['count'].value):
		p = Process(target = processor, args = (tasker, ))
		p.start()
		total.append(p)
	for p in total:
		p.join()
	task_producer.join()
	print(' Failed Result : ' + colors.RED_BG + ' ' + str(switch['Fail'].value) + ' ' + colors.ENDC )
	print(' Success Result : ' + colors.GREEN_BG + ' ' + str(switch['Success'].value) + ' ' + colors.ENDC)
	print('')
	uinput()

# Processing Main Process
'''	Block 0 = ZGrab
	Block 1 = Websocket Fronting
	Block 2 = Websocket Local
	Block 3 = HTTP/2	'''
def processor(tasker):
	while True:
		task = tasker.get()
		if task is None:
			break
		if switch['pinger'].value == 1:
			pinger()
		if switch['deep'].value in [1,2]:
			retry = switch['retry'].value
		else:
			retry = 1
		while not retry == 0:
			try:
				if switch['function'].value == 0:
					zgrab(task)
				elif switch['function'].value == 1:
					ws(task)
				elif switch['function'].value == 2:
					localws(task)
				else:
					h2c(task)
				retry = 0
			except(ssl.SSLError):
				print(' [' + colors.RED_BG + ' FAIL ' + colors.ENDC + '] ' + task + ' [' + colors.RED_BG + ' NOT SSL ' + colors.ENDC + ']')
				if switch['deep'].value == 2:
					retry -= 1
				else:
					retry = 0
					switch['Fail'].value += 1
			except(socket.gaierror) or (socket.timeout):
				print(' [' + colors.RED_BG + ' FAIL ' + colors.ENDC + '] ' + task + ' [' + colors.RED_BG + ' INVALID ' + colors.ENDC + ']')
				if switch['deep'].value == 2:
					retry -= 1
				else:
					retry = 0
					switch['Fail'].value += 1
			except(socket.error):
				print(' [' + colors.RED_BG + ' FAIL ' + colors.ENDC + '] ' + task + ' [' + colors.RED_BG + ' TIMEOUT ' + colors.ENDC + ']')
				if switch['deep'].value in [1,2]:
					retry -= 1
				else:
					retry = 0
					switch['Fail'].value += 1
			except Exception and OSError as e:
				print(e)
				retry = 0
''' Main Process '''
# Ping DNS over TCP to check connection
def pinger():
	while True:
		try:
			sock = socket.socket()
			sock.settimeout(5)
			sock.connect(('nghttp2.org', 80))
			sock.sendall(f'HEAD / HTTP/1.1\r\nHost: nghttp2.org\r\nConnection: Upgrade, HTTP2-Settings\r\nUpgrade: h2c\r\nHTTP2-Settings: \r\n\r\n'.encode())
			response = str(sock.recv(13))
			response = re.findall("b'HTTP\/[1-9]\.[1-9]\ (.*?)\ ", response)
			sock.close()
			if response[0] == '101':
				break
		except Exception and OSError as e:
			print(e)
			print("[" + colors.RED_BG + " Check Your Internet Connection! " + colors.ENDC + "]")
			sleep(3)

def saver(task, response):
	if not response:
		print(' [' + colors.RED_BG + ' FAIL ' + colors.ENDC + '] ' + task + '' + colors.RED_BG + ' EMPTY ' + colors.ENDC + ']')
		switch['Fail'].value += 1
	status = re.search("^b\'HTTP\/1\.[0-1]\ ([0-9]*)\ ", str(response)).group(1).rstrip()
	if switch['scope'].value in [1, 2]:
		try:
			server = re.search('Server\:\ (.*)', response.decode('utf-8')).group(1).rstrip()
			if server == 'cloudflare':
				print(task, file = open(f'{props["output"].value}-cloudflare.txt', 'a'))
				server = ' [' + colors.GREEN_BG + f' {server} ' + colors.ENDC + ']'
			elif server == 'CloudFront':
				print(task, file = open(f'{props["output"].value}-cloudfront.txt', 'a'))
				server = ' [' + colors.GREEN_BG + f' {server} ' + colors.ENDC + ']'
			else:
				server = ' [' + colors.RED_BG + f' {server} ' + colors.ENDC + ']'
		except:
			server = ' [' + colors.RED_BG + ' None ' + colors.ENDC + ']'
	else:
		server = ''
	if status == '101':
		print(' [' + colors.GREEN_BG + ' HIT ' + colors.ENDC + '] ' + task + ' [' + colors.GREEN_BG + ' ' + str(status) + ' ' + colors.ENDC + ']' + server)
		print(task, file = open(f'{props["output"].value}.txt', 'a'))
		switch['Success'].value += 1
	else:
		print(' [' + colors.RED_BG + ' FAIL ' + colors.ENDC + '] ' + task + ' [' + colors.RED_BG + ' ' + str(status) + ' ' + colors.ENDC + ']' + server)
		switch['Fail'].value += 1
	if (switch['scope'].value == 1) and (status in ['200', '301', '302', '403', '400']):
		print(task, file = open(f'{props["output"].value}-fronted.txt', 'a'))
	if (switch['scope'].value == 2) and status:
		print(task, file = open(f'{props["output"].value}-connect.txt', 'a'))

# Websocket SSL: Takes CDN/Local
''' Rot 0 = Websocket Fronting SSL Proxy Rotate
	Rot 1 = Websocket Fronting Direct
	Rot 2 = Websocket Fronting SSL Host Rotate
	Rot 3 = Websocket Fronting SSL	'''
def ws(task):
	sock = socket.socket()
	sock.settimeout(int(switch['timeout'].value))
	sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
	cont = ssl.create_default_context()
	cont.set_ciphers(cipher)
	if switch['rotate'].value == 0:
		sock = cont.wrap_socket(sock, server_hostname = f'{props["rotate"].value}')
		sock.connect((task, 443))
		sock.sendall(f'HEAD wss://{props["rotate"].value}/ HTTP/1.1\r\nHost: {props["fronting"].value}\r\n{props["payload"].value}\r\n'.encode())
	elif switch['rotate'].value == 1:
		sock.connect((task, 80))
		sock.sendall(f'HEAD / HTTP/1.1\r\nHost: {props["fronting"].value}\r\n{props["payload"].value}\r\n'.encode())
	else:
		if switch['rotate'].value == 2:
			sock = cont.wrap_socket(sock, server_hostname = task)
			sock.connect((f'{props["rotate"].value}', 443))
		else:
			sock = cont.wrap_socket(sock, server_hostname = task)
			sock.connect((task, 443))
		sock.sendall(f'HEAD wss://{task}/ HTTP/1.1\r\nHost: {props["fronting"].value}\r\n{props["payload"].value}\r\n'.encode())
	response = sock.recv(1024)
	status = saver(task, response)
	sock.close()
	return status

# Websocket Direct: Takes CDN/Local
'''	Rot 0 = Websocket Local Direct
	Rot 1 = Websocket Local SSL	'''
def localws(task):
	sock = socket.socket()
	sock.settimeout(int(switch['timeout'].value))
	sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
	cont = ssl.create_default_context()
	cont.set_ciphers(cipher)
	if switch['rotate'].value == 0:
		sock = cont.wrap_socket(sock, server_hostname = f'{task}')
		sock.connect((task, 443))
		sock.sendall(f'HEAD wss://{task} HTTP/1.1\r\nHost: {props["fronting"].value}\r\n{props["payload"].value}\r\n'.encode())
	else:
		sock.connect((task, 80))
		sock.sendall(f'HEAD / HTTP/1.1\r\nHost: {task}\r\n{props["payload"].value}\r\n'.encode())
	response = sock.recv(1024)
	saver(task, response)
	sock.close()

# HTTP/2 Direct: Takes CDN/Local
'''	Rot 0 = HTTP/2 Local Direct
	Rot 1 = HTTP/2 Fronting Direct	'''
def h2c(task):
	sock = socket.socket()
	sock.settimeout(int(switch['timeout'].value))
	sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
	sock.connect((task, 80))
	if switch['rotate'].value == 0:
		sock.sendall(f'HEAD / HTTP/1.1\r\nHost: {props["fronting"].value}\r\n{props["payload"].value}\r\n'.encode())
	else:
		sock.connect((task, 80))
		sock.sendall(f'HEAD / HTTP/1.1\r\nHost: {task}\r\n{props["payload"].value}\r\n'.encode())
	response = sock.recv(1024)
	saver(task, response)
	sock.close()

# ZGrab Mode: Only Local; Takes 443/80
'''	Rot 0 = Websocket Local SSL
	Rot 1 = Websocket Local Direct
	Rot 2 = HTTP/2 Local Direct	'''
def zgrab(task):
	if switch['rotate'].value == 0:
		commando = f"echo {task} | zgrab2 http --custom-headers-names='Upgrade,Sec-WebSocket-Key,Sec-WebSocket-Version,Connection' --custom-headers-values='websocket,dXP3jD9Ipw0B2EmWrMDTEw==,13,Upgrade' --remove-accept-header --dynamic-origin --use-https --port 443 --max-redirects {switch['timeout'].value} --retry-https --cipher-suite= portable -t 10 | jq '.data.http.result.response.status_code,.domain' | grep -A 1 -E --line-buffered '^101'"
	elif switch['rotate'].value == 1:
		commando = f"echo {task} | zgrab2 http --custom-headers-names='Upgrade,Sec-WebSocket-Key,Sec-WebSocket-Version,Connection' --custom-headers-values='websocket,dXP3jD9Ipw0B2EmWrMDTEw==,13,Upgrade' --remove-accept-header --dynamic-origin --port 80 --max-redirects 10 --cipher-suite= portable -t {switch['timeout'].value} | jq '.data.http.result.response.status_code,.domain' | grep -A 1 -E --line-buffered '^101'"
	else:
		commando = f"echo {task} | zgrab2 http --custom-headers-names='Upgrade,HTTP2-Settings,Connection' --custom-headers-values='h2c,AAMAAABkAARAAAAAAAIAAAAA,Upgrade' --remove-accept-header --dynamic-origin --port 80 --max-redirects 10 --cipher-suite= portable -t {switch['timeout'].value} | jq '.data.http.result.response.status_code,.domain' | grep -A 1 -E --line-buffered '^101'"
	commando = subprocess.Popen(commando, shell = True, stdin = subprocess.PIPE, stdout = subprocess.PIPE, stderr = subprocess.PIPE)
	commando = commando.stdout.read().decode('utf-8') + commando.stderr.read().decode('utf-8')
	response = re.split(r'\n',commando)
	if response[0] == '101':
		print(' [' + colors.GREEN_BG + ' HIT ' + colors.ENDC + '] ' + task)
		print(task, file = open(f'{props["output"].value}.txt', 'a'))
		switch['Success'].value += 1
	else:
		print(' [' + colors.RED_BG + ' FAIL ' + colors.ENDC + '] ' + task)
		switch['Fail'].value += 1

''' Frontier Section '''
# Script Updater
def updater():
	print('[' + colors.GREEN_BG + ' Script Update Available ' + colors.ENDC + ']')
	print('')
	inputs = { '1': 'Ignore Update', '2': 'Apply Update' }
	inputs = user_input(inputs)
	if inputs == '2':
		os.remove('wsee.py')

		destination = Path(__file__).resolve().parent / "wsee.py"
		destination.mkdir(exist_ok = True, parents = True)
		fs = fsspec.filesystem("github", org = "Guild-Net", repo = "wsee")
		fs.get(fs.ls("wsee.py"), destination.as_posix())

		destination = Path(__file__).resolve().parent / ".wsee"
		destination.mkdir(exist_ok = True, parents = True)
		fs = fsspec.filesystem("github", org = "Guild-Net", repo = "wsee")
		fs.get(fs.ls(".wsee/"), destination.as_posix(), recursive = True)

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
		print('')
		print('[' + colors.RED_BG + ' Checking for update... ' +  colors.ENDC + ']')
		print('')
		resp = requests.get('https://raw.githubusercontent.com/gilts/wsee/main/.wsee/VERSION')
		with open('./.wsee/VERSION') as f:
			verlocal = f.read()
		if parse_version(resp.text) > parse_version(verlocal):
			updater()
		else:
			print('[' + colors.RED_BG + ' No Update Available ' +  colors.ENDC + ']')
			print('')
			sleep(3)
	print("\033c\033[3J\033[2J\033[0m\033[H")

# Main Menu; Handles everything.
'''	Block 0 Rot 2 = HTTP/2 Local Direct ZGrab
	Block 0 Rot 1 = Websocket Local Direct ZGrab
	Block 0 Rot 0 = Websocket Local SSL ZGrab

	Block 1 Rot 3 = Websocket Fronting SSL
	Block 1 Rot 2 = Websocket Fronting SSL Host Rotate
	Block 1 Rot 1 = Websocket Fronting Direct
	Block 1 Rot 0 = Websocket Fronting SSL Proxy Rotate

	Block 2 Rot 1 = Websocket Local Direct
	Block 2 Rot 0 = Websocket Local SSL

	Block 3 Rot 1 = HTTP/2 Local Direct	
	Block 3 Rot 0 = HTTP/2 Fronting Direct	'''
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
			switch['function'].value = 1
			switch['rotate'].value = 3
		elif inputs == '2':
			switch['function'].value = 1
			switch['rotate'].value = 0
		elif inputs == '3':
			switch['function'].value = 1
			switch['rotate'].value = 2
		elif inputs == '4':
			switch['function'].value = 1
			switch['rotate'].value = 1
	elif inputs == '2':
		inputs = { '1': '[Local] Websocket SSL', '2': '[Local] Websocket Direct', '3': '[Local] Websocket SSL ZGrab', '4': '[Local] Websocket Direct ZGrab' }
		inputs = user_input(inputs)
		if inputs == '1':
			switch['function'].value = 2
			switch['rotate'].value = 0
		elif inputs == '2':
			switch['function'].value = 2
			switch['rotate'].value = 1
		elif inputs == '3':
			switch['function'].value = 0
			switch['rotate'].value = 0
		elif inputs == '4':
			switch['function'].value = 0
			switch['rotate'].value = 1
	elif inputs == '3':
		inputs = { '1': '[Fronting] HTTP/2 Direct', '2': '[Local] HTTP/2 Direct', '3': '[Local] HTTP/2 Direct ZGrab' }
		inputs = user_input(inputs)
		if inputs == '1':
			switch['function'].value = 3
			switch['rotate'].value = 0
		elif inputs == '2':
			switch['function'].value = 3
			switch['rotate'].value = 1
		elif inputs == '3':
			switch['function'].value = 0
			switch['rotate'].value = 2
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
		processor = input(' Custom Input: ')
		print()
		switch['file_type'].value = 2
	option(processor)
	executor(processor)

if __name__ == '__main__':
	os.chdir(dirname(abspath(__file__)))
	checker()
	global_var()
	menu()