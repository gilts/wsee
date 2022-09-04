import csv
import ssl
import socket
import traceback
import subprocess
import requests,re
import dns.resolver
import multiprocessing
import os, fnmatch; os.system('clear')
from time import sleep
from collections import defaultdict
from os.path import abspath, dirname
from multiprocessing import Process, cpu_count, Manager, Value
from requests.exceptions import ReadTimeout, Timeout, ConnectionError, ChunkedEncodingError, TooManyRedirects, InvalidURL

expected_response = 101
cflare_domain = 'id-herza.sshws.net'
cfront_domain = 'dhxqu5ob0t1lp.cloudfront.net'
payloads = {'Host': cfront_domain, 'Scheme': '', 'Grade': '', 'Conn': '', 'Key': '', 'Acc': '', 'Ver': ''}
switch = { 'dir': '0', 'isFunc': '', 'isCDN': '', 'isTLS': '', 'isWS': '', 'nametag': 'result' }
hostpath = 'host'

columns = defaultdict(list)
txtfiles= []

class colors:
	RED_BG = '\033[41m\033[1m'
	GREEN_BG = '\033[42m'
	ENDC = '\033[m'

def pinger():
	try:
		requ = requests.get("http://google.com")
		if requ.status_code == 200:
			return
		elif requ.status_code != expected_response:
			print("["+colors.RED_BG+" Check Your Internet Connection! "+colors.ENDC+"]")
			sleep(10)
			pinger()
	except requests.ConnectionError:
		print("["+colors.RED_BG+" Check Your Internet Connection! "+colors.ENDC+"]")
		sleep(10)
		pinger()

def option():
	if switch['isWS']=='1':
		payloads['Scheme']='wss'
		payloads['Conn']='Upgrade'
		payloads['Key']='dXP3jD9Ipw0B2EmWrMDTEw=='
		payloads['Acc']='GLWt4W8Ogwo6lmX9ZGa314RMRr0='
		payloads['Ver']='13'
		payloads['Grade']='websocket'
	elif switch['isWS']=='0':
		payloads['Scheme']='h2'
		payloads['Conn']='Upgrade, HTTP2-Settings'
		payloads['Key']=''
		payloads['Acc']=''
		payloads['Ver']=''
		payloads['Grade']='h2'
	print('[' + colors.RED_BG + ' Input your Output File Name ' + colors.ENDC + ']')
	nametag = input(' Output as : ')
	print('')
	switch['nametag']=f'{nametag}'
	return

def doma():
	global frontdom
	print('1. Custom Domain')
	print('2. Default CloudFront')
	print('3. Default CloudFlare')
	print('Q to Quit')
	print('M to Menu')
	print('')
	ansi=input(' Choose Option : ').lower()
	print('')
	if str(ansi)=='1':
		domain=input(' Domain : ')
		payloads['Host']=f'{domain}'
	elif str(ansi)=='2':
		payloads['Host']=f'{cfront_domain}'
	elif str(ansi)=='3':
		payloads['Host']=f'{cflare_domain}'
	elif str(ansi)=='q':
		exit()
	elif str(ansi)=='m':
		menu()
	else:
		print('['+colors.RED_BG+' GGRRR! ' + colors.ENDC + '] Invalid INPUT!' )
		print('')
		menu()
	frontdom = str(payloads['Host'])
	print('['+colors.GREEN_BG + f' {frontdom} '+ colors.ENDC + '] Selected as Domain Fronting!')
	print('['+colors.RED_BG+' Warning! ' + colors.ENDC + '] : [' + colors.RED_BG + ' INVALID ' + colors.ENDC + '] Domain Will Give 0 Result!' )
	print('')
	return

def filet():
	global domainlist, fileselector
	num_file = 1
	print('1. Check Files in Host Folder')
	print('2. Check Files in Current Folder')
	print('3. Check Files in Termux Host')
	print('4. Check Files in Termux')
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
	elif ans=='q':
		exit()
	elif ans=='m':
		menu()
	else:
		filet()
	print(' [' + colors.RED_BG + ' Files Found ' + colors.ENDC + '] ')
	for f in files:
		if fnmatch.fnmatch(f, '*.txt'):
			print( str(num_file),str(f))
			num_file=num_file+1
			txtfiles.append(str(f))
	print('')
	print(' M back to Menu ')
	fileselector = input(' Choose Target Files : ')
	if fileselector.isdigit():
		print('')
		print(' Target Chosen : ' + colors.RED_BG + ' '+txtfiles[int(fileselector)-1]+' '+colors.ENDC)
		direct = str(switch['dir'])
		if direct == '0':
			file_hosts = str(hostpath) +'/'+ str(txtfiles[int(fileselector)-1])
		elif direct == '1':
			file_hosts = str(txtfiles[int(fileselector)-1])
		elif direct == '2':
			file_hosts = './storage/shared/' + str(hostpath) +'/'+ str(txtfiles[int(fileselector)-1])
		elif direct == '3':
			file_hosts = './storage/shared/' + str(txtfiles[int(fileselector)-1])
	else:
		menu()

	with open(file_hosts) as f:
		parseddom = f.read().split()
	domainlist = list(set(parseddom))
	domainlist = list(filter(None, parseddom))
	print(' Total of Domains Loaded: ' + colors.RED_BG + ' ' +str(len(domainlist)) + ' '+colors.ENDC )
	print('')
	return

def csveat():
	global domainlist, fileselector
	num_file=1
	print('1. Check Files in Host Folder')
	print('2. Check Files in Current Folder')
	print('3. Check Files in Termux Host')
	print('4. Check Files in Termux')
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
	elif ans=='q':
		exit()
	elif ans=='m':
		menu()
	else:
		csveat()
	print(' [' + colors.RED_BG + ' Files Found ' + colors.ENDC + '] ')
	for f in files:
		if fnmatch.fnmatch(f, '*.csv'):
			print( str(num_file),str(f))
			num_file=num_file+1
			txtfiles.append(str(f))
	print('')
	print(' M back to Menu ')
	fileselector = input(' Choose Target Files : ')
	if fileselector.isdigit():
		print('')
		print(' Target Chosen : ' + colors.RED_BG + ' '+txtfiles[int(fileselector)-1]+' '+colors.ENDC)
		direct = str(switch['dir'])
		if direct == '0':
			file_hosts = str(hostpath) +'/'+ str(txtfiles[int(fileselector)-1])
		elif direct == '1':
			file_hosts = str(txtfiles[int(fileselector)-1])
		elif direct == '2':
			file_hosts = './storage/shared/' + str(hostpath) +'/'+ str(txtfiles[int(fileselector)-1])
		elif direct == '3':
			file_hosts = './storage/shared/' + str(txtfiles[int(fileselector)-1])
	else:
		menu()

	with open(file_hosts,'r') as csv_file:
		reader = csv.reader(csv_file)
		for row in reader:
			for (i,v) in enumerate(row):
				columns[i].append(v)
	parseddom=columns[9]+columns[3]
	domainlist = list(set(parseddom))
	domainlist = list(filter(None, parseddom))
	print(' Total of Domains Loaded: ' + colors.RED_BG + ' ' +str(len(domainlist)) + ' '+colors.ENDC )
	print('')
	return

def executor():
	with Manager() as manager:
		global Faily, Resultee
		Faily=Value('i',0)
		Resultee=Value('d',0)
		num_cpus = cpu_count()
		processes = []
		for process_num in range(num_cpus):
			section = domainlist[process_num::num_cpus]
			if switch['isFunc']=='0':
				p = Process(target=tcp, args=(section,Resultee,Faily))
			elif switch['isFunc']=='1':
				p = Process(target=socp, args=(section,Resultee,Faily))
			else:
				p = Process(target=grabber, args=(section,Resultee,Faily))
			p.start()
			processes.append(p)
		for p in processes:
			p.join()
		print('')
		print(' Failed Result : '  + colors.RED_BG + ' '+ str(Faily.value) +' '+ colors.ENDC )
		print(' Successfull Result : ' + colors.GREEN_BG + ' '+ str(Resultee.value) + ' '+colors.ENDC)
		return
 
def uinput():
	global Faily, Resultee
	print('')
	print('Scanning Finished!')
	print('1. Go Back to Menu')
	print('2. Scanning Again')
	print('3. Quit Instead')
	print('')
	ans=input('Choose Option: ')
	if ans=='2':
		return
	elif ans=='3':
		exit()
	else:
		menu()

def hacki():
	global domainlist, subd
	subd = input('\nInput Domain: ')
	subd = subd.replace('https://','').replace('http://','')
	r = requests.get('https://api.hackertarget.com/hostsearch/?q=' + subd, allow_redirects=False)
	if r.text == 'error invalid host':
		exit('ERR: error invalid host')
	else:
		domainlist = re.findall('(.*?),',r.text)
		return

def tcp(domainlist,Resultee,Faily):
	pinger()
	for domain in domainlist:
		try:
			if switch['isCDN']=='1':
				r = requests.get('http://' + domain, headers={'Host':f'{payloads["Host"]}','Connection':f'{payloads["Conn"]}','Upgrade':f'{payloads["Grade"]}','Sec-WebSocket-Key': f'{payloads["Key"]}', 'Sec-WebSocket-Version': f'{payloads["Ver"]}', 'Sec-Websocket-Accept': f'{payloads["Acc"]}', 'HTTP2-Settings': ''}, allow_redirects=False, verify=False)
			elif switch['isCDN']=='0':
				r = requests.get('http://' + domain, headers={'Connection':f'{payloads["Conn"]}','Upgrade':f'{payloads["Grade"]}','Sec-WebSocket-Key': f'{payloads["Key"]}', 'Sec-WebSocket-Version': f'{payloads["Ver"]}', 'Sec-Websocket-Accept': f'{payloads["Acc"]}', 'HTTP2-Settings': ''}, allow_redirects=False, verify=False)
			if r.status_code == expected_response:
				print(' ['+colors.GREEN_BG+' HIT '+colors.ENDC+'] ' + domain + ' [' +colors.GREEN_BG+' ' + str(r.status_code) + ' '+colors.ENDC+']')
				print(domain, file=open(f'{switch["nametag"]}.txt', 'a'))
				with Resultee.get_lock():
					Resultee.value +=1
			else:
				print(' ['+colors.RED_BG+' FAIL '+colors.ENDC+'] ' + domain + ' [' +colors.RED_BG+' ' + str(r.status_code) + ' '+colors.ENDC+']')
				with Faily.get_lock():
					Faily.value +=1
		except (Timeout, ReadTimeout, ConnectionError):
			print(" ["+colors.RED_BG+" FAIL "+colors.ENDC+"] " + domain + " [" + colors.RED_BG +" TIMEOUT "+colors.ENDC+"]")
			with Faily.get_lock():
				Faily.value +=1
		except(ChunkedEncodingError):
			print(" ["+colors.RED_BG+" FAIL "+colors.ENDC+"] " + domain + " [" + colors.RED_BG+" Invalid Length "+colors.ENDC + "]")
			with Faily.get_lock():
				Faily.value +=1
		except(TooManyRedirects):
			print(" ["+colors.RED_BG+" FAIL "+colors.ENDC+"] " + domain + " [" +colors.RED_BG+" Redirects Loop "+colors.ENDC+"]")
			with Faily.get_lock():
				Faily.value +=1
		except(InvalidURL):
			print(" ["+colors.RED_BG+" FAIL "+colors.ENDC+"] " + domain + " [" +colors.RED_BG+" Invalid URL "+colors.ENDC+"]")
			with Faily.get_lock():
				Faily.value +=1
		except Exception as e:
			print(e)
			traceback.print_exc()
			pass

def socp(domainlist,Resultee,Faily):
	pinger()
	for domain in domainlist:
		try:
			soct = socket.socket()
			soct.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
			soct.settimeout(3)
			soct.connect((domain, 80))
			if switch['isCDN']=='1':
				soct.sendall(bytes(f'GET / HTTP/1.1\r\nHost: {payloads["Host"]}\r\nUpgrade: {payloads["Grade"]}\r\nConnection: {payloads["Conn"]}\r\nSec-WebSocket-Key: {payloads["Key"]}\r\nSec-WebSocket-Version: {payloads["Ver"]}\r\nSec-Websocket-Accept: {payloads["Acc"]}\r\nHTTP2-Settings: \r\n\r\n', encoding='utf-8'))
			elif switch['isCDN']=='0':
				soct.sendall(bytes(f'GET / HTTP/1.1\r\nHost: {domain}\r\nUpgrade: {payloads["Grade"]}\r\nConnection: {payloads["Conn"]}\r\nSec-WebSocket-Key: {payloads["Key"]}\r\nSec-WebSocket-Version: {payloads["Ver"]}\r\nSec-Websocket-Accept: {payloads["Acc"]}\r\nHTTP2-Settings: \r\n\r\n', encoding='utf-8'))
			line = str(soct.recv(13))
			resu = re.findall("b'HTTP\/[1-9]\.[1-9]\ (.*?)\ ", line)
			if not resu:
				print(' ['+colors.RED_BG+' FAIL '+colors.ENDC+'] ' + domain + ' [' + colors.RED_BG +' EMPTY '+colors.ENDC+']')
				with Faily.get_lock():
					Faily.value +=1
			else:
				if int(resu[0]) == expected_response:
					print(' ['+colors.GREEN_BG+' HIT '+colors.ENDC+'] ' + domain + ' [' +colors.GREEN_BG+' ' + str(resu[0]) + ' '+colors.ENDC+']')
					print(domain, file=open(f'{switch["nametag"]}.txt', 'a'))
					with Resultee.get_lock():
						Resultee.value +=1
				elif int(resu[0]) != expected_response:
					print(' ['+colors.RED_BG+' FAIL '+colors.ENDC+'] ' + domain + ' [' +colors.RED_BG+' ' + str(resu[0]) + ' '+colors.ENDC+']')
					with Faily.get_lock():
						Faily.value +=1
			soct.close()
		except(ssl.SSLError):
			print(' ['+colors.RED_BG+' FAIL '+colors.ENDC+'] ' + domain + ' [' + colors.RED_BG +' NOT SSL '+colors.ENDC+']')
			with Faily.get_lock():
				Faily.value +=1
		except(socket.gaierror, socket.timeout):
			print(' ['+colors.RED_BG+' FAIL '+colors.ENDC+'] ' + domain + ' [' + colors.RED_BG +' INVALID '+colors.ENDC+']')
			with Faily.get_lock():
				Faily.value +=1
		except(socket.error):
			print(' ['+colors.RED_BG+' FAIL '+colors.ENDC+'] ' + domain + ' [' + colors.RED_BG +' TIMEOUT '+colors.ENDC+']')
			with Faily.get_lock():
				Faily.value +=1
		except Exception as e:
			print(e)
			traceback.print_exc()
			pass

def sli(domainlist,Resultee,Faily):
	pinger()
	for domain in domainlist:
		try:
			cont = ssl.create_default_context()
			cipher = (':ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:DHE-DSS-AES128-GCM-SHA256:kEDH+AESGCM:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA:ECDHE-ECDSA-AES256-SHA:DHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA:DHE-DSS-AES128-SHA256:DHE-RSA-AES256-SHA256:DHE-DSS-AES256-SHA:DHE-RSA-AES256-SHA:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!3DES:!MD5:!PSK')
			cont.set_ciphers(cipher)
			sock = cont.wrap_socket(socket.socket(), server_hostname = domain)
			sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
			sock.settimeout(3)
			sock.connect((domain, 443))
			if switch['isCDN']=='1':
				sock.sendall(bytes(f'GET {payloads["Scheme"]}://{domain}/ HTTP/1.1\r\nHost: {payloads["Host"]}\r\nUpgrade: {payloads["Grade"]}\r\nConnection: {payloads["Conn"]}\r\nSec-WebSocket-Key: {payloads["Key"]}\r\nSec-WebSocket-Version: {payloads["Ver"]}\r\nSec-Websocket-Accept: {payloads["Acc"]}\r\nHTTP2-Settings: \r\n\r\n', encoding='utf-8'))
			elif switch['isCDN']=='0':
				sock.sendall(bytes(f'GET {payloads["Scheme"]}://{domain}/ HTTP/1.1\r\nHost: {domain}\r\nUpgrade: {payloads["Grade"]}\r\nConnection: {payloads["Conn"]}\r\nSec-WebSocket-Key: {payloads["Key"]}\r\nSec-WebSocket-Version: {payloads["Ver"]}\r\nSec-Websocket-Accept: {payloads["Acc"]}\r\nHTTP2-Settings: \r\n\r\n', encoding='utf-8'))
			line = str(sock.recv(13))
			resu = re.findall("b'HTTP\/[1-9]\.[1-9]\ (.*?)\ ", line)
			if not resu:
				print(' ['+colors.RED_BG+' FAIL '+colors.ENDC+'] ' + domain + ' [' + colors.RED_BG +' EMPTY '+colors.ENDC+']')
				with Faily.get_lock():
					Faily.value +=1
			else:
				if int(resu[0]) == expected_response:
					print(' ['+colors.GREEN_BG+' HIT '+colors.ENDC+'] ' + domain + ' [' +colors.GREEN_BG+' ' + str(resu[0]) + ' '+colors.ENDC+']')
					print(domain, file=open(f'{switch["nametag"]}.txt', 'a'))
					with Resultee.get_lock():
						Resultee.value +=1
				elif int(resu[0]) != expected_response:
					print(' ['+colors.RED_BG+' FAIL '+colors.ENDC+'] ' + domain + ' [' +colors.RED_BG+' ' + str(resu[0]) + ' '+colors.ENDC+']')
					with Faily.get_lock():
						Faily.value +=1
			sock.close()
		except(ssl.SSLError):
			print(' ['+colors.RED_BG+' FAIL '+colors.ENDC+'] ' + domain + ' [' + colors.RED_BG +' NOT SSL '+colors.ENDC+']')
			with Faily.get_lock():
				Faily.value +=1
		except(socket.gaierror, socket.timeout, dns.exception.Timeout):
			print(' ['+colors.RED_BG+' FAIL '+colors.ENDC+'] ' + domain + ' [' + colors.RED_BG +' INVALID '+colors.ENDC+']')
			with Faily.get_lock():
				Faily.value +=1
		except(socket.error):
			print(' ['+colors.RED_BG+' FAIL '+colors.ENDC+'] ' + domain + ' [' + colors.RED_BG +' TIMEOUT '+colors.ENDC+']')
			with Faily.get_lock():
				Faily.value +=1
		except Exception as e:
			print(e)
			traceback.print_exc()
			pass

def grabber(domainlist,Resultee,Faily):
	for domain in domainlist:
		try:
			if switch['isTLS']=='1':
				if switch['isWS']=='1':
					commando=f"echo {domain} | zgrab2 http --custom-headers-names='Upgrade,Sec-WebSocket-Key,Sec-WebSocket-Version,Connection' --custom-headers-values='websocket,dXP3jD9Ipw0B2EmWrMDTEw==,13,Upgrade' --remove-accept-header --dynamic-origin --use-https --port 443 --max-redirects 10 --retry-https --cipher-suite= portable -t 10 | jq '.data.http.result.response.status_code,.domain' | grep -A 1 -E --line-buffered '^101'"
				elif switch['isWS']=='0':
					commando=f"echo {domain} | zgrab2 http --custom-headers-names='Upgrade,HTTP2-Settings,Connection' --custom-headers-values='h2,AAMAAABkAARAAAAAAAIAAAAA,Upgrade' --remove-accept-header --dynamic-origin --use-https --port 443 --max-redirects 10 --retry-https --cipher-suite= portable -t 10 | jq '.data.http.result.response.status_code,.domain' | grep -A 1 -E --line-buffered '^101'"
			elif switch['isTLS']=='0':
				if switch['isWS']=='1':
					commando =f"echo {domain} | zgrab2 http --custom-headers-names='Upgrade,Sec-WebSocket-Key,Sec-WebSocket-Version,Connection' --custom-headers-values='websocket,dXP3jD9Ipw0B2EmWrMDTEw==,13,Upgrade' --remove-accept-header --dynamic-origin --port 80 --max-redirects 10 --cipher-suite= portable -t 10 | jq '.data.http.result.response.status_code,.domain' | grep -A 1 -E --line-buffered '^101'"
				elif switch['isWS']=='0':
					commando =f"echo {domain} | zgrab2 http --custom-headers-names='Upgrade,HTTP2-Settings,Connection' --custom-headers-values='h2c,AAMAAABkAARAAAAAAAIAAAAA,Upgrade' --remove-accept-header --dynamic-origin --port 80 --max-redirects 10 --cipher-suite= portable -t 10 | jq '.data.http.result.response.status_code,.domain' | grep -A 1 -E --line-buffered '^101'"
			commando=subprocess.Popen(commando,shell=True,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
			commando = commando.stdout.read().decode('utf-8') + commando.stderr.read().decode('utf-8')
			rege = re.split(r'\n',commando)
			if rege[0]==f'{expected_response}':
				print(' ['+colors.GREEN_BG+' HIT '+colors.ENDC+'] ' + rege[1])
				print(rege[1], file=open(f'{switch["nametag"]}.txt', 'a'))
				with Resultee.get_lock():
					Resultee.value +=1
			else:
				print(' ['+colors.RED_BG+' FAIL '+colors.ENDC+'] ' + domain)
				with Faily.get_lock():
					Faily.value +=1
		except Exception as e:
			print(e)
			traceback.print_exc()
			print(' [' + colors.RED_BG+'Check Your ZGrab Installation!'+colors.ENDC+'] ' + domain)
			menu()

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
	print('3. H2C Socket')
	print('4. Local H2C Socket')
	print('q to Quit')
	print('')
	ans=input(' Choose Option : ').lower()
	print('')
	global headers, switch
	if str(ans)=='1':
		print('1. CDN SSL')
		print('2. CDN Direct')
		print('q to Quit')
		print('m to Menu')
		print('')
		ansi=input(' Choose Option : ').lower()
		print('')
		switch['isCDN']='1'
		switch['isWS']='1'
		if str(ansi)=='1':
			switch['isFunc']='1'
		elif str(ansi)=='2':
			switch['isFunc']='0'
		elif str(ansi)=='q':
			exit()
		else:
			menu()
	elif str(ans)=='2':
		print('1. Local SSL')
		print('2. Local Direct')
		print('3. Local SSL ZGrab')
		print('4. Local Direct ZGrab')
		print('q to Quit')
		print('')
		ansi=input(' Choose Option : ').lower()
		print('')
		switch['isCDN']='0'
		switch['isWS']='1'
		if str(ansi)=='1':
			switch['isFunc']='1'
		elif str(ansi)=='2':
			switch['isFunc']='0'
		elif str(ansi)=='3':
			switch['isFunc']='2'
			switch['isTLS']='1'
		elif str(ansi)=='4':
			switch['isFunc']='2'
			switch['isTLS']='0'
		elif str(ansi)=='q':
			exit()
		else:
			menu()
	elif str(ans)=='3':
		print('1. H2 SSL')
		print('2. H2C Direct')
		print('q to Quit')
		print('m to Menu')
		print('')
		ansi=input(' Choose Option : ').lower()
		print('')
		switch['isCDN']='1'
		switch['isWS']='0'
		if str(ansi)=='1':
			switch['isFunc']='1'
		elif str(ansi)=='2':
			switch['isFunc']='0'
		elif str(ansi)=='q':
			exit()
		else:
			menu()
	elif str(ans)=='4':
		print('1. Local H2C SSL')
		print('2. Local H2C Direct')
		print('3. Local H2C SSL ZGrab')
		print('3. Local H2C Direct ZGrab')
		print('q to Quit')
		print('')
		ansi=input(' Choose Option : ')
		print('')
		switch['isCDN']='0'
		switch['isWS']='0'
		if str(ansi)=='1':
			switch['isFunc']='1'
		elif str(ansi)=='2':
			switch['isFunc']='0'
		elif str(ansi)=='3':
			switch['isFunc']='2'
			switch['isTLS']='1'
		elif str(ansi)=='4':
			switch['isFunc']='2'
			switch['isTLS']='0'
		elif str(ansi)=='q':
			exit()
		else:
			menu()
	else:
		exit()
	print('1. Scan File (.txt)')
	print('2. Scan File (.csv)')
	print('3. Scan Online (HackerTarget)')
	print('Q to Quit')
	print('M to Menu')
	print('')
	opsi=input(' Choose Option :  ').lower()
	print('')
	if str(opsi)=='1':
		def text():
			global tag
			if switch['isCDN']=='1':
				doma()
			filet()
			option()
			print(payloads)
			executor()
			uinput()
			text()
		text()
	elif str(opsi)=='2':
		def csv():
			global tag
			if switch['isCDN']=='1':
				doma()
			csveat()
			option()
			print(payloads)
			executor()
			uinput()
			csv()
		csv()
	elif str(opsi)=='3':
		def enum():
			global tag
			if switch['isCDN']=='1':
				doma()
			hacki()
			option()
			print(payloads)
			executor()
			uinput()
			enum()
		enum()
	elif str(opsi)=='m':
		menu()
	else:
		exit()

if __name__ == '__main__':
	os.chdir(dirname(abspath(__file__)))
	if not os.path.exists(hostpath):
		os.makedirs(hostpath)
	menu()