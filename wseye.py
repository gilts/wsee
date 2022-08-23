import csv
import ssl
import socket
import traceback
import subprocess
import requests,re
import multiprocessing
import os, fnmatch; os.system('clear')
from time import sleep
from collections import defaultdict
from os.path import abspath, dirname
from concurrent.futures import ThreadPoolExecutor
from multiprocessing import Process, cpu_count, Manager, Value
from requests.exceptions import ReadTimeout, Timeout, ConnectionError, ChunkedEncodingError, TooManyRedirects, InvalidURL

expected_response = 101
cflare_domain = 'id-herza.sshws.net'
cfront_domain = 'dhxqu5ob0t1lp.cloudfront.net'
payloads = {'Host': cfront_domain}
switch = { 'dir': '0', 'func': '0', 'sub': '0', 'opt': '0', 'nametag': 'ano' }
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

def nametage():
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
		else:
			file_hosts = str(txtfiles[int(fileselector)-1])
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
		else:
			file_hosts = str(txtfiles[int(fileselector)-1])
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
			if switch['func']=='0':
				p = Process(target=wsee, args=(section,Resultee,Faily))
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

def Asyncutor():
	try:
		Faily=Value('i',0)
		Resultee=Value('d',0)
		num_cpus = cpu_count()
		with ThreadPoolExecutor(max_workers=num_cpus) as executor:
			if switch['func']=='0':
				executor.submit(wsee(domainlist,Resultee,Faily))
			else:
				executor.submit(grabber(domainlist,Resultee,Faily))
			executor.shutdown( cancel_futures = True )
	except Exception as e:
		print(e)
		traceback.print_exc()
		pass
	print('')
	print(' Failed Result : '  + colors.RED_BG + ' '+str(Faily.value) +' '+ colors.ENDC )
	print(' Successfull Result : ' + colors.GREEN_BG + ' '+str(Resultee.value)+ ' '+colors.ENDC)
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

def wsee(domainlist,Resultee,Faily):
	pinger()
	for domain in domainlist:
		try:
			if switch['opt']=='1':
				cont = ssl.SSLContext(ssl.PROTOCOL_TLS)
				sock = cont.wrap_socket(socket.socket(), server_hostname = domain)
				sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
				sock.settimeout(10)
				sock.connect((domain, 443))
				if switch['sub']=='0':
					sock.sendall(bytes(f'GET wss://{domain}/ HTTP/1.1\r\nHost: {domain}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n', encoding='utf-8'))
				elif switch['sub']=='1':
					sock.sendall(bytes(f'GET wss://{domain}/ HTTP/1.1\r\nHost: {payloads["Host"]}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n', encoding='utf-8'))
				elif switch['sub']=='2':
					sock.sendall(bytes(f'GET h2://{domain}/ HTTP/1.1\r\nHost: {domain}\r\nUpgrade: h2\r\nConnection: Upgrade, HTTP2-Settings\r\nHTTP2-Settings: \r\n\r\n', encoding='utf-8'))
				elif switch['sub']=='3':
					sock.sendall(bytes(f'GET h2://{domain}/ HTTP/1.1\r\nHost: {payloads["Host"]}\r\nUpgrade: h2\r\nConnection: Upgrade\r\nHTTP2-Settings: \r\n\r\n', encoding='utf-8'))
			elif switch['opt']=='0':
				sock = socket.socket()
				sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
				sock.settimeout(10)
				sock.connect((domain, 80))
				if switch['sub']=='0':
					sock.sendall(bytes(f'GET / HTTP/1.1\r\nHost: {domain}\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-Websocket-Key: dXP3jD9Ipw0B2EmWrMDTEw==\r\nSec-Websocket-Version: 13\r\n\r\n', encoding='utf-8'))
				elif switch['sub']=='1':
					sock.sendall(bytes(f'GET / HTTP/1.1\r\nHost: {payloads["Host"]}\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-Websocket-Key: dXP3jD9Ipw0B2EmWrMDTEw==\r\nSec-Websocket-Version: 13\r\n\r\n', encoding='utf-8'))
				elif switch['sub']=='2':
					sock.sendall(bytes(f'GET / HTTP/1.1\r\nHost: {domain}\r\nUpgrade: h2c\r\nConnection: Upgrade, HTTP2-Settings\r\nHTTP2-Settings: \r\n\r\n', encoding='utf-8'))
				elif switch['sub']=='3':
					sock.sendall(bytes(f'GET / HTTP/1.1\r\nHost: {payloads["Host"]}\r\nUpgrade: h2c\r\nConnection: Upgrade\r\nHTTP2-Settings: \r\n\r\n', encoding='utf-8'))
			line = str(sock.recv(13))
			r = re.findall("b'HTTP\/[1-9]\.[1-9]\ (.*?)\ ", line)
			print(r)
			if int(r[0]) == expected_response:
				print(' ['+colors.GREEN_BG+' HIT '+colors.ENDC+'] ' + domain)
				print(domain, file=open(f'{switch["nametag"]}.txt', 'a'))
				with Resultee.get_lock():
					Resultee.value +=1
			elif int(r[0]) != expected_response:
				print(' ['+colors.RED_BG+' FAIL '+colors.ENDC+'] ' + domain + ' [' +colors.RED_BG+' ' + str(r) + ' '+colors.ENDC+']')
				with Faily.get_lock():
					Faily.value +=1
		except (ssl.SSLError) as e:
			traceback.print_exc()
			print(' ['+colors.RED_BG+' FAIL '+colors.ENDC+'] ' + domain + ' [' + colors.RED_BG +' NOT SSL '+colors.ENDC+']')
			print('')
			with Faily.get_lock():
				Faily.value +=1
		except (socket.gaierror):
			print(' ['+colors.RED_BG+' FAIL '+colors.ENDC+'] ' + domain + ' [' + colors.RED_BG +' INVALID '+colors.ENDC+']')
			with Faily.get_lock():
				Faily.value +=1
		except socket.error as e:
			print(e)
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
			if switch['opt']=='2':
				if switch['sub']=='0':
					commando=f"echo {domain} | zgrab2 http --custom-headers-names='Upgrade,Sec-WebSocket-Key,Sec-WebSocket-Version,Connection' --custom-headers-values='websocket,dXP3jD9Ipw0B2EmWrMDTEw==,13,Upgrade' --remove-accept-header --dynamic-origin --use-https --port 443 --max-redirects 10 --retry-https --cipher-suite= portable -t 10 | jq '.data.http.result.response.status_code,.domain' | grep -A 1 -E --line-buffered '^101'"
				elif switch['sub']=='2':
					commando=f"echo {domain} | zgrab2 http --custom-headers-names='Upgrade,HTTP2-Settings,Connection' --custom-headers-values='h2,AAMAAABkAARAAAAAAAIAAAAA,Upgrade' --remove-accept-header --dynamic-origin --use-https --port 443 --max-redirects 10 --retry-https --cipher-suite= portable -t 10 | jq '.data.http.result.response.status_code,.domain' | grep -A 1 -E --line-buffered '^101'"
			elif switch['opt']=='3':
				if switch['sub']=='0':
					commando =f"echo {domain} | zgrab2 http --custom-headers-names='Upgrade,Sec-WebSocket-Key,Sec-WebSocket-Version,Connection' --custom-headers-values='websocket,dXP3jD9Ipw0B2EmWrMDTEw==,13,Upgrade' --remove-accept-header --dynamic-origin --port 80 --max-redirects 10 --cipher-suite= portable -t 10 | jq '.data.http.result.response.status_code,.domain' | grep -A 1 -E --line-buffered '^101'"
				elif switch['sub']=='2':
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
		switch['sub']='1'
		if str(ansi)=='1':
			switch['func']='0'
			switch['opt']='1'
		elif str(ansi)=='2':
			switch['func']='0'
			switch['opt']='0'
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
		switch['sub']='0'
		if str(ansi)=='1':
			switch['func']='0'
			switch['opt']='1'
		elif str(ansi)=='2':
			switch['func']='0'
			switch['opt']='0'
		elif str(ansi)=='3':
			switch['func']='1'
			switch['opt']='2'
		elif str(ansi)=='4':
			switch['func']='1'
			switch['opt']='3'
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
		switch['sub']='3'
		if str(ansi)=='1':
			switch['func']='0'
			switch['opt']='1'
		elif str(ansi)=='2':
			switch['func']='0'
			switch['opt']='0'
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
		switch['sub']='2'
		if str(ansi)=='1':
			switch['func']='0'
			switch['opt']='1'
		elif str(ansi)=='2':
			switch['func']='0'
			switch['opt']='0'
		elif str(ansi)=='3':
			switch['func']='1'
			switch['opt']='2'
		elif str(ansi)=='4':
			switch['func']='1'
			switch['opt']='3'
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
			if switch['sub']=='1':
				doma()
			filet()
			nametage()
			executor()
			uinput()
			text()
		text()
	elif str(opsi)=='2':
		def csv():
			global tag
			if switch['sub']=='1':
				doma()
			csveat()
			nametage()
			executor()
			uinput()
			csv()
		csv()
	elif str(opsi)=='3':
		def enum():
			global tag
			if switch['sub']=='1':
				doma()
			hacki()
			nametage()
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