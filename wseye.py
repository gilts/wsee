import csv
import json
import socket
###import threading
import traceback
import subprocess
import requests,re
import multiprocessing
import os, fnmatch; os.system('clear')
from time import sleep
from functools import wraps
from collections import defaultdict
from os.path import abspath, dirname
from requests.adapters import HTTPAdapter
from concurrent.futures import ThreadPoolExecutor
from multiprocessing import Process, cpu_count, Manager, Value
from requests.exceptions import ReadTimeout, Timeout, ConnectionError, ChunkedEncodingError, TooManyRedirects, InvalidURL

expected_response = 101
cflare_domain = 'id3.sshws.me'
cfront_domain = 'dhxqu5ob0t1lp.cloudfront.net'
payloads = { 'Host': cfront_domain, 'Upgrade': 'websocket', 'DNT':  '1', 'Accept-Language': '*', 'Accept': '*/*', 'Accept-Encoding': '*', 'Connection': 'keep-alive, upgrade', 'Upgrade-Insecure-Requests': '1', 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.66 Safari/537.36' }
hsocket = { 'Host': cfront_domain, 'Upgrade': 'h2c', 'DNT':  '1', 'Accept-Language': '*', 'Accept': '*/*', 'Accept-Encoding': '*', 'Connection': 'keep-alive, upgrade, HTTP2-Settings', 'Upgrade-Insecure-Requests': '1', 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.66 Safari/537.36' }
wsocket = { 'Connection': 'Upgrade', 'Sec-Websocket-Key': 'dXP3jD9Ipw0B2EmWrMDTEw==', 'Sec-Websocket-Version': '13', 'Upgrade': 'websocket' }
locket = { 'Connection': 'Upgrade, HTTP2-Settings', 'HTTP2-Settings': '', 'Upgrade': 'h2c' }
switch = { 'dir': '0', 'func': '0', 'sub': '0', 'opt': '0' }
hostpath = 'host'

columns = defaultdict(list)
txtfiles= []

class colors:
	RED_BG = '\033[41m\033[1m'
	GREEN_BG = '\033[42m'
	ENDC = '\033[m'

class FrontingAdapter(HTTPAdapter):
    def __init__(self, fronted_domain=None, **kwargs):
        self.fronted_domain = fronted_domain
        super(FrontingAdapter, self).__init__(**kwargs)
    def send(self, request, **kwargs):
        connection_pool_kwargs = self.poolmanager.connection_pool_kw
        if self.fronted_domain:
            connection_pool_kwargs["assert_hostname"] = self.fronted_domain
        elif "assert_hostname" in connection_pool_kwargs:
            connection_pool_kwargs.pop("assert_hostname", None)
        return super(FrontingAdapter, self).send(request, **kwargs)
    def init_poolmanager(self, *args, **kwargs):
        server_hostname = None
        if self.fronted_domain:
            server_hostname = self.fronted_domain
        super(FrontingAdapter, self).init_poolmanager(server_hostname=server_hostname, *args, **kwargs)

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
		hsocket['Host']=f'{domain}'
	elif str(ansi)=='2':
		payloads['Host']=f'{cfront_domain}'
		hsocket['Host']=f'{cfront_domain}'
	elif str(ansi)=='3':
		payloads['Host']=f'{cflare_domain}'
		hsocket['Host']=f'{cflare_domain}'
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
				p = Process(target=engine, args=(section,nametag,headers,Resultee,Faily))
			else:
				p = Process(target=grabber, args=(section,nametag,Resultee,Faily))
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
		global lock, Resultee, Faily
		###Resultee=0
		###Faily=0
		###lock = threading.Lock()
		Faily=Value('i',0)
		Resultee=Value('d',0)
		num_cpus = cpu_count()
		with ThreadPoolExecutor(max_workers=num_cpus) as executor:
			if switch['func']=='0':
				executor.submit(engine(domainlist,nametag,headers,Resultee,Faily))
			else:
				executor.submit(grabber(domainlist,nametag,Resultee,Faily))
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
		tag.has_run = False
		###Faily = 0
		###Resultee = 0
		return
	elif ans=='3':
		exit()
	else:
		tag.has_run = False
		###Faily = 0
		###Resultee = 0
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

def engine(domainlist,nametag,headers,Resultee,Faily):
	pinger()
	for domain in domainlist:
		try:
			if switch['opt']=='1':
				rs = requests.Session()
				rs.mount('https://', FrontingAdapter(fronted_domain=frontdom))
				r = rs.get("https://" + domain, headers=headers, timeout=1.0, allow_redirects=False)
			elif switch['opt']=='0':
				r = requests.get('http://' + domain, headers=headers, timeout=1.0, allow_redirects=False)
			if r.status_code == expected_response:
				print(' ['+colors.GREEN_BG+' HIT '+colors.ENDC+'] ' + domain)
				print(domain, file=open(f'{nametag}.txt', 'a'))
				with Resultee.get_lock():
					Resultee.value +=1
				####
				###lock.acquire()
				###Resultee+=1
				###lock.release()
				####
			elif r.status_code != expected_response:
				print(' ['+colors.RED_BG+' FAIL '+colors.ENDC+'] ' + domain + ' [' +colors.RED_BG+' ' + str(r.status_code) + ' '+colors.ENDC+']')
				with Faily.get_lock():
					Faily.value +=1
				####
				###lock.acquire()
				###Faily+=1
				###lock.release()
				####
		except (Timeout, ReadTimeout, ConnectionError):
			print(' ['+colors.RED_BG+' FAIL '+colors.ENDC+'] ' + domain + ' [' + colors.RED_BG +' TIMEOUT '+colors.ENDC+']')
			with Faily.get_lock():
				Faily.value +=1
			####
			###lock.acquire()
			###Faily+=1
			###lock.release()
			####
		except(ChunkedEncodingError):
			print(' ['+colors.RED_BG+' FAIL '+colors.ENDC+'] ' + domain + ' [' + colors.RED_BG+' Invalid Length '+colors.ENDC + ']')
			with Faily.get_lock():
				Faily.value +=1
			####
			###lock.acquire()
			###Faily+=1
			###lock.release()
			####
		except(TooManyRedirects):
			print(' ['+colors.RED_BG+' FAIL '+colors.ENDC+'] ' + domain + ' [' +colors.RED_BG+' Redirects Loop '+colors.ENDC+']')
			with Faily.get_lock():
				Faily.value +=1
			####
			###lock.acquire()
			###Faily+=1
			###lock.release()
			####
		except(InvalidURL):
			print(' ['+colors.RED_BG+' FAIL '+colors.ENDC+'] ' + domain + ' [' +colors.RED_BG+' Invalid URL '+colors.ENDC+']')
			with Faily.get_lock():
				Faily.value +=1
			####
			###lock.acquire()
			###Faily+=1
			###lock.release()
			####
		except Exception as e:
			print(e)
			traceback.print_exc()
			pass

def grabber(domainlist,nametag,Resultee,Faily):
	for domain in domainlist:
		try:
			if switch['opt']=='2':
				commando =f"echo {domain} | zgrab2 http --custom-headers-names='Upgrade,Sec-WebSocket-Key,Sec-WebSocket-Version,Connection' --custom-headers-values='websocket,dXP3jD9Ipw0B2EmWrMDTEw==,13,Upgrade' --remove-accept-header --dynamic-origin --use-https --port 443 --max-redirects 10 --retry-https --cipher-suite= portable -t 10 | jq '.data.http.result.response.status_code,.domain' | grep -A 1 -E --line-buffered '^101'"
			elif switch['opt']=='3':
				commando =f"echo {domain} | zgrab2 http --custom-headers-names='Host,Upgrade,Sec-WebSocket-Key,Sec-WebSocket-Version,Connection' --custom-headers-values='{frontdom},websocket,dXP3jD9Ipw0B2EmWrMDTEw==,13,Upgrade' --remove-accept-header --dynamic-origin --use-https --port 443 --max-redirects 10 --retry-https --cipher-suite= portable -t 10 | jq '.data.http.result.response.status_code,.domain' | grep -A 1 -E --line-buffered '^101'"
			elif switch['opt']=='4':
				commando =f"echo {domain} | zgrab2 http --custom-headers-names='Host,Upgrade,Sec-WebSocket-Key,Sec-WebSocket-Version,Connection' --custom-headers-values='{frontdom},websocket,dXP3jD9Ipw0B2EmWrMDTEw==,13,Upgrade' --remove-accept-header --dynamic-origin --port 80 --max-redirects 10 --retry-http --cipher-suite= portable -t 10 | jq '.data.http.result.response.status_code,.domain' | grep -A 1 -E --line-buffered '^101'"
			elif switch['opt']=='5':
				commando =f"echo {domain} | zgrab2 http --custom-headers-names='Upgrade,Sec-WebSocket-Key,Sec-WebSocket-Version,Connection' --custom-headers-values='websocket,dXP3jD9Ipw0B2EmWrMDTEw==,13,Upgrade' --remove-accept-header --dynamic-origin --port 80 --max-redirects 10 --retry-http --cipher-suite= portable -t 10 | jq '.data.http.result.response.status_code,.domain' | grep -A 1 -E --line-buffered '^101'"
			commando=subprocess.Popen(commando,shell=True,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
			commando = commando.stdout.read().decode('utf-8') + commando.stderr.read().decode('utf-8')
			rege = re.split(r'\n',commando)
			print(commando)
			if rege[0]==f'{expected_response}':
				print(' ['+colors.GREEN_BG+' HIT '+colors.ENDC+'] ' + rege[1])
				print(rege[1], file=open(f'{nametag}.txt', 'a'))
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
	ans=input(' Choose Option : ')
	print('')
	global headers, nametag
	if str(ans)=='1':
		print('1. CDN SSL')
		print('2. CDN Direct')
		print('3. CDN SSL ZGrab')
		print('4. CDN Direct ZGrab')
		print('q to Quit')
		print('m to Menu')
		print('')
		ans=input(' Choose Option : ').lower()
		print('')
		headers = payloads
		switch['sub']='1'
		if str(ans)=='1':
			switch['func']='0'
			switch['opt']='1'
		elif str(ans)=='2':
			switch['func']='0'
			switch['opt']='0'
		elif str(ans)=='3':
			switch['func']='1'
			switch['opt']='3'
		elif str(ans)=='4':
			switch['func']='1'
			switch['opt']='4'
		elif str(ans)=='q':
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
		ans=input(' Choose Option : ')
		print('')
		headers = wsocket
		switch['sub']='0'
		if str(ans)=='1':
			switch['func']='0'
			switch['opt']='1'
		elif str(ans)=='2':
			switch['func']='0'
			switch['opt']='0'
		elif str(ans)=='3':
			switch['func']='1'
			switch['opt']='2'
		elif str(ans)=='4':
			switch['func']='1'
			switch['opt']='5'
		elif str(ans)=='q':
			exit()
		else:
			menu()
	elif str(ans)=='3':
		print('1. H2C SSL')
		print('2. H2C Direct')
		print('3. H2C SSL ZGrab')
		print('4. H2C Direct ZGrab')
		print('q to Quit')
		print('m to Menu')
		print('')
		ans=input(' Choose Option : ').lower()
		print('')
		headers = hsocket
		switch['sub']='1'
		if str(ans)=='1':
			switch['func']='0'
			switch['opt']='1'
		elif str(ans)=='2':
			switch['func']='0'
			switch['opt']='0'
		elif str(ans)=='3':
			switch['func']='1'
			switch['opt']='3'
		elif str(ans)=='4':
			switch['func']='1'
			switch['opt']='4'
		elif str(ans)=='q':
			exit()
		else:
			menu()
	elif str(ans)=='4':
		print('1. Local H2C SSL')
		print('2. Local H2C Direct')
		print('2. Local H2C SSL ZGrab')
		print('3. Local H2C Direct ZGrab')
		print('q to Quit')
		print('')
		ans=input(' Choose Option : ')
		print('')
		headers = locket
		switch['sub']='0'
		if str(ans)=='1':
			switch['func']='0'
			switch['opt']='1'
		elif str(ans)=='2':
			switch['func']='0'
			switch['opt']='0'
		elif str(ans)=='3':
			switch['func']='1'
			switch['opt']='2'
		elif str(ans)=='4':
			switch['func']='1'
			switch['opt']='5'
		elif str(ans)=='q':
			exit()
		else:
			menu()
	else:
		exit()
	print('[' + colors.RED_BG + ' Input your Output File Name ' + colors.ENDC + ']')
	nametag = input(' Output as : ')
	print('')
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