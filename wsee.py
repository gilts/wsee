import requests,re
import sys
from requests.exceptions import ReadTimeout, Timeout, ConnectionError,ChunkedEncodingError,TooManyRedirects,InvalidURL
from urllib3.exceptions import ProtocolError,InvalidChunkLength
import os, fnmatch; os.system("clear")
import csv
from collections import defaultdict, Counter
from os.path import abspath, dirname
from multiprocessing import Process, cpu_count, Manager
from time import sleep

class colors:
	RED = '\033[31m'
	ENDC = '\033[m'
	GREEN = '\033[32m'
	YELLOW = '\033[33m'
	BLUE = '\033[34m'
	RED_BG = '\033[41m\033[1m'
	GREEN_BG = '\033[42m'

expected_response = 101
control_domain = 'd22236fd6eam5f.cloudfront.net'
payloads = { "Host": control_domain, "Upgrade": "websocket", "DNT":  "1", "Accept-Language": "*", "Accept": "*/*", "Accept-Encoding": "*", "Connection": "keep-alive, upgrade", "Upgrade-Insecure-Requests": "1", "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.66 Safari/537.36" }
wsocket = { "Connection": "Upgrade", "Sec-Websocket-Key": "dXP3jD9Ipw0B2EmWrMDTEw==", "Sec-Websocket-Version": "13", "Upgrade": "websocket" }
file_hosts = ""
columns = defaultdict(list)
txtfiles= []
hostpath = 'host'
R=[]
F=[]

def doma():
	global frontdom
	print("1. Insert custom fronting domain")
	print("2. Leave it as default")
	print("")
	ansi=input(" Choose Option : ")
	print("")
	if str(ansi)=="1":
		domain=input(" Domain : ")
		payloads["Host"]=f"{domain}"
		print("["+colors.GREEN_BG + f" {domain} "+ colors.ENDC + "] Selected as Domain Fronting!")
		print("["+colors.RED_BG+" Warning! " + colors.ENDC + "] : [" + colors.RED_BG + " INVALID " + colors.ENDC + "] Domain Will Give 0 Result!" )
		print("")
	else:
		payloads["Host"]=f"{control_domain}"
		print("["+colors.GREEN_BG + f" {control_domain} "+ colors.ENDC + "] Selected as Domain Fronting!")
		print("["+colors.RED_BG+" Warning! " + colors.ENDC + "] : [" + colors.RED_BG + " INVALID " + colors.ENDC + "] Domain Will Give 0 Result!" )
		print("")
	frontdom = str(payloads["Host"])
	return

def filet():
	global domainlist, fileselector
	num_file = 1
	files = os.listdir(hostpath)
	print(" [" + colors.RED_BG + " Files Found " + colors.ENDC + "] ")
	for f in files:
		if fnmatch.fnmatch(f, '*.txt'):
			print( str(num_file),str(f))
			num_file=num_file+1
			txtfiles.append(str(f))

	print("")
	print(" M back to Menu ")
	fileselector = input(" Choose Target Files : ")
	if fileselector.isdigit():
		print("")
		print(" Target Chosen : " + colors.RED_BG + " "+txtfiles[int(fileselector)-1]+" "+colors.ENDC)
		file_hosts = str(hostpath) +"/"+ str(txtfiles[int(fileselector)-1])
	else:
		menu()

	with open(file_hosts) as f:
		parseddom = f.read().split()

	domainlist = list(set(parseddom))
	domainlist = list(filter(None, parseddom))

	print(" Total of Domains Loaded: " + colors.RED_BG + " " +str(len(domainlist)) + " "+colors.ENDC )
	print("")
	return

def csveat():
	global domainlist, fileselector
	num_file=1
	files = os.listdir(hostpath)
	print(" [" + colors.RED_BG + " Files Found " + colors.ENDC + "] ")
	for f in files:
		if fnmatch.fnmatch(f, '*.csv'):
			print( str(num_file),str(f))
			num_file=num_file+1
			txtfiles.append(str(f))

	print("")
	print(" M back to Menu ")
	fileselector = input(" Choose Target Files : ")
	if fileselector.isdigit():
		print("")
		print(" Target Chosen : " + colors.RED_BG + " "+txtfiles[int(fileselector)-1]+" "+colors.ENDC)
		file_hosts = str(hostpath) +"/"+ str(txtfiles[int(fileselector)-1])
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

	print(" Total of Domains Loaded: " + colors.RED_BG + " " +str(len(domainlist)) + " "+colors.ENDC )
	print("")
	return

def executor():
	with Manager() as manager:
		global R, F
		num_cpus = cpu_count()
		processes = []
		R = manager.list()
		F = manager.list()
		for process_num in range(num_cpus):
			section = domainlist[process_num::num_cpus]
			p = Process(target=engine, args=(section,))
			p.start()
			processes.append(p)
		for p in processes:
			p.join()
		R = list(R)
		F = list(F)

		print("")
		print(" Failed Result : "  + colors.RED_BG + " "+str(len(F)) +" "+ colors.ENDC )
		print(" Successfull Result : " + colors.GREEN_BG + " "+str(len(R))+ " "+colors.ENDC)
		return

def uinput():
	print("")
	print("Scanning Finished!")
	print("1. Go Back to Menu")
	print("2. Scanning Again")
	print("3. Quit Instead")
	print("")
	ans=input("Choose Option: ")
	if ans=="2":
		return
	elif ans=="3":
		exit()
	else:
		menu()

def hacki():
	global domainlist, subd
	subd = input("\nInput Domain: ")
	subd = subd.replace("https://","").replace("http://","")
	r = requests.get("https://api.hackertarget.com/hostsearch/?q=" + subd, allow_redirects=False)
	if r.text == "error invalid host":
		exit("ERR: error invalid host")
	else:
		domainlist = re.findall("(.*?),",r.text)
		return

def engine(domainlist):
	for domain in domainlist:
		try:
			r = requests.get("http://" + domain, headers=headers, timeout=0.7, allow_redirects=False)
			if r.status_code == expected_response:
				print(" ["+colors.GREEN_BG+" HIT "+colors.ENDC+"] " + domain)
				print(domain, file=open(f"{nametag}.txt", "a"))
				R.append(str(domain))
			elif r.status_code != expected_response:
				print(" ["+colors.RED_BG+" FAIL "+colors.ENDC+"] " + domain + " [" +colors.RED_BG+" " + str(r.status_code) + " "+colors.ENDC+"]")
				F.append(str(domain))
		except (Timeout, ReadTimeout, ConnectionError):
			print(" ["+colors.RED_BG+" FAIL "+colors.ENDC+"] " + domain + " [" + colors.RED_BG +" TIMEOUT "+colors.ENDC+"]")
			F.append(str(domain))
			pass
		except(ChunkedEncodingError, ProtocolError, InvalidChunkLength):
			print(" ["+colors.RED_BG+" FAIL "+colors.ENDC+"] " + domain + " [" + colors.RED_BG+" Invalid Length "+colors.ENDC + "]")
			F.append(str(domain))
			pass
		except(TooManyRedirects):
			print(" ["+colors.RED_BG+" FAIL "+colors.ENDC+"] " + domain + " [" +colors.RED_BG+" Redirects Loop "+colors.ENDC+"]")
			F.append(str(domain))
			pass
		except(InvalidURL):
			print(" ["+colors.RED_BG+" FAIL "+colors.ENDC+"] " + domain + " [" +colors.RED_BG+" Invalid URL "+colors.ENDC+"]")
			F.append(str(domain))
			pass

def menu():
	print('''

__  _  ________ ____   ____  
\ \/ \/ /  ___// __ \_/ __ \ 
 \     /\___ \\  ___/\  ___/ 
  \/\_//____  >\___  >\___  >
            \/     \/     \/  

	''')
	print("    [" + colors.RED_BG + " Domain : Fronting " + colors.ENDC + "]")
	print("     ["+colors.RED_BG+" Author " + colors.ENDC + ":" + colors.GREEN_BG + " Kiynox " + colors.ENDC + "]")
	print("")

	print("1. CDN Websocket")
	print("2. Local Websocket")
	print("q to Quit")
	print("")
	ans=input(" Choose Option : ")
	print("")
	if str(ans)=="1":
		print("1. Scanning File List from .txt")
		print("2. Scanning File List from .csv")
		print("3. Scanning from Subdomain Enum [HackerTarget]")
		print("Q to Quit")
		print("")
		opsi=input(" Choose Option :  ")
		print("")

		if str(opsi)=="1":
			def text():
				global headers, nametag
				headers = payloads
				doma()
				filet()
				nametag = "["+str(txtfiles[int(fileselector)-1]).removesuffix(".txt") + f"]-[{frontdom}]-[CDN]-[TXT]"
				executor()
				uinput()
				text()
			text()

		elif str(opsi)=="2":
			def csv():
				global headers, nametag
				headers = payloads
				doma()
				csveat()
				nametag = "["+str(txtfiles[int(fileselector)-1]).removesuffix(".csv") + f"]-[{frontdom}]-[CDN]-[CSV]"
				executor()
				uinput()
				csv()
			csv()

		elif str(opsi)=="3":
			def enum():
				global headers, nametag
				headers = payloads
				doma()
				hacki()
				nametag = "["+str(subd) + f"]-[{frontdom}]-[CDN]-[ENUM]"
				executor()
				uinput()
				enum()
			enum()

	elif str(ans)=="2":
		print("1. Scanning File List from .txt")
		print("2. Scanning File List from .csv")
		print("3. Scanning from Subdomain Enum [HackerTarget]")
		print("Q to Quit")
		print("")
		opsi=input(" Choose Option :  ")
		print("")

		if str(opsi)=="1":
			def localtext():
				global headers
				headers = wsocket
				filet()
				nametag = "["+str(txtfiles[int(fileselector)-1]).removesuffix(".txt") + f"]-[LOCAL]-[TXT]"
				executor()
				uinput()
				localtext()
			localtext()

		elif str(opsi)=="2":
			def localcsv():
				global headers
				headers = wsocket
				csveat()
				nametag = "["+str(txtfiles[int(fileselector)-1]).removesuffix(".csv") + f"]-[LOCAL]-[CSV]"
				executor()
				uinput()
				localcsv()
			localcsv()

		elif str(opsi)=="3":
			def localenum():
				global headers
				headers = wsocket
				hacki()
				nametag = "["+str(subd) + f"]-[LOCAL]-[ENUM]"
				executor()
				uinput()
				localenum()
			localenum()

	else:
		exit()

os.chdir(dirname(abspath(__file__)))
if not os.path.exists(hostpath):
	os.makedirs(hostpath)
menu()