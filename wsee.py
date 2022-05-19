import requests,re
import sys
from requests.exceptions import ReadTimeout, Timeout, ConnectionError,ChunkedEncodingError,TooManyRedirects
from urllib3.exceptions import ProtocolError,InvalidChunkLength
import os, fnmatch; os.system("clear")
import csv
from collections import defaultdict
from os.path import abspath, dirname

class colors:
	RED = '\033[31m'
	ENDC = '\033[m'
	GREEN = '\033[32m'
	YELLOW = '\033[33m'
	BLUE = '\033[34m'
	RED_BG = '\033[41m\033[1m'
	GREEN_BG = '\033[42m'

class inf:
	expected_response = 101
	control_domain = 'd2f99r5bkcyeqq.cloudfront.net'
	payloads = { "Host": inf.control_domain, "Upgrade": "websocket", "DNT":  "1", "Accept-Language": "*", "Accept": "*/*", "Accept-Encoding": "*", "Connection": "keep-alive, upgrade", "Upgrade-Insecure-Requests": "1", "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.66 Safari/537.36" }
	file_hosts = ""
	result_success = []
	num_file = 1
	columns = defaultdict(list)
	txtfiles= []
	hostpath = 'host'

def text():
	global domainlist, headers
	headers = inf.payloads
	files = os.listdir(inf.hostpath)
	for f in files:
		if fnmatch.fnmatch(f, '*.txt'):
			print( str(inf.num_file),str(f))
			inf.num_file=inf.num_file+1
			inf.txtfiles.append(str(f))

	fileselector = input("Choose Target Files : ")
	print("Target Chosen : " + inf.txtfiles[int(fileselector)-1])
	inf.file_hosts = str(inf.hostpath) +"/"+ str(inf.txtfiles[int(fileselector)-1])

	with open(inf.file_hosts) as f:
		parseddom = f.read().split()
		
	domainlist = list(set(parseddom))
	domainlist = list(filter(None, parseddom))

	print(" Loaded: " + colors.GREEN + str(len(domainlist)) + colors.ENDC + " Total of Unique Host: " + str(len(parseddom)) + " host")
	print("")
	input(colors.GREEN + "[ENTER] Start Scan ....." + colors.ENDC)
	print("")

	num_cpus = cpu_count()
	processes = []
	for process_num in range(num_cpus):
		section = domainlist[process_num::num_cpus]
		p = Process(target=engine, args=(section,))
		p.start()
		processes.append(p)
	for p in processes:
		p.join()

	print(" Loaded : "  + colors.GREEN + str(len(diginfo.result_success)) + colors.ENDC)
	if len(diginfo.result_success) >= 0:
		print(" Successfull Result : ")
	print("")
	print("Scanning Finished!")
	print("1. Go Back to Menu")
	print("2. Scanning Again")
	print("3. Quit Instead")
	print("")
	ans=input("Choose Option: ")
	if ans=="2":
		fromtext()
	elif ans=="3":
		exit()
	else:
		menu()

def csv():
	global domainlist, headers
	headers = inf.payloads
	files = os.listdir(inf.hostpath)
	for f in files:
		if fnmatch.fnmatch(f, '*.csv'):
			print( str(inf.num_file),str(f))
			inf.num_file=inf.num_file+1
			inf.txtfiles.append(str(f))
	
	fileselector = input("Select File : ")
	print("File Selected : " + inf.txtfiles[int(fileselector)-1])
	inf.file_hosts = str(inf.hostpath) +"/"+ str(inf.txtfiles[int(fileselector)-1])
	
	with open(inf.file_hosts,'r') as csv_file:
		reader = csv.reader(csv_file)
	
		for row in reader:
			for (i,v) in enumerate(row):
				inf.columns[i].append(v)
	parseddom=inf.columns[9]+inf.columns[3]
	domainlist = list(set(parseddom))
	domainlist = list(filter(None, parseddom))

	print(" Loaded: " + colors.GREEN + str(len(domainlist)) + colors.ENDC + " Total of Unique Host: " + str(len(parseddom)) + " host")
	print("")
	input(colors.GREEN + "[ENTER] Start Scan ....." + colors.ENDC)
	print("")

	num_cpus = cpu_count()
	processes = []
	for process_num in range(num_cpus):
		section = domainlist[process_num::num_cpus]
		p = Process(target=engines, args=(section,))
		p.start()
		processes.append(p)
	for p in processes:
		p.join()

	print(" Loaded : "  + colors.GREEN + str(len(diginfo.result_success)) + colors.ENDC)
	if len(diginfo.result_success) >= 0:
		print(" Successfull Result : ")
	print("")
	print("Scanning Finished!")
	print("1. Go Back to Menu")
	print("2. Scanning Again")
	print("3. Quit Instead")
	print("")
	ans=input("Choose Option: ")
	if ans=="2":
		fromtext()
	elif ans=="3":
		exit()
	else:
		menu()


def enum():
	subd = input("\nInput Domain: ")
	subd = subd.replace("https://","").replace("http://","")
	r = requests.get("https://api.hackertarget.com/hostsearch/?q=" + subd, allow_redirects=False)
	yn = input("\nContinue Scanning? (y/n): ")
	if yn.lower() == "y":
		head = { "Host": inf.control_domain, "Upgrade": "websocket", "DNT":  "1", "Accept-Language": "*", "Accept": "*/*", "Accept-Encoding": "*", "Connection": "keep-alive, upgrade", "Upgrade-Insecure-Requests": "1", "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.66 Safari/537.36" }
		sukses = []
		if r.text == "error invalid host":
			exit("ERR: error invalid host")
		else:
			print("\nScanning Started... CTRL + Z to Exit!")
			subdo = re.findall("(.*?),",r.text)
			for sub in subdo:
				try:
					req = requests.get(f"http://{sub}",inf.headers=head,timeout=0.7,allow_redirects=False)
					if req.status_code == 101:
						print(" ["+colors.GREEN_BG+" HIT "+colors.ENDC+"] " + str(sub))
						sukses.append(str(sub))
					else:
						print(" ["+colors.RED_BG+ " FAIL " + colors.ENDC + "] " + sub + " [" +colors.RED + " "+str(req.status_code)+" "+colors.ENDC+"]")
				except (Timeout, ReadTimeout, ConnectionError):
					print(" ["+colors.RED_BG+" FAIL "+colors.ENDC+"] " + sub +" [" +colors.RED_BG+" TIMEOUT "+colors.ENDC+"]")
				except(ChunkedEncodingError, ProtocolError, InvalidChunkLength):
					print(" ["+colors.RED_BG+" FAIL "+colors.ENDC+"] " +sub +" [" +colors.RED_BG+" Invalid Length "+colors.ENDC+"]")
					pass
				except(TooManyRedirects):
					print(" ["+colors.RED_BG+" FAIL "+colors.ENDC+"] " + sub + " [" +colors.RED_BG+" Redirects Loop "+colors.ENDC+"]")
					pass
				except:
					pass
			print(" Loaded: " + colors.GREEN + str(len(sub)) + colors.ENDC)
			print("Successfull Result: \n")
			for res in sukses:
				print(res)
			exit()
	else:
		exit()

elif wsocket():
	wsocket = { "Connection": "Upgrade", "Sec-Websocket-Key": "dXP3jD9Ipw0B2EmWrMDTEw==", "Sec-Websocket-Version": "13", "Upgrade-Insecure-Requests": "1", "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.66 Safari/537.36", "Upgrade": "websocket" }

	files = os.listdir(inf.hostpath)
	for f in files:
		if fnmatch.fnmatch(f, '*.txt'):
			print( str(inf.num_file),str(f))
			inf.num_file=inf.num_file+1
			inf.txtfiles.append(str(f))

	fileselector = input("Choose Target Files : ")
	print("Target Chosen : " + inf.txtfiles[int(fileselector)-1])
	inf.file_hosts = str(inf.hostpath) +"/"+ str(inf.txtfiles[int(fileselector)-1])

	with open(inf.file_hosts) as f:
		parseddom = f.read().split()

	domainlist = list(set(parseddom))
	domainlist = list(filter(None, parseddom))
	print(" Loaded: " + colors.GREEN + str(len(domainlist)) + colors.ENDC + " Total of Unique Host: " + str(len(parseddom)) + " host")
	print("")
	input(colors.GREEN + "[ENTER] Start Scan ....." + colors.ENDC)
	print("")

	for domain in domainlist:
			try:
				r = requests.get("http://" + domain, inf.headers=wsocket, timeout=1, allow_redirects=False)
				if r.status_code == inf.expected_response:
					print(" ["+colors.GREEN_BG+" HIT "+colors.ENDC+"] " + domain)
					print(domain, file=open("RelateWebsocket.txt", "a"))
					inf.result_success.append(str(domain))
				elif r.status_code != inf.expected_response:
					print(" ["+colors.RED_BG+" FAIL "+colors.ENDC+"] " + domain + " [" +colors.RED_BG+" " + str(r.status_code) + " "+colors.ENDC+"]")
			except (Timeout, ReadTimeout, ConnectionError):
				print(" ["+colors.RED_BG+" FAIL "+colors.ENDC+"] " + domain + " ["+ colors.RED_BG+" TIMEOUT "+colors.ENDC+"]")
			except(ChunkedEncodingError, ProtocolError, InvalidChunkLength):
				print(" ["+colors.RED_BG+" FAIL "+colors.ENDC+"] " + domain + " [" +colors.RED_BG+" Invalid Length "+colors.ENDC+"]")
				pass
			except(TooManyRedirects):
				print(" ["+colors.RED_BG+" FAIL "+colors.ENDC+"] " + domain + " [" +colors.RED_BG + " Redirects Loop "+colors.ENDC+"]")
			except:
				pass
	
	print(" Loaded : "  + colors.GREEN + str(len(inf.result_success)) + colors.ENDC)
	if len(inf.result_success) >= 0:
		print(" Successfull Result : ")
	for result in inf.result_success:
		print(colors.GREEN + "  " + result + colors.ENDC)
	input("Continue..")
	menu()

def engine(domainlist):
	for domain in domainlist:
		try:
			r = requests.get("http://" + domain, inf.headers=inf.headers, timeout=0.7, allow_redirects=False)
			if r.status_code == inf.expected_response:
				print(" ["+colors.GREEN_BG+" HIT "+colors.ENDC+"] " + domain)
				print(domain, file=open("RelateCFront.txt", "a"))
				inf.result_success.append(str(domain))
			elif r.status_code != inf.expected_response:
				print(" ["+colors.RED_BG+" FAIL "+colors.ENDC+"] " + domain + " [" +colors.RED_BG+" " + str(r.status_code) + " "+colors.ENDC+"]")
		except (Timeout, ReadTimeout, ConnectionError):
			print(" ["+colors.RED_BG+" FAIL "+colors.ENDC+"] " + domain + " [" + colors.RED_BG +" TIMEOUT "+colors.ENDC+"]")
		except(ChunkedEncodingError, ProtocolError, InvalidChunkLength):
			print(" ["+colors.RED_BG+" FAIL "+colors.ENDC+"] " + domain + " [" + colors.RED_BG+" Invalid Length "+colors.ENDC + "]")
			pass
		except(TooManyRedirects):
			print(" ["+colors.RED_BG+" FAIL "+colors.ENDC+"] " + domain + " [" +colors.RED_BG+" Redirects Loop "+colors.ENDC+"]")
		except:
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
	
	print(" 1. Scanning File List from .txt")
	print(" 2. Scanning File List from .csv")
	print(" 3. Scanning from Subdomain Enum [HackerTarget]")
	print(" 4. Local Websocket Finder")
	print(" Q to Quit")
	opsi=input(" Choose Option :  ")
	if str(opsi)=="1":
		text()
	elif str(opsi)=="2":
		csv()
	elif str(opsi)=="3":
		enum()
	elif str(opsi)=="4":
		wsocket()
	else:
		exit()

os.chdir(dirname(abspath(__file__)))
if not os.path.exists(inf.hostpath):
	os.makedirs(inf.hostpath)
menu()