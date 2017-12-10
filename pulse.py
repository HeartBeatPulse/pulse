from OpenSSL import SSL
import requests
import os
import sys
import webbrowser
import re
import hashlib

def calcHash(filename):
		h = hashlib.md5()
	#	print filename
	#	sys.exit(0)
		with open(filename, 'rb') as f:
			buf = f.read()
			h.update(buf)
# where to save the results
		return h.hexdigest()

print("[*] Setting up the UserAgent")
os.system("sleep 1")
headers = {'User-Agent': 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:57.0) Gecko/20100101 Firefox/57.0'}
print("[*] Setting up the URL")
os.system("sleep 1")
url = 'https://cipribejean.000webhostapp.com/heartbeat.py'
print("[*] Getting the latest files")
os.system("sleep 1")
response = requests.get(url,headers=headers)
print("[*] Checking for Updates")
os.system("sleep 1")
data = response.text

f = open('temp.txt','w')
f.write(data)
f.close()
hash1 = calcHash("temp.txt")
hash2 = calcHash("heartbeat.py")
if hash1 > hash2 or hash1 < hash2:
	print("\t--> Version Change Detected")
	os.system("sleep 1")
	os.system("mv heartbeat.py old_heartbeat.py")
	os.system("mv temp.txt heartbeat.py")
	print("\t--> Updating the files")
	os.system("sleep 1")
else:
	os.system("rm temp.txt")
	print("\t--> NO Updates for now")
print("[*] HeartBeat is good to go")
print("[*] Launching HeartBeat")
os.system("sleep 1")
os.system("python heartbeat.py")
