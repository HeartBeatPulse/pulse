# General rules of code's implementation and annotation:
# 1. method's name starting with 'set' means that this object will assign the value to a variable.
# 2. method's name starting with 'get' means that this object returns the value of a variable.
# 3. __init__ means that the object's class accepts values at the instantiation time.
# 4. the keyword 'self' means that the value will be treated only inside the class. Each class has a 'self' keyword, meaning that each class will hold information only for their specific purpose.

import sys, os, re, time
import hashlib
import subprocess
import threading

# This class is meant to specify which platform is used for analysis: Win or Unix.
class Platform:

# This is the Class's Constructor
	def __init__(self,platformValue):
		self.platformValue = platformValue

# Check the platform value:
# if the 'platformValue' is 0 then it is Unix, otherwise is Windows.
		if platformValue == 0:
			pass
#			print('Platform Value {} means Unix'.format(self.platformValue))
		else:
			pass
#			print('Platform Value {} means Windows'.format(self.platformValue))
	def setPlatformValue(self, val):
		self.platformValue = val
	def setChunkSize(self,val):
		self.chunkSize = val
# Getter for this object. Returns the platformValue's value
	def getPlatformValue(self):
		return self.platformValue
	def getChunkSize(self):
		return self.chunkSize

# This is the main parser, it contains the methods to parse and search inside the extracted data.
class Parser:
	dll = []
	exes = []
	regs = []
	paths = []
	urls = []
	mails = []
	ips = []
	knownDomains = []
	sentences = []
	base64Strings = []
	
# This is the Class's Constructor
	def __init__(self,src_file,platform):
		strings = []
		print ("Platform value inside function is %s" %(platform))
		if platform == 0:
			cmd = "strings \"" + src_file + "\" > strings.txt"
			print cmd
			os.system(cmd)
		else:
			cmd = "strings.exe \"" + src_file + "\" > strings.txt"
			print cmd
			os.system(cmd)
		
		with open("strings.txt","r") as f:
			strings = f.readlines()
			for i in range(0,len(strings)):
				strings[i] = strings[i][:-1]

		self.data = strings
		with open("res/knownDomains.txt","r") as f:
			temp = f.readlines()
			for t in temp:
				self.knownDomains.append(t[:-1])



# This defines a regex to find URL-format Strings.
# it will match:
# 1. http://example.com
# 2. https://example.com
# 3. http://www.example.com
# 4. https://www.example.com
# 5. example.com (without http(s) or www)
# 6. www.example.com ( without http(s))
# 7. ww1.example.com ( or any other integer )
#
# it matches the threshold to each URL having at least 5 characters
# it stores the results into 'self.urls' variable, and increments the current index 
	def findURLs(self,chunk):
		start = time.time()
	    	res = re.findall(r'((https?:\/\/)?(ww[w0-9]+\.)?[a-zA-Z0-9\.\-\_\[\]\{\(\)]+\.[\[\]\{\(\)a-zA-Z]{2,7})',chunk)
	    	index = 0
	    	if res:
# This section is a check loop, for instance you might have 'ex.com' which could be skipped,
# so the loop will parse it and it will print it on the screen.
#
#			truePositive = res[0][0]
#			for i in range(0,len(res[0])):
#				if len(res[0][i]) > len(truePositive):
#					truePositive = res[0][i]
#			print "URL", truePositive
			for i in res[0]:
			    if not i in self.urls and len(i) > 4:
			    	self.urls.append(i)
				index += 1
	    	stop = time.time()
	#    	print ('Thread Execution Took %d' % (stop-start))


# A System Path is defined as any string starting with one letter, followed by the group ':\'.
# This function will look for any string which starts with 'AnyLetter':\{anything}

	def findSystemPaths(self,chunk):
		start = time.time()
	    	res = re.findall(r'([a-zA-Z]{1}:\\[a-zA-Z0-9-\\._]*)',chunk)
	    	index = 0
	    	if res:
			for i in res:
			    #print ('\tReg: %s' % (i) )
			    if not i in self.paths:
			    	self.paths.append(i)
			    index += 1
	    	stop = time.time()
	#    	print ('Thread Execution Took %d' % (stop-start))

	def findRegs(self, chunk):
	    start = time.time()
	    res = re.findall(r'(HK[.]{2}:[\/a-zA-Z0-9\{\}\.]{1,1000})',chunk)
	    index = 0
	    if res:
		for i in res:
		    #print ('\tReg: %s' % (i) )
		    if not i in self.regs:
		    	self.regs.append(i)
		    index += 1
	    stop = time.time()
	#    print ('Thread Execution Took %d' % (stop-start))

	def findDLL(self, chunk):
	    start = time.time()
	    res = re.findall(r'([a-zA-Z0-9\-]+\.dll|[a-zA-Z0-9\-]+\.DLL)',chunk)
	    index = 0
	    if res:
		for i in res:
	#            print i
#		    print ('\tDLL: %s' % (i) )
		    if not i in self.dll:
			    self.dll.append(i)
		    index += 1
	    stop = time.time()
	#    print ('Thread Execution Took %d' % (stop-start))


	def findMails(self, chunk):
	    start = time.time()
	    res = re.findall(r'([a-zA-Z0-9\-\.\[\]\{\}_]{3,100}@[a-zA-Z0-9\-\.\[\]\{\}\-_]+\.[\{\}\[\]\-a-zA-Z0-9]{2,7})',chunk)
            index = 0
	    if res:
		for i in res:
	#            print i
#		    print ('\tDLL: %s' % (i) )
		    if not i in self.mails:
			    self.mails.append(i)
		    index += 1
	    stop = time.time()
	#    print ('Thread Execution Took %d' % (stop-start))

	def findIPs(self,chunk):
		start = time.time()
	    	res = re.findall(r'([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})',chunk)
	    	index = 0
	    	if res:
			for i in res:
			    #print ('\tReg: %s' % (i) )
			    if not i in self.ips:
			    	self.ips.append(i)
			    index += 1
	    	stop = time.time()
	#    	print ('Thread Execution Took %d' % (stop-start))

	def findSentences(self,chunk):
		start = time.time()
	    	res = re.findall(r'(\w{3,}\s[\w{3,}\s]*)',chunk)
	    	index = 0
	    	if res:
			for i in res:
			    #print ('\tReg: %s' % (i) )
			    t = i.split(' ')
			    if not i in self.sentences and len(t) > 2:
			    	self.sentences.append(i)
			    index += 1
	    	stop = time.time()
	#    	print ('Thread Execution Took %d' % (stop-start))

	def findBase64(self,chunk):
		start = time.time()
	    	res = re.findall(r'[a-zA-Z0-9\/\+]{30,}[=]*',chunk)
	    	index = 0
	    	if res:
			for i in res:
			    if not i in self.base64Strings:
			    	self.base64Strings.append(i)
			    index += 1
	    	stop = time.time()
	#    	print ('Thread Execution Took %d' % (stop-start))

	def findexe(self,chunk):
		start = time.time()
	    	res = re.findall(r'([a-zA-Z0-9\-]+\.exe|[a-zA-Z0-9\-]+\.EXE)',chunk)
	    	index = 0
	    	if res:
			for i in res:
			    if not i in self.exes:
			    	self.exes.append(i)
			    index += 1
	    	stop = time.time()
	#    	print ('Thread Execution Took %d' % (stop-start))


	def heuristicExe(self, chunkNumber, chunkSize):
		index = 0
		print("[*] Iteration [%d] ===>> Looking for executables ... " %(chunkNumber))
		for current in range(chunkNumber*chunkSize,len(self.data)):
			if index < chunkSize:
				self.findexe(self.data[current])
			index+=1
		#print(parserObject.getRegs())


	def heuristicBase64(self, chunkNumber, chunkSize):
		index = 0
		print("[*] Iteration [%d] ===>> Looking for Base64 Strings ... " %(chunkNumber))
		for current in range(chunkNumber*chunkSize,len(self.data)):
			if index < chunkSize:
				self.findBase64(self.data[current])
			index+=1
		#print(parserObject.getRegs())


	def heuristicRegs(self, chunkNumber, chunkSize):
		index = 0
		print("[*] Iteration [%d] ===>> Looking for Registry Keys ... " %(chunkNumber))
		for current in range(chunkNumber*chunkSize,len(self.data)):
			if index < chunkSize:
				self.findRegs(self.data[current])
			index+=1
		#print(parserObject.getRegs())

	def heuristicDLL(self, chunkNumber, chunkSize):
		index = 0
		print("[*] Iteration [%d] ===>> Looking for DLLs ... " %(chunkNumber))
		for current in range(chunkNumber*chunkSize,len(self.data)):
			if index < chunkSize:
				self.findDLL(self.data[current])
			index+=1
		#print(parserObject.getDLL())


	def heuristicSysPaths(self, chunkNumber, chunkSize):
		index = 0
		print("[*] Iteration [%d] ===>> Looking for System Paths ... " %(chunkNumber))
		for current in range(chunkNumber*chunkSize,len(self.data)):
			if index < chunkSize:
				self.findSystemPaths(self.data[current])
			index+=1
		#print(parserObject.getSysPaths())
	
	def heuristicURLs(self, chunkNumber, chunkSize):
		index = 0
		print("[*] Iteration [%d] ===>> Looking for URLs ... " %(chunkNumber))
		for current in range(chunkNumber*chunkSize,len(self.data)):
			if index < chunkSize:
				self.findURLs(self.data[current])
			index+=1
		#print(parserObject.getURLs())

	def heuristicMails(self, chunkNumber, chunkSize):
		index = 0
		print("[*] Iteration [%d] ===>> Looking for Mails ... " %(chunkNumber))
		for current in range(chunkNumber*chunkSize,len(self.data)):
			if index < chunkSize:
				self.findMails(self.data[current])
			index+=1
		#print(parserObject.getMails())

	def heuristicIPs(self, chunkNumber, chunkSize):
		index = 0
		print("[*] Iteration [%d] ===>> Looking for IP Addresses ... " %(chunkNumber))
		for current in range(chunkNumber*chunkSize,len(self.data)):
			if index < chunkSize:
				self.findIPs(self.data[current])
			index+=1
		#print(parserObject.getIPs())

	def heuristicSentences(self, chunkNumber, chunkSize):
		index = 0
		print("[*] Iteration [%d] ===>> Looking for Sentences ... " %(chunkNumber))
		for current in range(chunkNumber*chunkSize,len(self.data)):
			if index < chunkSize:
				self.findSentences(self.data[current])
			index+=1
		#print(parserObject.getSentences())






# this method returns the whole data extracted from file
	def getData(self):
		return self.data
	def getDomains(self):
		return self.knownDomains
	def getDLL(self):
		return self.dll
	def getExes(self):
		return self.exes
	def getRegs(self):
		return self.regs
	def getSysPaths(self):
		return self.paths
	def getURLs(self):
		return self.urls
	def getMails(self):
		return self.mails
	def getIPs(self):
		return self.ips
	def getSentences(self):
		return self.sentences
	def getBase64Strings(self):
		return self.base64Strings


class DBS:
	def __init__(self):
		# check if dbs.txt exists
		print("[*] Database Object initialized")
	def getDatabaseEntries(self):	
		filename = []
		filesize = []
		filehash = []
		filetype = []
		print("[*] Checking database entries")
		try:
			with open('dbs.txt','r') as f:
				lines = f.readlines()
				#print str(len(lines)) + " lines"
				for line in lines:
					values = line.split(':')
					#print str(len(values)) + " elements"
					for i in range(len(values)):
						if values[i].endswith('\n'):
							values[i] = values[i][:-1]
					filename.append(values[0])
					filehash.append(values[1])
					filesize.append(values[2])
					filetype.append(values[3])

			dbs = {filename[0]:[filehash[0],filesize[0],filetype[0]]}
			for i in range(1,len(filename)):
				dbs[filename[i]] = [filehash[i],filesize[i],filetype[i]]
			return dbs
		except:
			f = open('dbs.txt','w')
			f.close()
			dbs = {}
			return dbs	
	def setNewEntry(self,fileName,hashValue,fileSize,fileSignature):
		# write values to dbs.txt
		with open('dbs.txt', 'r+') as f:
			f.seek(len(f.read()))
			f.write(fileName + ":" + hashValue + ":" + str(fileSize) + ":" + fileSignature)


class FileClass:
	path = ""
	name = ""
# This is the Class's Constructor
	def __init__(self):
		print("[*] New File Object")

	def calcFeatures(self,name):
		self.path = name
		self.hashValue = self.calcHash(name)
		self.size = self.calcFileSize(name)
		self.signature = self.calcSignature(name)
		if "/" in name:
			parts = name.split('/')
			filename = parts[len(parts)-1]
		else:
			filename = name
		self.name = filename
#		print self.name
#		print self.hashValue
#		print self.size
#		print self.signature
# see how much space is needed for the file in cause

	def calcFileSize(self, fd):
		f = open(fd,'rb')
		f.seek(0,2)
		return f.tell()

# check to see if the file is what it says it is

	def calcSignature(self, filename):
		temp = "\"" + filename
		filename = temp + "\""
	#	print filename
		info = subprocess.check_output("file " + filename, shell=True)
		intel = info.split(':')
		return intel[1]

	def calcHash(self,filename):
		h = hashlib.md5()
	#	print filename
	#	sys.exit(0)
		with open(filename, 'rb') as f:
			buf = f.read()
			h.update(buf)
# where to save the results
		return h.hexdigest()
# set up the file name/path
	def setName(self, fname):
		self.name = fname

# returns the name of the file
	def getFileName(self):
		return self.name

# returns the hash of the file
	def getFileHash(self):
		return self.hashValue

# returns the size of the file
	def getFileSize(self):
		return self.size

# returns the signature of the file
	def getFileSignature(self):
		return self.signature
# returns the file's path
	def getFilePath(self):
		return self.path

####################################################################
# Actual code
####################################################################

print("\n")
print("                   |\\")
print("                   | \\")
print("                   ||\\\\")
print("                   || \\\\")
print("                   ||  \\\\")
print(" __________________||   \\\\	   ______________________")
print(" ___________________|    \\\\      | _____________________")
print("                          \\\\     ||")
print("                           \\\\    ||")
print("                            \\\\   ||")
print("                             \\\\  ||")
print("                              \\\\ ||")
print("                               \\\\||")
print("                                \\ |")
print("                                 \\|")
print("\nManual 'how to, and what is this' is in progress")
print("Current Version: 1.1\n")
print("Current Developer: Ciprian Bejean\n")
print("For help just type 'help', without quotes")
print("By default the platform is set to Linux")
print(5*"\n")

def envs(filename):
	if filename == "":
		return 1
	else:
		return 0

def menu(file_1,platform,chunk):
	filename = ""
	while(1):
		inData = raw_input("~COMM$> ")
		if "platform" in inData:
			d = inData.split('=')
			env = d[len(d)-1]
			if 'linux' in env:
				platform.setPlatformValue(0) # means linux
			elif 'windows' in env or 'win' in env:
				platform.setPlatformValue(1) # means windows
		if "chunkSize" in inData:
			d = inData.split('=')
			env = d[len(d)-1]
			platform.setChunkSize(int(env))
		if "file" in inData:
			d = inData.split('=')
			env = d[len(d)-1]
			if env.startswith("\'"):
				filename = env[1:-2]
				print "Drag&Drop Style :)"
			else:
				filename = env
			print filename
			file_1.setName(filename)
		if "exit" in inData:
			sys.exit(0)
		if "help" in inData:
			print("SYNTAX\t\t\tDESCRIPTION\n")
			print("platform=linux \t\tSets the platform to be detected as Linux")
			print("platform=windows \tSets the platform to be detected as Windows")
			print("chunkSize=100 \t\tTells HeartBeat in how many parts should the file be parsed (you can set the number up to 30000)")
			print("file=myFile.exe \tTells HearBeat which file will be parsed (you can type the filename or just Drag&Drop it)")
			print("run\t\t\tSimply Start the Magic")

		if "show" in inData:
			print("Platform \t%s\nChunkSize \t%s\nFile \t\t%s\n" %(platform.getPlatformValue(), platform.getChunkSize(), file_1.getFileName()))
		if "run" in inData:
			if envs(filename) == 0:
				print "moving on"
				break

def main():
	# setting up the platform as being Unix
	platform = Platform(0)
	platform.setPlatformValue(0)
	platform.setChunkSize(10000)
	filename = ""
	file_1 = FileClass()
	menu(file_1,platform,platform.getChunkSize())
	filename = file_1.getFileName()
	file_1.calcFeatures(file_1.getFileName())
	startTime = time.time()
	#for i in range(0,len(sys.argv)):
	#	if "--platform" in sys.argv[i]:
	#		platform = Platform(int(sys.argv[i+1]))
	#	if "--chunkSize" in sys.argv[i]:
	#		platform.setChunkSize(int(sys.argv[i+1]))
	#	if "--file" in sys.argv[i]:
	#		filename = sys.argv[i+1]


	#++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++




	

	# Objects instantiation
	databaseObject = DBS()

	# setting up the dbs.txt file to read the entries already scanned by this script
	memoryData = databaseObject.getDatabaseEntries()
	#if len(memoryData) > 0:
	#	print(memoryData)
	#else:
	#	print("No entries found")
	lookFor = file_1.getFileHash()
	compareWithName = file_1.getFileName()

	print "Associating ", lookFor, 'with', compareWithName
	try:
		if not lookFor in memoryData[compareWithName]:
			print "[*] No related files found!"
			print "[*] Adding this to the Memory Lane"
			databaseObject.setNewEntry(file_1.getFileName(), file_1.getFileHash(), file_1.getFileSize(), file_1.getFileSignature())
		else:
			print "[*] FOUND IT", compareWithName, memoryData[compareWithName]
	except:
		print "[*] No related files found!"
		print "[*] Adding this to the Memory Lane"
		databaseObject.setNewEntry(file_1.getFileName(), file_1.getFileHash(), file_1.getFileSize(), file_1.getFileSignature())

	#++++++++++++++++++++++++++++++++++++++++++++++++++++++++





	parserObject = Parser(file_1.getFilePath(), platform.getPlatformValue())

	wholeData = parserObject.getData()

	chunkSize = platform.getChunkSize()
	chunkNumber = -(-len(wholeData)//chunkSize)
	print ("There will be %d chunks of Data ( %d chunks * %d rounds )" % (chunkNumber,chunkNumber,chunkSize))


	# keep the threads used for searching
	threads = []



	# go through every chunk by incrementing 'i'
	for i in range(0,chunkNumber):
		t = threading.Thread(target=parserObject.heuristicDLL, args=(i, chunkSize))
		threads.append(t)
		t = threading.Thread(target=parserObject.heuristicRegs, args=(i, chunkSize))
		threads.append(t)
		t = threading.Thread(target=parserObject.heuristicSysPaths, args=(i, chunkSize))
		threads.append(t)
		t = threading.Thread(target=parserObject.heuristicURLs, args=(i, chunkSize))
		threads.append(t)
		t = threading.Thread(target=parserObject.heuristicMails, args=(i, chunkSize))
		threads.append(t)
		t = threading.Thread(target=parserObject.heuristicIPs, args=(i, chunkSize))
		threads.append(t)
		t = threading.Thread(target=parserObject.heuristicSentences, args=(i, chunkSize))
		threads.append(t)
		t = threading.Thread(target=parserObject.heuristicBase64, args=(i, chunkSize))
		threads.append(t)
		t = threading.Thread(target=parserObject.heuristicExe, args=(i, chunkSize))
		threads.append(t)
		# TODO: here i will put the thread syntax for other scanning methods



	# starting the threads created above
	for thread in threads:
		thread.start()
		thread.join()

	# output the results
	# TODO: Here i will put the other methods's output
	dlls = parserObject.getDLL()
	exes = parserObject.getExes()
	regs = parserObject.getRegs()
	paths = parserObject.getSysPaths()
	urls = parserObject.getURLs()
	mails = parserObject.getMails()
	ips = parserObject.getIPs()
	domains = parserObject.getDomains()
	sentences = parserObject.getSentences()
	base64Strings = parserObject.getBase64Strings()

	print("[*] Displaying Verbose Information")
	index = 0
	print("[%d] Imported DLL files" %(len(dlls)))
	for dll in dlls:
		print("\t[%d] %s" %(index, dll))
		index +=1
	index = 0
	print("[%d] Executable Files" %(len(exes)))
	for exe in exes:
		print("\t[%d] %s" %(index, exe))
		index +=1
	index = 0
	print("[%d] Registry Paths Found" %(len(regs)))
	for reg in regs:
		print("\t[%d] %s" %(index, reg))
		index +=1
	index = 0
	print("[%d] System Paths Found" %(len(paths)))
	for path in paths:
		print("\t[%d] %s" %(index, path))
		index +=1
	index = 0
	print("[%d] URLs Found" %(len(urls)))
	for url in urls:
		ok = 0
		for d in domains:
			if url.endswith(d) or url.endswith(d[1:]):
	#			pass
				ok = 1
				break
		if ok == 1:
			print("\t[%d] %s" %(index, url))
		else:
			pass
#			print("\t\t[%d] %s FALSE POSITIVE" %(index, url))			
		index +=1

	index = 0
	print("[%d] Mails Found" %(len(mails)))
	for mail in mails:
		print("\t[%d] %s" %(index, mail))
		index +=1
	index = 0
	print("[%d] IP Addresses Found" %(len(ips)))
	for ip in ips:
		print("\t[%d] %s" %(index, ip))
		index +=1
	index = 0
	print("[%d] Sentences Found" %(len(sentences)))
	for sentence in sentences:
		print("\t[%d] %s" %(index, sentence))
		index +=1
	index = 0
	print("[%d] Base64 Strings Found" %(len(base64Strings)))
	for base64String in base64Strings:
#		try:
#			print("\t[%d] %s" %(index, base64String.decode('base64')))
#		except:
#			print("\t[%d] %s" %(index, base64String))
		index +=1

	stopTime = time.time()
	print(60*'-')
	print("Execution Took: %f seconds" %(stopTime-startTime))
	#sys.exit(0)

if __name__ == "__main__":main()



