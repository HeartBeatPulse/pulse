import os, sys, re

domains = []

f = open('testfile','r')
data = f.readlines()
for d in data:
	left = d.split(' ')
#	print left[0]
	res = re.search(r'(^\.[A-Z\.]+)',left[0])
	if res:
		print res.group().lower()
f.close()
