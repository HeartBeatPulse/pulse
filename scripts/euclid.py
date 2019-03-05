import os,sys,pprint
from math import sqrt

#p = [1,3]
#q = [2,5]
#euclidean_distance = sqrt( (p[0]-q[0])**2+(p[1]-q[1])**2 )
#print(euclidean_distance)

# k = sqrt power
# D = (P,Q)
# for n items:
# formula = SUM((Pn-Qn)**k)
# for k=2: euclidian distance
# for k=1: manhattan distance
# for k=0: Hamming ... logical AND 


def formula(k,P,Q):
	power = 1.0
#	print "Distance calculation method:",
	if k == 2:
#		print "Euclidian"
		power = power/k
	elif k == 1:
		print "Manhattan"
		power = power/k
	elif k == 0:
		print "Hamming"
		power = 0.0
#	print "exponent = ",power
	sum = 0
	for n in xrange(0,len(P)):
		dif = 0
#		print 'P',P
#		print 'Q',Q
#		print 'index',n
		if P[n] > Q[n]:
			dif = P[n]-Q[n]
		elif P[n] <= Q[n]:
			dif = Q[n]-P[n]
		sum += dif**k
#	print "Distance is SQRT(%d)" %sum
	return sum**power
#print 2**(float(1)/float(2))

# given a cluster, recalculate its centroid values :)
def calculate_centroid(cluster):
	new_centroid = [sum(x)/float(len(cluster)) for x in zip(*cluster)]
	return new_centroid

def clusterize(data_points,centroids):
	clusters = []
	for c in centroids:
		clusters.append([])
	for point in data_points:
		distances = []
		for c in centroids:
			distance = formula(2,point,c)
			distances.append(distance)
		min = 100.0
		cluster_no = 0
		for d in xrange(len(distances)):
			if distances[d] < min:
				min = distances[d]
				cluster_no = d
		if not point in clusters[cluster_no]:
			clusters[cluster_no].append(point)
	return clusters

def recalculate_centroids(clusters):
	index = 0
	new_centroids = []
	for cluster in clusters:
		new_centroids.append(calculate_centroid(cluster))
	return new_centroids


# assuming those values are our features extracted from files to be clustered
def getDataPoints():
	data_points = []
	data_points.append([2,0,1,4,9,2,1,1,1,4])
	data_points.append([12,3,3,12,4,4,4,1,2,3])
	data_points.append([3,0,5,9,12,0,2,3,4,7])
	data_points.append([2,5,14,6,2,2,3,4,1,5])
	data_points.append([14,6,2,8,22,1,5,12,4,14])
	data_points.append([2,8,1,12,19,18,16,3,5,7])
	data_points.append([1,12,0,16,14,6,2,8,18,20])
	data_points.append([0,16,4,29,12,3,17,8,19,20])
	data_points.append([4,29,12,33,14,6,2,8,22,30])
	data_points.append([12,33,0,1,0,0,0,1,7,44])
	data_points.append([21,10,21,14,19,23,11,10,12,14])
	data_points.append([12,13,3,12,24,4,34,13,12,33])
	data_points.append([13,0,5,19,12,10,12,3,24,37])
	data_points.append([2,15,14,6,12,22,3,14,1,5])
	data_points.append([14,16,2,18,22,31,5,12,34,14])
	data_points.append([2,28,1,12,19,18,16,33,52,7])
	data_points.append([11,12,30,16,14,26,22,28,18,20])
	data_points.append([40,16,14,29,12,3,17,38,19,21])
	data_points.append([42,29,12,33,14,46,42,38,22,30])
	data_points.append([12,33,20,1,10,10,20,31,17,44])
	return data_points


def clusterEmAll():
	data_points = getDataPoints()

	# we don't have actual file names, so we'll use generic names :|
	file_names = []
	for i in xrange(20):
		file_names.append('file_'+str(i))
	#pprint.pprint(data_points)

	n = 5
	centroids = []
	clusters = []
	for i in xrange(n):
		centroids.append(data_points[i])
		clusters.append([data_points[i]])
	constant = clusters

	old_clusters = sorted(clusters)
	isConstant = 0
	for k in xrange(1000):
		print "[%d] iteration" %k
		print "centroids:"
		for c in centroids:
			print "\t-->",c
		clusters = clusterize(data_points,centroids)
		centroids = recalculate_centroids(clusters)
		clusters = sorted(clusters)
		index = 0
		for old in old_clusters:
			print 'cluster[%d]:'%index
			for o in old:
				print '\t-->',o
			index += 1
		print 30*'-'
		# determine if the clusters were constant for the last 4 iterations
		if old_clusters == clusters:
			isConstant += 1
		# if the clusters are constant then print them out :D 
		if isConstant == 3:
			print "old_clusters:"
			index = 0
			for old in old_clusters:
				print 'cluster[%d]'%index
				for o in old:
#					print "\t-->",o
					print "\t-->",file_names[data_points.index(o)]
				index += 1
			print 30*'_'
			print "clusters:"
			index = 0
			for cluster in clusters:
				print 'cluster[%d]'%index
				for c in cluster:
#					print "\t-->",c
					print "\t-->",file_names[data_points.index(c)]
				index += 1
			print 30*'_'
			sys.exit(0)
		else:
			old_clusters = clusters
		print '+',60*'-','+'
	print 30*'-'



clusterEmAll()
