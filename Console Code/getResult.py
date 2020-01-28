"""
Technion - Israel Institute of Technology
Heavy-Hitter Detection on SmatNIC Project
Team: Yevhenii Liubchyk, Maria Shestakova
Instructors: Itzik Ashkenazi, Prof. Ori Rotenstreich
"""

import sys
import collections

############################## file from memory ##############################
# Download file HashPipeFlows which is obtained by the memory
f = open('HashPipeFlows', 'r')
listOfString = [line[:-1] for line in f if line != "*\n" and line != "\n"]
f.close()

listAux = [i.split(":  ")[1] for i in listOfString]
listOfString = [i.split("0x") for i in listAux]
listOfMem = []
for i in range(len(listOfString)):
	for j in range(len(listOfString[i])):
		if listOfString[i][j] != '':
			listOfMem.append(listOfString[i][j].rstrip())

# Delete empty parts of the memory
listOfMem = [mem for mem in listOfMem if mem != '00000000']

# Get 5-tuples and counters of all flows saved in file HashPipeFlows
HashPipeFlows = collections.Counter()
for i in range(0, len(listOfMem), 5):
	id = listOfMem[i+3][0:2] # protocol
	id += listOfMem[i] # srcAddr
	id += listOfMem[i+1] # dstAddr
	id += listOfMem[i+2] # srcPort + dstPort
	count = int(listOfMem[i+4],16)
	HashPipeFlows[id] += count
	
############################## file from tcpdump #############################
# Download file RealHeavyHitterFlows which is the result of a command tcpdump
f = open('RealHeavyHitterFlows', 'r')
listOfData = [line for line in f if line.find("0x0000:") != -1 or line.find("0x0010:") != -1 ]
f.close()

# Get 5-tuples of all flows saved in file RealHeavyHitterFlows
RealHeavyHitterFlows = collections.Counter()
for i in range(0, len(listOfData), 2):
	id = listOfData[i][32:34] # protocol
	id += listOfData[i][40:44] # srcAddr
	id += listOfData[i][45:49] # srcAddr
	id += listOfData[i+1][10:14] # dstAddr
	id += listOfData[i+1][15:19] # dstAddr
	id += listOfData[i+1][20:24] # srcPort
	id += listOfData[i+1][25:29] # dstPort
	RealHeavyHitterFlows[id] += 1

# Get K(numOfHH) - number of heavy-hitter flows which we want to check
# Update the K to optimal value
numOfHH = int(sys.argv[1])
if (numOfHH > len(HashPipeFlows)):
	numOfHH = len(HashPipeFlows)
if (numOfHH > len(RealHeavyHitterFlows)):
	numOfHH = len(RealHeavyHitterFlows)

####################### Accuracy of HashPipe Algorithm #######################
countOfHH = 0
for hh in HashPipeFlows.most_common(numOfHH):
	iterator = 0
	for item in RealHeavyHitterFlows.most_common(numOfHH):
		if hh[0] in item:
			countOfHH += 1
			break;
		iterator += 1

print("Accuracy: " + str(float(countOfHH*100)/numOfHH) + "%")

######### Average place of packets HashPipe Algorithm in sorted list #########
############ of Real "Heavy-Hitter" flows start from the heaviest ############
averageCount = 0
for hh in HashPipeFlows.most_common(numOfHH):
	iterator = 0
	for item in RealHeavyHitterFlows.most_common(len(RealHeavyHitterFlows)):
		if hh[0] in item:
			averageCount += iterator
			break;
		iterator += 1

print("Average: " + str(float(averageCount)/numOfHH))
print("Optimal average: " + str(float(numOfHH + 1)/2))