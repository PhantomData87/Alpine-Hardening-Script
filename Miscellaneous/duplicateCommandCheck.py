# By: Alonzo Ortiz-Sanchez

filePath = "../alpineHardenRedo.sh"
dupDic = {}
maxSize = 15
minSize = 5

def printDup(currentLineNum, currentText):
	print("Duplicate lines detect at:"+str(dupDic[currentText])+" and "+currentLineNum+" for;"+currentText)

# Open file, parse strings between the size of minSize and maxSize, then compare with existing strings via dupDic
# If new string, save its current position in dupDic
# Otherwise, if existing string is found in dupDic, then print previous known location
# Finally, filter out comments ("#")
def fileParser():
	with open(filePath, "r") as file:
		file.seek(0)
		line = file.readline()
		counter = 1
		while line:
			splitText = line.lstrip().split(None, maxSize)
			if len(splitText) == 0:
				line = file.readline()
				counter += 1
				continue
			elif splitText[0] == "#":
				line = file.readline()
				counter += 1
				continue
			elif len(splitText) >= maxSize:
				splitText[-1] = ""
			unitedText = ' '.join(splitText)
			if unitedText not in dupDic.keys() and len(splitText) >= minSize:
				dupDic[unitedText] = counter
			elif len(splitText) >= minSize:
				printDup(str(counter), unitedText)
			line = file.readline()
			counter += 1

fileParser()