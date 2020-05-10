#!/usr/bin/env python3
#
#    pdfaudit is a pdf auditing tool for security and privacy
#    Copyright (C) 2020  Joseph Heller, http://github.com/catch22eu/
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <https://www.gnu.org/licenses/>.
#

import os		# only used for checking file size, and file existance
import sys		# for aborting, getting/setting recursion limit
import argparse # ...

apversion='''pdfaudit v0.1'''
apdescription='''pdfaudit is a pdf auditing tool for security and privacy'''
apepilog='''pdfaudit Copyright (C) 2020 Joseph Heller
This program comes with ABSOLUTELY NO WARRANTY; for details type use '-w'.
This is free software, and you are welcome to redistribute it under certain 
conditions; use `-c' for details.'''
apwarranty='''
  Disclaimer of Warranty.

  THERE IS NO WARRANTY FOR THE PROGRAM, TO THE EXTENT PERMITTED BY
APPLICABLE LAW.  EXCEPT WHEN OTHERWISE STATED IN WRITING THE COPYRIGHT
HOLDERS AND/OR OTHER PARTIES PROVIDE THE PROGRAM "AS IS" WITHOUT WARRANTY
OF ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING, BUT NOT LIMITED TO,
THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
PURPOSE.  THE ENTIRE RISK AS TO THE QUALITY AND PERFORMANCE OF THE PROGRAM
IS WITH YOU.  SHOULD THE PROGRAM PROVE DEFECTIVE, YOU ASSUME THE COST OF
ALL NECESSARY SERVICING, REPAIR OR CORRECTION.

  Limitation of Liability.

  IN NO EVENT UNLESS REQUIRED BY APPLICABLE LAW OR AGREED TO IN WRITING
WILL ANY COPYRIGHT HOLDER, OR ANY OTHER PARTY WHO MODIFIES AND/OR CONVEYS
THE PROGRAM AS PERMITTED ABOVE, BE LIABLE TO YOU FOR DAMAGES, INCLUDING ANY
GENERAL, SPECIAL, INCIDENTAL OR CONSEQUENTIAL DAMAGES ARISING OUT OF THE
USE OR INABILITY TO USE THE PROGRAM (INCLUDING BUT NOT LIMITED TO LOSS OF
DATA OR DATA BEING RENDERED INACCURATE OR LOSSES SUSTAINED BY YOU OR THIRD
PARTIES OR A FAILURE OF THE PROGRAM TO OPERATE WITH ANY OTHER PROGRAMS),
EVEN IF SUCH HOLDER OR OTHER PARTY HAS BEEN ADVISED OF THE POSSIBILITY OF
SUCH DAMAGES.'''
apcopyright='''
pdfaudit is a pdf auditing tool for security and privacy
Copyright (C) 2020  Joseph Heller, http://github.com/catch22eu/

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
'''

#"pdfaudit is a command-line tool analyze pdf files for security and privacy\n\n"


whitespacelist = [0, 9, 10, 12, 13, 32] # per pdf specification
delimiterlist = [40, 41, 60, 62, 91, 93, 123, 125, 47] # ()<>[]{}/
newlinelist = [13, 10] # CR, LF
riskeykyes = ['OpenAction', 'AA', 'JavaScript', 'JS', 'GoTo', 'Launch', 'URI', 'SubmitForm', 'GoToR', 'RichMedia', 'ObjStm']
followlinkslist = ['Length', 'Size', 'Prev']
counttable = {}
crossreflist = {}
scannedobjects = {}
verbosity = 1 # 0 minimal, 1 default, 2 detail, 3 debug
currentobject = ''
globaldictvaluesize = 0
prevxref = 0
riskydictionary = {
	('S','GoTo')      : 'D',
	('S','GoToR')     : 'F',
	('S','GoToE')     : 'F',
	('S','Launch')    : ('F','Win','Mac','Unix'),
	('S','URI')       : 'URI',
	('S','SumbitForm'): 'F',
	('S','JavaScript'): 'JS',
#	('OpenAction','') : '',
#	('AA','')         : '',
	('Type','ObjStm') : '' # TODO: TBD
	}

#todo: consider / check applicability of:
#with open(filename, 'rb') as file:
#    for byte in iter(lambda: file.read(1), b''):
#        # Do stuff with byte
#


def noteof(file):
	return file.tell() < os.path.getsize(infile)

def iswhitespace(char):
	return char in whitespacelist

def isdelimiter(char):
	return char in delimiterlist
	
def nextchar(file):
# read next char, leave seek position as-is
# TODO: check EOF (for all occurrances actually in the script)
	singlebyte = chr(file.read(1)[0])
	file.seek(-1,1)
	return singlebyte

def vprint(string,verbositylevel=1,delimiter='\n'):
	if verbositylevel <= verbosity:
		print(string, end=delimiter)

def getword(file):
# Return next word or next delimiter
# PDF treats any sequency of consequtive white-space characters as one character
# TODO: check overall corectness ans efficiency of the if / elif flow
	foundword= ""
	delimiter=False
	while not delimiter and noteof(file):
		singlebyte = file.read(1)
		vprint("{POS: "+str(file.tell())+", value: "+str(singlebyte[0])+", stringempty: +"+str(foundword==""), 3)
		delimiter = (singlebyte[0] in whitespacelist + delimiterlist)
		if foundword == "" and singlebyte[0] in whitespacelist:
			# ignore trailing whitespaces
			vprint("TD",3)
			delimiter = False
		elif singlebyte[0] == 37: 
			# ignore % comments
			readcomment(file)
		elif not delimiter:
			# add non-whitespace/delimiter
			vprint("ND",3)
			foundword += chr(singlebyte[0])
		elif singlebyte[0] in delimiterlist:
			if foundword == "":
				# send delimiter if it's the first character we encounter
				vprint("TDEL",3)
				foundword += chr(singlebyte[0])
			else:
				# read this character next time; so seek one position back
				vprint("LDEL",3)
				file.seek(-1,1)
	return foundword

def getnexttwowords(file):
	startpos = file.tell()
	foundword1 = getword(file) 
	foundword2 = getword(file)
	file.seek(startpos)
	return foundword1, foundword2

def checkdictionary(dictionary):
# builds a dictionary of keys found to be risky. New keys are added in the dictionary as new key/object pairs, or an object is appended to already existing key/object pair(s) 
	global currentobject
	global counttable
	for i in list(dictionary.keys()):
		keyvaluepair = (i,dictionary.get(i))
		if keyvaluepair in list(riskydictionary.keys()):
			objectandvalue = (dictionary.get(i),dictionary.get(riskydictionary.get((i,dictionary.get(i)))))
			print(objectandvalue)
#			if dictionary.get(i) not in counttable.keys():
#				counttable[key]=[objectandvalue]
#			elif currentobject not in counttable[key]:
#				counttable[key].append(objectandvalue)

def getdictionary(file,followlinks=False):
# sequence of key - object pairs, of which at least the key is a /name (without slash)
# it may be followed by a stream, which is encapsulated by the words "stream" and "endstream"
# TODO: handling of specific keys and return values (Length, Size): from global to variables to returns from this function (as this function may be called recursively)
	global globaldictvaluesize # TODO: from global variable to return'd value from this function
	global prevxref # TODO: from global variable to return'd value from this function
	vprint("[DICT]", 2, '')
	getkey = ""
	getobject = ""
	dictionary = {}
	while getkey != '>' and getobject != '>':
		getkey = readobject(file).get("SingleString")
		getobject = readobject(file,getkey=='Length').get("SingleString") # TODO: a bit of a hack, but we want to follow links here to get the length value if it's stored by a referenced object (per pdf spec)
		dictionary[getkey] = getobject # First step to get rid of globals, and return a dictionary
		vprint("[KEY,OBJECT]: "+getkey+", "+getobject+" ",2)
		if getkey == 'Length': # for streams
			length = int(getobject)
			vprint("[Length]: "+str(length),2)
		elif getkey == 'Size': # for trailer
			globaldictvaluesize = int(getobject) # TODO: from global variable to return'd value from this function
		elif getkey == 'Prev': # previous xref start. TODO: can also be used elsewhere
			if isnum(getobject): # can something else than a number
				prevxref = int(getobject) # TODO: from global variable to return'd value from this function
			vprint("[Prevxref]: "+str(prevxref),2)
	checkdictionary(dictionary)
	nword, nnword = getnexttwowords(file)
	if nword == 'stream':
		getword(file) # /Length is the number of bytes from the beginning of the line following the keyword stream
		#TODO: followsymlinks handling in case stream can have symlinks
		vprint("[STREAM] "+str(length)+" bytes",2)
		file.seek(length,1)
		getword(file) # the word endstream
		#TODO: followsymlinks handling in case stream can have symlinks
	vprint("[DICT: end]",2)
	return dictionary # TODO: check if we can return more here
		
def translatestring(string):
# to be translated: \ddd, \n, \r, \t, \f, \b, \\, 
# to be ignored   : \ (otherwise)
	vprint("STRTR",2)

def getliteralstring(file):
# unbalanced parenthese ")" terminates the string
# to be escaped: \(, \) 
	foundstring= ""
	psinglechar = "("
	singlechar = ""
	parenthesecount = 1
	while parenthesecount > 0:
		psinglechar = singlechar
		singlechar = chr(file.read(1)[0])
		if psinglechar != 92:
			# count un-escaped parenthese if present, and add character to string
			if singlechar =='(':
				parenthesecount += 1
			elif singlechar ==')':
				parenthesecount -= 1
			if parenthesecount >0:
				foundstring += singlechar
		else:
			# escape the characters indicated below, replace last backslash
			if singlechar =='(':
				foundstring = foundstring [:-1] + '('
			elif singlechar ==')':
				foundstring = foundstring [:-1] + ')'
	vprint("[STR]"+foundstring,2)
	return foundstring

def gethexstring(file):
# Sequence of [0-9][A-F]or[a-f] pairs enclosed by <>, with whitespace characters ignored
# TODO uneven amount of pairs (append 0)
# TODO translate to string? 
	hexstring=""
	singlechar=""
	while singlechar != '>':
		singlechar = chr(file.read(1)[0])
		if singlechar != '>':
			hexstring += singlechar
	vprint("[HEX]"+hexstring,2)
	return hexstring

def getarray(file):
# Sequence of objects, []
	vprint("[ARRAY]",2)
	foundarray=""
	while ']' not in foundarray:
#		foundarray += readobject(file,followlinks=False)
		foundarray += getword(file)
		foundarray += ' ' # TODO: can be more elegantly: combine with previous, [:-2] with next
	foundarray = foundarray[:-2]
#	if isnum(foundarray):
#		print('jep, single number found here!')
#		return num(foundarray)
#	else:
	return foundarray

def num(s):
#https://stackoverflow.com/questions/379906/how-do-i-parse-a-string-to-a-float-or-int
	try:
		return int(s)
	except ValueError:
		return float(s)

def isnum(checkword):
#https://stackoverflow.com/questions/354038/how-do-i-check-if-a-string-is-a-number-float
	return checkword.replace('.','',1).replace('-','',1).isdigit()

def getname(file):
	foundword=getword(file)
	vprint("[W]:"+foundword,2)
	return foundword

def getobjectpos(key):
	obj=key[0] # TODO: not used?
	gen=key[1] # TODO: not used?
	pos=crossreflist.get(key)
	vprint("[OBJPOS]"+ hex(pos),2)
	return pos

def jumptoobject(file,objectnum,generation):
# returns foundvalue either by reading the object or the stored value stored from a previous scan
	global scannedobjects
	key = (num(objectnum),num(generation))
	if key in scannedobjects.keys():
		return scannedobjects[key]
	else:
		startpos = file.tell()
		key=num(objectnum),num(generation)
		vprint('[JUMPTO:'+objectnum+','+generation+']',2)
		file.seek(getobjectpos(key))
		foundvalue = readindirectobject(file).get('SingleString')
		file.seek(startpos)
		scannedobjects[key]=foundvalue
		return foundvalue

def readcomment(file):
	singlebyte = ''
	comment = ''
	notnewline = True
	while notnewline and noteof(file):
		singlebyte = file.read(1)
		comment += chr(singlebyte[0])
		notnewline = singlebyte[0] not in newlinelist
	vprint("[COMMENT:]"+comment,2)
	return comment

def readobject(file,followlinks=False):
#TODO: difference between < something, << something, <something
#TODO: stream which contains the word "endstream"
#TODO: this function is called from more than one location, but not every objct type is expected in each case. Implement warning for those unexpected cases.
#TODO: check correctness of handling: abc<def> vs abd<<def>> 	pword=""
	dictionary = {}
	foundword = getword(file)
	vprint(foundword,3)
	if foundword == 'true' or foundword == 'false': # boolean
		pass
	elif foundword == 'endobj':
		pass
	elif foundword == '<' and nextchar(file) == '<': # "<<"
		singlebyte = file.read(1)	# need to read next byte, as nextchar didn't progress
		getdictionary(file,followlinks)
		foundword = "<>"
	elif foundword == '<': # "<" note: depends on previous elif
		foundword = gethexstring(file)
	elif foundword == '(':
		foundword = getliteralstring(file)
	elif foundword == '>':
		pass
	elif foundword == '[':
		foundword = getarray(file)
	elif foundword == ']':
		pass
	elif isnum(foundword):
		nword, nnword = getnexttwowords(file)
		if isnum(nword) and nnword == 'R':
			getword(file)
			getword(file)
			if followlinks:
				foundword = jumptoobject(file,foundword,nword)
			else:
				foundword = foundword+' '+nword+' '+nnword
		else:
			vprint("[NUM]:"+foundword,2)
	elif ord(foundword[0]) == 47: # "/"
		foundword = getname(file)
	elif foundword == 'null':
		pass
	else:
		vprint("[ERROR: unexpected end of object] found: "+foundword,0)
		sys.exit(0)
		foundword = ""
	dictionary["SingleString"]=foundword
	return dictionary

def readindirectobject(file):
	ppword=""
	pword=""
	foundword=""
	while noteof(file):
		ppword = pword
		pword = foundword
		foundword = getword(file)
		vprint(foundword,3)
		if foundword == 'obj':
			vprint("[OBJ:"+ppword+","+pword+"]",2 , '')
			return readobject(file)
		elif foundword == 'endobj':
			vprint("[ENDOBJ]",2)
			return foundword
		elif foundword == 'endstream':
			vprint("[ENDSTREAM]",2)
			return foundword

def showthreats():
#	print(counttable)
	for i in list(counttable.keys()):	
		for j in list(counttable.get(i)):
			objectstring = str(j[0][0])+" "+str(j[0][1])
			valuestring = j[1]
			print("/"+i+" in object "+objectstring+" (at: "+hex(crossreflist.get(j[0]))+"): "+valuestring)

def getxref(file):
	vprint("[XREF]",2)
	startobj, countobj = getnexttwowords(file)
	while isnum(startobj) and isnum(countobj):
		startobj=num(getword(file))
		countobj=num(getword(file))
		vprint("number of objects in xref: "+str(countobj),2)
		vprint("[XREF]:"+str(startobj)+" "+str(countobj),2)
		for i in range(startobj,startobj+countobj):
			objectoffset = num(getword(file))
			objectgen = num(getword(file))
			objectinuse = getword(file)
			if objectinuse == 'n':
				crossreflist[i,objectgen]=objectoffset
				# this either inserts a new key, or updates an existing one.
			else: # 'f'
				if (i,objectgen) in list(crossreflist.keys()): #should normally be the case
					del crossreflist[i,objectgen-1] # per pdf spec: generations are incremented by 1
			vprint(str(i)+str(objectoffset)+str(objectgen)+str(objectinuse),3)
		startobj, countobj = getnexttwowords(file)
	vprint(crossreflist,2)
	numberofobjects = len(crossreflist)
	vprint("Number of objects: "+ str(numberofobjects)) 
	vprint("[XREF: End]",2)

def readtrailer(file):
	vprint("[TRAILER]",2)
	currentprevxref = prevxref
	readobject(file, False) # read trailer, expected as dictionary
	vprint("[TRAILER: size]: "+str(globaldictvaluesize),2)
	if currentprevxref != prevxref:
		vprint("[TRAILER: previous xref pos]: "+str(prevxref),2)
#		getxrefandtrailer(file,prevxref)
		return prevxref
	else:
		return 0
	vprint("[TRAILER: End]",2)

def findstartback(file,startstring):
	filepos=-3
	foundword = ""
	while foundword != startstring:
		filepos -= 1
		file.seek(filepos,2)
		foundword = getword(file)

def getstartxref(file):
	findstartback(file,'startxref')
	while noteof(file):
		foundword = getword(file)
		if isnum(foundword):
			start=num(foundword)
	vprint("[STARTXREF]: "+str(start),2)
	file.seek(0)
	return start

def getpdfversion(file):
# TODO: not parsed that well yet.
	file.seek(5)
	pdfversion = file.read(3)
#	pdfversion = readcomment(file)# [5:] # assumes 3 characters starting from 6th
	vprint("PDF version: "+str(pdfversion),1)

def iteratexref(file):
	j=0
	global currentobject
	for i in list(crossreflist.keys()):
		vprint("[XREFITER]:"+str(i),2)
		currentobject=i
		jumptoobject(file,str(i[0]),str(i[1])) # TODO: juggling with num to string to num
		print("progress: "+str(int(100*j/len(crossreflist)))+"%",end='\r')
		j += 1

def readpdf(file,startxrefpos):
# Main principle is to first read the trailer and recurse to the previous version of the pdf, then read the xref table, then read all objects from the pdf version we're handling
	file.seek(startxrefpos)
	foundword=''
	while foundword != 'trailer' and noteof(file): # doesn't check if next trailer is read instead
		foundword = getword(file)
	previousstartxrefpos = readtrailer(file)
	if previousstartxrefpos != 0:
		vprint("Reading previous version of pdf",1)
		readpdf(file,previousstartxrefpos)
	file.seek(startxrefpos) # need to get back to the beginning of the xref, since we read trailer
	if getword(file)=='xref': # TODO: also move if / else to getxref, like gettrailer
		getxref(file)
		vprint(list(crossreflist.keys())[0],3)
	else:
		vprint("[Error: xref not found]",0)
	iteratexref(file)
	vprint("Finished reading pdf version",1)

def readarguments():
	parser = argparse.ArgumentParser(description=apdescription,epilog=apepilog,formatter_class=argparse.RawDescriptionHelpFormatter)
	parser.add_argument('filename', type=str, help="pdf file to be audited")
	parser.add_argument('-d', type=int, default=1, help="detail level D of output: 0 minimal, 1 default, 2 detail, 3 debug")
	parser.add_argument('-v', action='version', help='show version', version=apversion)
	parser.add_argument('-w', action='version', help='show warranty', version=apwarranty)
	parser.add_argument('-c', action='version', help='show copyright', version=apcopyright)
	args = parser.parse_args()
	if os.path.isfile(args.filename):
		return args.filename, args.v
	else:
		print("File not found")
		sys.exit()

infile, verbosity = readarguments()
vprint("Scanning: "+infile,0)
with open(infile, 'rb') as file:
	getpdfversion(file)
	readpdf(file,getstartxref(file))
	showthreats()

