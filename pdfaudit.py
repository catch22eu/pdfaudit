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

import os							# only used for checking file size, and file existance
import sys							# for aborting, getting/setting recursion limit
import argparse 					# ...
import zlib							# at least for flatedecode
from ascii85 import ascii85decode 	# for decoding
from lzw import lzwdecode			# for decoding
from ccitt import ccittfaxdecode	# for decoding

apversion='''pdfaudit v0.6'''
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

whitespacelist = [0, 9, 10, 12, 13, 32] # per pdf specification
delimiterlist = [40, 41, 60, 62, 91, 93, 123, 125, 47] # ()<>[]{}/
newlinelist = [13, 10] # CR, LF
followlinkslist = ['Length', 'S'] # Need to follow links in these cases
readobjectdefaultlist = ['true', 'false', 'endobj', '>', ']', 'null']
characterlist="acdeghijklmopqsuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
printable=" !#$%&()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[]^_`abcdefghijklmnopqrstuvwxyz{|}~';"
counttable = {}
crossreflist = {}
objstmlist = {}
crossreflistcompressed = {}
crossreflistvfy = {}
scannedobjects = {}
verbosity = 1 # 0 minimal, 1 default, 2 detail, 3 debug
currentobject = ''
startobjsearchpos = 1
riskydictionary = {
#	('S','GoTo')      : 'D', # TODO: remove?
	('S','GoToR')     : 'F',
	('S','GoToE')     : 'F',
	('S','Launch')    : ('F','Win','Mac','Unix'), # TODO: list not yet implemented
	('S','URI')       : 'URI',
	('S','SumbitForm'): 'F',
	('S','JavaScript'): 'JS',
	('OpenAction','') : '', # TODO
	('AA','')         : '', # TODO
#	('Type','ObjStm') : 'Stream' # Not seen as a risk, we iterate through streams
	}

#TODO: consider / check applicability of:
#with open(filename, 'rb') as file:
#    for byte in iter(lambda: file.read(1), b''):
#        # Do stuff with byte
#
#TODO: translate to OOP in general
#TODO: get rid of global variables

def noteof(file):
	#TODO: does this cause performance issues; it gets called reading each charcter
	return file.tell() < os.path.getsize(infile)

def iswhitespace(char):
	return char in whitespacelist

def isdelimiter(char):
	return char in delimiterlist
	
def nextchar(file):
# read next char, leave seek position as-is
	nchar=file.read(1)
	if nchar==b'':
		return ""
	singlebyte = chr(nchar[0])
	file.seek(-1,1)
	return singlebyte

def makeprintable(string):
	pstring=""
	for i in range(len(string)):
		if string[i] in printable:
			pstring+=string[i]
		else:
			pstring+="."
	return pstring

def vprint(string,verbositylevel=1,delimiter='\n'):
	if verbositylevel <= verbosity:
		print(makeprintable(string), end=delimiter)

def halt(message=""):
	sys.exit("EXIT: "+message)

def num(s):
	if isinstance(s,str):
		return int(s)
	elif isinstance(s,tuple):
		return int(s[0])
	else:
		halt("Error converting object to number")

def getword(file):
# Return next word or next delimiter, or an empty string at EOF
# PDF treats any sequency of consequtive white-space characters as one character
# TODO: check overall corectness ans efficiency of the if / elif flow
	foundword= ""
	delimiter=False
	while not delimiter:
		singlebyte = file.read(1)
		if singlebyte == b'': # EOF
			return foundword
		if verbosity > 4:
			vprint("{POS: "+
				str(file.tell()-1)+
				", value: "+
				str(singlebyte[0])+
				", stringempty: +"+
				str(foundword==""), 3)
		delimiter = (singlebyte[0] in whitespacelist + delimiterlist)
		if foundword == "" and singlebyte[0] in whitespacelist:
			# ignore trailing whitespaces
			delimiter = False
		elif singlebyte[0] == 37: 
			# ignore % comments
			readcomment(file)
		elif not delimiter:
			# add non-whitespace/delimiter
			foundword += chr(singlebyte[0])
		elif singlebyte[0] in delimiterlist:
			if foundword == "":
				# send delimiter if it's the first character we encounter
				foundword += chr(singlebyte[0])
			else:
				# read this character next time; so seek one position back
				file.seek(-1,1)
	return foundword

def getnexttwowords(file):
	startpos = file.tell()
	foundword1 = getword(file) 
	foundword2 = getword(file)
	file.seek(startpos)
	return foundword1, foundword2

def dictionaryappendlist(dictionary,key,value):
	if key in dictionary:
		dictionary[key].append(value)
	else:
		dictionary[key]=[value]
	return dictionary

def checkdictionary(dictionary):
# builds a dictionary of keys found to be risky. New keys are added in the dictionary as new key/object pairs, or an object is appended to already existing key/object pair(s) 
	global currentobject
	global counttable
	for i in list(dictionary.keys()):
		keyvaluepair = (i,dictionary.get(i))
		keyvaluepairempty = (i,"")
		# TODO: incorrect below, and we can make use of the fact that dict.get() returns none if the key is not found
		if keyvaluepair in list(riskydictionary.keys()):
			objectandvalue = (	currentobject,
								"".join(dictionary.get(riskydictionary.get(keyvaluepair,""),"")))
			key=keyvaluepair[1]
			dictionaryappendlist(counttable,key,objectandvalue)
		elif keyvaluepairempty in list(riskydictionary.keys()):
			objectandvalue = (	currentobject,
								"".join(dictionary.get(i                                    ,"")))
			key=i
			dictionaryappendlist(counttable,key,objectandvalue)

def getdictionary(file,followlinks=False):
# sequence of key - object pairs, of which at least the key is a /name (without slash)
# it may be followed by a stream, which is encapsulated by the words "stream" and "endstream"
# TODO: handling of specific keys and return values (Length, Size): from global to variables to returns from this function (as this function may be called recursively)
	global globaldictvaluesize # TODO: from global variable to return'd value from this function
	vprint("[DICT]", 2, '')
	getkey = ""
	getobject = ""
	dictionary = {}
	while getkey != '>' and getobject != '>':
		getkey = readobject(file)#.get("SingleString")
		getobject = readobject(file,getkey in followlinkslist)
		dictionary[getkey] = getobject
#		vprint("[KEY,OBJECT]: "+getkey+", "+getobject+" ",2) #TODO: remove/adapt: getobject can be something else than string
	nword, nnword = getnexttwowords(file)
	if nword == 'stream':
		#TODO: followsymlinks handling in case stream can have symlinks
		length=num(dictionary.get("Length"))
		getword(file) # actually read the word 'stream' (including trailing delimiter)
		file.seek(-1,1) #stream follows after 'stream\r\n' or 'stream\n'
		if ord(nextchar(file)) == 13: # \r
			file.read(2) # read 'stream\r\n'
		else:
			file.read(1) # read 'stream\n'
		stream=file.read(length)
		vprint(" ",2)
		vprint("[STREAM] "+str(length)+" bytes",2)
		if "Filter" in list(dictionary.keys()):
			filterlist = dictionary.get("Filter")
			if isinstance(filterlist,str):
				filterlist=[filterlist]
			for streamfilter in list(filterlist):
				vprint("[DECODE]: "+streamfilter+" ",2,'')
				if streamfilter == "FlateDecode":
					try:
						stream=zlib.decompress(stream)
						vprint(makeprintable(stream),3)
					except:
						try:
							vprint("zlib error; streamlength: "+str(len(stream))+
								", firstbyte: "+str(stream[0])+
								", lastbyte: "+str(stream[len(stream)-1])+
								", ZLIB runtime version: "+zlib.ZLIB_RUNTIME_VERSION,2)
						except:
							vprint("No return stream given by zlib",2)
				elif streamfilter == 'ASCII85Decode':
					stream=ascii85decode(stream)
				elif streamfilter == 'LZWDecode':
					stream=lzwdecode(stream)
#				elif streamfilter == 'CCITTFaxDecode':
#					vprint("[FILTER]: "+streamfilter,3)
#					ccittfaxdecode(stream) #TODO: needs additional arguments
				elif streamfilter == '/':
					pass
				else:
					vprint("Filter not implemented: "+streamfilter,1)
					# TODO: use counttable instead to give list of unimplemented filters with objects at the end of the scan. 
					# TODO: need to break here if multiple compressions are used of which one fails to prevent error out. 
		getword(file) # the word endstream
		vprint("[STREAM: end]",2)
		if dictionary.get("Type")=="XRef":
			vprint("[XRef]",2)
			dictionary["Stream"]=stream
		elif dictionary.get("Type")=="ObjStm":
			vprint("[STREAM]: open ObjStm",2)
			f=open(".pdfaudit","w+b")
			f.write(stream)
			f.write(bytearray([13,13,13]))
			f.seek(0)
			iterateobjstm(f,num(dictionary.get("N")))
			f.close()
			#TODO: delete file
			vprint("[STREAM]: close ObjStm",2)
		else:
			dictionary["Stream"]=stream.decode('utf-8','ignore')
		#TODO: followsymlinks handling in case stream can have symlinks
	vprint("[DICT: end]",2,'')
	checkdictionary(dictionary)
	return dictionary # TODO: check if we can return more here
		
def iterateobjstm(file,n):
# First read n objectnumber/byteoffset pairs, then iterate through all objects. The objects are also stored in the scannedobjects list
	global scannedobjects
	key={}
	for i in range(n):
		objectnumber = getword(file)
		byteoffset = getword(file)
		vprint(objectnumber+" "+byteoffset+" ",2,"")
		#TODO: we currently read all objects, but some might be deleted in xref?
		key[n] = (num(objectnumber),0)
		#TODO: give list of objects instead of following:
		#vprint('[ObJStm Object: '+objectnumber+',0]',2)
	for i in range(n):
		vprint("[ObjStm Object]: "+str(i),2,'')
		scannedobjects[key[n]]=readobject(file)

def translatestring(string):
# translates: \ddd, \n, \r, \t, \f, \b, \\, and ignores a single \
	tstring=string
	tstring=tstring.replace(chr(92)+chr(13),"")
	tstring=tstring.replace(chr(92)+chr(10),"")
	tstring=tstring.replace(chr(92)+"n"    ,chr(10))
	tstring=tstring.replace(chr(92)+"r"    ,chr(13))
	tstring=tstring.replace(chr(92)+"t"    ,chr(9))
	tstring=tstring.replace(chr(92)+"b"    ,chr(8))
	tstring=tstring.replace(chr(92)+"f"    ,chr(12))
	tstring=tstring.replace(chr(92)+"("    ,"(")
	tstring=tstring.replace(chr(92)+")"    ,")")
	i=0
	sstring=""
	while i < len(tstring)-1:
		if tstring[i]==chr(92) and tstring[i+1].isdecimal(): #replace \d, \dd or \ddd
			for j in range(4,1,-1): 
				minpos=min(i+j,len(tstring)-1)
				if tstring[i+1:minpos].isdecimal():
					sstring+=chr(int(tstring[i+1:minpos]))
					i+=j-1
					break
		elif tstring[i]==chr(92) and tstring[i+1]==chr(92): # replace \\ by \
			sstring+=chr(92)
			i+=1
		elif tstring[i]==chr(92): # a single \ is to be ignored
			pass
		else:
			sstring+=tstring[i]
			if i==len(tstring)-2 and tstring[i+1]!=chr(92): # handle last char
				sstring+=tstring[i+1]
		i+=1
	tstring=sstring
	return tstring

def getliteralstring(file):
# unbalanced parenthese ")" terminates the string
# to be escaped: \(, \) 
	vprint("[STR]",3,'')
	foundstring= ""
	psinglechar = "("
	singlechar = ""
	parenthesecount = 1
	while parenthesecount > 0:
		psinglechar = singlechar
		singlechar = chr(file.read(1)[0])
		if psinglechar != "\\":
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
	foundstring=translatestring(foundstring)
	vprint(foundstring,2)
	return foundstring

def translatehexstring(string):
	hexlist="0123456789aAbBcCdDeEfF"
	sstring=""
	for i in range(len(string)): # remove non-hex characters
		if string[i] in hexlist:
			sstring+=string[i]
	if len(sstring) % 2 != 0: # add trailing 0 if needed
		sstring+=str(0)
	tstring=""
	for i in range(0,len(sstring),2): # convert hex values to chars
		tstring+=chr(int(sstring[i:i+2],16))
	return tstring

def gethexstring(file):
# Sequence of [0-9][A-F]or[a-f] pairs enclosed by <>, with whitespace characters ignored
# TODO uneven amount of pairs (append 0)
# TODO translate to string? 
	vprint("[HEX]",3,'')
	hexstring=""
	singlechar=""
	while singlechar != '>':
		singlechar = chr(file.read(1)[0])
		if singlechar != '>':
			hexstring += singlechar
	hexstring=translatehexstring(hexstring)
	vprint(hexstring+" ",2,'')
	return hexstring

def getarray(file):
# returns single object or a list of objects
	vprint("[ARRAY]",3,'')
	foundarray=[]
	while ']' not in foundarray:
		foundarray.append(readobject(file,followlinks=False))
	foundarray = foundarray[:-1]
	if len(foundarray)==1:
		return foundarray[0]
	else:
		return foundarray

def isnum(checkword):
#https://stackoverflow.com/questions/354038/how-do-i-check-if-a-string-is-a-number-float
	return checkword.replace('.','',1).replace('-','',1).isdigit()

def translatename(string):
	sstring=""
	i=0
	while i<len(string): 
		if string[i]=="#": # TODO: errors out non-valid names like /name#
			sstring+=chr(int(string[i+1:i+3],16))
			i+=3
		else:
			sstring+=string[i]
			i+=1
	return sstring

def getname(file):
	vprint(" ",2)
	vprint("[NAME]",3,'')
	foundword=getword(file)
	foundword=translatename(foundword)
	vprint(foundword+" ",2,'')
	return foundword

def getobjectpos(key):
# Returns the object location found from the xref tables, or if it's not there, from the findobjects() scan done earlier. 
	if key in list(crossreflist.keys()):
		pos=crossreflist.get(key)
	elif key in list(crossreflistvfy.keys()):
		pos=crossreflistvfy.get(key)
	else:
		halt("Object not found in crossreflist: "+str(key[0])+" "+str(key[1]))
	vprint("[OBJPOS]"+ hex(pos),2)
	return pos

def jumptoobject(file,objectnum,generation):
	global scannedobjects
	key = (num(objectnum),num(generation))
	if key in scannedobjects.keys():
		vprint("[STORED]",2,'')
		return scannedobjects[key]
	else:
		vprint("[JMP]",2,'')
		startpos = file.tell()
		key=num(objectnum),num(generation) # TODO: did we do this alread?
		vprint('[JUMPTO:'+objectnum+','+generation+']',2)
		file.seek(getobjectpos(key))
		foundvalue = readindirectobject(file)#.get('SingleString')
		file.seek(startpos)
		scannedobjects[key]=foundvalue
		return foundvalue

def readcomment(file):
	singlebyte = ''
	comment = ''
	while True:
		singlebyte = file.read(1)
		if singlebyte == b'': # EOF
			break
		elif singlebyte[0] not in newlinelist:
			comment += chr(singlebyte[0])
		else:
			break
	vprint("[COMMENT:]"+makeprintable(comment),3)
	return comment

def readobject(file,followlinks=False):
#returns either a string, an array of objects, or a dictionary
#TODO: difference between < something, << something, <something
#TODO: stream which contains the word "endstream"
#TODO: this function is called from more than one location, but not every objct type is expected in each case. Implement warning for those unexpected cases.
#TODO: check correctness of handling: abc<def> vs abd<<def>> 	pword=""
	foundword = getword(file)
	vprint(foundword,4)
	if foundword == '<':
		if nextchar(file) == '<':
			singlebyte = file.read(1)
			return getdictionary(file,followlinks)
		else:
			return gethexstring(file)
	elif foundword == '(':
		return getliteralstring(file)
	elif foundword == '[':
		return getarray(file)
	elif isnum(foundword):
		nword, nnword = getnexttwowords(file)
		if isnum(nword) and nnword == 'R':
			getword(file)
			getword(file)
			if followlinks:
				foundword = jumptoobject(file,foundword,nword)
			else:
				foundword = foundword+' '+nword+' '+nnword
				vprint(foundword+" ",2,'')
		else:
			vprint("[NUM]:",3,'')
			vprint(foundword+' ',2,'')
		return foundword
	elif ord(foundword[0]) == 47: # "/"
		return getname(file)
	elif foundword in readobjectdefaultlist:
		return foundword
	else:
		halt("Unexpected end of object, found: "+foundword+" at: "+hex(file.tell()))

def readindirectobject(file):
# Returns an object or trailer, or the word 'endobj' or 'endstream'. Note that is is also used to scan over the xref table in order to read and return the trailer object. 
	ppword=""
	pword=""
	foundword="x"
	while foundword!="":
		ppword = pword
		pword = foundword
		foundword = getword(file)
		vprint(foundword,4)
		if foundword == 'obj':
			vprint("[OBJ:"+ppword+","+pword+"]",2 , '')
			return readobject(file)
		elif foundword =='trailer':
			vprint("[TRAILER]",2)
			return readobject(file)
		elif foundword == 'endobj': #TODO: do we ever reach this? consider deleting
			vprint("[ENDOBJ]",2)
			return foundword
		elif foundword == 'endstream': #TODO: do we ever reach this? consider deleting
			vprint("[ENDSTREAM]",2)
			return foundword
'''
def findobjects(file,startpos):
# Almost similar to readinidirectobject(); we do a quick scan here to find obj/endobj pairs, and build a dictionary of object positions to compare with the xref tables. 
	global crossreflistvfy
	currentpos=file.tell()
	vprint("[FINDOBJS]: scanning for objects from "+hex(startpos)+" to "+hex(currentpos),2)
	file.seek(startpos)
	ppword=""
	pword=""
	pppos = 0
	ppos = 0
	pos = 0
	foundword="x"
#	while foundword!="": # just scan complete document
	while file.tell()<currentpos:
		while nextchar(file) not in "0123456789abcdefghijklmnopqrstuvwxyz":
#			print(".") #DEBUG
			file.read(1)
		pppos = ppos
		ppos = pos
		pos = file.tell()
		ppword = pword
		pword = foundword
		foundword = getword(file)
#		print(foundword,"at:",hex(pos),"currentpos at:",hex(file.tell())) #DEBUG
		if foundword == 'obj':
			vprint("("+ppword+" "+pword+") at: "+hex(pppos)+" ",2 , '')
			crossreflistvfy[num(ppword),num(pword)]=pppos
			while getword(file) != 'endobj': # TODO: check need to add other delimiters like >, >>, ] 
				pass
#	print(crossreflistvfy)
	file.seek(currentpos)
'''

'''
def isxrefstream(file,pos):
	currentpos=file.tell()
	file.seek(pos)
	if getword(file)=='xref':
		file.seek(currentpos)
		return False
	else: # TODO: should check here if it is an object, or otherwise elsewhere
		file.seek(currentpos)
		return True
'''

def getdocumentstructure(file):
# Based on findobjects (TODO: combine?), scans the complete pdf to retrieve the document structure. Purpose is to find all objects, their locations, being either indirect objects or objects from objectsreams. This is done by just scanning the document from the start. This strategy deviates from the standard strategy from the pdf specification, where the pdf document is supposed to be read from the back to retreive the document structure from (compressed) xref tables. The standard strategy poses problems for malformed pdf files, when references are pointing to incorrect object locations. For these situations a document scan as described above needs to be performed anyhow to continue reading the pdf and not error out. The issue at hand is that some maliciuos pdf's may be altered in such a way, that pdf readers that are able to deal with malformed pdf's might still be able to read these pdf's and pose a risk. Pdfaudit therefore regards it's own constructed document structure as basis  instead of the method described in the pdf specificaton. The penalty however is processing speed, as the document is read twice. 
# Less relevant, but note that there are basically 3 types of pdf files with respect to cross reference tables. 1) a pdf file with one or more regular xref tables, which are pointed to by startxref at the end of a pdf and the Prev entries in the trailer in case there are more pdf revisions. 2) no xref table but a cross refernce stream instead (it has per pdf specificatin no xref and no trailer section, and startxref points to the cross reference stream). 3) a hybrid version containing both types of xross refence tables.
	global verbosity
	vprint("[GETSTRUCTURE]",2)
	file.seek(1)
	ppword=""
	pword=""
	pppos = 0
	ppos = 0
	pos = 0
	foundword="x"
	while foundword!="": # just scan complete document
		while nextchar(file) not in "0123456789abcdefghijklmnopqrstuvwxyz":
#			print(".") #DEBUG
			file.read(1)
		pppos = ppos
		ppos = pos
		pos = file.tell()
		ppword = pword
		pword = foundword
		foundword = getword(file)
#		print(foundword,"at:",hex(pos),"currentpos at:",hex(file.tell())) #DEBUG
		if foundword == 'obj':
			vprint("    "+ppword+" "+pword+" obj at: "+hex(pppos)+" ",2)
			crossreflist[num(ppword),num(pword)]=pppos
			while foundword != 'endobj': # TODO: check need to add other delimiters like >, >>, ] 
				foundword = getword(file)
				if foundword == 'ObjStm':
					vprint("        has ObjStm",2)
					objstmlist[num(ppword),num(pword)]=pppos
#			print(hex(file.tell())) # DEBUG
# TODO: add progress indicator here, like done in iterateobjectlist()
		elif foundword == 'xref':
			vprint("xref at: "+hex(pos),2)
			# TODO: read xref table, and check if this matches the object locations
		elif foundword == 'trailer':
			vprint("trailer at: "+hex(pos),2)
			pverbosity=verbosity
			verbosity=1
			trailer=readobject(file)
			if trailer.get("Prev",0) != 0:
				vprint("    Prev is: "+hex(int(trailer.get("Prev"))),2)
			if trailer.get("XRefStm",0) != 0:
				vprint("    XRefStm is: "+hex(int(trailer.get("XRefStm"))),2)
			verbosity=pverbosity
		elif foundword == 'startxref':
			vprint("startxref at: "+hex(pos),2)
			startxref=int(getword(file))
			vprint("    points to: "+hex(startxref),2)
# TODO: the next section errors out on malformed pdf's, so commented out; as explained above, we scan the actual pdf from the beginning to locate the object postions anyways. 
#			if isxrefstream(file,startxref):
#				vprint("    which is a cross reference stream",2)
#				currentpos=file.tell()
#				file.seek(startxref)
#				pverbosity=verbosity
#				verbosity=1
#				getxrefstream(file)
#				file.seek(currentpos)
#				verbosity=pverbosity
#			else:
#				vprint("    points to xref",2)
			vprint("EOF or new PDF revision",2)
#	print(objstmlist) #DEBUG
#	print(crossreflist) #DEBUG
	iterateobjectlist(file,objstmlist)
	iterateobjectlist(file,crossreflist)
	showthreats()

def showthreats():
#	print(counttable) #DEBUG
	for i in list(counttable.keys()):	
		for j in list(counttable.get(i)):
			objectstring = str(j[0][0])+" "+str(j[0][1])
			valuestring = j[1]
			print("/"+i+
				" in object "+objectstring+
				" (at: "+hex(crossreflist.get(j[0]))+
				"): "+valuestring)

'''
def getxref(file):
# Read the crossreference table, and stores object locations in crossreflist
	global crossreflist
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
				vprint("("+str(i)+" "+str(objectgen)+") at: "+hex(objectoffset),2,'')
				if crossreflistvfy[i,objectgen]==objectoffset: #TODO: could be possible that we did not find this object
					crossreflist[i,objectgen]=objectoffset
					vprint(" (OK) ",2,'')
				else:
					crossreflist[i,objectgen]=crossreflistvfy[i,objectgen]
					vprint(" (NOK) ",2,'')
				# this either inserts a new key, or updates an existing one.

			else: # 'f'
				if (i,objectgen) in list(crossreflist.keys()): #should normally be the case
					del crossreflist[i,objectgen-1] # per pdf spec: generations are incremented by 1
			vprint(str(i)+str(objectoffset)+str(objectgen)+str(objectinuse),3)
		startobj, countobj = getnexttwowords(file)
	vprint("[XREF: End]",2)

def findstartback(file,startstring):
# Returns the previous file position of the whole search string
	filepos = file.tell()
	foundword = ""
	while True:
		filepos -= 1 # TODO: does not check if we're passing the beginning of the file (malformed pdfs can cuse this situation)
		file.seek(filepos)
		if file.read(1)[0] in whitespacelist:
			foundword = getword(file)
			if foundword == startstring:
				vprint("[FIND]: "+startstring+" found at: "+hex(filepos+1),3)
				return filepos+1

def checkxrefpos(file,xrefpos):
# First checks if the given position starts with "xref", or two numbers (indicating an object). Otherwise searches for 'xref' from the current position as last resort. 
	currentpos=file.tell()
	file.seek(xrefpos)
	word1, word2 = getnexttwowords(file)
	if word1=='xref' or (isnum(word1) and isnum(word2)):
		return xrefpos
	else:
		file.seek(currentpos)
		findstartback(file,'xref')
		realxrefpos=findstartback(file,"xref")
		vprint("Malformed pdf, incorrect xref position, was: "+hex(xrefpos)+" is: "+hex(realxrefpos),1)
		return realxrefpos

def getstartxref(file):
# Searches backwards for "startxref" from the end of the file, and returns the start of "xref"
# TODO: for linarized PDF's, it seems like the reference in startxref may not only point to an XREF table, but also to an object containing a xrefstream. 
	file.seek(os.path.getsize(infile) -10) #start reading from the back
	startxrefpos=findstartback(file,"startxref")
	vprint("[STARTXREF] at: "+hex(startxrefpos),2)
	while noteof(file):
		foundword = getword(file)
		if isnum(foundword):
			start=num(foundword)
	file.seek(startxrefpos)
	start=checkxrefpos(file,start)
	vprint("[XREF]: at "+hex(start),2)
	file.seek(startxrefpos)
	return start
'''

def getpdfversion(file):
	file.seek(0)
	versionstring=readcomment(file)
	vprint("PDF version: "+versionstring,2)
	if "PDF" not in versionstring:
		halt("Incorrect PDF header, found: "+versionstring)

def iterateobjectlist(file,objectlist):
#TODO: progress counter
	j=0
	global currentobject
	vprint("[XREFITER] Number of objects: "+ str(len(objectlist)),2) # TODO: comparing with this number is inaccurate, as the list grows for each pdf version of the document, while the old objects are already scanned. 	
	for i in list(objectlist):
		vprint("[XREFITERCMP]:"+str(i[0])+" "+str(i[1]),2)
		currentobject=i
		jumptoobject(file,str(i[0]),str(i[1])) # TODO: juggling with num to string to num
		if verbosity<2:
			print("progress: "+str(int(100*j/len(objectlist)))+"%, scanning object: "
				+str(i[0])+" "+str(i[1])+"             ",end='\r')
		j += 1
	print("                                                            ",end='\r')

'''
def iteratexref(file):
	j=0
	global currentobject
	vprint("Number of objects: "+ str(len(crossreflist))) # TODO: comparing with this number is inaccurate, as the list grows for each pdf version of the document, while the old objects are already scanned. 
	for i in list(crossreflist.keys()):
		vprint("[XREFITER]:"+str(i),2)
		currentobject=i
		jumptoobject(file,str(i[0]),str(i[1])) # TODO: juggling with num to string to num
		if verbosity<2:
			print("progress: "+str(int(100*j/len(crossreflist)))+"%, scanning object: "
				+str(i[0])+" "+str(i[1])+"             ",end='\r')
		j += 1
	print("                                                            ",end='\r')

def iteratecompressedxref(file,ObjStmList):
#TODO: progress counter
	# j=0
	global currentobject
	#TODO: check if the object read tracker needs to be updated here as well. Or should this be done downstream?
	vprint("[XREFITER] Number of objects: "+ str(len(ObjStmList))) # TODO: comparing with this number is inaccurate, as the list grows for each pdf version of the document, while the old objects are already scanned. 	
	for i in list(ObjStmList):
		vprint("[XREFITERCMP]:"+str(i)+" 0",2)
		currentobject=(i,0)
		jumptoobject(file,str(i),"0") # TODO: juggling with num to string to num
#		if verbosity<2:
#			print("progress: "+str(int(100*j/len(crossreflist)))+"%, scanning object: "
#				+str(i[0])+" "+str(i[1])+"             ",end='\r')
#		j += 1
'''

'''
def bytesum(b1,b2):
	bsum=bytearray(len(b1))
	for i in range(len(b1)):
		bsum[i]=(b1[i]+b2[i])%256
	return bsum

def getxrefstream(file):
# the complete dictionary is retrieved. The stream inside the dicionary contains the crossreference table, which may have have been coded with a predictor. In that case, the predictor is executed on the stream to retrieve the bare stream. First part of this stream is the object list (which consists of N pairs object number and offset from the first object in the stream), which is read, and the last part are the objects references itself. The result is stored in the global crossreflist(comressed) lists, and the indirect objects that contain ObjStm's is returned. 
	global crossreflist
	global crossreflistcompressed
	vprint(" ",2)
	vprint("[XREF Stream]",2,'')
	xrefdictionary=readindirectobject(file)
#	print(xrefdictionary)
	stream=xrefdictionary.get("Stream")
	w=xrefdictionary.get("W")
	w=[num(w[0]), num(w[1]), num(w[2])]
#	print(w)
	n=sum(w)
	predictor=False
	fieldstart=0
	if "DecodeParms" in list(xrefdictionary.keys()):
		if num(xrefdictionary.get("DecodeParms").get("Predictor","0"))>1:
			predictor=True
			fieldstart=1
			vprint("[Predictor]",2,'')
			n+=1
	objectlist = [stream[i:i+n] for i in range(0, len(stream), n)] # list comprehension
	vprint("[XREF Stream objects]: "+xrefdictionary.get("Size"),3)
	predictorlist=[i[0] for i in objectlist] # list comprehension; get first column
	fieldlist=[i[fieldstart:n] for i in objectlist] # list comprehension; get rest of the column
#	print(fieldlist) # DEBUG
#	print(predictorlist) # DEBUG

	xreflist=[]
	if predictor:
		for i in range(len(fieldlist)-1):
#			print(fieldlist[i]) #DEBUG
			if predictorlist[i+1]==2:
				fieldlist[i+1]=bytesum(fieldlist[i],fieldlist[i+1])
			else:
				halt("XREF Stream predictor not implemented")
	for field in list(fieldlist):
		entry=[]
		for i in range(len(w)):
			fstart=sum(w[0:i])
			fend=sum(w[0:i])+w[i]
			entry.append(int.from_bytes(field[fstart:fend],byteorder='big', signed=False))
		xreflist.append(entry)

#	print(xreflist) # DEBUG
	# TODO: implement reading and using Index (first object number and number of entries), defaults to [0 size]
	xreflistsize=len(crossreflist)
	cxreflistsize=len(crossreflistcompressed)
	ObjStmList=[]
	for i in range(len(xreflist)): #TODO: this is the same as regular xref handling; combine?
		field3=xreflist[i][2] # object generation or index 
		field2=xreflist[i][1] # object number or offset
		field1=xreflist[i][0] # field type
		if field1==1: # e.g. 'n'
			crossreflist[i,field3]=field2
			# this either inserts a new key, or updates an existing one.
			vprint("        "+str(i)+" "+str(field3)+ " is at: "+hex(field2),2)
		elif field1==0: # e.g. 'f'
			if (i,field3) in list(crossreflist.keys()): #should normally be the case
				del crossreflist[i,field3-1] # per pdf spec: generations are incremented by 1
				vprint("        "+str(field2)+" "+str(field3)+" deleted",2)
		elif field1==2: # compressed objects list
			# The objects found are not stored here, but when scanning the ObjStm. We need however to store all object nunbers that contain compressed objects, in order to scan these later. 
			if xreflist[i][1] not in list(ObjStmList):
				vprint("ObjStm Object found: "+str(field2)+" 0",2)
				ObjStmList.append(field2)
				vprint("        "+str(field3)+" 0 is in ObjStm: "+str(field2)+" 0",2)
				vprint("        "+str(field2)+" 0 has ObjStm",2)
		else:
			pass
#			halt("Unexpected type found reading cross reference stream")
	vprint("[XREF Stream]: END",2,'')
	return ObjStmList
'''

'''
def readpdf(file,xrefpos):
# Main principle is to first read the trailer and recurse to the previous version of the pdf, then read the xref table, then read all objects from the pdf version we're handling. Note that readindirectobject() is used to find and read the trailer. 
# Per PDF spec, the Crossreference table and trailer are structured like this:
# xref
#   entries with crossreference information 
# trailer
#   << dictionary >>
# startxref
#   start psotion of xref
# %%EOF
	global startobjsearchpos
	ObjStmList=[]
	file.seek(xrefpos)
	dictionary=readindirectobject(file)
	if dictionary.get("Prev",0) != 0:
		file.seek(xrefpos-10)
		previousxrexpos=int(checkxrefpos(file,int(dictionary.get("Prev"))))
		vprint("[Prevxref]: "+hex(previousxrexpos),2)
		readpdf(file,previousxrexpos)
	file.seek(xrefpos)
	findobjects(file,startobjsearchpos)
	startobjsearchpos=file.tell()
	file.seek(xrefpos) # need to get back to the beginning of the xref, since we read trailer
	#TODO: obfusc...pdf has both Prev and XRefStm
	if getword(file)=='xref':
		getxref(file)
		vprint(list(crossreflist.keys())[0],3)
	else: # assume to read a cross reference stream
		ObjStmList=getxrefstream(file)
	#TODO: XrefStm and possibliity both xref and crossreference stream exist in pdf spec. 
	iteratecompressedxref(file,ObjStmList)
	iteratexref(file)
	vprint("Scanned objects: "+str(len(scannedobjects))

#		+"/"+str(len(xreflist))
		)
'''

def readarguments():
# note: Parameters starting with - or -- are usually considered optional. All other parameters are positional parameters and as such required by design (like positional function arguments).
	parser = argparse.ArgumentParser(description=apdescription,epilog=apepilog,formatter_class=argparse.RawDescriptionHelpFormatter)
	parser.add_argument('filename', type=str, help="pdf file to be audited")
	parser.add_argument('-d', type=int, default=1, help="detail level D of output: 0 minimal, 1 default, 2 detail, 3 debug")
	parser.add_argument('-s', action='store_true', help="show pdf document structure and exit")
	parser.add_argument('-v', action='version', help='show version', version=apversion)
	parser.add_argument('-w', action='version', help='show warranty', version=apwarranty)
	parser.add_argument('-c', action='version', help='show copyright', version=apcopyright)
	args = parser.parse_args()
	if os.path.isfile(args.filename):
		return args.filename, args.d, args.s
	else:
		halt("File not found")

infile, verbosity, showstructure = readarguments()
vprint("Scanning: "+infile,0)
with open(infile, 'rb') as file:
	getpdfversion(file)
	getdocumentstructure(file)
#	if showstructure:
#		verbosity = 2
#		getdocumentstructure(file)
#		halt("show structure")
#	readpdf(file,getstartxref(file))
#	showthreats()

