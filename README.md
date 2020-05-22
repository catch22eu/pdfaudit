# pdfaudit
PDF file security and privacy auditing tool written in Python

The tool parses a pdf file looking for the following keys:
(GoTo), GoToR and GoToE,
Launch,
URI,
SumbitForm,
JavaScript,
OpenAction,
AA

PDFaudit outputs the content of the corresponding values and object location to aid assessment of security and privacy risks. 

The tool is currently in development, with currently about 80% of the required code implemented. The pdf standard has multiple options to store document information, which makes it a challenge to cover all possible scenario's. Moreover, the document specification is at some instances less consicely defined, making room for multiple interpretations. Combined with the current development phase of pdfaudit, a high succes rate can not yet be guaranteed of the tool parsing each pdf correctly in the first place, and detecting and reporting the security and privacy threats. The end goal however is to be compatible with at least the ISO 32000-1:2008, which covers PDF versions up to and including PDF1.7

### Prerequisites

PDFaudit is written in Python, and uses Python3 code

```
TBD
```

### Installing

A step by step series of examples that tell you how to get a development env running

Say what the step will be

```
Give the example
```

And repeat

```
until finished
```


### TODO list
1) DCTDecode filter
2) Refactorig iterations in general
3) Speed optimizations (like don't uncompress if not needed)
4) Determine if a split between high and low-risk threats is useful

## Version History
#### v0.4
##### New:
- /OpenAction and /AA
##### Bugfixes
- Fixed incorrect escape handling in strings 

#### v0.3: 21 May 2020
##### New: 
- Ability to scan object streams
- Some speed optimizations
##### Bugfixes:
- Only read DecodeParms if they exist
- EOF was not handled correctly in readword function

#### v0.2: 20 May 2020
##### New:
- Ability to read cross reference streams

#### v0.1
First rudimentary version

## License

pdfaudit Copyright (C) 2020 Joseph Heller

This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more details.

## Acknowledgments

* Didier Stevens for sharing his knowledge on maliciuos pdf files
* Yusuke Shinyama, for some of the decoding filters





