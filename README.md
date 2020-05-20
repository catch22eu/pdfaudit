# pdfaudit
PDF file security and privacy auditing tool written in Python

The tool parses a pdf file looking for the following keys:
GoTo, GoToR and GoToE,
Launch,
URI,
SumbitForm,
JavaScript,
OpenAction (TODO),
AA (TODO), and
ObjStm

pdfaudit outputs the content of the corresponding values and object location to aid assessment of the security or privacy risks. 

The tool is currently in development, with currently about 80% of the required code implemented with following pdf versions in mind:
PDF1.0 (1992)
PDF1.1 (1994)
PDF1.2 (1996)
PDF1.3 (1999)
PDF1.4 (2001)
PDF1.5 (2003)
PDF1.6 (2005)
PDF1.7 (2006)

TODO list:
1) Key handling of OpenAction and AA
2) DCTDecode filter
3) Compressed objects
4) Refactorig in general
5) Speed optimizations (like don't uncompress if not needed)

This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more details.

Version History:
v0.2: 20 May 2020
New:
- Ability to read cross reference streams

v0.1
First rudimentary version


