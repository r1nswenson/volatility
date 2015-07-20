To generate python classes from agent xml output follow below steps...

1) create/update the appropriate xsd using any availble tools (ex:http://www.freeformatter.com/xsd-generator.html)

2) Run easy_install generateds.

3) Run easy_install lxml

4) Run Python c:\python27\scripts\generateds.py -o processdatastructure.py --external-encoding="utf-8" process.xsd

5) Use processdatastructure in admemoryanalysis.py

 
