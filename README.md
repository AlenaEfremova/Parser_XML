Parser_XML
========================
The console application receives a link to an XML file and an optional file to record the results as parameters.
If the file to be recorded is not specified, the application outputs the results to the console.

The application processes files 
([example](https://www.redhat.com/security/data/oval/com.redhat.rhsa-RHEL8.xml)) 
that contain `<definition>` tags. 
Each `<definition>` of xml is represented as a json containing the following fields: 
- ***id*** - value of attribute *id* of tag `<definition>`
- ***title*** - value of tag `<title>`
- ***issued*** - value of attribute *date* of tag `<issued>`, formatted as "dd.mm.yyyy"
- ***rhsa_id*** - value of attribute *ref_id* of tag `<reference>` that has an *source="RHSA"*
- ***cve_list*** - value of attribute *ref_id* of tag `<reference>` that has an *source="CVE"*
- ***links*** - a list of all links contained in the child tags of the tag `<advisory>`
- ***criteria*** - values of the *comment* attributes of the `<criterion>` tags taking into account the value 
of the *operator* attribute of the parent tag.

Running Parser_XML
------------------------
To run it, you need to run the command from the terminal/command line inside the Parser_XML directory, 
the file for writing the results must be inside the directory.  
```
$ python parse_xml.py -u https://www.redhat.com/security/data/oval/com.redhat.rhsa-RHEL8.xml -o output_file.txt
```
To output the results to the console, run the following command from the terminal:
```
$ python parse_xml.py -u https://www.redhat.com/security/data/oval/com.redhat.rhsa-RHEL8.xml
```


