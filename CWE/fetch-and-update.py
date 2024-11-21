#!/bin/python3
import requests
import re
import os
import zipfile
import json
import io
import xml.etree.ElementTree as ET
BASEDIR = os.path.dirname(os.path.realpath(__file__))

if not os.path.exists(BASEDIR+'/data/'):
    os.makedirs(BASEDIR+'/data/')

r = requests.get('https://cwe.mitre.org/data/xml/cwec_latest.xml.zip')
z = zipfile.ZipFile(io.BytesIO(r.content))
xmlfile = z.open(z.namelist()[0])
root = ET.fromstring(xmlfile.read())

cwes = []

print("[+] Downloading latest CWE references")
for w in root.find('{http://cwe.mitre.org/cwe-7}Weaknesses'):
    desc = ""
    if w.find('{http://cwe.mitre.org/cwe-7}Description') is not None:
        desc += re.sub(' +', ' ', w.find('{http://cwe.mitre.org/cwe-7}Description').text.strip().replace('\t', ' ').replace('\n', ' '))
    if w.find('{http://cwe.mitre.org/cwe-7}Extended_Description') is not None and w.find('{http://cwe.mitre.org/cwe-7}Extended_Description').text is not None:
        desc += " "
        desc += re.sub(' +', ' ', w.find('{http://cwe.mitre.org/cwe-7}Extended_Description').text.strip().replace('\t', ' ').replace('\n', ' '))

    cwe = {
        'id': w.attrib['ID'],
        'name': w.attrib['Name'],
        'description': desc,
    }
    cwes.append(cwe)

with open(BASEDIR+'/data/cwes-latest.json', "w") as cwe_json_file:
    cwe_json_file.write(json.dumps({
        'cwes': cwes
    }))
# with zipfile.ZipFile(BASEDIR+'/data/cwes-latest.json.zip', 'w', zipfile.ZIP_DEFLATED) as zf:
#     zf.write(BASEDIR+'/data/cwes-latest.json', arcname='cwes.json')


print("[+] Building diff file from latest CWE references. no diff by default")
with open(BASEDIR+'/data/cwes-diff.json', "w") as cwe_json_file:
    cwe_json_file.write(json.dumps({
        'cwes': []
    }))
