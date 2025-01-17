#!/bin/python3
import requests
import re
import os
from os.path import isfile, join
import zipfile
import json
from tqdm import tqdm
BASEDIR = os.path.dirname(os.path.realpath(__file__))


if not os.path.exists(BASEDIR+'/nvd/'):
    os.makedirs(BASEDIR+'/nvd/')

print("[+] Downloading CVE dictionary from NVD")
r = requests.get('https://nvd.nist.gov/vuln/data-feeds#JSON_FEED')
for filename in re.findall("nvdcve-1.1-[0-9]*\.json\.zip|nvdcve-1.1-modified\.json\.zip", r.text):
    r_file = requests.get("https://static.nvd.nist.gov/feeds/json/cve/1.1/" + filename, stream=True)
    with open(BASEDIR+"/nvd/" + filename, 'wb') as f:
        pbar = tqdm(unit="B", unit_scale=True, total=int(r_file.headers['Content-Length']), desc=filename)
        for chunk in r_file.iter_content(chunk_size=1024):
            f.write(chunk)
            pbar.update(1024)
        pbar.close()

files = [f for f in os.listdir(BASEDIR+"/nvd/") if isfile(join(BASEDIR+"/nvd/", f))]
files.sort()
for file in files:
    print("file:", file, join(BASEDIR+"/nvd/", file))
    archive = zipfile.ZipFile(BASEDIR+"/nvd/"+file, 'r')
    jsonfile = archive.open(archive.namelist()[0])
    cve_dict = json.loads(jsonfile.read())

    for cve_entry in tqdm(cve_dict['CVE_Items']):
        cve_id = cve_entry['cve']['CVE_data_meta']['ID']
        cve_year = cve_id.split('-')[1]

        if not os.path.exists(BASEDIR+'/data/'+cve_year):
            os.makedirs(BASEDIR+'/data/'+cve_year)

        with open(BASEDIR+'/data/'+cve_year+'/'+cve_id+'.json', 'w') as outfile:
            json.dump(cve_entry, outfile)
    jsonfile.close()
