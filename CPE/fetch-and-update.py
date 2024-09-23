#!/bin/python3
import requests
import os
import shutil
import zipfile
import json
import xml.etree.ElementTree as ET
from tqdm import tqdm


CPE_FILENAME_ZIP = 'official-cpe-dictionary_v2.3.xml.zip'
CPEMATCH_FILENAME_ZIP = 'nvdcpematch-1.0.json.zip'
BASEDIR = os.path.dirname(os.path.realpath(__file__))

if not os.path.exists(BASEDIR+'/data/'):
    os.makedirs(BASEDIR+'/data/')
if not os.path.exists(BASEDIR+'/nvd/'):
    os.makedirs(BASEDIR+'/nvd/')

cpes = {}
counters = {'cpes': 0, 'vendors': 0, 'products': 0}
counters_diff = {'cpes': 0}

# print("[+] Backup old files")
# try:
#     shutil.move(BASEDIR+'/data/cpes.json', BASEDIR+'/data/cpes.json.old')
#     has_backup = True
# except Exception:
#     has_backup = False

print("[+] Downloading CPE dictionary from NVD")
r = requests.get('https://nvd.nist.gov/feeds/xml/cpe/dictionary/'+CPE_FILENAME_ZIP, stream=True)
with open(BASEDIR+"/nvd/"+CPE_FILENAME_ZIP, 'wb') as f:
    pbar = tqdm(unit="B", unit_scale=True, total=int(r.headers['Content-Length']))
    for chunk in r.iter_content(chunk_size=1024):
        f.write(chunk)
        pbar.update(1024)
    pbar.close()

# Process Official CPE dictionnary
print("[+] Processing CPE dictionary from NVD")
z = zipfile.ZipFile(BASEDIR+"/nvd/"+CPE_FILENAME_ZIP, 'r')
xmlfile = z.open(z.namelist()[0])
root = ET.fromstring(xmlfile.read())

for xcpe in tqdm(root.findall('{http://cpe.mitre.org/dictionary/2.0}cpe-item')):
    cpe_vector = xcpe.find('{http://scap.nist.gov/schema/cpe-extension/2.3}cpe23-item').attrib['name']
    cpe_title = xcpe.find('{http://cpe.mitre.org/dictionary/2.0}title').text
    cpe_vendor = cpe_vector.split(':')[3]
    cpe_product = cpe_vector.split(':')[4]

    if cpe_vendor not in cpes.keys():
        cpes.update({cpe_vendor: {}})
        counters.update({'vendors': counters['vendors']+1})
    if cpe_product not in cpes[cpe_vendor].keys():
        cpes[cpe_vendor].update({cpe_product: {}})
        counters.update({'products': counters['products']+1})
    if cpe_vector not in cpes[cpe_vendor][cpe_product].keys():
        cpes[cpe_vendor][cpe_product].update({cpe_vector: cpe_title})
        counters.update({'cpes': counters['cpes']+1})

# Quickfix: comment CPE Match Feed data, because:
# - as JSON is very large and kills the process with `json.loads` (we should use pandas to process the data),
# - as data seems to be redundant with CPE Dictionary.
#
# # Process NVD CPE matches
# print("[+] Downloading CPE matches from NVD")
# r = requests.get('https://nvd.nist.gov/feeds/json/cpematch/1.0/'+CPEMATCH_FILENAME_ZIP, stream=True)
# with open(BASEDIR+"/nvd/"+CPEMATCH_FILENAME_ZIP, 'wb') as f:
#     pbar = tqdm(unit="B", unit_scale=True, total=int(r.headers['Content-Length']))
#     for chunk in r.iter_content(chunk_size=1024):
#         f.write(chunk)
#         pbar.update(1024)
#
# print("[+] Processing CPE matches from NVD")
# archive = zipfile.ZipFile(os.path.join(BASEDIR+"/nvd/", CPEMATCH_FILENAME_ZIP), 'r')
# jsonfile = archive.open(archive.namelist()[0])
# cpes_dict = json.loads(jsonfile.read())
#
# for cpe in tqdm(cpes_dict['matches']):
#     cpe_vector = cpe['cpe23Uri']
#     cpe_title = cpe['cpe23Uri'].replace('_', ' ').title()
#     cpe_vendor = cpe_vector.split(':')[3]
#     cpe_product = cpe_vector.split(':')[4]
#
#     if cpe_vendor not in cpes.keys():
#         cpes.update({cpe_vendor: {}})
#         counters.update({'vendors': counters['vendors']+1})
#     if cpe_product not in cpes[cpe_vendor].keys():
#         cpes[cpe_vendor].update({cpe_product: {}})
#         counters.update({'products': counters['products']+1})
#     if cpe_vector not in cpes[cpe_vendor][cpe_product].keys():
#         cpes[cpe_vendor][cpe_product].update({cpe_vector: cpe_title})
#         counters.update({'cpes': counters['cpes']+1})

# with open(BASEDIR+'/data/cpes-latest.json', "w") as jf:
#     jf.write(json.dumps({
#         'cpes': cpes
#     }))
#     print(counters)

# with zipfile.ZipFile(BASEDIR+'/data/cpes.json.zip', 'w', zipfile.ZIP_DEFLATED) as zf:
#     zf.write(BASEDIR+'/data/cpes.json', arcname='cpes.json')

print("[+] Building diff file from latest CPE references")
with open(BASEDIR+'/data/cpes-base.json', "r") as jfo:
    cpes_oldies = json.loads(jfo.read())['cpes']
    cpes_diffs = {}

    # Loop over new vendors list
    for n_vendor in cpes.keys():
        for n_product in cpes[n_vendor].keys():
            for n_cpe in cpes[n_vendor][n_product].keys():
                try:
                    cpes_oldies[n_vendor][n_product][n_cpe]
                    is_new = False
                except KeyError:  # Fuck les jaloux
                    is_new = True

                if is_new:
                    cpes_diffs = {
                        **cpes_diffs,
                        **{
                            n_vendor: {
                                n_product: {
                                    n_cpe: cpes[n_vendor][n_product][n_cpe]
                                }
                            }
                        }
                    }
                    counters_diff.update({'cpes': counters_diff['cpes']+1})

    print(counters_diff)

    with open(BASEDIR+'/data/cpes-diff.json', "w") as jf:
        jf.write(json.dumps({
            'cpes': cpes_diffs
        }))
    # with zipfile.ZipFile(BASEDIR+'/data/cpes-diff.json.zip', 'w', zipfile.ZIP_DEFLATED) as zf:
    #     zf.write(BASEDIR+'/data/cpes-diff.json', arcname='cpes-diff.json')
