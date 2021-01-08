#!/bin/python3
import requests
import os
import shutil
import json
from tqdm import tqdm
import zipfile


BASEDIR = os.path.dirname(os.path.realpath(__file__))
if not os.path.exists(BASEDIR+'/data/'):
    os.makedirs(BASEDIR+'/data/')

#
# print("[+] Backup old files")
# try:
#     shutil.move(BASEDIR+'/data/via.json', BASEDIR+'/data/via.json.old')
#     has_backup = True
# except Exception:
#     has_backup = False


try:
    print("[+] Download latest VIA references")
    r = requests.get('https://www.cve-search.org/feeds/via4.json', stream=True)
    with open(BASEDIR+"/data/via-latest.json", 'wb') as f:
        pbar = tqdm(unit="B", unit_scale=True, total=int(r.headers['Content-Length']), desc="Download VIA.json")
        for chunk in r.iter_content(chunk_size=1024):
            f.write(chunk)
            pbar.update(1024)
        pbar.close()

    # with zipfile.ZipFile(BASEDIR+'/data/via.json.zip', 'w', zipfile.ZIP_DEFLATED) as zf:
    #     zf.write(BASEDIR+'/data/via.json', arcname='via.json')

except Exception as e:
    print(e)
    pass


print("[+] Building diff file from latest VIA references")
vias_diffs = {}
with open(BASEDIR+'/data/via-base.json', "r") as jfo:
    vias_oldies = json.loads(jfo.read())['cves']

    with open(BASEDIR+'/data/via-latest.json', "r") as jf:
        vias_news = json.loads(jf.read())['cves']

        # Loop over CVES from new VIA
        for cve_id in vias_news.keys():

            # if cve_id == 'CVE-2020-13935':
            #     print(vias_news[cve_id])
            #     break
            if cve_id not in vias_oldies.keys():
                # New CVE:
                vias_diffs.update({cve_id: vias_news[cve_id]})
            else:
                for subitem in vias_news[cve_id]:
                    if subitem not in vias_oldies[cve_id].keys() or vias_oldies[cve_id][subitem] != vias_news[cve_id][subitem]:
                        vias_diffs = {
                            **vias_diffs,
                            **{cve_id: vias_news[cve_id][subitem]}
                        }

with open(BASEDIR+'/data/via-diff.json', "w") as jf:
    jf.write(json.dumps({
        'cves': vias_diffs
    }))
# with zipfile.ZipFile(BASEDIR+'/data/via-diff.json.zip', 'w', zipfile.ZIP_DEFLATED) as zf:
#     zf.write(BASEDIR+'/data/via-diff.json', arcname='via-diff.json')
