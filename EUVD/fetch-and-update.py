#!/usr/bin/env -S python3 -OO
# coding:utf8

# Copyright (c) 2020-2025, Patrowl and contributors
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# Redistributions of source code must retain the above copyright notice, this
# list of conditions and the following disclaimer.  Redistributions in binary
# form must reproduce the above copyright notice, this list of conditions and the
# following disclaimer in the documentation and/or other materials provided with
# the distribution
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

# 

import requests
import os
from datetime import datetime, timedelta
from dateutil.parser import parse
import json
from tqdm import tqdm

BASEDIR = os.path.dirname(os.path.realpath(__file__))
DAYS_BEFORE = int(os.environ.get("EUVD_DAYS_BEFORE", 1))
TO_DATE = str(os.environ.get("EUVD_TO_DATE", ""))
EUVD_BASEURL = "https://euvdservices.enisa.europa.eu"
EUVD_SEARCH_ENDPOINT = "/api/search"
EUVD_API_HEADERS = {"Content-Type": "application/json", "User-Agent": "PatrowlHears-Agent"}
RESULTS_PER_PAGE = int(os.environ.get("RESULTS_PER_PAGE", 100))
FIRST_PAGE = int(os.environ.get("FIRST_PAGE", 0))
KEV_FILENAME = os.environ.get("KEV_FILENAME", f"{BASEDIR}/data/kev.json")

def get_vulns(days_before:int=1, page:int=0, is_exploited:bool=False):
    from_date = (datetime.now() - timedelta(days=days_before)).strftime("%Y-%m-%d")
    params = {"fromDate": from_date, "page": page, "size": RESULTS_PER_PAGE}
    if TO_DATE != "":
        params["toUpdatedDate"] = TO_DATE
    if is_exploited:
        params["exploited"] = "true"
    try:
        r = requests.get(
            EUVD_BASEURL + EUVD_SEARCH_ENDPOINT,
            params=params, headers=EUVD_API_HEADERS,
            timeout=(10, 30),
        )
    except Exception as e:
        print(r.request.url)
        print(f"[-] Error querying EUVD: {e}")
        return {}

    return r.json()

def parse_vuln(vuln):
    if "datePublished" in vuln and vuln["datePublished"] != "":
        try:
            vuln["datePublished"] = parse(vuln["datePublished"]).isoformat()
        except Exception:
            pass
    if "dateUpdated" in vuln and vuln["dateUpdated"] != "":
        try:
            vuln["dateUpdated"] = parse(vuln["dateUpdated"]).isoformat()
        except Exception:
            pass
    if "exploitedSince" in vuln and vuln["exploitedSince"] != "":
        try:
            vuln["exploitedSince"] = parse(vuln["exploitedSince"]).isoformat()
            vuln["isExploited"] = True
        except Exception:
            pass
    else:
        vuln["isExploited"] = False
    if "references" in vuln and vuln["references"] != "":
        try:
            vuln["references"] = [ref.strip() for ref in vuln["references"].split("\n") if ref.strip() != ""]
        except Exception:
            pass
    if "aliases" in vuln and vuln["aliases"] != "":
        try:
            vuln["aliases"] = [alias.strip() for alias in vuln["aliases"].split("\n") if alias.strip() != ""]
        except Exception:
            pass
    return vuln

# def is_updated(vuln, days_before=1):
#     if "dateUpdated" in vuln and vuln["dateUpdated"] != "":
#         try:
#             date_updated = parse(vuln["dateUpdated"])
#             if date_updated >= datetime.now() - timedelta(days=days_before):
#                 return True
#         except Exception:
#             pass
#     return False

if not os.path.exists(BASEDIR + "/data/"):
    os.makedirs(BASEDIR + "/data/")

print(f"[+] Querying EUVD for vulnerabilities updated in the last {DAYS_BEFORE} days...")
page = FIRST_PAGE
vulns = get_vulns(days_before=DAYS_BEFORE, page=page)
pbar = tqdm(total=vulns['total'], unit='vulns')
nb_new_vulns = 0
print(f"[+] Retrieving {vulns['total']} vulnerabilities from EUVD.")
while "items" in vulns and len(vulns["items"]) > 0:
    for vuln in vulns["items"]:
        v = parse_vuln(vuln)
        v_id = v["id"]
        v_year = v_id.split('-')[1]
        year_dir = BASEDIR+'/data/'+v_year
        if not os.path.exists(year_dir):
            os.makedirs(year_dir)

        # print(f"[+] Saving vulnerability {v_id}, exploitable={v["isExploited"]}...")
        vuln_path = f"{year_dir}/{v_id}.json"
        if os.path.exists(vuln_path) is False:
            nb_new_vulns += 1
            
        with open(vuln_path, 'w') as outfile:
            json.dump(v, outfile)
        pbar.update(1)
    page += 1
    vulns = get_vulns(days_before=DAYS_BEFORE, page=page)

pbar.close()
print(f"[+] EUVD vulns fetch-and-update completed. {nb_new_vulns} new vulnerabilities added.")


print(f"[+] Querying EUVD for known vulnerabilities vulnerabilities in the last {DAYS_BEFORE} days...")
page = 0
vulns = get_vulns(days_before=DAYS_BEFORE, page=page, is_exploited=True)
pbar = tqdm(total=vulns['total'], unit='KEV')
nb_new_kev_vulns = 0
kev_vulns = {}
if os.path.exists(KEV_FILENAME):
    with open(KEV_FILENAME, 'r') as infile:
        kev_vulns = json.load(infile)

print(f"[+] Retrieving {vulns['total']} vulnerabilities from EUVD.")
while "items" in vulns and len(vulns["items"]) > 0:
    for vuln in vulns["items"]:
        v = parse_vuln(vuln)
        v_id = v["id"]
        if v_id not in kev_vulns:
            kev_vulns[v_id] = {
                "datePublished": v["datePublished"],
                "dateUpdated": v["dateUpdated"],
                "exploitedSince": v["exploitedSince"],
                "aliases": v["aliases"],
            }
            nb_new_kev_vulns += 1
            
        pbar.update(1)
    page += 1
    vulns = get_vulns(days_before=DAYS_BEFORE, page=page, is_exploited=True)

pbar.close()
with open(KEV_FILENAME, 'w') as outfile:
    json.dump(kev_vulns, outfile)
print(f"[+] EUVD KEV fetch-and-update completed. {nb_new_kev_vulns} new vulnerabilities added.")