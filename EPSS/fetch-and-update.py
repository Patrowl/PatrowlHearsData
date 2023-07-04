#!/usr/bin/env -S python3 -OO
# coding:utf8

# Copyright (c) 2020-2023, Patrowl and contributors
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

import requests
import gzip
import os
import json
import shutil
from tqdm import tqdm
BASEDIR = os.path.dirname(os.path.realpath(__file__))
EPSS_FILENAME = "epss_scores-current.csv.gz"

if not os.path.exists(BASEDIR+'/data/'):
    os.makedirs(BASEDIR+'/data/')

print("[+] Downloading latest EPSS data")
r_file = requests.get(f"https://epss.cyentia.com/{EPSS_FILENAME}", stream=True)
with open(f"{BASEDIR}/data/{EPSS_FILENAME}", 'wb') as f:
    pbar = tqdm(unit="B", unit_scale=True, total=int(r_file.headers['Content-Length']), desc=EPSS_FILENAME)
    for chunk in r_file.iter_content(chunk_size=1024):
        f.write(chunk)
        pbar.update(1024)


epss_data = {}
epss_data_previous = {}
epss_data_diff = {}

print("[+] Archiving and loading previous EPSS data (if any)")
has_previous = False
if os.path.isfile(BASEDIR+'/data/epss-latest.json'):
    shutil.copyfile(
        BASEDIR+'/data/epss-latest.json',
        BASEDIR+'/data/epss-previous.json'
    )
    has_previous = True
    with open(BASEDIR+'/data/epss-previous.json', 'r') as f_previous:
        epss_data_previous = json.load(f_previous)['epss']

print("[+] Checking latest EPSS data")
with gzip.open(f"{BASEDIR}/data/{EPSS_FILENAME}",'r') as fin:
    epss_score_date = fin.readline().strip().decode("utf-8").split(',')[1].replace('score_date:', '')
    print(epss_score_date)
    next(fin) # Skip the header line
    for line in fin:        
        cve_id, epss, percentile = line.strip().decode("utf-8").split(',')
        epss_data[cve_id] = {'epss': epss, 'percentile': percentile, 'date': epss_score_date}
        
        if has_previous and cve_id in epss_data_previous.keys() and (
                epss != epss_data_previous[cve_id]['epss'] or
                percentile != epss_data_previous[cve_id]['percentile']
            ):
            epss_data_diff[cve_id] = {'epss': epss, 'percentile': percentile, 'date': epss_score_date}

print("[+] Storing latest EPSS data")
with open(BASEDIR+'/data/epss-latest.json', "w") as epss_json_file:
    epss_json_file.write(json.dumps({
        'epss': epss_data
    }))

print("[+] Storing diff EPSS data")
with open(BASEDIR+'/data/epss-diff.json', "w") as epss_json_file:
    epss_json_file.write(json.dumps({
        'epss': epss_data_diff
    }))
