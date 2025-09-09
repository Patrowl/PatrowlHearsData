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

import requests
import os
import json
import shutil

BASEDIR = os.path.dirname(os.path.realpath(__file__))
KEV_FILENAME = "kev.json"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
SLACK_TOKEN = os.getenv("SLACK_TOKEN", None)
SLACK_CHANNEL = os.getenv("SLACK_CHANNEL", "cert-cves-global")

def send_slack_message(message):
    if not SLACK_TOKEN or not SLACK_CHANNEL:
        return False

    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {SLACK_TOKEN}"
    }

    payload = {
        "channel": SLACK_CHANNEL,
        "text": message
    }

    response = requests.post("https://slack.com/api/chat.postMessage", headers=headers, json=payload)
    return response.ok

if not os.path.exists(BASEDIR + "/data/"):
    os.makedirs(BASEDIR + "/data/")

print("[+] Downloading and storing latest KEV data")
r_file = requests.get(KEV_URL)
KEV_FILE = f"{BASEDIR}/data/{KEV_FILENAME}"
if r_file.ok:
    with open(f"{KEV_FILE}.new", "wb") as f:
        for chunk in r_file.iter_content(chunk_size=1024 * 8):
            if chunk:
                f.write(chunk)
                f.flush()

    old_kev_list = json.load(open(KEV_FILE))
    new_kev_list = json.load(open(f"{KEV_FILE}.new"))

    old_cves = [item['cveID'] for item in old_kev_list['vulnerabilities']]
    new_cves = [item['cveID'] for item in new_kev_list['vulnerabilities']]
    added_cves = list(set(new_cves) - set(old_cves))
    # print(f"[+] {len(added_cves)} new CVE(s) in KEV list: {', '.join(added_cves)}")
    # print(f"[+] KEV list updated and stored in {KEV_FILE}")

    if len(added_cves) > 0:
        message = f":warning: *{len(added_cves)} new CVE(s) added to the KEV list* :warning:\n"
        for cve in new_kev_list['vulnerabilities']:
            if cve['cveID'] in added_cves:
                message += f"• *{cve['cveID']}* - {cve['vendorProject']} {cve['product']} - {cve['dateAdded']} - {cve['shortDescription']}\n"
        send_slack_message(message)
    
    # Replace old KEV file with the new one
    shutil.move(f"{KEV_FILE}.new", KEV_FILE)
