#!/usr/bin/env -S python3 -OO
# coding:utf8

# Copyright (c) 2020-2026, Patrowl and contributors
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

import os
import shutil
import git
import datetime
from dateutil.parser import parse
import json
from libs import probe, format_impacts
from ghsa_to_cpe import advisory_to_cpe_suggestions
BASEDIR = os.path.dirname(os.path.realpath(__file__))
BASEDIR_DATA = f"{BASEDIR}/data"
BASEDIR_TMP = f"{BASEDIR}/tmp"
BASEDIR_ADV = f"{BASEDIR_TMP}/advisories/github-reviewed"

# Format references to the required structure
def format_references(references):
    res_references = []

    for reference in references:
        url = probe(reference, ["url"])
        if url == "":
            continue

        res_references.append({
            "url": url,
            "name": "",
            "refsource": "",
            "tags": probe(reference, ["type"], [])
        })

    return res_references

# Format problem types (CWE) to the required structure
def format_problem_types(cwe_ids):
    if len(cwe_ids) == 0:
        return [{
            "description": [
                {
                    "lang": "en",
                    "value": "NVD-CWE-noinfo"
                }
            ]
        }]
    
    problemtypes = []

    for cwe_id in cwe_ids:
        problemtypes.append({
            "lang": "en",
            "value": cwe_id
        })

    return [{"description": problemtypes}]

def format_cpes(affected):
    cpe_matches = advisory_to_cpe_suggestions(affected)
    # print(cpe_matches)
    configurations = {
        "CVE_data_version": "4.0",
        "nodes": []
    }  

    for affected in cpe_matches['affected']:
        if affected["ecosystem"] == "Maven":
            # not yet supported
            continue
        node = {
            "operator": "OR",
            "cpe_match": affected["cpe"]['cpeMatch']
            
        }
        if len(affected["cpe"]['representative_exact_criteria']) > 0:
            for rep_cpe in affected["cpe"]['representative_exact_criteria']:
                node["cpe_match"].append({
                    "cpe23Uri": rep_cpe,
                    "vulnerable": True,
                })
        configurations["nodes"].append(node)

    return configurations


print("[+] Downloading GHSA reports from Github repo github/advisory-database")
if os.path.exists(BASEDIR+'/tmp') and os.path.isdir(BASEDIR+'/tmp'):
    shutil.rmtree(BASEDIR+'/tmp')
# git.Repo.clone_from(
#     'https://github.com/github/advisory-database',
#     BASEDIR_TMP,
#     depth=1
# )
git.Repo.clone_from(
    'https://github.com/github/advisory-database',
    BASEDIR_TMP,
    multi_options=[
        '--depth=1',
        '--single-branch',
    ],
)
shutil.rmtree(f"{BASEDIR_TMP}/.git")

for year in range(2017, datetime.datetime.now().year + 1):
    # Check if dir exists
    if not os.path.exists(f"{BASEDIR_ADV}/{year}"):
        continue

    # if not os.path.isdir(f"{BASEDIR_DATA}/{year}"):
    #     os.makedirs(f"{BASEDIR_DATA}/{year}")

    for month_dir in os.listdir(f"{BASEDIR_ADV}/{year}"):
        for ghsa_dir in os.listdir(f"{BASEDIR_ADV}/{year}/{month_dir}"):
            for filename in os.listdir(f"{BASEDIR_ADV}/{year}/{month_dir}/{ghsa_dir}"):
                if filename.endswith(".json"):
                    with open(f"{BASEDIR_ADV}/{year}/{month_dir}/{ghsa_dir}/{filename}", "r") as f:
                        ghsa_data = json.load(f)
                        if "aliases" in ghsa_data and len(ghsa_data["aliases"]) > 0:
                            for alias in ghsa_data["aliases"]:
                                if alias.startswith("CVE-"):
                                    cve_id = alias
                                    print(f"[+] Found CVE {cve_id} in {filename}")

                                    cve_content = {
                                        "publishedDate": parse(ghsa_data["published"], ignoretz=True).strftime("%Y-%m-%dT%H:%MZ"),
                                        "lastModifiedDate": parse(ghsa_data["modified"], ignoretz=True).strftime("%Y-%m-%dT%H:%MZ"),
                                        "cve": {
                                            "data_type": "CVE",
                                            "data_format": "MITRE",
                                            "data_version": "1.0",
                                            "CVE_data_meta": {
                                                "ID": cve_id,
                                                "ASSIGNER": ""
                                            },
                                            "description": {
                                                "description_data": [{
                                                    "lang": "en",
                                                    "value": probe(ghsa_data, ["summary"], "") + "\n\n" + probe(ghsa_data, ["details"], "")
                                                }]
                                            },
                                            "references": {
                                                "reference_data": format_references(probe(ghsa_data, ["references"], [])),
                                            },
                                            "problemtype": {
                                                "problemtype_data": format_problem_types(probe(ghsa_data, ["database_specific", "cwe_ids"], [])),
                                            }
                                        },
                                        "impact": format_impacts(probe(ghsa_data, ["severity"])),
                                        "configurations": format_cpes(ghsa_data),
                                        "ghsa_metadata": {
                                            "id": ghsa_data["id"],
                                            "summary": probe(ghsa_data, ["summary"], ""),
                                            "url": f"https://github.com/advisories/{ghsa_data['id']}",
                                            "github_reviewed": probe(ghsa_data, ["database_specific", "github_reviewed"], False),
                                            "github_reviewed_at": parse(probe(ghsa_data, ["database_specific", "github_reviewed_at"], ""), ignoretz=True).strftime("%Y-%m-%dT%H:%MZ") if probe(ghsa_data, ["database_specific", "github_reviewed_at"], "") != "" else "",
                                            "affected_packages": probe(ghsa_data, ["affected"], []),
                                        }
                                    }

                                    cve_year = cve_id.split('-')[1]
                                    year_dir = BASEDIR+'/data/'+cve_year
                                    if not os.path.exists(year_dir):
                                        os.makedirs(year_dir)

                                    with open(f"{BASEDIR_DATA}/{cve_year}/{cve_id}.json", "w") as f_out:
                                        json.dump(cve_content, f_out, indent=4)