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
import os
import requests
import zipfile
import json
from datetime import datetime, timedelta
from dateutil.parser import parse
from tqdm import tqdm
from libs import probe, get_cpe_matches, get_monitored_technologies
BASEDIR = os.path.dirname(os.path.realpath(__file__))
DAYS_BEFORE = int(os.environ.get("DAYS_BEFORE", 2))
START_YEAR = 2002
NUCLEI_VENDORS_FILE = os.path.join(BASEDIR, "nuclei_vendors.txt")

last_check_date = datetime.now() - timedelta(days=DAYS_BEFORE)

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
            "tags": probe(reference, ["tags"], [])
        })

    return res_references

# Format problem types (CWE) to the required structure
def format_problem_types(problem_types):
    def_problemtypes = [{
        "description": [
            {
                "lang": "en",
                "value": "NVD-CWE-noinfo"
            }
        ]
    }]

    res_problemtypes = []
    cwe_values = []

    for problem_type in problem_types:
        if "description" not in problem_type.keys():
            continue

        for description in problem_type["description"]:
            value = "NVD-CWE-noinfo"
            if "CWE-" in description["value"]:
                value = description["value"].split(' ')[0]
            
            if value in cwe_values:
                continue
            cwe_values.append(value)

            res_problemtypes.append({
                "lang": "en",
                "value": value
            })

    if len(res_problemtypes) == 0:
        return def_problemtypes

    # return res_problemtypes
    return [{"description": res_problemtypes}]

def _select_nvd_cvss(cvss_metrics):
    # select source ""nvd@nist.gov"" as default. If not present, select the first one.
    for metric in cvss_metrics:
        if metric.get("source") == "nvd@nist.gov":
            metric.pop("source")
            metric.pop("type")
            return metric
    metric = cvss_metrics[0]
    metric.pop("source")
    metric.pop("type")
    return metric

def format_impacts(metrics):
    impacts = {}

    if "cvssMetricV2" in metrics.keys():
        cvss_metric = _select_nvd_cvss(metrics["cvssMetricV2"])
        cvss_metric["cvssV2"] = cvss_metric.pop("cvssData")
        impacts.update({
            "baseMetricV2": {
                "cvssV2": cvss_metric["cvssV2"],
                "exploitabilityScore": cvss_metric["exploitabilityScore"],
                "impactScore": cvss_metric["impactScore"],
                "severity": cvss_metric["baseSeverity"],
                "obtainAllPrivilege": cvss_metric.get("obtainAllPrivilege", False),
                "obtainUserPrivilege": cvss_metric.get("obtainUserPrivilege", False),
                "obtainOtherPrivilege": cvss_metric.get("obtainOtherPrivilege", False),
                "userInteractionRequired": cvss_metric.get("userInteractionRequired", False)
            }
        })
    if "cvssMetricV30" in metrics.keys():
        cvss_metric = _select_nvd_cvss(metrics["cvssMetricV30"])
        cvss_metric["cvssV3"] = cvss_metric.pop("cvssData")
        impacts.update({
            "baseMetricV3": cvss_metric
        })
    if "cvssMetricV31" in metrics.keys():
        # cvss_metric = metrics["cvssMetricV31"][0]
        cvss_metric = _select_nvd_cvss(metrics["cvssMetricV31"])
        cvss_metric["cvssV3"] = cvss_metric.pop("cvssData")
        impacts.update({
            "baseMetricV3": cvss_metric
        })
    if "cvssMetricV40" in metrics.keys():
        cvss_metric = _select_nvd_cvss(metrics["cvssMetricV40"])
        cvss_metric["cvssV4"] = cvss_metric.pop("cvssData")
        impacts.update({
            "baseMetricV4": cvss_metric
        })

    return impacts

def format_cpes(configurations):
    global cpe_matches, patrowl_vendors
    cpes = {
        "CVE_data_version": "4.0",
        "nodes": []
    }

    for configuration in configurations:
        for node in configuration.get("nodes", []):
            new_node = {
                "operator": node.get("operator", "OR"),
                "negate": node.get("negate", False),
                "children": [],
                "cpe_match": [],
            }
            for cpe_match in node.get("cpeMatch", []):
                new_cpe_match = {
                    "vulnerable": cpe_match.get("vulnerable", False),
                    "cpe23Uri": cpe_match.get("criteria", ""),
                    "matchCriteriaId" : cpe_match.get("matchCriteriaId", ""),
                    "cpe_name": []
                }
                for field in ["versionStartIncluding", "versionStartExcluding", "versionEndIncluding", "versionEndExcluding"]:
                    if field in cpe_match.keys():
                        new_cpe_match[field] = cpe_match[field]
                new_node["cpe_match"].append(new_cpe_match)

                # Limit CPE enrichment to Patrowl's monitored technologies only
                if len(new_cpe_match.keys()) > 4:
                    # Dynamic CPE, keep the match CriteriaId for later processing
                    vendor = cpe_match['criteria'].split(":")[3]
                    product = cpe_match['criteria'].split(":")[4]
                    # print("  - Found dynamic CPE:", cpe_match["criteria"], vendor, product, cpe_match.get("matchCriteriaId", ""))
                    if vendor in patrowl_vendors and product in patrowl_vendors[vendor]:
                        # Check the CPE is dynamic or not
                        # print("  - Found monitored & dynamic CPE:", cpe_match["criteria"])
                        mcid = cpe_match["matchCriteriaId"]
                        matching_cpes = []

                        if mcid in cpe_matches:
                            for cpe in cpe_matches[mcid]:
                                matching_cpes.append(cpe["cpeName"])
                        
                        # matching_cpes = clean_duplicated_cpes([node], matching_cpes)
                        # print("    - Enriched dynamic CPEs:", matching_cpes)
                        if len(matching_cpes) > 0:
                            matching_cpes = sorted(set(matching_cpes))  # Remove duplicates
                            for cpe in matching_cpes:
                                new_node["cpe_match"].append({
                                    "vulnerable": True,
                                    "cpe23Uri": cpe,
                                    "cpe_name": []
                            })
    
            cpes["nodes"].append(new_node)

    return cpes

# Create a temporary directory to store downloaded files
if not os.path.exists(BASEDIR+'/tmp-nvd/'):
    os.makedirs(BASEDIR+'/tmp-nvd/')

# Loading latest CPE matches from NVD feeds
cpe_matches = get_cpe_matches(BASEDIR)

# Load monitored technologies from Patrowl's Nuclei templates
patrowl_vendors = get_monitored_technologies(NUCLEI_VENDORS_FILE)

print("[+] Downloading CVE dictionaries by year from NVD v2")
for year in range(2002, datetime.now().year + 1):
    filename = f"nvdcve-2.0-{year}.json.zip"
    r_file = requests.get(f"https://nvd.nist.gov/feeds/json/cve/2.0/{filename}", stream=True)

    with open(BASEDIR+"/tmp-nvd/" + filename, 'wb') as f:
        pbar = tqdm(unit="B", unit_scale=True, total=int(r_file.headers['Content-Length']), desc=filename)
        for chunk in r_file.iter_content(chunk_size=1024):
            f.write(chunk)
            pbar.update(1024)
        pbar.close()

print("[+] CVE dictionaries downloaded successfully!")
print("[+] Unzipping and processing CVE dictionaries...")
for year in range(START_YEAR, datetime.now().year + 1):
    archive = zipfile.ZipFile(f"{BASEDIR}/tmp-nvd/nvdcve-2.0-{year}.json.zip", 'r')
    jsonfile = archive.open(archive.namelist()[0])
    cves_dict = json.loads(jsonfile.read())["vulnerabilities"]

    for cve_entry in tqdm(cves_dict):
        # print(cve_entry)
        cve = cve_entry["cve"]
        date_updated = parse(cve["lastModified"], ignoretz=True)
        
        # Check if CVE was updated in the last DAYS_BEFORE days
        if last_check_date > date_updated:
            continue

        cve_id = probe(cve, ["id"])

        cve_content = {
            "publishedDate": parse(cve["published"], ignoretz=True).strftime("%Y-%m-%dT%H:%MZ"),
            "lastModifiedDate": date_updated.strftime("%Y-%m-%dT%H:%MZ"),
            "cve": {
                "data_type": "CVE",
                "data_format": "MITRE",
                "data_version": "1.0",
                "CVE_data_meta": {
                    "ID": cve_id,
                    "ASSIGNER": probe(cve, ["sourceIdentifier"])
                },
                "description": {
                    "description_data": probe(cve, ["descriptions"], []),
                },
                "references": {
                    "reference_data": format_references(probe(cve, ["references"], [])),
                },
                "problemtype": {
                    "problemtype_data": format_problem_types(probe(cve, ["weaknesses"], [])),
                }
            },
            "impact": format_impacts(probe(cve, ["metrics"])),
            "configurations": format_cpes(probe(cve, ["configurations"], {}))
        }
        # print(json.dumps(cve_content, indent=4, default=str))

        cve_year = cve_id.split('-')[1]
        year_dir = BASEDIR+'/data/'+cve_year
        if not os.path.exists(year_dir):
            os.makedirs(year_dir)

        with open(f"{year_dir}/{cve_id}.json", 'w') as outfile:
            json.dump(cve_content, outfile)

        # break
    # break


    